mod aggregate;
mod history;
mod live;
mod maintenance;
mod persistence;
mod storage;

pub use aggregate::{HistoryPoint, MetricAggregate, network_metric_key};
pub(crate) use history::read_aggregate;
pub use history::{AggregateHistory, AggregateQuery, aggregate_history, read_minutes, read_window};
pub(crate) use live::dashboard_live;
pub use live::{LiveSample, LiveStore, attach_live, latest_live, live};
pub use maintenance::{maintain, maintain_at};
pub use storage::{
    agent_storage_settings, policy, storage_settings, update_policy, update_storage_settings,
};

use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
};
use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sinan_protocol::{
    AgentSettings, TelemetryAck, TelemetryBatch, TelemetrySample, telemetry::now_millis,
};
use sqlx::Row;
use std::{collections::HashSet, io::Read};

const MAX_BODY: usize = 1024 * 1024;

fn decode(headers: &HeaderMap, bytes: &Bytes) -> ApiResult<TelemetryBatch> {
    if bytes.len() > MAX_BODY {
        return Err(ApiError::BadRequest("遥测批次超过大小上限".into()));
    }
    let body = match headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        None | Some("identity") => bytes.to_vec(),
        Some("gzip") => {
            let mut result = Vec::new();
            GzDecoder::new(bytes.as_ref())
                .take((MAX_BODY + 1) as u64)
                .read_to_end(&mut result)
                .map_err(|_| ApiError::BadRequest("遥测压缩数据无效".into()))?;
            if result.len() > MAX_BODY {
                return Err(ApiError::BadRequest("遥测解压大小超过上限".into()));
            }
            result
        }
        _ => return Err(ApiError::BadRequest("不支持的遥测编码".into())),
    };
    serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("遥测批次格式无效".into()))
}

fn valid_sample(sample: &TelemetrySample, now: i64) -> bool {
    let nonnegative = |value: Option<f64>| {
        value.is_none_or(|value| value.is_finite() && (0.0..=1.0e18).contains(&value))
    };
    sample.sampled_at > 0
        && sample.sampled_at <= now + 60_000
        && sample.sampled_at >= now - 7 * 86_400_000
        && sample.metrics.network_interfaces.len() <= 256
        && sample.metrics.disks.len() <= 256
        && sample.metrics.gpus.len() <= 32
        && ["memory_total", "disk_total"].into_iter().all(|key| {
            sample
                .metrics
                .extra
                .get(key)
                .is_none_or(|value| value.is_null() || value.as_u64().is_some())
        })
        && sample
            .metrics
            .cpu_percent
            .is_none_or(|v| v.is_finite() && (0.0..=100.0).contains(&v))
        && sample.metrics.gpus.iter().all(|v| {
            v.model.len() <= 256
                && !v.model.contains('\0')
                && v.usage_percent
                    .is_none_or(|v| v.is_finite() && (0.0..=100.0).contains(&v))
        })
        && [
            sample.metrics.load_1,
            sample.metrics.load_5,
            sample.metrics.load_15,
        ]
        .into_iter()
        .all(nonnegative)
        && sample
            .metrics
            .network_interfaces
            .iter()
            .all(|(name, value)| {
                name.len() <= 1024
                    && !name.contains('\0')
                    && nonnegative(value.receive_bytes_per_sec)
                    && nonnegative(value.transmit_bytes_per_sec)
            })
        && sample.metrics.disks.iter().all(|v| {
            v.name.len() <= 1024
                && v.mount_point.len() <= 4096
                && !v.name.contains('\0')
                && !v.mount_point.contains('\0')
                && [
                    v.read_bytes_per_sec,
                    v.write_bytes_per_sec,
                    v.read_iops,
                    v.write_iops,
                    v.await_ms,
                ]
                .into_iter()
                .all(nonnegative)
                && v.utilization_percent
                    .is_none_or(|value| value.is_finite() && (0.0..=100.0).contains(&value))
        })
}

pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult<Json<TelemetryAck>> {
    let server = auth::require_agent(&state, &headers).await?;
    let batch = decode(&headers, &bytes)?;
    let now = now_millis();
    let mut ids = HashSet::new();
    if batch.samples.is_empty()
        || batch.samples.len() > 64
        || !batch
            .samples
            .iter()
            .all(|v| valid_sample(v, now) && ids.insert(v.id))
    {
        return Err(ApiError::BadRequest("遥测样本重复、过期或格式无效".into()));
    }
    Ok(Json(
        persistence::save(&state.pool, server, batch, now).await?,
    ))
}

pub async fn agent_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AgentSettings>> {
    let server = auth::require_agent(&state, &headers).await?;
    read_settings(&state, server).await
}

async fn read_settings(state: &AppState, server: i64) -> ApiResult<Json<AgentSettings>> {
    let value: serde_json::Value =
        sqlx::query_scalar("SELECT agent_settings FROM servers WHERE id=$1 AND deleted_at IS NULL")
            .bind(server)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    Ok(Json(
        serde_json::from_value(value).map_err(anyhow::Error::from)?,
    ))
}

pub async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<AgentSettings>> {
    auth::require_admin(&state, &headers).await?;
    read_settings(&state, server).await
}

pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(settings): Json<AgentSettings>,
) -> ApiResult<Json<AgentSettings>> {
    auth::require_admin(&state, &headers).await?;
    if !settings.valid() {
        return Err(ApiError::BadRequest(
            "采样与上传间隔必须在 1–60 秒内，上传间隔不能小于采样间隔".into(),
        ));
    }
    let result =
        sqlx::query("UPDATE servers SET agent_settings=$2 WHERE id=$1 AND deleted_at IS NULL")
            .bind(server)
            .bind(serde_json::to_value(&settings).map_err(anyhow::Error::from)?)
            .execute(&state.pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(settings))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub since: Option<i64>,
}

pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Query(query): Query<HistoryQuery>,
) -> ApiResult<Json<Vec<TelemetrySample>>> {
    auth::require_admin(&state, &headers).await?;
    read_history(&state, server, query).await
}

pub(crate) async fn read_history(
    state: &AppState,
    server: i64,
    query: HistoryQuery,
) -> ApiResult<Json<Vec<TelemetrySample>>> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(server)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let since = query
        .since
        .unwrap_or(now_millis() - 3_600_000)
        .max(now_millis() - 2 * 3_600_000);
    let rows = sqlx::query("SELECT id,sampled_at,metrics FROM telemetry_samples WHERE server_id=$1 AND sampled_at>=$2 ORDER BY sampled_at DESC LIMIT 7200")
        .bind(server).bind(since).fetch_all(&state.pool).await?;
    let mut samples = rows
        .into_iter()
        .map(|row| {
            Ok(TelemetrySample {
                id: row.get("id"),
                sampled_at: row.get("sampled_at"),
                metrics: serde_json::from_value(row.get("metrics"))?,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()
        .map_err(anyhow::Error::from)?;
    samples.reverse();
    Ok(Json(samples))
}
