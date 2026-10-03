use super::*;
use serde_json::{Value, json};
use sinan_protocol::telemetry::TelemetrySettings;
use std::{collections::HashMap, sync::Mutex};

const MAX_LIVE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct LiveSample {
    pub sample: TelemetrySample,
    pub received_at: i64,
}

struct Entry {
    value: LiveSample,
    bytes: usize,
}

#[derive(Default)]
pub struct LiveStore {
    entries: Mutex<HashMap<i64, Entry>>,
}

impl LiveStore {
    pub fn get(&self, server: i64) -> Option<LiveSample> {
        self.entries
            .lock()
            .ok()?
            .get(&server)
            .filter(|entry| now_millis() - entry.value.received_at <= 600_000)
            .map(|entry| entry.value.clone())
    }
    fn publish(&self, server: i64, sample: TelemetrySample, now: i64) -> ApiResult<()> {
        let bytes = serde_json::to_vec(&sample)
            .map_err(anyhow::Error::from)?
            .len();
        if bytes > 128 * 1024 {
            return Err(ApiError::BadRequest("实时样本超过大小上限".into()));
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("live cache lock poisoned"))?;
        if entries
            .get(&server)
            .is_some_and(|entry| entry.value.sample.sampled_at >= sample.sampled_at)
        {
            return Ok(());
        }
        entries.retain(|_, entry| now - entry.value.received_at <= 600_000);
        entries.insert(
            server,
            Entry {
                value: LiveSample {
                    sample,
                    received_at: now,
                },
                bytes,
            },
        );
        let mut total: usize = entries.values().map(|entry| entry.bytes).sum();
        while total > MAX_LIVE_BYTES {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.value.received_at)
                .map(|(id, _)| *id);
            let Some(oldest) = oldest else { break };
            if let Some(entry) = entries.remove(&oldest) {
                total -= entry.bytes;
            }
        }
        Ok(())
    }
}

pub fn latest_live(state: &AppState, server: i64) -> Option<LiveSample> {
    state.telemetry_live.get(server)
}

pub async fn live(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(sample): Json<TelemetrySample>,
) -> ApiResult<Json<Value>> {
    let server = auth::require_agent(&state, &headers).await?;
    let now = now_millis();
    if !valid_sample(&sample, now) {
        return Err(ApiError::BadRequest("实时样本格式或时间无效".into()));
    }
    let sampled_at = sample.sampled_at;
    state.telemetry_live.publish(server, sample, now)?;
    // Receipt is explicitly not a durable ACK; the Agent keeps its outbox.
    Ok(Json(json!({"accepted":true,"sampled_at":sampled_at})))
}

pub async fn attach_live(
    state: &AppState,
    servers: &mut [crate::servers::Server],
) -> ApiResult<()> {
    let ids: Vec<i64> = servers.iter().map(|server| server.id).collect();
    let rows = sqlx::query("SELECT id,telemetry_settings FROM servers WHERE id=ANY($1)")
        .bind(&ids)
        .fetch_all(&state.pool)
        .await?;
    let settings: HashMap<i64, TelemetrySettings> = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.get("id"),
                serde_json::from_value(row.get("telemetry_settings"))?,
            ))
        })
        .collect::<Result<_, serde_json::Error>>()
        .map_err(anyhow::Error::from)?;
    let now = now_millis();
    for server in servers {
        server.metrics_persisted_at = server.metrics_sampled_at;
        server.served_at = now;
        server.telemetry_settings = settings.get(&server.id).cloned();
        if let Some(value) = latest_live(state, server.id)
            .filter(|value| Some(value.sample.sampled_at) >= server.metrics_sampled_at)
        {
            server.metrics_sampled_at = Some(value.sample.sampled_at);
            server.latest_metrics =
                serde_json::to_value(value.sample.metrics).map_err(anyhow::Error::from)?;
            server.metrics_received_at = Some(value.received_at);
        }
        server.metrics_stale = is_stale(server.metrics_sampled_at, &server.agent_settings, now);
    }
    Ok(())
}

fn is_stale(sampled: Option<i64>, settings: &Value, now: i64) -> bool {
    let settings: AgentSettings = serde_json::from_value(settings.clone()).unwrap_or_default();
    let allowance = (settings.sample_interval_secs * 3 + settings.upload_interval_secs * 2).max(15)
        as i64
        * 1000;
    sampled.is_none_or(|at| now.saturating_sub(at) > allowance)
}

pub(crate) async fn dashboard_live(state: &AppState, admin: bool) -> ApiResult<Value> {
    let rows=sqlx::query("SELECT id,last_seen,last_heartbeat_at,NULLIF(metrics_sampled_at,0) AS metrics_sampled_at,latest_metrics,agent_settings FROM servers WHERE deleted_at IS NULL AND COALESCE(asset_settings->>'hidden','false')<>'true' ORDER BY id").fetch_all(&state.pool).await?;
    let now = now_millis();
    let mut servers = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.get("id");
        let persisted: Option<i64> = row.get("metrics_sampled_at");
        let mut sampled = persisted;
        let mut received = None;
        let mut metrics: Value = row.get("latest_metrics");
        if let Some(value) =
            latest_live(state, id).filter(|value| Some(value.sample.sampled_at) >= persisted)
        {
            sampled = Some(value.sample.sampled_at);
            received = Some(value.received_at);
            metrics = serde_json::to_value(value.sample.metrics).map_err(anyhow::Error::from)?;
        }
        let last_seen: Option<i64> = row.get("last_seen");
        servers.push(json!({"id":id,"last_seen":last_seen,"last_heartbeat_at":row.get::<Option<i64>,_>("last_heartbeat_at"),"online":last_seen.is_some_and(|seen|now/1000-seen<=60),"metrics_sampled_at":sampled,"metrics_received_at":received,"metrics_persisted_at":persisted,"metrics_stale":is_stale(sampled,&row.get("agent_settings"),now),"latest_metrics":if admin {metrics} else {crate::dashboard::public_metrics(&metrics)}}));
    }
    Ok(json!({"served_at":now,"public_view":!admin,"servers":servers}))
}
