use super::{
    api::{authorize, authorize_steps},
    model::{Plan, label},
};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

pub async fn schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "operations:read").await?;
    let rows=sqlx::query("SELECT targets,to_jsonb(s) AS value FROM operations_schedules s ORDER BY created_at DESC LIMIT 100").fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    for row in rows {
        let ids: Vec<i64> = row.get("targets");
        if authorize(&state, &headers, &ids, false).await.is_ok() {
            values.push(row.get("value"));
        }
    }
    Ok(Json(values))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    name: String,
    plan: Plan,
    targets: Vec<i64>,
    next_run_at: i64,
    interval_secs: i64,
    timezone_offset_minutes: i32,
    missed_policy: String,
    max_runs: i32,
}

pub async fn save_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Schedule>,
) -> ApiResult<Json<Value>> {
    request.plan.validate(&request.targets)?;
    label(&request.name, 128)?;
    let actor = authorize(&state, &headers, &request.targets, true).await?;
    authorize_steps(&state, &headers, &request.targets, &request.plan).await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let now = now_timestamp();
    if request.next_run_at < now
        || request.next_run_at > now + 31536000
        || !(300..=31536000).contains(&request.interval_secs)
        || !(-720..=840).contains(&request.timezone_offset_minutes)
        || !(1..=10000).contains(&request.max_runs)
        || !matches!(request.missed_policy.as_str(), "skip" | "run_once")
    {
        return Err(ApiError::BadRequest(
            "计划时间、时区、周期、错过策略或最大次数无效".into(),
        ));
    }
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    let typed_steps =
        super::typed_steps::preview(&state, &mut tx, &request.targets, &request.plan).await?;
    sqlx::query("INSERT INTO operations_schedules(id,name,requested_by,spec,targets,next_run_at,interval_secs,timezone_offset_minutes,missed_policy,max_runs,paused,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false,$11,$11)")
        .bind(id).bind(request.name).bind(actor).bind(json!({"plan":request.plan,"typed_steps":typed_steps})).bind(request.targets).bind(request.next_run_at).bind(request.interval_secs).bind(request.timezone_offset_minutes).bind(request.missed_policy).bind(request.max_runs).bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"status":"scheduled"})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pause {
    paused: bool,
}

pub async fn pause_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Pause>,
) -> ApiResult<Json<Value>> {
    let row = sqlx::query("SELECT targets,spec FROM operations_schedules WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let ids: Vec<i64> = row.get("targets");
    authorize(&state, &headers, &ids, true).await?;
    if !request.paused {
        let spec: Value = row.get("spec");
        let plan: Plan =
            serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
        authorize_steps(&state, &headers, &ids, &plan).await?;
        control_center::require_recent_proof(&state, &headers).await?;
    }
    sqlx::query("UPDATE operations_schedules SET paused=$2,updated_at=$3 WHERE id=$1")
        .bind(id)
        .bind(request.paused)
        .bind(now_timestamp())
        .execute(&state.pool)
        .await?;
    Ok(Json(json!({"id":id,"paused":request.paused})))
}

pub async fn maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "operations:read").await?;
    let rows=sqlx::query("SELECT targets,to_jsonb(m) AS value FROM operations_maintenance m WHERE ends_at>$1 ORDER BY starts_at LIMIT 100").bind(now_timestamp()).fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    for row in rows {
        let ids: Vec<i64> = row.get("targets");
        if authorize(&state, &headers, &ids, false).await.is_ok() {
            values.push(row.get("value"));
        }
    }
    Ok(Json(values))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maintenance {
    name: String,
    targets: Vec<i64>,
    starts_at: i64,
    ends_at: i64,
    suppress_notifications: bool,
    block_new_tasks: bool,
}

pub async fn save_maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Maintenance>,
) -> ApiResult<Json<Value>> {
    label(&request.name, 128)?;
    if request.targets.is_empty()
        || request.targets.len() > 256
        || request.ends_at <= request.starts_at
        || request.ends_at <= now_timestamp()
        || request.ends_at - request.starts_at > 2592000
    {
        return Err(ApiError::BadRequest(
            "维护目标或窗口无效，最长为 30 天".into(),
        ));
    }
    let actor = authorize(&state, &headers, &request.targets, true).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_maintenance(id,name,targets,starts_at,ends_at,suppress_notifications,block_new_tasks,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(id).bind(request.name).bind(request.targets).bind(request.starts_at).bind(request.ends_at).bind(request.suppress_notifications).bind(request.block_new_tasks).bind(actor).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(json!({"id":id})))
}
