use super::super::{account_on, client::Cloud, failure, lock, operations, resource};
use super::{Job, Policy, jobs, policy};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{patch, post},
};
use serde::Deserialize;
use sqlx::types::Json as SqlJson;
use uuid::Uuid;

pub(in super::super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/plugins/alicloud/resources/{id}/power-policy",
            patch(update_policy),
        )
        .route(
            "/api/plugins/alicloud/resources/{id}/power-preview",
            post(preview),
        )
        .route(
            "/api/plugins/alicloud/resources/{id}/power-resume",
            post(resume),
        )
        .route(
            "/api/plugins/alicloud/power-jobs/{id}/confirm",
            post(confirm),
        )
        .route("/api/plugins/alicloud/power-jobs/{id}/cancel", post(cancel))
        .route(
            "/api/plugins/alicloud/power-jobs/{id}/dismiss",
            post(dismiss),
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWrite {
    revision: i64,
    policy: Policy,
}
async fn update_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PolicyWrite>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    input.policy.validate()?;
    let initial = resource(&state.pool, id).await?;
    let mut tx = lock(&state.pool, initial.account_id).await?;
    let r = jobs::fresh(&mut tx, id).await?;
    if r.kind != "ecs" || r.revision != input.revision {
        return Err(ApiError::Conflict(
            "仅 ECS 支持启停策略，请刷新配置后重试".into(),
        ));
    }
    sqlx::query("UPDATE alicloud_resources SET power_policy=$2,revision=revision+1,next_power_at=0,threshold_hold=CASE WHEN $3 THEN threshold_hold ELSE false END WHERE id=$1")
        .bind(id).bind(SqlJson(&input.policy)).bind(input.policy.enabled && input.policy.threshold_action=="stop").execute(&mut *tx).await?;
    cancel_queued(&mut tx, id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn cancel_queued(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, id: Uuid) -> ApiResult<()> {
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE alicloud_power_jobs SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status IN ('preview','queued')").bind(id).bind(now).execute(&mut **tx).await?;
    sqlx::query("UPDATE alicloud_operations SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status IN ('preview','queued')").bind(id).bind(now).execute(&mut **tx).await?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    revision: i64,
    action: String,
    stop_mode: String,
}
async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Preview>,
) -> ApiResult<Json<Job>> {
    auth::require_admin(&state, &headers).await?;
    if !matches!(input.action.as_str(), "start" | "stop") || !policy::valid_mode(&input.stop_mode) {
        return Err(ApiError::BadRequest(
            "请选择开机、停机及有效的停机模式".into(),
        ));
    }
    let initial = resource(&state.pool, id).await?;
    let mut tx = lock(&state.pool, initial.account_id).await?;
    let account = account_on(&mut tx, initial.account_id).await?;
    let r = jobs::fresh(&mut tx, id).await?;
    let now = sinan_protocol::now_timestamp();
    if r.kind != "ecs" || !account.enabled || r.revision != input.revision {
        return Err(ApiError::Conflict(
            "仅支持已启用账号的 ECS，请刷新配置后重试".into(),
        ));
    }
    if input.action == "start" && r.power_policy.blocks_start(&account, &r, now) {
        return Err(ApiError::Conflict(
            "流量停机保护生效，或当前账单无法验证；请核对用量及阈值策略".into(),
        ));
    }
    operations::idle(&mut tx, id).await?;
    let cloud = Cloud::new(&state.pool).map_err(failure)?;
    let before = cloud.power_state(&account, &r).await.map_err(failure)?;
    before
        .validate(&input.action, &input.stop_mode)
        .map_err(failure)?;
    jobs::state_on(&mut tx, id, &before, now).await?;
    sqlx::query("UPDATE alicloud_power_jobs SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status='preview'").bind(id).bind(now).execute(&mut *tx).await?;
    let job = jobs::prepare(
        &mut tx,
        &account,
        &r,
        &before,
        jobs::Intent {
            action: &input.action,
            mode: &input.stop_mode,
            source: "manual",
            key: None,
            expires_at: now + 300,
        },
        now,
    )
    .await?
    .ok_or(ApiError::Busy)?;
    tx.commit().await?;
    Ok(Json(jobs::load(&state.pool, job).await?))
}
async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Job>)> {
    auth::require_admin(&state, &headers).await?;
    confirm_on(&state.pool, id).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(jobs::load(&state.pool, id).await?),
    ))
}
pub(super) async fn confirm_on(pool: &sqlx::PgPool, id: Uuid) -> ApiResult<()> {
    let initial = jobs::load(pool, id).await?;
    let initial_r = resource(pool, initial.resource_id).await?;
    let mut tx = lock(pool, initial_r.account_id).await?;
    let job: Job = sqlx::query_as("SELECT * FROM alicloud_power_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if matches!(
        job.status.as_str(),
        "queued" | "running" | "uncertain" | "succeeded"
    ) {
        return Ok(());
    }
    let account = account_on(&mut tx, initial_r.account_id).await?;
    let r = jobs::fresh(&mut tx, initial_r.id).await?;
    if job.source != "manual"
        || job.status != "preview"
        || !jobs::allowed(&job, &account, &r, sinan_protocol::now_timestamp())
    {
        return Err(ApiError::Conflict(
            "预览已过期、配置变化或流量保护生效，请重新预览".into(),
        ));
    }
    operations::idle(&mut tx, r.id).await?;
    sqlx::query("UPDATE alicloud_power_jobs SET status='queued',updated_at=$2 WHERE id=$1")
        .bind(id)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE alicloud_resources SET manual_hold=$2 WHERE id=$1")
        .bind(r.id)
        .bind(job.action == "stop")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
async fn resume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Option<Json<Revision>>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let Json(input) =
        input.ok_or_else(|| ApiError::BadRequest("请携带当前资源修订号恢复自动策略".into()))?;
    resume_on(&state.pool, id, input.revision).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    revision: i64,
}
pub(super) async fn resume_on(pool: &sqlx::PgPool, id: Uuid, revision: i64) -> ApiResult<()> {
    let initial = resource(pool, id).await?;
    let mut tx = lock(pool, initial.account_id).await?;
    let r = jobs::fresh(&mut tx, id).await?;
    if r.kind != "ecs" {
        return Err(ApiError::BadRequest("仅 ECS 支持启停策略".into()));
    }
    if r.revision != revision {
        return Err(ApiError::Conflict(
            "启停策略或资源配置已变化，请刷新后重试".into(),
        ));
    }
    operations::idle(&mut tx, id).await?;
    sqlx::query("UPDATE alicloud_resources SET manual_hold=false,next_power_at=0,revision=revision+1 WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    cancel_queued(&mut tx, id).await?;
    tx.commit().await?;
    Ok(())
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    close(&state.pool, id, false).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn dismiss(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    close(&state.pool, id, true).await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn close(pool: &sqlx::PgPool, id: Uuid, dismiss: bool) -> ApiResult<()> {
    let initial = jobs::load(pool, id).await?;
    let r = resource(pool, initial.resource_id).await?;
    let mut tx = lock(pool, r.account_id).await?;
    let job: Job = sqlx::query_as("SELECT * FROM alicloud_power_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let status = if dismiss && job.status == "uncertain" {
        sqlx::query("UPDATE alicloud_resources SET power_policy=jsonb_set(power_policy,'{enabled}','false'),auto_enabled=false,manual_hold=true,revision=revision+1 WHERE id=$1").bind(r.id).execute(&mut *tx).await?;
        cancel_queued(&mut tx, r.id).await?;
        "dismissed"
    } else if !dismiss && matches!(job.status.as_str(), "preview" | "queued") {
        "cancelled"
    } else {
        return Err(ApiError::Conflict(
            "任务已发送，只能核对云端结果，不能撤回".into(),
        ));
    };
    sqlx::query("UPDATE alicloud_power_jobs SET status=$2,updated_at=$3 WHERE id=$1")
        .bind(id)
        .bind(status)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
