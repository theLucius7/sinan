use super::{models::*, service};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
    subscription_parser::PARSER_VERSION,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::json;
use sinan_protocol::now_timestamp;
use sqlx::PgConnection;
use uuid::Uuid;

pub(super) async fn enqueue(
    connection: &mut PgConnection,
    source: &SourceRow,
) -> ApiResult<Option<Uuid>> {
    if source.archived || source.deleted_at.is_some() {
        return Ok(None);
    }
    if let Some(job) = service::active_job(connection, source.id).await? {
        return Ok((job.settings_revision == source.settings_revision
            && job.identity_epoch == source.identity_epoch
            && job.status != "cancelling")
            .then_some(job.id));
    }
    let id = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO singbox_subscription_source_jobs(id,source_id,settings_revision,identity_epoch,parser_version,status,stage,created_at) VALUES($1,$2,$3,$4,$5,'queued','queued',$6)")
        .bind(id).bind(source.id).bind(source.settings_revision).bind(source.identity_epoch).bind(PARSER_VERSION).bind(now).execute(&mut *connection).await?;
    sqlx::query("UPDATE singbox_ordered_subscription_sources SET next_refresh_at=$2 WHERE id=$1")
        .bind(source.id)
        .bind((source.kind == "url").then_some(now + source.refresh_interval_secs))
        .execute(connection)
        .await?;
    Ok(Some(id))
}

pub(super) async fn supersede(connection: &mut PgConnection, source: i64) -> ApiResult<()> {
    let error = json!(SourceFailure::new(
        "done",
        "superseded",
        "来源设置已改变，本任务不再更新当前来源"
    ));
    sqlx::query("UPDATE singbox_subscription_source_jobs SET status=CASE WHEN status='queued' THEN 'superseded' ELSE 'cancelling' END,stage=CASE WHEN status='queued' THEN 'done' ELSE stage END,finished_at=CASE WHEN status='queued' THEN $2 ELSE finished_at END,error=$3 WHERE source_id=$1 AND status IN ('queued','running','cancelling')")
        .bind(source).bind(now_timestamp()).bind(error).execute(connection).await?;
    Ok(())
}

pub async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<JobView>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(
        sqlx::query_as::<_, JobView>(&format!(
            "SELECT {JOB_COLUMNS} FROM singbox_subscription_source_jobs WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?,
    ))
}

pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    ProtectedJson(input): ProtectedJson<SourceRevisionInput>,
) -> ApiResult<(StatusCode, Json<JobView>)> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let source = service::load_source(&mut tx, id, true).await?;
    if input.settings_revision != source.settings_revision {
        return Err(ApiError::Conflict("来源设置已被修改，请刷新后重试".into()));
    }
    if source.archived {
        return Err(ApiError::Conflict("来源已归档，不能刷新".into()));
    }
    if source.kind != "url" {
        return Err(ApiError::BadRequest(
            "粘贴或上传来源请使用更新内容操作，不能在线刷新".into(),
        ));
    }
    let (id, status) = if let Some(job) = service::active_job(&mut tx, source.id).await? {
        if job.settings_revision != source.settings_revision
            || job.identity_epoch != source.identity_epoch
            || job.status == "cancelling"
        {
            return Err(ApiError::Conflict(
                "此来源的旧任务正在停止，等待确认后再刷新".into(),
            ));
        }
        (job.id, StatusCode::OK)
    } else {
        (
            enqueue(&mut tx, &source).await?.ok_or(ApiError::NotFound)?,
            StatusCode::ACCEPTED,
        )
    };
    let job = sqlx::query_as::<_, JobView>(&format!(
        "SELECT {JOB_COLUMNS} FROM singbox_subscription_source_jobs WHERE id=$1"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((status, Json(job)))
}

pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<JobView>> {
    auth::require_admin(&state, &headers).await?;
    let source_id: i64 =
        sqlx::query_scalar("SELECT source_id FROM singbox_subscription_source_jobs WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let mut tx = state.pool.begin().await?;
    // All writers lock the source before its task, including tombstoned sources.
    sqlx::query("SELECT id FROM singbox_ordered_subscription_sources WHERE id=$1 FOR UPDATE")
        .bind(source_id)
        .fetch_one(&mut *tx)
        .await?;
    let error = json!(SourceFailure::new(
        "done",
        "cancelled",
        "管理员取消了来源任务"
    ));
    sqlx::query("UPDATE singbox_subscription_source_jobs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'cancelling' END,stage=CASE WHEN status='queued' THEN 'done' ELSE stage END,finished_at=CASE WHEN status='queued' THEN $2 ELSE finished_at END,error=$3 WHERE id=$1 AND status IN ('queued','running')")
        .bind(id).bind(now_timestamp()).bind(error).execute(&mut *tx).await?;
    let job = sqlx::query_as::<_, JobView>(&format!(
        "SELECT {JOB_COLUMNS} FROM singbox_subscription_source_jobs WHERE id=$1"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(job))
}
