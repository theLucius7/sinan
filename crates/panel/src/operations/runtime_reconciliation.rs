use super::{
    api::{authorize, history, targets},
    model::label,
    typed_steps,
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
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inspection {
    server_id: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reconciliation {
    server_id: i64,
    checkpoint_request_id: Uuid,
    evidence: String,
}

async fn authorize_target(
    state: &AppState,
    headers: &HeaderMap,
    job: Uuid,
    server: i64,
) -> ApiResult<i64> {
    let ids = targets(&state.pool, job).await?;
    if !ids.contains(&server) {
        return Err(ApiError::NotFound);
    }
    let actor = authorize(state, headers, &ids, true).await?;
    control_center::require_server(state, headers, server, "proxy:write").await?;
    control_center::require_recent_proof(state, headers).await?;
    Ok(actor)
}

async fn original(tx: &mut Transaction<'_, Postgres>, job: Uuid, server: i64) -> ApiResult<Uuid> {
    // Acquire the job before any server/runtime row, matching the worker order.
    let status: String =
        sqlx::query_scalar("SELECT status FROM operations_jobs WHERE id=$1 FOR UPDATE")
            .bind(job)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    if !matches!(status.as_str(), "uncertain" | "cancel_requested") {
        return Err(ApiError::Conflict(
            "只可核对执行结果未知的已派发部署；先刷新任务回执".into(),
        ));
    }
    sqlx::query_scalar("SELECT runtime_operation_id FROM operations_target_steps WHERE job_id=$1 AND server_id=$2 AND state='uncertain' AND runtime_operation_id IS NOT NULL ORDER BY position DESC LIMIT 1")
        .bind(job).bind(server).fetch_optional(&mut **tx).await?.ok_or_else(||ApiError::Conflict("此服务器没有待核对的签名部署执行".into()))
}

pub(super) async fn checkpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job): Path<Uuid>,
    Json(input): Json<Inspection>,
) -> ApiResult<Json<Value>> {
    let actor = authorize_target(&state, &headers, job, input.server_id).await?;
    let mut tx = state.pool.begin().await?;
    let request = original(&mut tx, job, input.server_id).await?;
    let checkpoint =
        crate::plugins::singbox::operations_workflows::request_automation_deployment_checkpoint_tx(
            &mut tx, request,
        )
        .await?;
    history(&mut tx,job,Some(actor),"runtime_reconciliation_checkpoint_requested",json!({"server_id":input.server_id,"original_request_id":request,"checkpoint_request_id":checkpoint.request_id,"read_only":true,"original_result":"unknown"}),now_timestamp()).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"job_id":job,"server_id":input.server_id,"original_request_id":request,"checkpoint_request_id":checkpoint.request_id,"expires_at":checkpoint.expires_at,"state":"pending","original_result":"unknown"}),
    ))
}

pub(super) async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job): Path<Uuid>,
    Json(input): Json<Reconciliation>,
) -> ApiResult<Json<Value>> {
    let actor = authorize_target(&state, &headers, job, input.server_id).await?;
    label(&input.evidence, 4096)?;
    let mut tx = state.pool.begin().await?;
    let request = original(&mut tx, job, input.server_id).await?;
    let receipt =
        crate::plugins::singbox::operations_workflows::reconcile_automation_deployment_tx(
            &mut tx,
            request,
            input.checkpoint_request_id,
            &input.evidence,
        )
        .await?;
    typed_steps::sync(&mut tx, job, now_timestamp()).await?;
    sqlx::query("UPDATE operations_target_steps SET state='skipped',finished_at=$2 WHERE job_id=$1 AND state='pending'")
        .bind(job).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE operations_jobs SET status='cancel_requested',cancel_requested_at=COALESCE(cancel_requested_at,$2),updated_at=$2,failure_reason='实际固定配置已核对；原执行结果仍未知，后续步骤已停止，不重新执行原动作' WHERE id=$1")
        .bind(job).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM operations_server_locks l WHERE l.job_id=$1 AND l.server_id=$2 AND NOT EXISTS(SELECT 1 FROM operations_target_steps t WHERE t.job_id=l.job_id AND t.server_id=l.server_id AND t.state IN ('pending','queued','running','cancel_requested','uncertain'))")
        .bind(job).bind(input.server_id).execute(&mut *tx).await?;
    history(&mut tx,job,Some(actor),"runtime_deployment_manually_reconciled",json!({"server_id":input.server_id,"original_request_id":request,"checkpoint_request_id":input.checkpoint_request_id,"evidence":input.evidence,"receipt":receipt,"original_result":"unknown","success":null,"next_steps":"stopped"}),now_timestamp()).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"job_id":job,"server_id":input.server_id,"state":"reconciled","original_result":"unknown","success":null,"receipt":receipt,"next_steps":"stopped","automatic_replay":false}),
    ))
}
