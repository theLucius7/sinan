use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::Value;
use sinan_protocol::{RuntimeOperationRequest, RuntimeOperationResult, TaskAck, now_timestamp};
use sqlx::Row;
use uuid::Uuid;

pub async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<RuntimeOperationRequest>>> {
    let server = auth::require_agent(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    // Share the server lock order with retirement and operation creation.
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let accepting = match crate::fleet::ensure_accepts_tasks_tx(&mut tx, server).await {
        Ok(()) => true,
        Err(ApiError::Conflict(_)) => false,
        Err(error) => return Err(error),
    };
    let now = now_timestamp();
    let rows = sqlx::query("SELECT id,spec,dispatched_at,automation_job_id FROM runtime_operations WHERE server_id=$1 AND result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL ORDER BY requested_at,id LIMIT 16 FOR UPDATE")
        .bind(server).fetch_all(&mut *tx).await?;
    let mut requests = Vec::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let request: RuntimeOperationRequest =
            serde_json::from_value(row.get("spec")).map_err(anyhow::Error::from)?;
        if !request.valid() || request.id != id {
            return Err(ApiError::Conflict("保存的运行时操作身份无效".into()));
        }
        let permitted = if let Some(job) = row.get::<Option<Uuid>, _>("automation_job_id") {
            if request.expires_at <= now && row.get::<Option<i64>, _>("dispatched_at").is_none() {
                sqlx::query("UPDATE runtime_operations SET cancelled_at=$2 WHERE id=$1 AND dispatched_at IS NULL").bind(id).bind(now).execute(&mut *tx).await?;
                continue;
            }
            let actor: Option<i64> = sqlx::query_scalar("SELECT j.requested_by FROM operations_jobs j JOIN operations_server_locks l ON l.job_id=j.id AND l.server_id=$2 WHERE j.id=$1 AND j.status IN ('queued','running') AND j.cancel_requested_at IS NULL AND j.expires_at>$3 AND EXISTS(SELECT 1 FROM operations_target_steps t WHERE t.job_id=j.id AND t.server_id=$2 AND t.runtime_operation_id=$4 AND t.state IN ('queued','running'))")
                .bind(job).bind(server).bind(now).bind(id).fetch_optional(&mut *tx).await?;
            let authorized = if let Some(actor) = actor {
                crate::control_center::actor_server_allowed(
                    &state.pool,
                    actor,
                    server,
                    "operations:write",
                )
                .await?
                    && crate::control_center::actor_server_allowed(
                        &state.pool,
                        actor,
                        server,
                        "proxy:write",
                    )
                    .await?
            } else {
                false
            };
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) OR EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND (lifecycle IN ('draining','retired') OR (lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$2 AND (maintenance_until IS NULL OR maintenance_until>$2)))) OR EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND block_new_tasks AND starts_at<=$2 AND ends_at>$2) OR EXISTS(SELECT 1 FROM fleet_operations WHERE server_id=$1 AND reconciled_at IS NULL AND status IN ('queued','dispatched','unknown')) OR EXISTS(SELECT 1 FROM remote_commands WHERE server_id=$1 AND state IN ('queued','claimed','running','cancel_requested')) OR EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND (status IN ('queued','running','cleaning','cancel_requested') OR (NOT agent_completed AND job ? 'id')))")
                .bind(server).bind(now).fetch_one(&mut *tx).await?;
            authorized
                && !blocked
                && crate::plugins::singbox::operations_workflows::automation_dispatch_matches_tx(
                    &mut tx, server, id,
                )
                .await?
        } else {
            accepting
        };
        if !permitted {
            continue;
        }
        sqlx::query("UPDATE runtime_operations SET dispatched_at=COALESCE(dispatched_at,$2) WHERE id=$1 AND cancelled_at IS NULL").bind(id).bind(now).execute(&mut *tx).await?;
        requests.push(request);
    }
    tx.commit().await?;
    Ok(Json(requests))
}

pub async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(result): Json<RuntimeOperationResult>,
) -> ApiResult<Json<TaskAck>> {
    let server = auth::require_agent(&state, &headers).await?;
    if result.id != id || !result.valid() || result.finished_at > now_timestamp() + 60 {
        return Err(ApiError::BadRequest("运行时操作结果无效".into()));
    }
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT spec,result,dispatched_at FROM runtime_operations WHERE id=$1 AND server_id=$2 FOR UPDATE").bind(id).bind(server).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let request: RuntimeOperationRequest =
        serde_json::from_value(row.get("spec")).map_err(anyhow::Error::from)?;
    if request.module != result.module
        || request.operation != result.operation
        || result.finished_at < request.requested_at
        || row.get::<Option<i64>, _>("dispatched_at").is_none()
    {
        return Err(ApiError::Conflict("运行时操作身份或执行时间不匹配".into()));
    }
    let value = serde_json::to_value(&result).map_err(anyhow::Error::from)?;
    if let Some(previous) = row.get::<Option<Value>, _>("result") {
        if previous != value {
            return Err(ApiError::Conflict("已完成的运行时操作结果不可修改".into()));
        }
    } else {
        sqlx::query("UPDATE runtime_operations SET result=$2 WHERE id=$1")
            .bind(id)
            .bind(value)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(TaskAck { ids: vec![id] }))
}
