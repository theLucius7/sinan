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
    let retiring: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1)")
            .bind(server)
            .fetch_one(&mut *tx)
            .await?;
    if retiring {
        return Ok(Json(Vec::new()));
    }
    let rows: Vec<Value> = sqlx::query_scalar("UPDATE runtime_operations SET dispatched_at=COALESCE(dispatched_at,$2) WHERE server_id=$1 AND result IS NULL RETURNING spec").bind(server).bind(now_timestamp()).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(anyhow::Error::from)?,
    ))
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
