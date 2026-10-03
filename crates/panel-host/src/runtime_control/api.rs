use super::{checkpoint_required, request_barrier, request_checkpoint};
use crate::{
    AppState,
    auth::require_admin,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::{RuntimeCheckpoint, now_timestamp, runtime_module_valid};
use sqlx::Row;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/servers/{id}/runtime-control", get(status))
        .route(
            "/api/servers/{id}/runtime-control/checkpoint",
            post(checkpoint),
        )
        .route("/api/servers/{id}/runtime-control/barrier", post(barrier))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointInput {
    module: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BarrierInput {
    module: String,
    minimum_revision: u64,
}

fn module_valid(module: &str) -> ApiResult<()> {
    if !runtime_module_valid(module) {
        return Err(ApiError::BadRequest("模块标识无效".into()));
    }
    Ok(())
}

async fn live_server(state: &AppState, id: i64) -> ApiResult<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

async fn checkpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<CheckpointInput>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers).await?;
    live_server(&state, id).await?;
    module_valid(&input.module)?;
    let request = request_checkpoint(&state, id, &input.module)
        .await
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    Ok(Json(json!({"request":request})))
}

async fn barrier(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<BarrierInput>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers).await?;
    live_server(&state, id).await?;
    module_valid(&input.module)?;
    let request = request_barrier(&state, id, &input.module, input.minimum_revision)
        .await
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    Ok(Json(json!({"request":request})))
}

async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers).await?;
    live_server(&state, id).await?;
    let mut tx = state.pool.begin().await?;
    let capabilities = super::lock_server(&mut tx, id).await?;
    let rows = sqlx::query("SELECT module,checkpoint_json,verified_at,minimum_revision,barrier_request_id FROM runtime_module_checkpoints WHERE server_id=$1 ORDER BY module LIMIT 64")
        .bind(id).fetch_all(&mut *tx).await?;
    let mut checkpoints = Vec::new();
    for row in rows {
        let checkpoint: RuntimeCheckpoint =
            serde_json::from_value(row.get("checkpoint_json")).map_err(anyhow::Error::from)?;
        let current = super::confirmed_is_current(&mut tx, id, &checkpoint.binding).await?;
        let barrier_request_id: Option<uuid::Uuid> = row.get("barrier_request_id");
        let barrier_result: Option<Value> = sqlx::query_scalar("SELECT result_json FROM runtime_control_receipts WHERE request_id=$1 AND outcome='verified'")
            .bind(barrier_request_id).fetch_optional(&mut *tx).await?;
        let barrier_current = current
            && super::supports(
                &capabilities,
                sinan_protocol::RUNTIME_RECOVERY_BARRIER_CAPABILITY,
            )
            && barrier_result
                .as_ref()
                .is_some_and(|result| result.get("observed") == Some(&json!(checkpoint)));
        checkpoints.push(json!({"module":row.get::<String,_>("module"),"checkpoint":checkpoint,"current":current,
            "verified_at":row.get::<i64,_>("verified_at"),"minimum_revision":row.get::<i64,_>("minimum_revision"),
            "barrier_request_id":barrier_request_id,"barrier_current":barrier_current}));
    }
    let rows = sqlx::query("SELECT q.request_id,q.module,q.kind,q.request_digest,q.created_at,q.expires_at,q.state,r.result_json,r.received_at,r.outcome FROM runtime_control_requests q LEFT JOIN runtime_control_receipts r USING(request_id) WHERE q.server_id=$1 ORDER BY q.created_at DESC,q.request_id DESC LIMIT 64")
        .bind(id).fetch_all(&mut *tx).await?;
    let now = now_timestamp();
    let requests: Vec<Value> = rows.into_iter().map(|row| {
        let state: String = row.get("state");
        let expires_at: i64 = row.get("expires_at");
        json!({"request_id":row.get::<uuid::Uuid,_>("request_id"),"module":row.get::<String,_>("module"),
            "kind":row.get::<String,_>("kind"),"request_digest":row.get::<String,_>("request_digest"),
            "created_at":row.get::<i64,_>("created_at"),"expires_at":expires_at,
            "state":if state=="pending" && expires_at<=now {"expired"} else {&state},
            "result":row.get::<Option<Value>,_>("result_json"),"received_at":row.get::<Option<i64>,_>("received_at"),
            "outcome":row.get::<Option<String>,_>("outcome")})
    }).collect();
    tx.commit().await?;
    Ok(Json(
        json!({"checkpoint_required":checkpoint_required(&state,id).await?,"checkpoints":checkpoints,"requests":requests}),
    ))
}
