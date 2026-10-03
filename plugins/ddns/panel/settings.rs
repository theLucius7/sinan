use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Serialize, FromRow)]
struct Server {
    id: i64,
    name: String,
    online: bool,
    enabled: bool,
    interface_names: Vec<String>,
    public_discovery_available: bool,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/servers", get(list))
        .route("/api/plugins/ddns/servers/{id}/enable", post(enable))
        .route("/api/plugins/ddns/servers/{id}/disable", post(disable))
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Server>>> {
    auth::require_admin(&state, &headers).await?;
    crate::control_center::require_capability(&state, &headers, "dns:read").await?;
    let actor = crate::control_center::authenticate(&state, &headers).await?;
    let servers: Vec<Server> = sqlx::query_as("SELECT s.id,s.name,COALESCE(s.last_seen>=$1-60,false) AS online,COALESCE(p.enabled,false) AS enabled,ARRAY(SELECT jsonb_object_keys(CASE WHEN jsonb_typeof(s.static_info->'interface_addresses')='object' THEN s.static_info->'interface_addresses' ELSE '{}'::jsonb END)) AS interface_names,COALESCE(jsonb_typeof(s.static_info->'discovered_public_ips')='array',false) AS public_discovery_available FROM servers s LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='ddns' WHERE s.deleted_at IS NULL ORDER BY s.id")
        .bind(sinan_protocol::now_timestamp()).fetch_all(&state.pool).await?;
    Ok(Json(
        servers
            .into_iter()
            .filter(|server| actor.allows_server(server.id))
            .collect(),
    ))
}

async fn enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    auth::require_admin(&state, &headers).await?;
    crate::control_center::require_server(&state, &headers, id, "dns:write").await?;
    set_enabled(&state.pool, id, true).await?;
    Ok(Json(serde_json::json!({"enabled":true})))
}

async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    auth::require_admin(&state, &headers).await?;
    crate::control_center::require_server(&state, &headers, id, "dns:write").await?;
    set_enabled(&state.pool, id, false).await?;
    Ok(Json(serde_json::json!({"enabled":false})))
}

pub(super) async fn set_enabled(pool: &sqlx::PgPool, id: i64, enabled: bool) -> ApiResult<()> {
    let mut tx = pool.begin().await?;
    // Serialize with worker claims, so an acknowledged disable cannot be
    // followed by a newly claimed rule using the old activation state.
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await?;
    let available: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1))")
        .bind(id).fetch_one(&mut *tx).await?;
    if enabled && !available {
        return Err(ApiError::Conflict("服务器不存在或已退役".into()));
    }
    let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ddns_rules WHERE server_id=$1 AND lease_until>$2)",
    )
    .bind(id)
    .bind(sinan_protocol::now_timestamp())
    .fetch_one(&mut *tx)
    .await?;
    if busy {
        return Err(ApiError::Conflict(
            "该服务器仍有 DDNS 同步进行中，请稍后操作".into(),
        ));
    }
    sqlx::query("INSERT INTO server_plugins(server_id,plugin,enabled,source,enabled_at) VALUES($1,'ddns',$2,'administrator',$3) ON CONFLICT(server_id,plugin) DO UPDATE SET enabled=EXCLUDED.enabled,source='administrator',enabled_at=EXCLUDED.enabled_at")
        .bind(id).bind(enabled).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
