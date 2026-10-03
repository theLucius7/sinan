mod access;
mod administrators;
pub mod credentials;
mod events;
pub mod guard;
mod search;
pub mod system;
mod tool_security;
mod workspace;

pub use access::{
    Principal, actor_server_allowed, authenticate, require_actor_capability, require_actor_server,
    require_capability, require_owner, require_recent_proof, require_server,
};

use crate::{AppState, auth, error::ApiResult};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use std::net::SocketAddr;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/control-center/me", get(me))
        .route("/api/control-center/events", get(events::subscribe))
        .route(
            "/api/control-center/export/servers",
            get(events::export_servers),
        )
        .route("/api/control-center/reauth", post(reauthenticate))
        .route(
            "/api/control-center/administrators",
            get(administrators::list).post(administrators::create),
        )
        .route(
            "/api/control-center/administrators/{id}",
            put(administrators::update),
        )
        .route(
            "/api/control-center/tokens",
            get(administrators::tokens).post(administrators::create_token),
        )
        .route(
            "/api/control-center/tokens/{id}",
            axum::routing::delete(administrators::revoke_token),
        )
        .route(
            "/api/control-center/sessions",
            get(administrators::sessions),
        )
        .route(
            "/api/control-center/sessions/{id}",
            axum::routing::delete(administrators::revoke_session),
        )
        .route(
            "/api/control-center/credentials",
            get(credentials::list).post(credentials::create),
        )
        .route(
            "/api/control-center/credentials/{id}/rotate",
            post(credentials::rotate),
        )
        .route(
            "/api/control-center/credentials/{id}",
            axum::routing::delete(credentials::disable),
        )
        .route(
            "/api/control-center/preferences/{key}",
            get(workspace::preference).put(workspace::save_preference),
        )
        .route("/api/control-center/search", get(search::search))
        .route("/api/control-center/audit", get(workspace::audit))
        .route("/api/control-center/retention", get(workspace::retention))
        .route(
            "/api/control-center/retention/{kind}",
            put(workspace::update_retention),
        )
        .route("/api/control-center/health", get(system::health))
        .route(
            "/api/control-center/tool-security",
            get(tool_security::inventory),
        )
        .route(
            "/api/control-center/tool-security/refresh",
            post(tool_security::refresh),
        )
        .route("/api/control-center/observers", post(system::observe))
}
async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    Ok(Json(json!(authenticate(&state, &headers).await?)))
}
async fn reauthenticate(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<auth::LoginRequest>,
) -> ApiResult<Json<Value>> {
    let proof = auth::proof::prepare(&state, &headers, peer, input).await?;
    let mut tx = state.pool.begin().await?;
    proof.lock(&mut tx).await?;
    let now = now_timestamp();
    sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3) ON CONFLICT(session_hash) DO UPDATE SET verified_at=EXCLUDED.verified_at,expires_at=EXCLUDED.expires_at")
        .bind(proof.session).bind(now).bind(now+300).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"verified_at":now,"expires_at":now+300})))
}
pub async fn run(state: AppState) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(60));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let result = system::maintain(&state.pool).await;
        let status = if result.is_ok() { "healthy" } else { "failed" };
        if let Err(error) = result {
            tracing::warn!(%error,"control center retention maintenance failed");
        }
        if let Err(error) = system::heartbeat(
            &state.pool,
            "control-center",
            status,
            json!({"source":"retention-cycle"}),
        )
        .await
        {
            tracing::warn!(%error,"control center heartbeat failed");
        }
    }
}
