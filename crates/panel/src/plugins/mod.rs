#[path = "../../../../plugins/alicloud/panel/mod.rs"]
pub mod alicloud;
#[path = "../../../../plugins/cloud_api/panel/mod.rs"]
pub(crate) mod cloud_api;
#[path = "../../../../plugins/ddns/panel/mod.rs"]
pub mod ddns;
#[path = "../../../../plugins/singbox/panel/mod.rs"]
pub mod singbox;

use crate::AppState;
use axum::Router;

/// Runtime evidence supplied by plugins; silence does not establish idleness.
pub struct ActivityEvidence {
    pub configured: bool,
    pub last_positive_at: Option<i64>,
}

pub async fn runtime_activity_on(
    connection: &mut sqlx::PgConnection,
    server_id: i64,
    checked_at: i64,
) -> crate::error::ApiResult<ActivityEvidence> {
    singbox::runtime_activity_on(connection, server_id, checked_at).await
}

pub fn router() -> Router<AppState> {
    singbox::router()
        .merge(ddns::routes())
        .merge(alicloud::routes())
}

pub async fn run(state: AppState) {
    use crate::maintenance::supervise;
    // Supervise each plugin separately: one plugin's panic must not stop the others.
    let pool = state.pool.clone();
    tokio::join!(
        supervise("sing-box", move || singbox::run(state.clone())),
        supervise("ddns", {
            let pool = pool.clone();
            move || ddns::run(pool.clone())
        }),
        supervise("alicloud", move || alicloud::run(pool.clone()))
    );
}

pub async fn ingest_usage(
    state: &AppState,
    server_id: i64,
    batch: sinan_protocol::UsageBatch,
) -> anyhow::Result<()> {
    singbox::usage::ingest(state, server_id, batch).await
}

pub async fn manifest_modules(
    state: &AppState,
    server_id: i64,
    info: &serde_json::Value,
) -> crate::error::ApiResult<std::collections::BTreeMap<String, sinan_protocol::ModuleManifest>> {
    let mut modules = std::collections::BTreeMap::new();
    if let Some(module) = singbox::agent::manifest_module(state, server_id, info).await? {
        modules.insert("singbox".into(), module);
    }
    Ok(modules)
}

pub async fn bundle(state: &AppState, server_id: i64, rev: i64) -> crate::error::ApiResult<String> {
    singbox::agent::bundle(state, server_id, rev).await
}
