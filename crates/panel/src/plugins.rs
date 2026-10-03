//! Compiled plugin set: the only place that names concrete business plugins.

pub use sinan_panel_host::plugin_api::ActivityEvidence;
pub use sinan_plugin_alicloud as alicloud;
pub use sinan_plugin_ddns as ddns;
pub use sinan_plugin_singbox as singbox;

use std::collections::BTreeMap;

use axum::Router;
use sinan_panel_host::{
    AppState,
    error::ApiResult,
    plugin_api::{self, HookFuture, PanelPlugins},
};
use sinan_protocol::{ModuleManifest, UsageBatch};

struct Compiled;

impl PanelPlugins for Compiled {
    fn ingest_usage<'a>(
        &'a self,
        state: &'a AppState,
        server_id: i64,
        batch: UsageBatch,
    ) -> HookFuture<'a, anyhow::Result<()>> {
        Box::pin(singbox::usage::ingest(state, server_id, batch))
    }

    fn manifest_modules<'a>(
        &'a self,
        state: &'a AppState,
        server_id: i64,
        info: &'a serde_json::Value,
    ) -> HookFuture<'a, ApiResult<BTreeMap<String, ModuleManifest>>> {
        Box::pin(async move {
            let mut modules = BTreeMap::new();
            if let Some(module) = singbox::agent::manifest_module(state, server_id, info).await? {
                modules.insert("singbox".into(), module);
            }
            Ok(modules)
        })
    }

    fn bundle<'a>(
        &'a self,
        state: &'a AppState,
        server_id: i64,
        rev: i64,
    ) -> HookFuture<'a, ApiResult<String>> {
        Box::pin(singbox::agent::bundle(state, server_id, rev))
    }

    fn runtime_activity_on<'a>(
        &'a self,
        connection: &'a mut sqlx::PgConnection,
        server_id: i64,
        checked_at: i64,
    ) -> HookFuture<'a, ApiResult<ActivityEvidence>> {
        Box::pin(singbox::runtime_activity_on(
            connection, server_id, checked_at,
        ))
    }
}

static COMPILED: Compiled = Compiled;

/// Registers the compiled plugins with the host; repeated calls are harmless.
pub fn install() {
    plugin_api::install(&COMPILED);
}

pub fn router() -> Router<AppState> {
    install();
    singbox::router()
        .merge(ddns::routes())
        .merge(alicloud::routes())
}

pub async fn run(state: AppState) {
    use sinan_panel_host::maintenance::supervise;
    install();
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

// Direct entry points kept for embedders of the previous public API.

pub async fn runtime_activity_on(
    connection: &mut sqlx::PgConnection,
    server_id: i64,
    checked_at: i64,
) -> ApiResult<ActivityEvidence> {
    singbox::runtime_activity_on(connection, server_id, checked_at).await
}

pub async fn ingest_usage(
    state: &AppState,
    server_id: i64,
    batch: UsageBatch,
) -> anyhow::Result<()> {
    singbox::usage::ingest(state, server_id, batch).await
}

pub async fn manifest_modules(
    state: &AppState,
    server_id: i64,
    info: &serde_json::Value,
) -> ApiResult<BTreeMap<String, ModuleManifest>> {
    COMPILED.manifest_modules(state, server_id, info).await
}

pub async fn bundle(state: &AppState, server_id: i64, rev: i64) -> ApiResult<String> {
    singbox::agent::bundle(state, server_id, rev).await
}
