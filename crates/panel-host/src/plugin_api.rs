//! Hooks through which the host reaches business plugins without naming them.
//!
//! The host owns the device channel and the shared diagnostic services, but the
//! messages it relays (usage batches, module manifests, configuration bundles)
//! belong to plugins. The panel binary installs one [`PanelPlugins`]
//! implementation at startup; the host only calls through this interface.

use std::{collections::BTreeMap, future::Future, pin::Pin, sync::OnceLock};

use sinan_protocol::{ModuleManifest, UsageBatch};

use crate::{
    AppState,
    error::{ApiError, ApiResult},
};

pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runtime evidence supplied by plugins; silence does not establish idleness.
pub struct ActivityEvidence {
    pub configured: bool,
    pub last_positive_at: Option<i64>,
}

/// Device-channel hooks implemented by the assembled plugin set.
pub trait PanelPlugins: Send + Sync {
    /// Records one device usage batch; an error leaves the batch unacknowledged.
    fn ingest_usage<'a>(
        &'a self,
        state: &'a AppState,
        server_id: i64,
        batch: UsageBatch,
    ) -> HookFuture<'a, anyhow::Result<()>>;

    /// Lists the modules a device must run, keyed by module identifier.
    fn manifest_modules<'a>(
        &'a self,
        state: &'a AppState,
        server_id: i64,
        info: &'a serde_json::Value,
    ) -> HookFuture<'a, ApiResult<BTreeMap<String, ModuleManifest>>>;

    /// Returns the published configuration bundle at one revision.
    fn bundle<'a>(
        &'a self,
        state: &'a AppState,
        server_id: i64,
        rev: i64,
    ) -> HookFuture<'a, ApiResult<String>>;

    /// Reports whether runtime traffic is configured and when it was last seen.
    fn runtime_activity_on<'a>(
        &'a self,
        connection: &'a mut sqlx::PgConnection,
        server_id: i64,
        checked_at: i64,
    ) -> HookFuture<'a, ApiResult<ActivityEvidence>>;
}

static INSTALLED: OnceLock<&'static dyn PanelPlugins> = OnceLock::new();

/// Installs the plugin set once; later calls keep the first installation.
pub fn install(plugins: &'static dyn PanelPlugins) {
    let _ = INSTALLED.set(plugins);
}

fn installed() -> Option<&'static dyn PanelPlugins> {
    INSTALLED.get().copied()
}

pub async fn ingest_usage(
    state: &AppState,
    server_id: i64,
    batch: UsageBatch,
) -> anyhow::Result<()> {
    match installed() {
        Some(plugins) => plugins.ingest_usage(state, server_id, batch).await,
        None => anyhow::bail!("no plugin accepts usage batches"),
    }
}

pub async fn manifest_modules(
    state: &AppState,
    server_id: i64,
    info: &serde_json::Value,
) -> ApiResult<BTreeMap<String, ModuleManifest>> {
    match installed() {
        Some(plugins) => plugins.manifest_modules(state, server_id, info).await,
        None => Ok(BTreeMap::new()),
    }
}

pub async fn bundle(state: &AppState, server_id: i64, rev: i64) -> ApiResult<String> {
    match installed() {
        Some(plugins) => plugins.bundle(state, server_id, rev).await,
        None => Err(ApiError::NotFound),
    }
}

pub async fn runtime_activity_on(
    connection: &mut sqlx::PgConnection,
    server_id: i64,
    checked_at: i64,
) -> ApiResult<ActivityEvidence> {
    match installed() {
        Some(plugins) => {
            plugins
                .runtime_activity_on(connection, server_id, checked_at)
                .await
        }
        None => Ok(ActivityEvidence {
            configured: false,
            last_positive_at: None,
        }),
    }
}
