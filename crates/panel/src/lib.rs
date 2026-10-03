#![forbid(unsafe_code)]
//! Panel assembly: the host crate plus the compiled business plugins.
//!
//! Host modules and the plugin paths are re-exported so the public Rust API
//! (`sinan_panel::auth`, `sinan_panel::plugins::singbox`, ...) stays unchanged.

pub use sinan_panel_host::{
    AgentConnection, AppState, agent_api, agent_updates, artifacts, auth, commands, config,
    dashboard, diagnostic_plugins, diagnostics, error, exchange, frontend, installation,
    ip_quality, latency_tasks, maintenance, notifications, passkeys, plugin_api, probes, releases,
    retirement, runtime_control, runtime_operations, runtime_validations, server_assets,
    server_traffic, servers, settings, statistics, telemetry, traffic_correction,
};

pub mod plugins;
pub mod publisher;

// Compatibility exports preserve the public Rust embedding API.
pub use plugins::singbox::proxy_users as users;
pub use plugins::singbox::{accesses, business, deployments, nodes, subscriptions, usage};

/// Builds the panel router with every compiled plugin registered.
pub fn router(state: AppState) -> axum::Router {
    sinan_panel_host::router(state, plugins::router())
}
