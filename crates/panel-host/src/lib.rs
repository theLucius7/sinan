#![forbid(unsafe_code)]
//! Panel host: shared services, the device channel and the plugin interface.
//!
//! The host never names a business plugin; the `sinan-panel` binary assembles
//! plugins through [`plugin_api`] and the router passed to [`router`].

pub mod agent_api;
pub mod agent_updates;
pub mod artifacts;
pub mod auth;
pub mod commands;
pub mod config;
pub mod dashboard;
pub mod diagnostic_plugins;
pub mod diagnostics;
pub mod error;
pub mod exchange;
pub mod frontend;
pub mod installation;
pub mod ip_quality;
pub mod latency_tasks;
pub mod maintenance;
pub mod notifications;
pub mod passkeys;
pub mod plugin_api;
pub mod probes;
pub mod releases;
pub mod retirement;
pub mod runtime_control;
pub mod runtime_operations;
pub mod runtime_validations;
pub mod server_assets;
pub mod server_traffic;
pub mod servers;
pub mod settings;
pub mod statistics;
pub mod telemetry;
pub mod traffic_correction;

mod routes;
mod state;

pub use routes::router;
pub use state::{AgentConnection, AppState};
