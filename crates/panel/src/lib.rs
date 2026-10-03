#![forbid(unsafe_code)]

pub mod agent_api;
pub mod agent_updates;
pub mod artifacts;
pub mod auth;
pub mod commands;
pub mod config;
pub mod control_center;
pub mod dashboard;
pub mod diagnostic_plugins;
pub mod diagnostics;
pub mod error;
pub mod exchange;
pub mod fleet;
pub mod frontend;
pub mod installation;
pub mod ip_quality;
pub mod latency_tasks;
pub mod maintenance;
pub mod network_configuration;
pub mod network_workbench;
pub mod notifications;
pub mod operations;
pub mod passkeys;
pub mod plugins;
pub mod probes;
pub mod settings;
pub mod statistics;
pub mod traffic_correction;
// Compatibility exports preserve the public Rust embedding API.
pub use plugins::singbox::proxy_users as users;
pub use plugins::singbox::{accesses, business, deployments, nodes, subscriptions, usage};
pub mod publisher;
pub mod releases;
pub mod retirement;
pub mod runtime_control;
pub mod runtime_operations;
pub mod runtime_validations;
pub mod server_assets;
pub mod server_traffic;
pub mod servers;
pub mod telemetry;

mod routes;
mod state;

pub use routes::router;
pub use state::{AgentConnection, AppState};
