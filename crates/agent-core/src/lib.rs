#![forbid(unsafe_code)]

#[cfg(test)]
#[path = "../../protocol/tests/support/release.rs"]
mod release_test_support;

pub mod artifacts;
pub mod config;
pub mod fake;
pub mod fleet;
pub mod identity;
mod panel_tls;
pub mod reconcile;
pub mod retirement;
pub mod runtime_operations;
mod runtime_platform;
pub mod runtime_validations;
pub mod state;
#[cfg(unix)]
pub mod system;
#[cfg(windows)]
#[path = "system/windows.rs"]
pub mod system;
pub mod system_forwarding;
pub mod system_network;
pub mod tasks;
pub mod telemetry;
pub mod transport;
pub mod upgrade;
pub mod usage;

pub use config::Config;
pub use state::{SharedState, State};
