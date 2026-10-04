//! Typed network and hardware workbench using the shared diagnostic lifecycle.
mod api;
mod authorization;
mod engine;
mod http_probe;
mod models;
mod plugin;
mod prepare;
mod reports;
use crate::AppState;
pub(crate) use authorization::delivery as authorize_delivery;
use axum::{
    Router,
    routing::{get, patch, post},
};
pub use engine::tick;
pub use models::{Check, Execution, Observation, Plan};
pub use plugin::NetworkWorkbenchPlugin;
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/network-workbench/catalog", get(api::catalog))
        .route(
            "/api/network-workbench/targets",
            get(api::targets).post(api::save_target),
        )
        .route(
            "/api/network-workbench/targets/{id}",
            patch(api::update_target).delete(api::delete_target),
        )
        .route(
            "/api/network-workbench/tools",
            get(api::tools).post(api::save_tool),
        )
        .route(
            "/api/network-workbench/providers",
            get(reports::providers).post(reports::save_provider),
        )
        .route(
            "/api/network-workbench/plans",
            get(api::plans).post(api::save_plan),
        )
        .route("/api/network-workbench/plans/{id}", patch(api::update_plan))
        .route(
            "/api/network-workbench/plans/{id}/run",
            post(api::start_plan),
        )
        .route(
            "/api/network-workbench/runs",
            get(api::runs).post(api::start),
        )
        .route("/api/network-workbench/runs/{id}", get(api::run))
        .route("/api/network-workbench/runs/{id}/cancel", post(api::cancel))
        .route("/api/network-workbench/runs/{id}/resume", post(api::resume))
        .route(
            "/api/network-workbench/runs/{id}/import",
            post(reports::import),
        )
        .route(
            "/api/network-workbench/runs/{id}/shares",
            post(reports::share),
        )
        .route(
            "/api/network-workbench/shares/{id}/revoke",
            post(reports::revoke),
        )
        .route("/api/network-workbench/compare", post(reports::compare))
        .route(
            "/api/network-workbench/ip-history/{address}",
            get(reports::ip_history),
        )
        .route(
            "/api/network-workbench/exit-history/{server}",
            get(reports::exit_history),
        )
        .route("/api/network-workbench/pairings", post(reports::pairing))
        .route("/network-report/{token}", get(reports::shared))
        .route("/network-pairing/{token}", post(reports::paired_result))
}
