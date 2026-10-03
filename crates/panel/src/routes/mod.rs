mod agent;
mod artifacts;
mod diagnostics;
mod servers;
mod system;

use axum::{Router, extract::DefaultBodyLimit, routing::get};

use crate::{AppState, dashboard, frontend, plugins};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(system::routes())
        .merge(crate::control_center::router())
        .merge(crate::fleet::router())
        .merge(crate::network_workbench::router())
        .merge(crate::network_configuration::router())
        .merge(crate::operations::router())
        .merge(crate::runtime_control::routes())
        .merge(servers::routes())
        .merge(diagnostics::routes())
        .merge(agent::routes())
        .merge(artifacts::routes())
        .merge(dashboard::routes())
        .merge(plugins::router())
        .fallback(frontend::serve)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::control_center::guard::guard,
        ))
        .with_state(state)
}
