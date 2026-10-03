mod agent;
mod artifacts;
mod diagnostics;
mod servers;
mod system;

use axum::{Router, extract::DefaultBodyLimit, routing::get};

use crate::{AppState, dashboard, frontend};

/// Builds the panel router; `plugins` carries the routes of the assembled plugins.
pub fn router(state: AppState, plugins: Router<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(system::routes())
        .merge(crate::runtime_control::routes())
        .merge(servers::routes())
        .merge(diagnostics::routes())
        .merge(agent::routes())
        .merge(artifacts::routes())
        .merge(dashboard::routes())
        .merge(plugins)
        .fallback(frontend::serve)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}
