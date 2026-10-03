use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, diagnostic_plugins, diagnostics, ip_quality};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/servers/{id}/diagnostics",
            get(diagnostics::service::get),
        )
        .route(
            "/api/servers/{id}/diagnostics/{plugin}",
            post(diagnostics::service::create),
        )
        .route("/api/servers/{id}/ip-quality", get(ip_quality::get))
        .route(
            "/api/servers/{id}/ip-quality/node-query",
            post(diagnostic_plugins::nodequality::node_queries::create),
        )
        .route(
            "/api/servers/{id}/ip-quality/refresh",
            post(ip_quality::refresh),
        )
        .route(
            "/api/servers/{id}/node-quality",
            get(diagnostics::legacy_get),
        )
        .route(
            "/api/servers/{id}/node-quality/refresh",
            post(ip_quality::refresh),
        )
        .route(
            "/api/servers/{id}/node-quality/reports",
            get(diagnostics::get).post(diagnostics::create),
        )
        .route(
            "/api/servers/{id}/diagnostics/{job}/cancel",
            post(diagnostics::cancellation::request),
        )
        .route(
            "/api/plugins/tcpquality/servers/{id}/targets",
            get(diagnostic_plugins::tcpquality::list_targets),
        )
        .route(
            "/api/plugins/tcpquality/servers/{id}/targets/{probe}",
            axum::routing::patch(diagnostic_plugins::tcpquality::set_region),
        )
}
