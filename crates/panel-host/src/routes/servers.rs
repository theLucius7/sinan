use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, commands, latency_tasks, probes, servers, telemetry, traffic_correction};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/servers/{id}/traffic-correction",
            post(traffic_correction::correct),
        )
        .route("/api/servers", get(servers::list).post(servers::create))
        .route(
            "/api/servers/{id}",
            get(servers::get)
                .patch(servers::update)
                .delete(servers::remove),
        )
        .route(
            "/api/servers/{id}/enrollment",
            post(servers::issue_enrollment),
        )
        .route(
            "/api/servers/{id}/agent-settings",
            get(telemetry::settings).patch(telemetry::update_settings),
        )
        .route("/api/servers/{id}/metrics", get(telemetry::history))
        .route(
            "/api/servers/{id}/history",
            get(telemetry::aggregate_history),
        )
        .route(
            "/api/servers/{id}/telemetry-settings",
            get(telemetry::storage_settings).patch(telemetry::update_storage_settings),
        )
        .route(
            "/api/telemetry/policy",
            get(telemetry::policy).patch(telemetry::update_policy),
        )
        .route(
            "/api/servers/{id}/commands",
            get(commands::list).post(commands::create),
        )
        .route(
            "/api/servers/{id}/commands/{command}/cancel",
            post(commands::cancel),
        )
        .route(
            "/api/servers/{id}/probes",
            get(probes::list).post(probes::create),
        )
        .route(
            "/api/servers/{id}/probes/{probe}",
            axum::routing::patch(probes::update).delete(probes::remove),
        )
        .route("/api/servers/{id}/probe-results", get(probes::history))
        .route("/api/probes/overview", get(probes::overview))
        .route(
            "/api/latency-tasks",
            get(latency_tasks::list).post(latency_tasks::create),
        )
        .route(
            "/api/latency-tasks/{id}",
            axum::routing::patch(latency_tasks::update).delete(latency_tasks::remove),
        )
}
