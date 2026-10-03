use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    AppState, agent_api, agent_updates, artifacts, commands, diagnostics, probes, retirement,
    runtime_operations, runtime_validations, servers, telemetry,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/agent/v1/enroll", post(servers::enroll))
        .route("/api/agent/v1/ws", get(agent_api::websocket))
        .route(
            "/api/agent/v1/retirement/receipt",
            post(retirement::receipt),
        )
        .route("/api/agent/v1/manifest", get(agent_api::manifest))
        .route(
            "/api/agent/v1/runtime-validations",
            get(runtime_validations::pending),
        )
        .route(
            "/api/agent/v1/runtime-validations/{id}/result",
            post(runtime_validations::complete),
        )
        .route(
            "/api/agent/v1/runtime-operations",
            get(runtime_operations::pending),
        )
        .route(
            "/api/agent/v1/runtime-operations/{id}",
            post(runtime_operations::complete),
        )
        .route("/api/agent/v1/settings", get(telemetry::agent_settings))
        .route(
            "/api/agent/v1/telemetry-settings",
            get(telemetry::agent_storage_settings),
        )
        .route("/api/agent/v1/update", get(agent_updates::available))
        .route("/api/agent/v1/telemetry", post(telemetry::ingest))
        .route("/api/agent/v1/telemetry/live", post(telemetry::live))
        .route("/api/agent/v1/commands", get(commands::pending))
        .route(
            "/api/agent/v1/commands/lifecycle",
            get(commands::pending_lifecycle),
        )
        .route("/api/agent/v1/commands/{id}/claim", post(commands::claim))
        .route(
            "/api/agent/v1/commands/{id}/control",
            get(commands::control),
        )
        .route(
            "/api/agent/v1/commands/{id}/started",
            post(commands::started),
        )
        .route(
            "/api/agent/v1/commands/{id}",
            post(commands::complete).layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        .route("/api/agent/v1/probes", get(probes::agent_list))
        .route("/api/agent/v1/probe-lease", get(probes::agent_lease))
        .route(
            "/api/agent/v1/probes/authorized",
            get(probes::agent_authorized_list),
        )
        .route("/api/agent/v1/probe-results", post(probes::ingest))
        .route("/api/agent/v1/diagnostics", get(diagnostics::pending))
        .route(
            "/api/agent/v1/diagnostics/cancellations",
            get(diagnostics::cancellation::pending),
        )
        .route(
            "/api/agent/v1/diagnostics/{id}/cancel-confirmation",
            post(diagnostics::cancellation::confirm),
        )
        .route("/api/agent/v1/diagnostics/{id}", post(diagnostics::update))
        .route(
            "/api/agent/v1/diagnostics/{id}/sections",
            post(diagnostics::upload_section),
        )
        .route("/api/agent/v1/bundles/{rev}", get(agent_api::bundle))
        .route(
            "/api/agent/v1/artifacts/{name}/{version}/{arch}",
            get(artifacts::download),
        )
}
