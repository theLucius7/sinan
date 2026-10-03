use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, artifacts, releases};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/artifacts", get(artifacts::list))
        .route("/api/artifacts/targets", get(releases::target_options))
        .route(
            "/api/artifacts/agent-versions",
            get(releases::list_agent_versions),
        )
        .route(
            "/api/bootstrap/versions",
            get(releases::bootstrap_agent_versions),
        )
        .route("/api/artifacts/import-release", post(releases::import))
        .route("/api/bootstrap/{version}/{arch}", get(artifacts::bootstrap))
        .route("/install.sh", get(artifacts::install_script))
        .route("/install.ps1", get(artifacts::install_powershell))
}
