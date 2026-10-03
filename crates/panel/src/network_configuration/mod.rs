mod acme;
mod acme_executor;
mod certificate_deployments;
mod certificates;
mod dns_challenges;
mod documents;
mod models;
mod operations;
mod server_migrations;
mod x509;

use crate::AppState;
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(documents::routes())
        .merge(certificates::routes())
        .merge(acme::routes())
        .merge(certificate_deployments::routes())
        .merge(dns_challenges::routes())
        .merge(operations::routes())
        .merge(server_migrations::routes())
}

pub async fn run(state: AppState) {
    acme::run(state).await
}

pub(crate) fn certificate_metadata(public_chain: &str) -> anyhow::Result<serde_json::Value> {
    let certificate = x509::parse(public_chain)?;
    Ok(
        serde_json::json!({"fingerprint":certificate.fingerprint,"not_before":certificate.not_before,"not_after":certificate.not_after,"names":certificate.names}),
    )
}
