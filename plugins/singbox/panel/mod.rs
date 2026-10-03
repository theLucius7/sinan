#![forbid(unsafe_code)]
//! sing-box business plugin: proxy users, nodes, chains, sources and publication.
//!
//! The plugin reaches panel services only through the `sinan-panel-host` API.

pub mod accesses;
mod activity;
pub mod agent;
pub mod business;
pub mod catalog;
pub mod chains;
pub mod deployments;
pub mod entitlements;
pub mod external_access;
pub mod mixed_paths;
mod node_protocol;
mod node_settings;
pub mod nodes;
pub mod ordered_paths;
pub mod packages;
pub mod policies;
mod portal;
pub mod proxy_resources;
pub mod proxy_users;
pub mod publisher;
pub mod runtime_operations;
pub mod settings;
pub mod sources;
pub mod statistics;
mod subscription_fetch;
pub mod subscription_parser;
pub mod subscription_sources;
pub mod subscriptions;
pub mod usage;

pub use activity::runtime_activity_on;

use axum::{
    Router,
    routing::{delete, get, post},
};
#[cfg(test)]
pub(crate) use sinan_panel_host::config;
pub(crate) use sinan_panel_host::{
    AppState, agent_api, artifacts, auth, error, passkeys, plugin_api, runtime_control,
};

pub async fn run(state: AppState) {
    tokio::join!(
        publisher::run(state.clone()),
        subscription_sources::worker::run(state)
    );
}

pub fn router() -> Router<AppState> {
    let management = Router::new()
        .route("/statistics", get(statistics::summary))
        .route("/policy-groups", get(policies::list).post(policies::create))
        .route(
            "/policy-groups/{id}",
            axum::routing::put(policies::update).delete(policies::remove),
        )
        .route(
            "/package-groups",
            get(packages::list).post(packages::create),
        )
        .route(
            "/package-groups/{id}",
            axum::routing::put(packages::update).delete(packages::remove),
        )
        .route("/chains", get(chains::list).post(chains::create))
        .route("/chains/ordered-batch", post(ordered_paths::create_batch))
        .route("/chains/{id}", delete(chains::remove))
        .route("/ordered-proxy-resources", get(proxy_resources::list))
        .route(
            "/ordered-proxy-resources/{kind}/{id}",
            get(proxy_resources::get)
                .patch(ordered_paths::update_resource)
                .delete(proxy_resources::remove),
        )
        .route(
            "/ordered-proxy-resources/chain/{id}/apply-node-versions",
            post(ordered_paths::apply_node_versions),
        )
        .route(
            "/users/{id}/policy-groups",
            get(policies::user_get).put(policies::user_set),
        )
        .route("/users/{id}/package", post(packages::assign))
        .route("/users/{id}/entitlement", get(entitlements::get))
        .route("/servers", get(settings::list))
        .route("/servers/{id}", get(settings::get))
        .route("/servers/{id}/enable", post(settings::enable))
        .route("/servers/{id}/deployments", get(deployments::get))
        .route("/servers/{id}/deployments/check", post(deployments::check))
        .route(
            "/servers/{id}/runtime-operations",
            get(runtime_operations::list).post(runtime_operations::create),
        )
        .route("/nodes", get(nodes::list).post(nodes::create))
        .route(
            "/nodes/{id}",
            get(nodes::get).patch(nodes::update).delete(nodes::remove),
        )
        .route("/users", get(proxy_users::list).post(proxy_users::create))
        .route(
            "/users/{id}",
            get(proxy_users::get)
                .patch(proxy_users::update)
                .delete(proxy_users::remove),
        )
        .route(
            "/users/{id}/subscription/reset",
            post(proxy_users::reset_subscription),
        )
        .route("/users/{id}/subscription", get(subscriptions::preview))
        .route(
            "/users/{id}/external-accesses",
            get(external_access::get).put(external_access::put),
        )
        .route(
            "/users/{id}/accesses",
            get(accesses::list).post(accesses::grant),
        )
        .route(
            "/users/{user_id}/accesses/{node_id}",
            delete(accesses::revoke),
        )
        .route("/usage", get(usage::summary))
        .merge(catalog::router())
        .merge(sources::router())
        .merge(portal::router())
        .merge(mixed_paths::router());
    Router::new()
        .nest(
            "/api/plugins/sing-box",
            management.merge(subscription_sources::routes()),
        )
        .route("/sub/{token}", get(subscriptions::get))
}
