use axum::{
    Router,
    routing::{get, post},
};

use crate::{AppState, auth, exchange, notifications, settings, statistics};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .merge(auth::passkeys::routes())
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/me", get(auth::me))
        .route("/api/statistics", get(statistics::summary))
        .route("/api/exchange-rates", get(exchange::get))
        .route("/api/exchange-rates/refresh", post(exchange::refresh))
        .route("/api/settings", get(settings::get).patch(settings::update))
        .route("/api/notifications", get(notifications::list))
        .route("/api/notifications/channels", get(notifications::channels))
        .route(
            "/api/notifications/webhook",
            get(notifications::webhook_settings::get)
                .patch(notifications::webhook_settings::update)
                .delete(notifications::webhook_settings::remove),
        )
        .route(
            "/api/notifications/webhook/test",
            post(notifications::test_webhook),
        )
        .route(
            "/api/notifications/telegram/test",
            post(notifications::test_telegram),
        )
        .route(
            "/api/alert-rules",
            get(notifications::rules::list).post(notifications::rules::create),
        )
        .route(
            "/api/alert-rules/{id}",
            axum::routing::patch(notifications::rules::update).delete(notifications::rules::remove),
        )
        .route("/api/security/totp", get(auth::totp_status))
        .route("/api/security/totp/setup", post(auth::totp_setup))
        .route("/api/security/totp/confirm", post(auth::totp_confirm))
        .route("/api/security/totp/disable", post(auth::totp_disable))
}
