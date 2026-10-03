use super::{
    lock_settings,
    webhook::{self, Config, Preset},
};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
    settings,
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;
use serde_json::{Value, json};

pub(super) fn view(config: Option<&Config>) -> Value {
    json!({
        "enabled": config.is_some_and(|value| value.enabled),
        "preset": config.map(|value| value.preset).unwrap_or_default(),
        "url_configured": config.is_some_and(|value| !value.url.is_empty()),
        "headers_configured": config.is_some_and(|value| !value.headers.is_empty()),
        "body_configured": config.is_some_and(|value| !value.body.is_empty()),
    })
}

pub async fn get(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(view(
        settings::read(&state.pool).await?.webhook.as_ref(),
    )))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    enabled: bool,
    preset: Preset,
    url: Option<String>,
    headers: Option<String>,
    body: Option<String>,
    #[serde(default)]
    clear_headers: bool,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<Update>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let mut settings = lock_settings(&mut tx).await?;
    // Changing provider never inherits credentials or templates from the previous provider.
    let previous = settings
        .webhook
        .as_ref()
        .filter(|value| value.preset == update.preset);
    let pick = |new: Option<String>, old: Option<&String>| {
        new.filter(|value| !value.trim().is_empty())
            .or_else(|| old.cloned())
            .unwrap_or_default()
    };
    let config = Config {
        enabled: update.enabled,
        preset: update.preset,
        url: pick(
            update.url.map(|value| value.trim().to_owned()),
            previous.map(|value| &value.url),
        ),
        headers: if update.clear_headers {
            String::new()
        } else {
            pick(update.headers, previous.map(|value| &value.headers))
        },
        body: pick(update.body, previous.map(|value| &value.body)),
    };
    webhook::validate(&config).map_err(|message| ApiError::BadRequest(message.into()))?;
    if !config.enabled || settings.webhook.as_ref() != Some(&config) {
        sqlx::query("UPDATE notification_outbox SET status='cancelled' WHERE channel='webhook' AND status='pending'")
            .execute(&mut *tx).await?;
    }
    if settings.webhook.as_ref() != Some(&config) {
        sqlx::query("DELETE FROM notification_channel_tests WHERE channel='webhook'")
            .execute(&mut *tx)
            .await?;
    }
    let result = view(Some(&config));
    settings.webhook = Some(config);
    sqlx::query("UPDATE panel_settings SET settings=$1 WHERE singleton")
        .bind(json!(settings))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub async fn remove(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let mut settings = lock_settings(&mut tx).await?;
    settings.webhook = None;
    sqlx::query("UPDATE panel_settings SET settings=$1 WHERE singleton")
        .bind(json!(settings))
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE notification_outbox SET status='cancelled' WHERE channel='webhook' AND status='pending'").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM notification_channel_tests WHERE channel='webhook'")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(view(None)))
}
