mod channels;
mod evaluation;
mod events;
mod outbox;
pub mod plugin;
mod resources;
mod retry;
pub mod rules;
mod telegram;
mod template;
pub mod webhook;
pub mod webhook_settings;
use crate::{AppState, auth, error::ApiResult, settings::Settings};
use axum::{Json, extract::State, http::HeaderMap};
pub use channels::{channels, test_telegram, test_webhook};
pub use evaluation::evaluate;
pub use outbox::dispatch;
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
pub use template::valid as valid_template;

#[derive(Serialize, FromRow)]
pub struct Event {
    id: i64,
    server_id: i64,
    server_name: String,
    last_seen: Option<i64>,
    category: String,
    message: String,
    details: Value,
    opened_at: i64,
    resolved_at: Option<i64>,
    resolution: Option<String>,
    deliveries: Value,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Event>>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(sqlx::query_as("SELECT e.*, COALESCE((SELECT jsonb_agg(jsonb_build_object('id',o.id,'channel',o.channel,'kind',o.kind,'status',o.status,'attempts',o.attempts,'last_error',o.last_error,'next_attempt_at',o.next_attempt_at,'last_attempt_at',o.last_attempt_at,'delivered_at',o.delivered_at) ORDER BY o.id) FROM notification_outbox o WHERE o.event_id=e.id),'[]'::jsonb) AS deliveries FROM server_alert_events e ORDER BY e.id DESC LIMIT 200").fetch_all(&state.pool).await?))
}

pub(super) async fn lock_settings(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<Settings> {
    let value: Value =
        sqlx::query_scalar("SELECT settings FROM panel_settings WHERE singleton FOR UPDATE")
            .fetch_one(&mut **tx)
            .await?;
    Ok(serde_json::from_value(value)?)
}
