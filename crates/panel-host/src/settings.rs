use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub public_dashboard: bool,
    pub notification_enabled: bool,
    pub offline_alerts: bool,
    pub offline_minutes: u16,
    pub expiry_alert_days: u16,
    pub traffic_alert_percentage: u8,
    pub telegram_enabled: bool,
    pub telegram_chat_id: String,
    pub telegram_token: String,
    pub telegram_thread_id: Option<i32>,
    pub telegram_template: String,
    pub webhook: Option<crate::notifications::webhook::Config>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            public_dashboard: false,
            notification_enabled: true,
            offline_alerts: true,
            offline_minutes: 5,
            expiry_alert_days: 0,
            traffic_alert_percentage: 0,
            telegram_enabled: false,
            telegram_chat_id: String::new(),
            telegram_token: String::new(),
            telegram_thread_id: None,
            telegram_template:
                "司南 · {{title}}\n服务器：{{server}}\n{{message}}\n时间：{{time}}\n事件：{{event}}"
                    .into(),
            webhook: None,
        }
    }
}

impl Settings {
    fn view(&self) -> Value {
        json!({"public_dashboard":self.public_dashboard,"notification_enabled":self.notification_enabled,"offline_alerts":self.offline_alerts,
            "expiry_alert_days":self.expiry_alert_days,"traffic_alert_percentage":self.traffic_alert_percentage,
            "offline_minutes":self.offline_minutes,"telegram_enabled":self.telegram_enabled,
            "telegram_thread_id":self.telegram_thread_id,"telegram_template":self.telegram_template,
            "telegram_chat_id":self.telegram_chat_id,"telegram_token_configured":!self.telegram_token.is_empty()})
    }
    pub fn telegram_ready(&self) -> bool {
        self.notification_enabled
            && self.telegram_enabled
            && !self.telegram_token.is_empty()
            && !self.telegram_chat_id.is_empty()
    }
    pub fn webhook_ready(&self) -> bool {
        self.notification_enabled && self.webhook.as_ref().is_some_and(|config| config.enabled)
    }
}

pub async fn read(pool: &PgPool) -> ApiResult<Settings> {
    let value: Value = sqlx::query_scalar("SELECT settings FROM panel_settings WHERE singleton")
        .fetch_one(pool)
        .await?;
    serde_json::from_value(value).map_err(|error| ApiError::Internal(error.into()))
}

pub async fn get(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(read(&state.pool).await?.view()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    public_dashboard: bool,
    offline_alerts: bool,
    offline_minutes: u16,
    telegram_enabled: bool,
    telegram_chat_id: String,
    telegram_token: Option<String>,
    notification_enabled: Option<bool>,
    expiry_alert_days: Option<u16>,
    traffic_alert_percentage: Option<u8>,
    // Missing preserves the topic; zero clears it without ambiguous JSON null handling.
    telegram_thread_id: Option<i32>,
    telegram_template: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<Update>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let value: Value =
        sqlx::query_scalar("SELECT settings FROM panel_settings WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    let old: Settings = serde_json::from_value(value).map_err(anyhow::Error::from)?;
    let settings = Settings {
        public_dashboard: update.public_dashboard,
        notification_enabled: update
            .notification_enabled
            .unwrap_or(old.notification_enabled),
        offline_alerts: update.offline_alerts,
        offline_minutes: update.offline_minutes,
        expiry_alert_days: update.expiry_alert_days.unwrap_or(old.expiry_alert_days),
        traffic_alert_percentage: update
            .traffic_alert_percentage
            .unwrap_or(old.traffic_alert_percentage),
        telegram_enabled: update.telegram_enabled,
        telegram_chat_id: update.telegram_chat_id.trim().into(),
        telegram_token: update
            .telegram_token
            .map(|token| token.trim().into())
            .unwrap_or_else(|| old.telegram_token.clone()),
        telegram_thread_id: update
            .telegram_thread_id
            .map(|id| (id != 0).then_some(id))
            .unwrap_or(old.telegram_thread_id),
        telegram_template: update
            .telegram_template
            .unwrap_or_else(|| old.telegram_template.clone()),
        webhook: old.webhook.clone(),
    };
    let valid_token = settings.telegram_token.is_empty()
        || settings
            .telegram_token
            .split_once(':')
            .is_some_and(|(id, secret)| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_digit())
                    && secret.len() >= 20
                    && secret
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            });
    let chat = &settings.telegram_chat_id;
    let valid_chat = chat.is_empty()
        || chat.parse::<i64>().is_ok()
        || chat.strip_prefix('@').is_some_and(|v| {
            !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
    if !(2..=1440).contains(&settings.offline_minutes)
        || settings.expiry_alert_days > 365
        || (settings.traffic_alert_percentage != 0
            && !(50..=100).contains(&settings.traffic_alert_percentage))
        || settings.telegram_thread_id.is_some_and(|id| id < 1)
        || !crate::notifications::valid_template(&settings.telegram_template)
        || settings.telegram_token.len() > 256
        || !valid_token
        || !valid_chat
        || chat.len() > 128
        || (settings.telegram_enabled && (settings.telegram_token.is_empty() || chat.is_empty()))
    {
        return Err(ApiError::BadRequest(
            "设置无效：离线阈值需为 2–1440 分钟，到期为 0–365 天，流量阈值为 0 或 50–100%；请检查 Telegram 凭据、话题 ID 和消息模板".into(),
        ));
    }
    sqlx::query("UPDATE panel_settings SET settings=$1 WHERE singleton")
        .bind(json!(settings))
        .execute(&mut *tx)
        .await?;
    // Do not deliver stale notifications to a newly configured recipient.
    if !settings.telegram_ready()
        || old.telegram_chat_id != settings.telegram_chat_id
        || old.telegram_token != settings.telegram_token
        || old.telegram_thread_id != settings.telegram_thread_id
        || old.telegram_template != settings.telegram_template
    {
        sqlx::query("UPDATE notification_outbox SET status='cancelled' WHERE channel='telegram' AND status='pending'")
            .execute(&mut *tx)
            .await?;
    }
    if old.telegram_chat_id != settings.telegram_chat_id
        || old.telegram_token != settings.telegram_token
        || old.telegram_thread_id != settings.telegram_thread_id
        || old.telegram_template != settings.telegram_template
    {
        sqlx::query("DELETE FROM notification_channel_tests WHERE channel='telegram'")
            .execute(&mut *tx)
            .await?;
    }
    if !settings.notification_enabled {
        sqlx::query("UPDATE notification_outbox SET status='cancelled' WHERE status='pending'")
            .execute(&mut *tx)
            .await?;
    }
    if !settings.offline_alerts {
        sqlx::query("UPDATE notification_outbox o SET status='cancelled' FROM server_alert_events e WHERE o.event_id=e.id AND e.category='offline' AND o.status='pending'").execute(&mut *tx).await?;
    }
    for (category, enabled) in [
        ("expiry", settings.expiry_alert_days > 0),
        ("traffic", settings.traffic_alert_percentage > 0),
    ] {
        if !enabled {
            sqlx::query("UPDATE notification_outbox o SET status='cancelled' FROM server_alert_events e WHERE o.event_id=e.id AND e.category=$1 AND o.status='pending'")
                .bind(category).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(Json(settings.view()))
}
