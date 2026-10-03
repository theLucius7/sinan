use super::{lock_settings, telegram, template, webhook};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde_json::{Value, json};

pub async fn channels(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let value: Value =
        sqlx::query_scalar("SELECT settings FROM panel_settings WHERE singleton FOR SHARE")
            .fetch_one(&mut *tx)
            .await?;
    let settings: crate::settings::Settings =
        serde_json::from_value(value).map_err(anyhow::Error::from)?;
    let mut channels = Vec::new();
    for (channel, configured, enabled) in [
        (
            "telegram",
            !settings.telegram_token.is_empty() && !settings.telegram_chat_id.is_empty(),
            settings.telegram_enabled,
        ),
        (
            "webhook",
            settings.webhook.is_some(),
            settings.webhook.as_ref().is_some_and(|value| value.enabled),
        ),
    ] {
        let counts: Value = sqlx::query_scalar("SELECT jsonb_build_object('pending',COUNT(*) FILTER(WHERE status='pending'),'failed',COUNT(*) FILTER(WHERE status='failed'),'sent',COUNT(*) FILTER(WHERE status='sent'),'next_attempt_at',MIN(next_attempt_at) FILTER(WHERE status='pending')) FROM notification_outbox WHERE channel=$1")
            .bind(channel).fetch_one(&mut *tx).await?;
        let last_delivery: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('status',status,'attempts',attempts,'last_error',last_error,'attempted_at',last_attempt_at,'delivered_at',delivered_at) FROM notification_outbox WHERE channel=$1 AND last_attempt_at IS NOT NULL ORDER BY last_attempt_at DESC,id DESC LIMIT 1")
            .bind(channel).fetch_optional(&mut *tx).await?;
        let test: Option<Value> = sqlx::query_scalar("SELECT jsonb_build_object('attempted_at',attempted_at,'success',success,'last_error',last_error) FROM notification_channel_tests WHERE channel=$1")
            .bind(channel).fetch_optional(&mut *tx).await?;
        channels.push(json!({"channel":channel,"configured":configured,"enabled":enabled,"notification_enabled":settings.notification_enabled,"counts":counts,"last_delivery":last_delivery,"test":test}));
    }
    tx.commit().await?;
    Ok(Json(json!(channels)))
}

pub async fn test_telegram(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    test(&state, "telegram").await
}

pub async fn test_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    test(&state, "webhook").await
}

async fn test(state: &AppState, channel: &str) -> ApiResult<Json<Value>> {
    let mut tx = state.pool.begin().await?;
    let settings = lock_settings(&mut tx).await?;
    match channel {
        "telegram"
            if settings.telegram_token.is_empty() || settings.telegram_chat_id.is_empty() =>
        {
            return Err(ApiError::BadRequest("请先保存机器人令牌与会话 ID".into()));
        }
        "webhook" if settings.webhook.is_none() => {
            return Err(ApiError::BadRequest("请先保存 Webhook 配置".into()));
        }
        _ => {}
    }
    let now = sinan_protocol::now_timestamp();
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT attempted_at FROM notification_channel_tests WHERE channel=$1 FOR UPDATE",
    )
    .bind(channel)
    .fetch_optional(&mut *tx)
    .await?;
    // Preserve the existing Telegram cooldown across old and new panel versions.
    let legacy: i64 = if channel == "telegram" {
        sqlx::query_scalar("SELECT sent_at FROM notification_test_limit WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?
    } else {
        0
    };
    if now.saturating_sub(previous.unwrap_or(0).max(legacy)) < 30 {
        return Err(ApiError::Busy);
    }
    sqlx::query("INSERT INTO notification_channel_tests(channel,attempted_at,success,last_error) VALUES($1,$2,NULL,NULL) ON CONFLICT(channel) DO UPDATE SET attempted_at=$2,success=NULL,last_error=NULL")
        .bind(channel).bind(now).execute(&mut *tx).await?;
    if channel == "telegram" {
        sqlx::query("UPDATE notification_test_limit SET sent_at=$1 WHERE singleton")
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    let timestamp: String = sqlx::query_scalar(
        "SELECT to_char(to_timestamp($1) AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') || ' UTC'",
    )
    .bind(now as f64)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let message = "这是一条手动测试消息，用于确认通知配置。";
    let result = if channel == "telegram" {
        let text = template::render(
            &settings.telegram_template,
            ["测试通知", "示例服务器", message, &timestamp, "测试"],
        );
        telegram::send(
            &settings.telegram_token,
            &settings.telegram_chat_id,
            settings.telegram_thread_id,
            &text,
        )
        .await
    } else {
        let config = settings.webhook.as_ref().expect("configured channel");
        match webhook::render(
            &config.body,
            &webhook::Message {
                title: "测试通知",
                server: "示例服务器",
                message,
                time: &timestamp,
                event: "test",
                event_id: "test",
                category: "test",
            },
        ) {
            Ok(body) => webhook::send(config, &body).await,
            Err(message) => Err(telegram::Failure {
                message: message.into(),
                retry_after: None,
            }),
        }
    };
    // A settings change may have removed this record while the test was in flight.
    let mut result_tx = state.pool.begin().await?;
    let current = lock_settings(&mut result_tx).await?;
    let unchanged = if channel == "webhook" {
        current.webhook == settings.webhook
    } else {
        current.telegram_token == settings.telegram_token
            && current.telegram_chat_id == settings.telegram_chat_id
            && current.telegram_thread_id == settings.telegram_thread_id
            && current.telegram_template == settings.telegram_template
    };
    if unchanged {
        sqlx::query("UPDATE notification_channel_tests SET success=$3,last_error=$4 WHERE channel=$1 AND attempted_at=$2")
        .bind(channel).bind(now).bind(result.is_ok()).bind(result.as_ref().err().map(|failure| &failure.message)).execute(&mut *result_tx).await?;
    }
    result_tx.commit().await?;
    result.map_err(|failure| ApiError::BadRequest(failure.message))?;
    Ok(Json(json!({"sent":true})))
}
