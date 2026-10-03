use super::{telegram, template, webhook};
use crate::settings::Settings;

pub fn render(
    settings: &Settings,
    message: &webhook::Message<'_>,
) -> Vec<(&'static str, Result<String, String>)> {
    let mut payloads = Vec::new();
    if settings.telegram_ready() {
        payloads.push((
            "telegram",
            Ok(template::render(
                &settings.telegram_template,
                [
                    message.title,
                    message.server,
                    message.message,
                    message.time,
                    message.event_id,
                ],
            )),
        ));
    }
    if settings.webhook_ready()
        && let Some(config) = &settings.webhook
    {
        payloads.push((
            "webhook",
            webhook::render(&config.body, message).map_err(str::to_owned),
        ));
    }
    payloads
}
pub async fn send(
    settings: &Settings,
    channel: &str,
    message: &str,
) -> Result<(), (String, Option<i64>)> {
    let result = if channel == "webhook"
        && let Some(config) = &settings.webhook
    {
        webhook::send(config, message).await
    } else if channel == "telegram" {
        telegram::send(
            &settings.telegram_token,
            &settings.telegram_chat_id,
            settings.telegram_thread_id,
            message,
        )
        .await
    } else {
        return Err(("通知渠道未配置".into(), None));
    };
    result.map_err(|e| (e.message, e.retry_after))
}
