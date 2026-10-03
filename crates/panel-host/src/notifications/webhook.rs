use super::telegram::Failure;
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{str::FromStr, time::Duration};

pub const DEFAULT_BODY: &str = r#"{"event":"{{event}}","event_id":"{{event_id}}","category":"{{category}}","node":"{{server}}","title":"{{title}}","message":"{{message}}","site":"{{site}}","time":"{{time}}"}"#;
const KEYS: [&str; 9] = [
    "title", "server", "node", "message", "time", "event", "event_id", "category", "site",
];

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    #[default]
    Custom,
    Bark,
    Discord,
    Slack,
    Wecom,
    Dingtalk,
    Feishu,
    Ntfy,
    Gotify,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub enabled: bool,
    pub preset: Preset,
    pub url: String,
    pub headers: String,
    pub body: String,
}

pub(super) fn validate(config: &Config) -> Result<(), &'static str> {
    let url = Url::parse(&config.url).map_err(|_| "Webhook 地址无效")?;
    if config.url.len() > 2048
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || config.url.chars().any(char::is_whitespace)
    {
        return Err("Webhook 地址必须为 HTTP 或 HTTPS，不得包含用户信息、空白或片段");
    }
    headers(&config.headers)?;
    if config.body.len() > 16 * 1024 {
        return Err("Webhook 模板不得超过 16 KiB");
    }
    let mut body: Value = serde_json::from_str(&config.body)
        .map_err(|_| "Webhook 模板必须为有效 JSON；占位符需位于字符串内")?;
    substitute(&mut body, &["example"; 9])?;
    Ok(())
}

fn headers(raw: &str) -> Result<HeaderMap, &'static str> {
    if raw.len() > 8192 || raw.lines().count() > 32 {
        return Err("Webhook 请求头过长");
    }
    let mut result = HeaderMap::new();
    result.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or("Webhook 请求头需为每行一个名称: 值")?;
        let name = HeaderName::from_str(name.trim()).map_err(|_| "Webhook 请求头名称无效")?;
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "trailer"
                | "te"
                | "upgrade"
        ) || name.as_str().starts_with("proxy-")
        {
            return Err("Webhook 不允许覆盖连接或代理请求头");
        }
        let value = HeaderValue::from_str(value.trim()).map_err(|_| "Webhook 请求头内容无效")?;
        result.insert(name, value);
    }
    Ok(result)
}

fn replace(template: &str, values: &[&str; 9]) -> Result<String, &'static str> {
    let mut output = String::new();
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("{{") {
        if before.contains("}}") {
            return Err("Webhook 模板占位符无效");
        }
        output.push_str(before);
        let (key, tail) = after.split_once("}}").ok_or("Webhook 模板占位符未闭合")?;
        let index = KEYS
            .iter()
            .position(|known| *known == key)
            .ok_or("Webhook 模板含未知占位符")?;
        output.push_str(values[index]);
        rest = tail;
    }
    if rest.contains("}}") {
        return Err("Webhook 模板占位符无效");
    }
    output.push_str(rest);
    Ok(output)
}

fn substitute(value: &mut Value, values: &[&str; 9]) -> Result<(), &'static str> {
    match value {
        Value::String(text) => *text = replace(text, values)?,
        Value::Array(items) => {
            for item in items {
                substitute(item, values)?;
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                if key.contains("{{") || key.contains("}}") {
                    return Err("Webhook 占位符仅支持 JSON 字符串值");
                }
                substitute(item, values)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub struct Message<'a> {
    pub title: &'a str,
    pub server: &'a str,
    pub message: &'a str,
    pub time: &'a str,
    pub event: &'a str,
    pub event_id: &'a str,
    pub category: &'a str,
}

pub(super) fn render(body: &str, message: &Message<'_>) -> Result<String, &'static str> {
    let mut body: Value = serde_json::from_str(body).map_err(|_| "Webhook 模板必须为有效 JSON")?;
    substitute(
        &mut body,
        &[
            message.title,
            message.server,
            message.server,
            message.message,
            message.time,
            message.event,
            message.event_id,
            message.category,
            "司南",
        ],
    )?;
    let result = body.to_string();
    if result.len() > 64 * 1024 {
        return Err("Webhook 替换后的消息超过 64 KiB");
    }
    Ok(result)
}

fn failure(message: &str) -> Failure {
    Failure {
        message: message.into(),
        retry_after: None,
    }
}

fn acknowledged(preset: Preset, bytes: &[u8], body: &str) -> bool {
    let value = serde_json::from_slice::<Value>(bytes).unwrap_or(Value::Null);
    match preset {
        Preset::Custom => true,
        Preset::Slack => std::str::from_utf8(bytes).is_ok_and(|text| text.trim() == "ok"),
        Preset::Discord => value.get("id").and_then(Value::as_str).is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 32
                && id.bytes().all(|byte| byte.is_ascii_digit())
                && id.bytes().any(|byte| byte != b'0')
        }),
        Preset::Bark => value.get("code").and_then(Value::as_i64) == Some(200),
        Preset::Wecom | Preset::Dingtalk => value.get("errcode").and_then(Value::as_i64) == Some(0),
        Preset::Feishu => {
            let code = value.get("code");
            let legacy = value.get("StatusCode");
            (code.is_some() || legacy.is_some())
                && code.is_none_or(|code| code.as_i64() == Some(0))
                && legacy.is_none_or(|code| code.as_i64() == Some(0))
        }
        Preset::Gotify => value
            .get("id")
            .and_then(Value::as_i64)
            .is_some_and(|id| id > 0),
        Preset::Ntfy => {
            let sent = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
            value.get("event").and_then(Value::as_str) == Some("message")
                && value.get("id").and_then(Value::as_str).is_some_and(|id| {
                    !id.is_empty()
                        && id.len() <= 128
                        && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
                && value
                    .get("topic")
                    .and_then(Value::as_str)
                    .is_some_and(|topic| {
                        !topic.is_empty()
                            && sent.get("topic").and_then(Value::as_str) == Some(topic)
                    })
        }
    }
}

pub(super) async fn send(config: &Config, body: &str) -> Result<(), Failure> {
    if body.len() > 64 * 1024 {
        return Err(failure("Webhook 替换后的消息超过 64 KiB"));
    }
    let mut target = Url::parse(&config.url).map_err(|_| failure("Webhook 地址无效"))?;
    if config.preset == Preset::Discord {
        // Without confirmation Discord can return success even when no message was saved.
        let parameters: Vec<_> = target
            .query_pairs()
            .filter(|(name, _)| name != "wait")
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        target.set_query(None);
        target
            .query_pairs_mut()
            .extend_pairs(parameters)
            .append_pair("wait", "true");
    }
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|_| failure("Webhook 客户端初始化失败"))?;
    let headers = headers(&config.headers).map_err(failure)?;
    let mut response = client
        .post(target)
        .headers(headers)
        .body(body.to_owned())
        .send()
        .await
        .map_err(|_| failure("Webhook 请求失败，请检查地址、认证配置与网络"))?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| super::retry::after(value, std::time::SystemTime::now()));
    if !status.is_success() {
        return Err(Failure {
            message: format!(
                "Webhook 未接受通知（HTTP {}），请检查配置或稍后重试",
                status.as_u16()
            ),
            retry_after,
        });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("Webhook 响应读取失败"))?
    {
        if bytes.len() + chunk.len() > 64 * 1024 {
            return Err(failure("Webhook 响应超过 64 KiB"));
        }
        bytes.extend_from_slice(&chunk);
    }
    if acknowledged(config.preset, &bytes, body) {
        Ok(())
    } else {
        Err(failure(
            "Webhook 返回业务失败或缺少成功标记，请检查预设、认证与机器人安全设置",
        ))
    }
}

#[cfg(test)]
#[path = "webhook_tests.rs"]
mod tests;
