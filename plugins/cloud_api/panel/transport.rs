use super::Failure;
use futures_util::StreamExt;
use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use std::time::{Duration, SystemTime};

pub fn client() -> Result<Client, Failure> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|_| "client_error".into())
}

pub async fn json(request: RequestBuilder) -> Result<Value, Failure> {
    json_inner(request, false).await
}
pub async fn power_json(request: RequestBuilder) -> Result<Value, Failure> {
    json_inner(request, true).await
}
pub fn power_rejection(value: &Value) -> Option<&'static str> {
    match value["Code"].as_str()? {
        "OperationDenied.NoStock"
        | "Invalid.PrivatePoolOptions.NoStock"
        | "LackResource"
        | "OperationDenied.SpotPriceLowerThanPublicPrice" => Some("capacity_unavailable"),
        "InsufficientBalance" | "InstanceExpired" | "DiskInArrears" => Some("insufficient_balance"),
        "InstanceLockedForSecurity" => Some("resource_locked"),
        "InvalidInstanceId.NotFound" => Some("resource_not_found"),
        "IncorrectInstanceStatus" | "InvalidParameter" | "Forbidden.RAM" => {
            Some("request_rejected")
        }
        _ => None,
    }
}
async fn json_inner(request: RequestBuilder, power: bool) -> Result<Value, Failure> {
    let response = request
        .send()
        .await
        .map_err(|_| Failure::from("network_error"))?;
    let status = response.status().as_u16();
    if status == 429 {
        return Err(Failure {
            code: "rate_limited",
            retry_after: response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| retry_after(v, SystemTime::now()))
                .unwrap_or(300),
        });
    }
    if !(200..300).contains(&status) && !(power && (400..500).contains(&status)) {
        return Err(match status {
            401 | 403 => "authentication_failed",
            404 => "resource_missing",
            300..=399 => "redirect_refused",
            500..=599 => "provider_unavailable",
            _ => "provider_rejected",
        }
        .into());
    }
    const LIMIT: usize = 256 * 1024;
    if response.content_length().is_some_and(|v| v > LIMIT as u64) {
        return Err("response_too_large".into());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Failure::from("network_error"))?;
        if bytes.len() + chunk.len() > LIMIT {
            return Err("response_too_large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| Failure::from("invalid_response"))?;
    if power && let Some(code) = power_rejection(&value) {
        return Err(code.into());
    }
    if !(200..300).contains(&status) {
        return Err("provider_rejected".into());
    }
    Ok(value)
}

pub fn retry_after(value: &str, now: SystemTime) -> Option<i64> {
    let value = value.trim();
    let seconds = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse::<u64>().ok()?
    } else {
        let duration = httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or_default();
        duration
            .as_secs()
            .saturating_add(u64::from(duration.subsec_nanos() != 0))
    };
    Some(seconds.clamp(60, 3600) as i64)
}
