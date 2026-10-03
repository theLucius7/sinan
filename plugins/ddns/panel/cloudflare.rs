use super::model::{Rule, domain, identifier};
use futures_util::StreamExt;
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    future::Future,
    net::IpAddr,
    time::{Duration, SystemTime},
};

const RESPONSE_LIMIT: usize = 256 * 1024;

pub(super) use crate::cloud_api::Failure;

pub(super) struct Cloudflare {
    client: Client,
    base: Url,
}

#[derive(Debug)]
pub(super) struct Outcome {
    pub record_id: String,
    pub status: &'static str,
}

#[derive(Deserialize)]
struct Record {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    comment: Option<String>,
}

impl Cloudflare {
    pub fn new() -> Result<Self, Failure> {
        Ok(Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(6))
                .build()
                .map_err(|_| Failure::from("client_error"))?,
            base: Url::parse("https://api.cloudflare.com/client/v4/")
                .map_err(|_| Failure::from("client_error"))?,
        })
    }

    #[cfg(test)]
    pub fn local(base: &str) -> Self {
        let mut client = Self::new().unwrap();
        client.base = Url::parse(base).unwrap();
        assert_eq!(client.base.host_str(), Some("127.0.0.1"));
        client
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, Failure> {
        let url = self
            .base
            .join(path)
            .map_err(|_| Failure::from("invalid_response"))?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(token)
            .query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| Failure::from("network_error"))?;
        let status = response.status();
        if status.as_u16() == 429 {
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
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => "authentication_failed",
                404 => "resource_missing",
                400 | 409 => "provider_rejected",
                500..=599 => "provider_unavailable",
                300..=399 => "redirect_refused",
                _ => "http_error",
            }
            .into());
        }
        if response
            .content_length()
            .is_some_and(|length| length > RESPONSE_LIMIT as u64)
        {
            return Err("response_too_large".into());
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Failure::from("network_error"))?;
            if bytes.len() + chunk.len() > RESPONSE_LIMIT {
                return Err("response_too_large".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Value =
            serde_json::from_slice(&bytes).map_err(|_| Failure::from("invalid_response"))?;
        if envelope["success"] != true
            || envelope
                .get("errors")
                .is_some_and(|errors| errors.as_array().is_none_or(|errors| !errors.is_empty()))
        {
            return Err("provider_rejected".into());
        }
        Ok(envelope)
    }

    pub async fn reconcile_guarded<G, Check, Checked>(
        &self,
        rule: &Rule,
        ip: IpAddr,
        mut check: Check,
    ) -> Result<Outcome, Failure>
    where
        Check: FnMut() -> Checked,
        Checked: Future<Output = Result<G, Failure>>,
    {
        let config = &rule.config;
        if !identifier(&config.zone_id) {
            return Err("invalid_configuration".into());
        }
        let zone_path = format!("zones/{}", config.zone_id);
        let zone = self
            .call(Method::GET, &zone_path, &rule.api_token, &[], None)
            .await?;
        let zone_name = zone["result"]["name"]
            .as_str()
            .and_then(domain)
            .ok_or(Failure::from("invalid_response"))?;
        if zone["result"]["id"] != config.zone_id || zone_name.starts_with("*.") {
            return Err("invalid_response".into());
        }
        if config.record_name != zone_name
            && !config.record_name.ends_with(&format!(".{zone_name}"))
        {
            return Err("zone_mismatch".into());
        }
        if zone["result"]["status"] != "active" {
            return Err("zone_inactive".into());
        }
        let path = format!("{zone_path}/dns_records");
        let listing = self
            .call(
                Method::GET,
                &path,
                &rule.api_token,
                &[
                    ("name.exact", &config.record_name),
                    ("per_page", "100"),
                    ("page", "1"),
                ],
                None,
            )
            .await?;
        let records: Vec<Record> = serde_json::from_value(listing["result"].clone())
            .map_err(|_| Failure::from("invalid_response"))?;
        let total = listing["result_info"]["total_count"].as_u64();
        let pages = listing["result_info"]["total_pages"].as_u64();
        // A DDNS name has at most one record of each managed family. Refuse an
        // incomplete list rather than guessing which record may be changed.
        if total != Some(records.len() as u64)
            || pages.is_none_or(|pages| pages > 1)
            || records.len() > 100
        {
            return Err("record_conflict".into());
        }
        if records.iter().any(|r| {
            domain(&r.name).as_deref() != Some(config.record_name.as_str()) || !identifier(&r.id)
        }) {
            return Err("invalid_response".into());
        }
        if records
            .iter()
            .any(|r| matches!(r.record_type.as_str(), "CNAME" | "NS"))
        {
            return Err("record_conflict".into());
        }
        let matching: Vec<_> = records
            .iter()
            .filter(|r| r.record_type == config.record_type)
            .collect();
        if matching.len() > 1 {
            return Err("record_conflict".into());
        }
        let marker = format!("sinan-ddns:{}", rule.id);
        let ttl = if config.proxied { 1 } else { config.ttl };
        let (method, path, body, previous_id) = if let Some(record) = matching.first() {
            let owned = rule.record_id.as_deref() == Some(record.id.as_str())
                || record.comment.as_deref() == Some(marker.as_str());
            if !owned && !config.adopt_existing {
                return Err("record_not_owned".into());
            }
            if record.content.parse::<IpAddr>().ok() == Some(ip)
                && record.ttl == ttl
                && record.proxied == config.proxied
            {
                // A read that began while eligible cannot turn stale state into success.
                let _guard = check().await?;
                return Ok(Outcome {
                    record_id: record.id.clone(),
                    status: "unchanged",
                });
            }
            (
                Method::PATCH,
                format!("{path}/{}", record.id),
                json!({"name":config.record_name,"type":config.record_type,"content":ip.to_string(),"ttl":ttl,"proxied":config.proxied}),
                Some(record.id.as_str()),
            )
        } else {
            (
                Method::POST,
                path,
                json!({"name":config.record_name,"type":config.record_type,"content":ip.to_string(),"ttl":ttl,"proxied":config.proxied,"comment":marker}),
                None,
            )
        };
        // Keep the caller's local eligibility/lease guard through the bounded write.
        // External API side effects still cannot be rolled back by a database transaction.
        let _guard = check().await?;
        let response = self
            .call(method, &path, &rule.api_token, &[], Some(body))
            .await?;
        let written: Record = serde_json::from_value(response["result"].clone())
            .map_err(|_| Failure::from("invalid_response"))?;
        if !identifier(&written.id)
            || previous_id.is_some_and(|id| id != written.id)
            || domain(&written.name).as_deref() != Some(config.record_name.as_str())
            || written.record_type != config.record_type
            || written.content.parse::<IpAddr>().ok() != Some(ip)
            || written.ttl != ttl
            || written.proxied != config.proxied
            || (previous_id.is_none() && written.comment.as_deref() != Some(marker.as_str()))
        {
            return Err("invalid_response".into());
        }
        Ok(Outcome {
            record_id: written.id,
            status: "updated",
        })
    }
}

pub(super) fn retry_after(value: &str, now: SystemTime) -> Option<i64> {
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
