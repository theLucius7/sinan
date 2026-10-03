use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Provider {
    #[default]
    Cloudflare,
    Tencent,
    Aliyun,
    Huawei,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AddressSource {
    #[default]
    Agent,
    Interface,
    Discovered,
    Manual,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(default)]
    pub provider: Provider,
    #[serde(default)]
    pub line: String,
    pub name: String,
    pub server_id: i64,
    pub zone_id: String,
    pub record_name: String,
    pub record_type: String,
    pub ttl: u32,
    pub proxied: bool,
    pub interval_secs: u32,
    pub enabled: bool,
    #[serde(default)]
    pub adopt_existing: bool,
    #[serde(default)]
    pub address_source: AddressSource,
    #[serde(default)]
    pub manual_ip: Option<String>,
    #[serde(default)]
    pub credential_id: Option<Uuid>,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub account_id: Option<Uuid>,
}

impl Config {
    pub fn normalize(&mut self) -> ApiResult<()> {
        self.name = self.name.trim().into();
        self.zone_id = self.zone_id.trim().to_ascii_lowercase();
        self.record_name = domain(&self.record_name)
            .ok_or_else(|| ApiError::BadRequest("请输入完整域名，可使用 *.example.com".into()))?;
        if self.name.is_empty() || self.name.len() > 128 || self.name.chars().any(char::is_control)
        {
            return Err(ApiError::BadRequest("名称不能为空或超过 128 字节".into()));
        }
        self.line = self.line.trim().into();
        match self.provider {
            Provider::Cloudflare | Provider::Huawei => {
                if !identifier(&self.zone_id) {
                    return Err(ApiError::BadRequest(
                        "Zone ID 必须为 32 位十六进制字符".into(),
                    ));
                }
                if !self.line.is_empty() {
                    return Err(ApiError::BadRequest("此提供方只支持默认线路".into()));
                }
            }
            Provider::Tencent | Provider::Aliyun => {
                self.zone_id = domain(&self.zone_id)
                    .filter(|v| !v.starts_with("*."))
                    .ok_or_else(|| {
                        ApiError::BadRequest("请填写托管的根域名，例如 example.com".into())
                    })?;
                if self.record_name != self.zone_id
                    && !self.record_name.ends_with(&format!(".{}", self.zone_id))
                {
                    return Err(ApiError::BadRequest("记录不属于所填根域名".into()));
                }
                if self.line.is_empty() {
                    self.line = if self.provider == Provider::Tencent {
                        "0"
                    } else {
                        "default"
                    }
                    .into();
                }
                if self.line.len() > 64
                    || !self
                        .line
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-=".contains(&b))
                {
                    return Err(ApiError::BadRequest("解析线路标识无效".into()));
                }
            }
        }
        if self.server_id <= 0 || !matches!(self.record_type.as_str(), "A" | "AAAA") {
            return Err(ApiError::BadRequest("请选择服务器与 A / AAAA 类型".into()));
        }
        if self.address_source == AddressSource::Interface {
            let name = self
                .interface_name
                .as_deref()
                .map(str::trim)
                .filter(|name| {
                    !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
                })
                .ok_or_else(|| ApiError::BadRequest("请明确选择地址来源网卡".into()))?;
            self.interface_name = Some(name.into());
        } else {
            self.interface_name = None;
        }
        if self.address_source == AddressSource::Manual {
            let ip = self
                .manual_ip
                .as_deref()
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
                .filter(|ip| ddns_public_ip(*ip) && ip.is_ipv4() == (self.record_type == "A"))
                .ok_or_else(|| {
                    ApiError::BadRequest("手工地址必须为当前记录类型的有效公网地址".into())
                })?;
            self.manual_ip = Some(ip.to_string());
        } else {
            self.manual_ip = None;
        }
        if !(60..=86400).contains(&self.interval_secs) {
            return Err(ApiError::BadRequest("同步间隔必须为 60–86400 秒".into()));
        }
        if self.proxied && self.provider != Provider::Cloudflare {
            return Err(ApiError::BadRequest("代理开关仅适用于 Cloudflare".into()));
        }
        if self.proxied {
            self.ttl = 1;
        }
        let automatic = self.provider == Provider::Cloudflare && self.ttl == 1;
        if !automatic && !(60..=86400).contains(&self.ttl) {
            return Err(ApiError::BadRequest(
                "TTL 必须为 1（自动）或 60–86400 秒".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn identifier(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    let (prefix, host) = value
        .strip_prefix("*.")
        .map_or(("", value), |host| ("*.", host));
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || ":/%?#@\\[]*".contains(c))
    {
        return None;
    }
    let url = reqwest::Url::parse(&format!("https://{host}/")).ok()?;
    let host = url.host_str()?;
    let name = format!("{prefix}{host}");
    if name.len() > 253
        || host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return None;
    }
    Some(name)
}

pub(super) fn token(value: &str) -> ApiResult<String> {
    let value = value.trim();
    if !(16..=256).contains(&value.len())
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        return Err(ApiError::BadRequest(
            "请输入有效的 Cloudflare API Token".into(),
        ));
    }
    Ok(value.into())
}

#[derive(FromRow, Serialize)]
pub(super) struct Rule {
    pub id: Uuid,
    #[sqlx(json)]
    pub config: Config,
    #[serde(skip)]
    pub api_token: String,
    #[serde(skip)]
    pub access_key_id: String,
    #[serde(skip)]
    pub access_key_secret: String,
    pub revision: i64,
    pub record_id: Option<String>,
    pub last_ip: Option<String>,
    pub last_success_at: Option<i64>,
    pub attempted_at: Option<i64>,
    pub next_run_at: i64,
    pub failures: i32,
    pub status: String,
    pub error_code: Option<String>,
    #[serde(skip)]
    pub lease_until: i64,
}

#[cfg(test)]
pub(super) use super::observation::Observation;
use super::observation::ddns_public_ip;
pub(super) use super::observation::{locked_observation, observation, view};
