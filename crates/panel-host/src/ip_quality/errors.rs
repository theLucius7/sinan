use reqwest::{Error, dns};
use serde::{Deserialize, Serialize};
use std::{error::Error as StdError, io};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryErrorKind {
    Dns,
    Connect,
    Tls,
    Timeout,
    #[serde(rename = "http_403")]
    Http403,
    #[serde(rename = "http_429")]
    Http429,
    HttpOther,
    NonJson,
    SchemaMismatch,
    BodyError,
    ResponseLimit,
    RequestError,
    NotPublic,
    NotAttempted,
    InvalidOrigin,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(super) struct QueryError {
    pub kind: QueryErrorKind,
    pub http_status: Option<u16>,
    message: String,
}

impl QueryError {
    pub fn new(kind: QueryErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            http_status: None,
            message: message.into(),
        }
    }

    pub fn http(status: u16) -> Self {
        let (kind, reason) = match status {
            403 => (QueryErrorKind::Http403, "查询入口拒绝访问"),
            429 => (QueryErrorKind::Http429, "查询入口限制请求频率"),
            _ => (QueryErrorKind::HttpOther, "查询入口返回非成功状态"),
        };
        Self {
            kind,
            http_status: Some(status),
            message: format!("{reason}（HTTP {status}），此数据库信息未知"),
        }
    }

    pub fn request(error: &Error, reading_body: bool) -> Self {
        let (kind, message) = if error.is_timeout() {
            (QueryErrorKind::Timeout, "质量查询超时")
        } else if contains_source::<DnsLookupError>(error) {
            (QueryErrorKind::Dns, "查询入口的 DNS 解析失败")
        } else if contains_source::<rustls::Error>(error)
            || contains_source::<rustls::pki_types::InvalidDnsNameError>(error)
        {
            (QueryErrorKind::Tls, "查询入口的 TLS 握手或证书验证失败")
        } else if error.is_connect() {
            (QueryErrorKind::Connect, "无法连接查询入口")
        } else if reading_body || error.is_body() {
            (QueryErrorKind::BodyError, "质量查询响应读取失败")
        } else {
            (QueryErrorKind::RequestError, "质量查询请求失败，原因未分类")
        };
        Self::new(kind, message)
    }
}

fn contains_source<T: StdError + 'static>(error: &(dyn StdError + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(current) = source {
        if current.is::<T>() {
            return true;
        }
        // io::Error may contain a rustls error without exposing it via source().
        source = current
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .map(|inner| inner as &(dyn StdError + 'static))
            .or_else(|| current.source());
    }
    false
}

#[derive(Debug, thiserror::Error)]
#[error("DNS lookup failed")]
pub(super) struct DnsLookupError(#[source] pub io::Error);

pub(super) struct QualityDnsResolver;

impl dns::Resolve for QualityDnsResolver {
    fn resolve(&self, name: dns::Name) -> dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host, 0)).await.map_err(|error| {
                Box::new(DnsLookupError(error)) as Box<dyn StdError + Send + Sync>
            })?;
            Ok(Box::new(addresses) as dns::Addrs)
        })
    }
}
