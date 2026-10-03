//! Shared subscription download for both source stacks.
//!
//! One network and security policy: public HTTPS targets only, checked DNS
//! answers pinned for the connection, same-origin redirects, bounded and
//! deadline-limited bodies, and a fixed set of credential headers. Each stack
//! adapts [`Failure`] to its own error vocabulary.

use futures_util::{Stream, StreamExt};
use reqwest::{
    Client, Url,
    header::{self, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io::{Cursor, Read},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::Duration,
};
use tokio::time::Instant;

pub(crate) const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_URL_BYTES: usize = 8192;
const MAX_AUTH_BYTES: usize = 8192;
const MAX_CACHE_HEADER_BYTES: usize = 2048;
const MAX_TRAFFIC_HEADER_BYTES: usize = 8192;
const MAX_USER_AGENT_BYTES: usize = 256;
const MAX_DNS_ADDRESSES: usize = 64;
const MAX_REDIRECTS: usize = 3;
const AUTH_HEADERS: [&str; 3] = ["authorization", "cookie", "x-api-key"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Url,
    PrivateAddress,
    AuthHeaders,
    UserAgent,
    Cache,
    UnexpectedNotModified,
    Dns,
    DnsEmpty,
    DnsLimit,
    Timeout,
    Tls,
    Connection,
    Read,
    Client,
    RedirectLimit,
    Redirect,
    RedirectOrigin,
    Http,
    Html,
    BodyLimit,
    DecompressedLimit,
    UnsupportedEncoding,
    CorruptBody,
    InvalidLength,
    InvalidEncodingHeader,
}

/// A download failure. The message never contains the URL, headers or body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub kind: FailureKind,
    pub message: &'static str,
    pub http_status: Option<u16>,
}

const fn failure(kind: FailureKind, message: &'static str) -> Failure {
    Failure {
        kind,
        message,
        http_status: None,
    }
}

const TIMEOUT: Failure = failure(FailureKind::Timeout, "订阅获取超过总时间限制");
const BODY_LIMIT: Failure = failure(FailureKind::BodyLimit, "订阅正文超过 2 MiB 限制");
const REDIRECT_LIMIT: Failure = failure(FailureKind::RedirectLimit, "订阅重定向超过三次限制");

// Requests deliberately do not implement Debug: paths and headers are secrets.
pub(crate) struct Request<'a> {
    pub url: &'a str,
    pub auth_headers: &'a BTreeMap<String, String>,
    pub etag: Option<&'a str>,
    pub last_modified: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

pub(crate) enum Outcome {
    Modified {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
        traffic: Option<String>,
    },
    NotModified {
        etag: Option<String>,
        last_modified: Option<String>,
        traffic: Option<String>,
    },
}

pub(crate) fn validate_url(input: &str) -> Result<Url, Failure> {
    if input.is_empty()
        || input.len() > MAX_URL_BYTES
        || input.trim() != input
        || input.bytes().any(|b| b.is_ascii_control() || b == b'\\')
        || input
            .get(..8)
            .is_none_or(|prefix| !prefix.eq_ignore_ascii_case("https://"))
    {
        return Err(failure(
            FailureKind::Url,
            "订阅地址为空、包含控制字符或超过大小限制",
        ));
    }
    let url = Url::parse(input).map_err(|_| failure(FailureKind::Url, "订阅地址格式不合法"))?;
    if url.as_str().len() > MAX_URL_BYTES
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
        || url.port_or_known_default().is_none_or(|port| port == 0)
    {
        return Err(failure(
            FailureKind::Url,
            "订阅地址须为无用户信息和片段的 HTTPS 地址",
        ));
    }
    let host = hostname(&url)?;
    let blocked = match host.parse::<IpAddr>() {
        Ok(ip) => !public_address(ip),
        Err(_) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            host == "localhost"
                || [".localhost", ".local", ".internal"]
                    .iter()
                    .any(|suffix| host.ends_with(suffix))
        }
    };
    if blocked {
        return Err(failure(
            FailureKind::PrivateAddress,
            "订阅地址不属于允许公网范围",
        ));
    }
    // URL normalization can discard an empty userinfo marker; reject it too.
    if input
        .split_once("://")
        .is_some_and(|(_, rest)| authority_has_userinfo(rest))
    {
        return Err(failure(FailureKind::Url, "订阅地址不能携带用户信息"));
    }
    Ok(url)
}

fn authority_has_userinfo(rest: &str) -> bool {
    rest.split(['/', '?', '#'])
        .next()
        .is_none_or(|authority| authority.is_empty() || authority.contains('@'))
}

pub(crate) fn validate_auth_headers(
    input: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Failure> {
    if input.len() > AUTH_HEADERS.len() {
        return Err(failure(FailureKind::AuthHeaders, "认证头最多三项"));
    }
    let mut result = BTreeMap::new();
    let mut bytes = 0usize;
    for (name, value) in input {
        let name = name.to_ascii_lowercase();
        if !AUTH_HEADERS.contains(&name.as_str())
            || value.is_empty()
            || value.trim().is_empty()
            || value.bytes().any(|b| b.is_ascii_control())
            || HeaderValue::from_str(value).is_err()
        {
            return Err(failure(
                FailureKind::AuthHeaders,
                "认证头名称或内容不符合要求",
            ));
        }
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
        if bytes > MAX_AUTH_BYTES || result.insert(name, value.clone()).is_some() {
            return Err(failure(
                FailureKind::AuthHeaders,
                "认证头重复或超过大小限制",
            ));
        }
    }
    Ok(result)
}

pub(crate) fn validate_user_agent(value: &str) -> Result<(), Failure> {
    if value.is_empty()
        || value.len() > MAX_USER_AGENT_BYTES
        || value.bytes().any(|byte| !(32..127).contains(&byte))
        || value.trim().is_empty()
    {
        Err(failure(
            FailureKind::UserAgent,
            "请求标识须为 1 至 256 字节的可打印 ASCII 文本",
        ))
    } else {
        Ok(())
    }
}

/// Whether a stored validator can be sent back as a conditional request header.
pub(crate) fn valid_cache_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CACHE_HEADER_BYTES
        && !value.bytes().any(|b| b.is_ascii_control())
        && HeaderValue::from_str(value).is_ok()
}

pub(crate) fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && b[0] != 0
                && b[0] < 224
                && !(b[0] == 100 && (64..=127).contains(&b[1]))
                && !(b[0] == 198 && matches!(b[1], 18 | 19))
                && !(b[0] == 192 && b[1] == 0 && b[2] == 0)
                && !(b[0] == 192 && b[1] == 88 && b[2] == 99)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only ordinary global unicast. Protocol assignments, tunnels,
            // documentation and every IPv4 embedding cannot bypass IPv4 policy.
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && s[0] != 0x3fff
        }
    }
}

fn checked_addresses(addresses: Vec<SocketAddr>, port: u16) -> Result<Vec<SocketAddr>, Failure> {
    if addresses.is_empty() {
        return Err(failure(FailureKind::DnsEmpty, "订阅主机没有可用地址"));
    }
    if addresses.len() > MAX_DNS_ADDRESSES {
        return Err(failure(FailureKind::DnsLimit, "订阅主机返回过多地址"));
    }
    if addresses
        .iter()
        .any(|a| a.port() != port || !public_address(a.ip()))
    {
        return Err(failure(
            FailureKind::PrivateAddress,
            "订阅地址解析到非允许公网范围",
        ));
    }
    Ok(addresses
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn hostname(url: &Url) -> Result<String, Failure> {
    let host = url
        .host_str()
        .ok_or(failure(FailureKind::Url, "订阅地址缺少主机"))?;
    // Url displays IPv6 hosts with brackets; DNS and IP parsing need the bare host.
    Ok(host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned())
}

fn sensitive(value: &str, problem: Failure) -> Result<HeaderValue, Failure> {
    let mut value = HeaderValue::from_str(value).map_err(|_| problem)?;
    value.set_sensitive(true);
    Ok(value)
}

fn request_headers(request: &Request<'_>) -> Result<HeaderMap, Failure> {
    let mut headers = HeaderMap::new();
    for (name, value) in validate_auth_headers(request.auth_headers)? {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| failure(FailureKind::AuthHeaders, "认证头名称不合法"))?;
        let value = sensitive(
            &value,
            failure(FailureKind::AuthHeaders, "认证头内容不合法"),
        )?;
        headers.insert(name, value);
    }
    let invalid_cache = failure(FailureKind::Cache, "条件请求缓存无效");
    for (name, value) in [
        (header::IF_NONE_MATCH, request.etag),
        (header::IF_MODIFIED_SINCE, request.last_modified),
    ] {
        if let Some(value) = value {
            if !valid_cache_value(value) {
                return Err(invalid_cache);
            }
            headers.insert(name, sensitive(value, invalid_cache)?);
        }
    }
    if let Some(value) = request.user_agent {
        validate_user_agent(value)?;
        let value = HeaderValue::from_str(value).map_err(|_| {
            failure(
                FailureKind::UserAgent,
                "请求标识须为 1 至 256 字节的可打印 ASCII 文本",
            )
        })?;
        headers.insert(header::USER_AGENT, value);
    }
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate"),
    );
    Ok(headers)
}

type ResponseBody = Pin<Box<dyn Stream<Item = Result<Vec<u8>, Failure>> + Send>>;

struct DownloadResponse {
    status: u16,
    headers: HeaderMap,
    body: ResponseBody,
}

// The production implementation never substitutes an unchecked address. Tests
// replace this private transport to inspect exactly what was checked and sent.
trait Network: Sync {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, Failure>> + Send;
    fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        headers: HeaderMap,
        deadline: Instant,
    ) -> impl Future<Output = Result<DownloadResponse, Failure>> + Send;
}

struct PublicNetwork;

impl Network for PublicNetwork {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Failure> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| failure(FailureKind::Dns, "订阅主机 DNS 查询失败"))?;
        Ok(addresses.take(MAX_DNS_ADDRESSES + 1).collect())
    }

    async fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        headers: HeaderMap,
        deadline: Instant,
    ) -> Result<DownloadResponse, Failure> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TIMEOUT);
        }
        let host = hostname(url)?;
        // Decompression stays under the bounded decoder below, never inside reqwest.
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(Policy::none())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .resolve_to_addrs(&host, addresses)
            .connect_timeout(remaining.min(CONNECT_TIMEOUT))
            .timeout(remaining)
            .build()
            .map_err(|_| failure(FailureKind::Client, "无法初始化订阅连接"))?;
        let response = client
            .get(url.clone())
            .headers(headers)
            .send()
            .await
            .map_err(network_failure)?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = Box::pin(response.bytes_stream().map(|chunk| {
            let chunk = chunk.map_err(network_failure)?;
            if chunk.len() > MAX_BODY_BYTES {
                return Err(BODY_LIMIT);
            }
            Ok(chunk.to_vec())
        }));
        Ok(DownloadResponse {
            status,
            headers,
            body,
        })
    }
}

fn network_failure(error: reqwest::Error) -> Failure {
    if error.is_timeout() {
        return TIMEOUT;
    }
    if tls_cause(&error, 0) {
        return failure(FailureKind::Tls, "订阅 HTTPS 证书或 TLS 握手失败");
    }
    if error.is_connect() {
        failure(FailureKind::Connection, "无法连接订阅服务")
    } else {
        failure(FailureKind::Read, "订阅响应读取失败")
    }
}

fn tls_cause(error: &(dyn std::error::Error + 'static), depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    if error.downcast_ref::<rustls::Error>().is_some() {
        return true;
    }
    // io::Error::source forwards the wrapped error's source. Inspect get_ref
    // as well so the actual rustls error is not skipped during TLS failures.
    if error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
        .is_some_and(|inner| tls_cause(inner, depth + 1))
    {
        return true;
    }
    error
        .source()
        .is_some_and(|inner| tls_cause(inner, depth + 1))
}

fn response_header(headers: &HeaderMap, name: HeaderName, limit: usize) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    (!value.is_empty() && value.len() <= limit && !value.bytes().any(|b| b.is_ascii_control()))
        .then(|| value.to_owned())
}

fn cache_header(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    response_header(headers, name, MAX_CACHE_HEADER_BYTES)
}

fn traffic_header(headers: &HeaderMap) -> Option<String> {
    response_header(
        headers,
        HeaderName::from_static("subscription-userinfo"),
        MAX_TRAFFIC_HEADER_BYTES,
    )
}

fn redirect_url(
    current: &Url,
    original: &Url,
    headers: &HeaderMap,
    hop: usize,
) -> Result<Url, Failure> {
    if hop >= MAX_REDIRECTS {
        return Err(REDIRECT_LIMIT);
    }
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= MAX_URL_BYTES)
        .ok_or(failure(FailureKind::Redirect, "订阅重定向地址缺失或无效"))?;
    if location.trim() != location || location.bytes().any(|b| b.is_ascii_control() || b == b'\\') {
        return Err(failure(
            FailureKind::Redirect,
            "订阅重定向地址包含不允许的字符",
        ));
    }
    if location.contains("://") {
        validate_url(location)?;
    }
    if location
        .strip_prefix("//")
        .is_some_and(authority_has_userinfo)
    {
        return Err(failure(
            FailureKind::Redirect,
            "订阅重定向地址不能携带用户信息",
        ));
    }
    let target = current
        .join(location)
        .map_err(|_| failure(FailureKind::Redirect, "订阅重定向地址无效"))?;
    same_origin(original, &validate_url(target.as_str())?)?;
    Ok(target)
}

fn same_origin(original: &Url, target: &Url) -> Result<(), Failure> {
    if target.origin() == original.origin() {
        Ok(())
    } else {
        Err(failure(
            FailureKind::RedirectOrigin,
            "订阅重定向到不同来源，须明确更换地址",
        ))
    }
}

fn html(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("text/html")
                || value.split(';').next().unwrap_or("").trim() == "application/xhtml+xml"
        })
}

struct DeadlineReader<'a> {
    inner: Cursor<&'a [u8]>,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "source decode deadline",
            ));
        }
        self.inner.read(buffer)
    }
}

fn decode_body(
    bytes: Vec<u8>,
    encoding: Option<&str>,
    deadline: Instant,
) -> Result<Vec<u8>, Failure> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(BODY_LIMIT);
    }
    if Instant::now() >= deadline {
        return Err(TIMEOUT);
    }
    let encoding = encoding.unwrap_or("identity").trim().to_ascii_lowercase();
    let corrupt = match encoding.as_str() {
        "identity" | "" => return Ok(bytes),
        "gzip" => "订阅 gzip 正文损坏或不完整",
        "deflate" => "订阅 deflate 正文损坏或不完整",
        _ => {
            return Err(failure(
                FailureKind::UnsupportedEncoding,
                "订阅使用了不支持的压缩编码",
            ));
        }
    };
    let reader = DeadlineReader {
        inner: Cursor::new(bytes.as_slice()),
        deadline,
    };
    let decoder: Box<dyn Read + '_> = if encoding == "gzip" {
        Box::new(flate2::read::MultiGzDecoder::new(reader))
    } else {
        Box::new(flate2::read::ZlibDecoder::new(reader))
    };
    let mut body = Vec::new();
    decoder
        .take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| {
            if Instant::now() >= deadline {
                TIMEOUT
            } else {
                failure(FailureKind::CorruptBody, corrupt)
            }
        })?;
    if body.len() > MAX_BODY_BYTES {
        return Err(failure(
            FailureKind::DecompressedLimit,
            "订阅解压后超过 2 MiB 限制",
        ));
    }
    Ok(body)
}

pub(crate) async fn fetch(request: &Request<'_>) -> Result<Outcome, Failure> {
    fetch_with_deadline(request, &PublicNetwork, Instant::now() + FETCH_TIMEOUT).await
}

async fn fetch_with_deadline<N: Network>(
    request: &Request<'_>,
    network: &N,
    deadline: Instant,
) -> Result<Outcome, Failure> {
    tokio::time::timeout_at(deadline, fetch_with(request, network, deadline))
        .await
        .map_err(|_| TIMEOUT)?
}

async fn fetch_with<N: Network>(
    request: &Request<'_>,
    network: &N,
    deadline: Instant,
) -> Result<Outcome, Failure> {
    let original = validate_url(request.url)?;
    let headers = request_headers(request)?;
    let mut url = original.clone();
    for hop in 0..=MAX_REDIRECTS {
        // Credentials are attached only to the original origin, even if a
        // future change produced a target without the redirect parser.
        same_origin(&original, &url)?;
        let host = hostname(&url)?;
        let port = url.port_or_known_default().expect("validated port");
        let addresses = checked_addresses(network.resolve(&host, port).await?, port)?;
        let mut response = network
            .get(&url, &addresses, headers.clone(), deadline)
            .await?;
        if response.status == 304 {
            if request.etag.is_none() && request.last_modified.is_none() {
                return Err(failure(
                    FailureKind::UnexpectedNotModified,
                    "未建立条件缓存却收到 304 响应",
                ));
            }
            return Ok(Outcome::NotModified {
                etag: cache_header(&response.headers, header::ETAG),
                last_modified: cache_header(&response.headers, header::LAST_MODIFIED),
                traffic: traffic_header(&response.headers),
            });
        }
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            url = redirect_url(&url, &original, &response.headers, hop)?;
            continue;
        }
        if !(200..300).contains(&response.status) {
            let message = match response.status {
                403 => "订阅服务拒绝访问（403）",
                429 => "订阅服务限制请求频率（429）",
                _ => "订阅服务返回非成功 HTTP 状态",
            };
            return Err(Failure {
                http_status: Some(response.status),
                ..failure(FailureKind::Http, message)
            });
        }
        if let Some(value) = response.headers.get(header::CONTENT_LENGTH) {
            let length = value
                .to_str()
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or(failure(FailureKind::InvalidLength, "订阅正文长度声明无效"))?;
            if length > MAX_BODY_BYTES as u64 {
                return Err(BODY_LIMIT);
            }
        }
        if html(&response.headers) {
            return Err(failure(FailureKind::Html, "订阅服务返回 HTML 页面"));
        }
        let etag = cache_header(&response.headers, header::ETAG);
        let last_modified = cache_header(&response.headers, header::LAST_MODIFIED);
        let traffic = traffic_header(&response.headers);
        let encoding = response
            .headers
            .get(header::CONTENT_ENCODING)
            .map(|v| {
                v.to_str()
                    .map(str::to_owned)
                    .map_err(|_| failure(FailureKind::InvalidEncodingHeader, "订阅压缩编码无效"))
            })
            .transpose()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.body.next().await {
            let chunk = chunk?;
            if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
                return Err(BODY_LIMIT);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = decode_body(bytes, encoding.as_deref(), deadline)?;
        return Ok(Outcome::Modified {
            body,
            etag,
            last_modified,
            traffic,
        });
    }
    Err(REDIRECT_LIMIT)
}

#[cfg(test)]
mod tests;
