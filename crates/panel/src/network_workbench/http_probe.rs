//! Bounded HTTP/1.1 observations measured on the connection serving the request.
use super::models::{Check, Execution, Family};
use crate::error::{ApiError, ApiResult};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const BODY_LIMIT: usize = 64 * 1024;
const HEADER_LIMIT: usize = 16 * 1024;

fn conflict(message: impl Into<String>) -> ApiError {
    ApiError::Conflict(message.into())
}
fn milliseconds(timer: Instant) -> f64 {
    timer.elapsed().as_secs_f64() * 1000.0
}
fn host(url: &reqwest::Url) -> ApiResult<&str> {
    url.host_str()
        .map(|v| v.trim_matches(['[', ']']))
        .ok_or_else(|| conflict("HTTP目标缺少主机"))
}
fn authorized(execution: &Execution, url: &reqwest::Url) -> ApiResult<()> {
    let target = execution.target.as_ref().ok_or(ApiError::NotFound)?;
    if !host(url)?.eq_ignore_ascii_case(target.host.trim_matches(['[', ']']))
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(conflict("HTTP请求或重定向离开授权目标，已停止"));
    }
    if target.authorization.trim().is_empty()
        || target
            .authorized_until
            .is_some_and(|until| until <= now_timestamp())
    {
        return Err(conflict("HTTP目标授权缺失或已到期"));
    }
    Ok(())
}

pub(super) async fn probe(execution: &Execution) -> ApiResult<(Value, String)> {
    let Check::Http {
        url,
        family,
        expected_status,
        expected_content,
        follow_redirects,
        ..
    } = &execution.check
    else {
        return Err(conflict("此阶段计时仅用于HTTP请求"));
    };
    let mut current = reqwest::Url::parse(url).map_err(anyhow::Error::from)?;
    let started = Instant::now();
    let maximum = Duration::from_secs(u64::from(execution.budget.duration_secs).min(60));
    tokio::time::timeout(maximum, async {
        let mut requests = Vec::new();
        let mut redirects = Vec::new();
        loop {
            authorized(execution, &current)?;
            let response = tokio::time::timeout(Duration::from_secs(10), request(&current, *family))
                .await.map_err(|_| conflict("HTTP请求超过10秒阶段截止"))??;
            requests.push(response.timings.clone());
            if *follow_redirects && matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                if redirects.len() == 5 { return Err(conflict("HTTP重定向超过5次上限")); }
                let location = response.location.as_deref().ok_or_else(|| conflict("重定向缺少Location"))?;
                let next = current.join(location).map_err(anyhow::Error::from)?;
                authorized(execution, &next)?;
                redirects.push(next.to_string());
                current = next;
                continue;
            }
            let raw = String::from_utf8_lossy(&response.body).into_owned();
            let data = json!({"status_code":response.status,"expected_status":expected_status,
                "content_match":expected_content.as_ref().is_none_or(|text|raw.contains(text)),
                "redirects":redirects,"total_ms":milliseconds(started),
                "phase_timings_available":true,"phase_timings":response.timings,"requests":requests,
                "timing_method":"same HTTP/1.1 request connection; monotonic phase durations; TTFB from completed request write to first response byte",
                "body_bytes":response.body.len(),"body_limit_bytes":BODY_LIMIT,"header_limit_bytes":HEADER_LIMIT});
            return Ok((data, raw));
        }
    }).await.map_err(|_| conflict("HTTP检测超过方案总时长上限"))?
}

struct Response {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
    timings: Value,
}
async fn request(url: &reqwest::Url, family: Family) -> ApiResult<Response> {
    let started = Instant::now();
    let name = host(url)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| conflict("HTTP端口无效"))?;
    let dns = Instant::now();
    let numeric = name.parse::<IpAddr>().ok();
    let addresses: Vec<_> = tokio::net::lookup_host((name, port))
        .await
        .map_err(anyhow::Error::from)?
        .filter(|address| match family {
            Family::Ipv4 => address.is_ipv4(),
            Family::Ipv6 => address.is_ipv6(),
        })
        .take(64)
        .collect();
    let dns_ms = milliseconds(dns);
    if addresses.is_empty() {
        return Err(conflict("HTTP目标没有选定地址族"));
    }
    let connecting = Instant::now();
    let tcp = TcpStream::connect(addresses.as_slice())
        .await
        .map_err(anyhow::Error::from)?;
    let connect_ms = milliseconds(connecting);
    let peer = tcp.peer_addr().map_err(anyhow::Error::from)?;
    let authority = if name.contains(':') {
        format!("[{name}]:{port}")
    } else {
        format!("{name}:{port}")
    };
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let message = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: sinan-panel/{}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let (mut response, tls_ms) = if url.scheme() == "https" {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(anyhow::Error::from)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from(name.to_owned())
            .map_err(anyhow::Error::from)?;
        let tls = Instant::now();
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| conflict(format!("HTTP TLS握手失败：{error}")))?;
        let tls_ms = milliseconds(tls);
        (exchange(stream, message.as_bytes()).await?, Some(tls_ms))
    } else {
        (exchange(tcp, message.as_bytes()).await?, None)
    };
    response.timings["url"] = json!(url.as_str());
    response.timings["resolved_address"] = json!(peer.ip().to_string());
    response.timings["port"] = json!(peer.port());
    response.timings["dns_ms"] = json!(dns_ms);
    response.timings["resolution_method"] = json!(if numeric.is_some() {
        "numeric_address"
    } else {
        "system_resolver_cache_or_dns"
    });
    response.timings["dns_wire_query_observed"] = json!(false);
    response.timings["connect_ms"] = json!(connect_ms);
    response.timings["tls_ms"] = json!(tls_ms);
    response.timings["tls_state"] = json!(if tls_ms.is_some() {
        "verified"
    } else {
        "not_applicable"
    });
    response.timings["total_ms"] = json!(milliseconds(started));
    Ok(response)
}

struct Head {
    status: u16,
    location: Option<String>,
    length: Option<usize>,
    chunked: bool,
}
fn parse_head(bytes: &[u8]) -> ApiResult<Head> {
    let text = std::str::from_utf8(bytes).map_err(|_| conflict("HTTP响应头编码无效"))?;
    let mut lines = text.split("\r\n");
    let mut status = lines.next().unwrap_or_default().split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(conflict("HTTP响应协议无效"));
    }
    let code = status
        .next()
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|v| (100..=599).contains(v))
        .ok_or_else(|| conflict("HTTP状态码无效"))?;
    let mut result = Head {
        status: code,
        location: None,
        length: None,
        chunked: false,
    };
    for line in lines.filter(|v| !v.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return Err(conflict("HTTP响应头折行不受支持"));
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| conflict("HTTP响应头格式无效"))?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "content-length" => {
                let length = value
                    .parse::<usize>()
                    .map_err(|_| conflict("HTTP响应长度无效"))?;
                if result.length.is_some_and(|previous| previous != length) {
                    return Err(conflict("HTTP响应长度冲突"));
                }
                result.length = Some(length);
            }
            "transfer-encoding" => {
                if result.chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err(conflict("HTTP传输编码不受支持"));
                }
                result.chunked = true;
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err(conflict("HTTP服务未遵循identity编码请求"));
            }
            "location" => {
                if result.location.is_some() {
                    return Err(conflict("HTTP重定向位置冲突"));
                }
                result.location = Some(value.to_owned());
            }
            _ => {}
        }
    }
    if result.chunked && result.length.is_some() {
        return Err(conflict("HTTP响应长度与传输编码冲突"));
    }
    Ok(result)
}
async fn head<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: Option<u8>,
    remaining: usize,
) -> ApiResult<Vec<u8>> {
    let mut bytes = prefix.into_iter().collect::<Vec<_>>();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= remaining {
            return Err(conflict("HTTP响应头超过16KiB上限"));
        }
        bytes.push(reader.read_u8().await.map_err(anyhow::Error::from)?);
    }
    Ok(bytes)
}
async fn line<R: AsyncRead + Unpin>(reader: &mut R, maximum: usize) -> ApiResult<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n") {
        if bytes.len() >= maximum {
            return Err(conflict("HTTP分块元数据超过上限"));
        }
        bytes.push(reader.read_u8().await.map_err(anyhow::Error::from)?);
    }
    Ok(bytes)
}
async fn body<R: AsyncRead + Unpin>(reader: &mut R, response: &Head) -> ApiResult<Vec<u8>> {
    let mut bytes = Vec::new();
    if response.status == 204 || response.status == 304 {
        return Ok(bytes);
    }
    if response.chunked {
        let mut overhead = 0;
        loop {
            let size_line = line(reader, 128).await?;
            overhead += size_line.len();
            if overhead > HEADER_LIMIT {
                return Err(conflict("HTTP分块元数据超过16KiB上限"));
            }
            let text = std::str::from_utf8(&size_line).map_err(|_| conflict("HTTP分块长度无效"))?;
            let token = text.trim_end().split(';').next().unwrap_or_default();
            if token.is_empty() || !token.bytes().all(|v| v.is_ascii_hexdigit()) {
                return Err(conflict("HTTP分块长度无效"));
            }
            let length =
                usize::from_str_radix(token, 16).map_err(|_| conflict("HTTP分块长度无效"))?;
            if length == 0 {
                loop {
                    let trailer = line(reader, HEADER_LIMIT.saturating_sub(overhead)).await?;
                    overhead += trailer.len();
                    if overhead > HEADER_LIMIT {
                        return Err(conflict("HTTP尾部头超过16KiB上限"));
                    }
                    if trailer == b"\r\n" {
                        return Ok(bytes);
                    }
                    if !trailer.contains(&b':') {
                        return Err(conflict("HTTP尾部头格式无效"));
                    }
                }
            }
            if length > BODY_LIMIT.saturating_sub(bytes.len()) {
                return Err(conflict("响应超过64KiB受控上限"));
            }
            let start = bytes.len();
            bytes.resize(start + length, 0);
            reader
                .read_exact(&mut bytes[start..])
                .await
                .map_err(anyhow::Error::from)?;
            let mut ending = [0; 2];
            reader
                .read_exact(&mut ending)
                .await
                .map_err(anyhow::Error::from)?;
            overhead += 2;
            if ending != *b"\r\n" {
                return Err(conflict("HTTP分块结束格式无效"));
            }
        }
    }
    if let Some(length) = response.length {
        if length > BODY_LIMIT {
            return Err(conflict("响应超过64KiB受控上限"));
        }
        bytes.resize(length, 0);
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(anyhow::Error::from)?;
    } else {
        let mut buffer = [0; 4096];
        loop {
            let count = reader
                .read(&mut buffer)
                .await
                .map_err(anyhow::Error::from)?;
            if count == 0 {
                break;
            }
            if count > BODY_LIMIT.saturating_sub(bytes.len()) {
                return Err(conflict("响应超过64KiB受控上限"));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    Ok(bytes)
}
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    message: &[u8],
) -> ApiResult<Response> {
    let writing = Instant::now();
    stream
        .write_all(message)
        .await
        .map_err(anyhow::Error::from)?;
    stream.flush().await.map_err(anyhow::Error::from)?;
    let write_ms = milliseconds(writing);
    let waiting = Instant::now();
    let mut reader = BufReader::new(stream);
    let first = reader.read_u8().await.map_err(anyhow::Error::from)?;
    let ttfb_ms = milliseconds(waiting);
    let mut header_bytes = 0;
    let mut prefix = Some(first);
    let mut informational = 0;
    let response = loop {
        let bytes = head(
            &mut reader,
            prefix.take(),
            HEADER_LIMIT.saturating_sub(header_bytes),
        )
        .await?;
        header_bytes += bytes.len();
        let parsed = parse_head(&bytes)?;
        if !(100..200).contains(&parsed.status) {
            break parsed;
        }
        informational += 1;
        if parsed.status == 101 || informational > 4 {
            return Err(conflict("HTTP升级或过多临时响应不受支持"));
        }
    };
    let bytes = body(&mut reader, &response).await?;
    Ok(Response {
        status: response.status,
        location: response.location,
        body: bytes,
        timings: json!({"request_write_ms":write_ms,"ttfb_ms":ttfb_ms,"status_code":response.status,"informational_responses":informational}),
    })
}

#[cfg(test)]
mod tests {
    use super::super::models::{Budget, Target};
    use super::*;
    use tokio::net::TcpListener;
    use uuid::Uuid;
    fn execution(url: String) -> Execution {
        let id = Uuid::new_v4();
        Execution {
            schema: 1,
            source_server: None,
            role: "source:panel".into(),
            source_label: "面板".into(),
            budget: Budget::default(),
            target: Some(Target {
                id,
                name: "loopback fixture".into(),
                host: "127.0.0.1".into(),
                region: String::new(),
                carrier: String::new(),
                purpose: "isolated HTTP test".into(),
                authorization: "fixture only".into(),
                authorized_until: None,
            }),
            check: Check::Http {
                target_id: id,
                url,
                family: Family::Ipv4,
                expected_status: 200,
                expected_content: Some("fixture".into()),
                follow_redirects: true,
            },
        }
    }
    async fn fixture(
        response: &'static [u8],
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = head(&mut stream, None, HEADER_LIMIT).await.unwrap();
            tokio::time::sleep(delay).await;
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
            request
        });
        (format!("http://{address}/fixture?sample=1"), task)
    }
    #[tokio::test]
    async fn stage_timings_and_body_come_from_one_actual_request() {
        let (url, task) = fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nfixture",
            Duration::from_millis(25),
        )
        .await;
        let (data, body) = probe(&execution(url)).await.unwrap();
        let request = task.await.unwrap();
        assert!(request.starts_with(b"GET /fixture?sample=1 HTTP/1.1\r\n"));
        assert_eq!(body, "fixture");
        assert_eq!(data["content_match"], true);
        assert_eq!(data["requests"].as_array().unwrap().len(), 1);
        let phases = &data["phase_timings"];
        assert!(phases["ttfb_ms"].as_f64().unwrap() >= 20.0);
        assert!(phases["tls_ms"].is_null());
        assert_eq!(phases["tls_state"], "not_applicable");
        assert_eq!(phases["resolution_method"], "numeric_address");
        let elapsed: f64 = ["dns_ms", "connect_ms", "request_write_ms", "ttfb_ms"]
            .iter()
            .map(|key| {
                let value = phases[*key].as_f64().unwrap();
                assert!(value.is_finite() && value >= 0.0);
                value
            })
            .sum();
        assert!(phases["total_ms"].as_f64().unwrap() >= elapsed);
        assert!(data["total_ms"].as_f64().unwrap() >= phases["total_ms"].as_f64().unwrap());
    }
    #[tokio::test]
    async fn chunked_content_is_decoded_on_the_measured_connection() {
        let (url,task) = fixture(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfix\r\n4\r\nture\r\n0\r\nX-Fixture: yes\r\n\r\n",Duration::ZERO).await;
        let (data, body) = probe(&execution(url)).await.unwrap();
        task.await.unwrap();
        assert_eq!(body, "fixture");
        assert_eq!(data["body_bytes"], 7);
    }
    #[tokio::test]
    async fn redirect_to_unauthorized_host_stops_before_another_connection() {
        let (url, task) = fixture(
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://example.invalid/\r\n\r\n",
            Duration::ZERO,
        )
        .await;
        let error = probe(&execution(url)).await.unwrap_err();
        task.await.unwrap();
        assert!(error.to_string().contains("授权目标"));
    }
    #[tokio::test]
    async fn declared_body_larger_than_budget_is_refused_without_reading_it() {
        let (url, task) = fixture(
            b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
            Duration::ZERO,
        )
        .await;
        let error = probe(&execution(url)).await.unwrap_err();
        task.await.unwrap();
        assert!(error.to_string().contains("64KiB"));
    }
}
