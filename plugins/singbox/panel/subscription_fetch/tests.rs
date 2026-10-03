use super::*;
use std::{collections::VecDeque, io::Write, sync::Mutex};

enum PlannedResponse {
    Response {
        status: u16,
        headers: HeaderMap,
        chunks: Vec<Vec<u8>>,
    },
    Failure(FailureKind),
    Pending,
    PendingBody,
}
struct SentRequest {
    url: String,
    addresses: Vec<SocketAddr>,
    headers: HeaderMap,
}
struct MockNetwork {
    resolutions: Mutex<VecDeque<Vec<SocketAddr>>>,
    responses: Mutex<VecDeque<PlannedResponse>>,
    sent: Mutex<Vec<SentRequest>>,
    dns_pending: bool,
}
impl MockNetwork {
    fn new(resolutions: Vec<Vec<SocketAddr>>, responses: Vec<PlannedResponse>) -> Self {
        Self {
            resolutions: Mutex::new(resolutions.into()),
            responses: Mutex::new(responses.into()),
            sent: Mutex::new(vec![]),
            dns_pending: false,
        }
    }
}
impl Network for MockNetwork {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, Failure> {
        if self.dns_pending {
            return std::future::pending().await;
        }
        Ok(self
            .resolutions
            .lock()
            .unwrap()
            .pop_front()
            .expect("planned resolution"))
    }
    async fn get(
        &self,
        url: &Url,
        addresses: &[SocketAddr],
        headers: HeaderMap,
        _deadline: Instant,
    ) -> Result<DownloadResponse, Failure> {
        self.sent.lock().unwrap().push(SentRequest {
            url: url.as_str().to_owned(),
            addresses: addresses.to_vec(),
            headers,
        });
        let planned = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("planned response");
        match planned {
            PlannedResponse::Response {
                status,
                headers,
                chunks,
            } => Ok(DownloadResponse {
                status,
                headers,
                body: Box::pin(futures_util::stream::iter(chunks.into_iter().map(Ok))),
            }),
            PlannedResponse::Failure(kind) => Err(failure(kind, "固定失败分类")),
            PlannedResponse::Pending => std::future::pending().await,
            PlannedResponse::PendingBody => Ok(DownloadResponse {
                status: 200,
                headers: HeaderMap::new(),
                body: Box::pin(futures_util::stream::pending()),
            }),
        }
    }
}

struct Config {
    url: String,
    auth_headers: BTreeMap<String, String>,
    etag: Option<String>,
    last_modified: Option<String>,
    user_agent: Option<String>,
}
impl Config {
    fn request(&self) -> Request<'_> {
        Request {
            url: &self.url,
            auth_headers: &self.auth_headers,
            etag: self.etag.as_deref(),
            last_modified: self.last_modified.as_deref(),
            user_agent: self.user_agent.as_deref(),
        }
    }
}
fn config() -> Config {
    Config {
        url: "https://download.example.invalid/subscription?token=private-marker".into(),
        auth_headers: BTreeMap::new(),
        etag: None,
        last_modified: None,
        user_agent: None,
    }
}
fn addresses() -> Vec<SocketAddr> {
    vec![
        "8.8.8.8:443".parse().unwrap(),
        "[2606:4700::1111]:443".parse().unwrap(),
    ]
}
fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    pairs
        .iter()
        .map(|(k, v)| {
            (
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            )
        })
        .collect()
}
fn response(status: u16, pairs: &[(&str, &str)], chunks: Vec<Vec<u8>>) -> PlannedResponse {
    PlannedResponse::Response {
        status,
        headers: headers(pairs),
        chunks,
    }
}
fn success<T>(result: Result<T, Failure>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected {:?}", error.kind),
    }
}
fn error<T>(result: Result<T, Failure>) -> Failure {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected failure"),
    }
}
async fn run(config: &Config, network: &MockNetwork) -> Result<Outcome, Failure> {
    fetch_with_deadline(
        &config.request(),
        network,
        Instant::now() + Duration::from_secs(2),
    )
    .await
}

#[test]
fn literal_targets_reject_special_ipv4_and_embedded_or_reserved_ipv6() {
    for ip in [
        "0.0.0.0",
        "0.0.0.1",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.168.0.1",
        "100.64.0.1",
        "192.0.0.9",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::7f00:1",
        "::ffff:8.8.8.8",
        "::ffff:127.0.0.1",
        "::ffff:0:7f00:1",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "fc00::1",
        "fd00::1",
        "fe80::1",
        "2001::1",
        "2001:20::1",
        "2001:db8::1",
        "2002:808:808::1",
        "3fff::1",
        // The whole 3fff::/16 stays blocked, not only the documentation /20.
        "3fff:1000::1",
        "5f00::1",
    ] {
        assert!(!public_address(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "2003::1",
        "2600::1",
        "2a00::1",
        "2606:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(public_address(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn url_and_auth_validation_are_write_only_and_do_not_allow_header_overrides() {
    for url in [
        "http://download.example.invalid/a",
        "file:///tmp/a",
        "https://user:pass@download.example.invalid/a",
        "https://@download.example.invalid/",
        "https://download.example.invalid/#token",
        "https://127.1/a",
        "https://2130706433/",
        "https://0x7f000001/",
        "https://[::ffff:8.8.8.8]/",
        "https://localhost./",
        "https://service.local/",
        "https://metadata.internal/",
        "https://METADATA.INTERNAL./",
        "https://download.example.invalid:0/",
        " https://download.example.invalid/",
        "https:\\\\download.example.invalid\\a",
    ] {
        assert!(validate_url(url).is_err(), "{url}");
    }
    assert_eq!(
        validate_url("https://metadata.internal/").unwrap_err().kind,
        FailureKind::PrivateAddress
    );
    assert!(validate_url("https://download.example.invalid:8443/sub?token=example").is_ok());
    assert!(validate_url("https://[2606:4700::1111]/sub").is_ok());
    assert!(
        validate_url(&format!(
            "https://download.example.invalid/{}",
            "中".repeat(1000)
        ))
        .is_err()
    );
    for name in [
        "User-Agent",
        "Host",
        "Origin",
        "Referer",
        "Proxy-Authorization",
        "X-Other",
    ] {
        assert!(validate_auth_headers(&BTreeMap::from([(name.into(), "example".into())])).is_err());
    }
    for value in ["", " ", "secret\r\nHost: example.invalid", "secret\t"] {
        assert!(
            validate_auth_headers(&BTreeMap::from([("authorization".into(), value.into())]))
                .is_err()
        );
    }
    let input = BTreeMap::from([
        ("Authorization".into(), "Bearer example".into()),
        ("COOKIE".into(), "account=example".into()),
        ("X-API-Key".into(), "example".into()),
    ]);
    let actual = success(validate_auth_headers(&input));
    assert_eq!(actual.len(), 3);
    assert_eq!(actual["authorization"], "Bearer example");
    assert!(
        validate_auth_headers(&BTreeMap::from([
            ("Authorization".into(), "a".into()),
            ("authorization".into(), "b".into())
        ]))
        .is_err()
    );
    assert!(
        validate_auth_headers(&BTreeMap::from([(
            "cookie".into(),
            "x".repeat(MAX_AUTH_BYTES)
        )]))
        .is_err()
    );
}

#[test]
fn user_agent_cannot_inject_headers_or_grow_unbounded() {
    for valid in [
        "Sinan-subscription-import/1",
        "sing-box/1.14.2",
        "Client (test; compat)",
    ] {
        assert!(validate_user_agent(valid).is_ok());
    }
    for invalid in [
        "",
        " ",
        "agent\r\nAuthorization: secret",
        "agent\tvalue",
        "中文",
        "agent\u{7f}",
    ] {
        assert_eq!(
            validate_user_agent(invalid).unwrap_err().kind,
            FailureKind::UserAgent
        );
    }
    assert!(validate_user_agent(&"a".repeat(257)).is_err());
}

#[tokio::test]
async fn mixed_dns_answers_are_rejected_before_any_connection() {
    for blocked in ["127.0.0.1:443", "10.0.0.1:443", "[::ffff:8.8.8.8]:443"] {
        let network =
            MockNetwork::new(vec![vec![addresses()[0], blocked.parse().unwrap()]], vec![]);
        assert_eq!(
            error(run(&config(), &network).await).kind,
            FailureKind::PrivateAddress
        );
        assert!(network.sent.lock().unwrap().is_empty());
    }
    for (answers, kind) in [
        (vec![], FailureKind::DnsEmpty),
        (
            vec![addresses()[0]; MAX_DNS_ADDRESSES + 1],
            FailureKind::DnsLimit,
        ),
        (
            vec!["8.8.8.8:8443".parse().unwrap()],
            FailureKind::PrivateAddress,
        ),
    ] {
        let network = MockNetwork::new(vec![answers], vec![]);
        assert_eq!(error(run(&config(), &network).await).kind, kind);
        assert!(network.sent.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn checked_addresses_and_secrets_are_only_sent_to_the_same_origin() {
    let mut config = config();
    config
        .auth_headers
        .insert("Authorization".into(), "Bearer example-secret".into());
    config.etag = Some("\"v1\"".into());
    let first = addresses();
    let second = vec!["1.1.1.1:443".parse().unwrap()];
    let network = MockNetwork::new(
        vec![first.clone(), second.clone()],
        vec![
            response(302, &[("location", "/next?token=second")], vec![]),
            response(
                200,
                &[
                    ("etag", "\"v2\""),
                    ("subscription-userinfo", "upload=1; download=2"),
                ],
                vec![b"trojan://example@proxy.example.invalid:443".to_vec()],
            ),
        ],
    );
    match success(run(&config, &network).await) {
        Outcome::Modified {
            body,
            etag,
            traffic,
            ..
        } => {
            assert!(body.starts_with(b"trojan://"));
            assert_eq!(etag.as_deref(), Some("\"v2\""));
            assert_eq!(traffic.as_deref(), Some("upload=1; download=2"));
        }
        _ => panic!("expected modified"),
    }
    let sent = network.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].addresses.iter().copied().collect::<BTreeSet<_>>(),
        first.into_iter().collect()
    );
    assert_eq!(sent[1].addresses, second);
    assert!(sent[1].url.ends_with("/next?token=second"));
    for request in sent.iter() {
        assert_eq!(request.headers["authorization"], "Bearer example-secret");
        assert!(request.headers["authorization"].is_sensitive());
        assert!(request.headers.get("referer").is_none());
        assert!(request.headers.get("user-agent").is_none());
        assert_eq!(request.headers["if-none-match"], "\"v1\"");
        assert!(request.headers["if-none-match"].is_sensitive());
        assert_eq!(request.headers["accept-encoding"], "gzip, deflate");
    }
}

#[tokio::test]
async fn a_configured_user_agent_is_sent_and_an_invalid_one_sends_nothing() {
    let mut config = config();
    config.user_agent = Some("sing-box/1.14.2".into());
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(
            200,
            &[],
            vec![b"trojan://a@b.example:443".to_vec()],
        )],
    );
    success(run(&config, &network).await);
    assert_eq!(
        network.sent.lock().unwrap()[0].headers["user-agent"],
        "sing-box/1.14.2"
    );
    config.user_agent = Some("agent\r\nAuthorization: secret".into());
    let network = MockNetwork::new(vec![], vec![]);
    assert_eq!(
        error(run(&config, &network).await).kind,
        FailureKind::UserAgent
    );
    assert!(network.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_stored_cache_validators_are_rejected_before_sending() {
    let oversized = "x".repeat(MAX_CACHE_HEADER_BYTES + 1);
    for etag in ["", "\"v1\"\n", oversized.as_str()] {
        let mut config = config();
        config.etag = Some(etag.into());
        let network = MockNetwork::new(vec![], vec![]);
        assert_eq!(error(run(&config, &network).await).kind, FailureKind::Cache);
        assert!(network.sent.lock().unwrap().is_empty());
        assert!(!valid_cache_value(etag));
    }
}

#[tokio::test]
async fn cross_origin_and_excess_redirects_never_send_the_next_request() {
    for target in [
        "https://other.example.invalid/a",
        "http://download.example.invalid/a",
        "https://download.example.invalid:8443/a",
        "https://127.0.0.1/a",
        "https://127.1/private",
        "//2130706433/private",
        "https://0x7f000001/private",
        "https://[::ffff:127.0.0.1]/private",
        "https://localhost/private",
        "https://user:pass@download.example.invalid/a",
        "https://@download.example.invalid/a",
        "//@download.example.invalid/a",
        "https:////@download.example.invalid/a",
        "https:\\download.example.invalid\\private",
        "https://download.example.invalid/#secret",
        "https://[invalid",
        "\thttps://download.example.invalid/private",
        "https://download.example.invalid/\tignored",
    ] {
        let network = MockNetwork::new(
            vec![addresses()],
            vec![response(302, &[("location", target)], vec![])],
        );
        let failure = error(run(&config(), &network).await);
        assert!(
            matches!(
                failure.kind,
                FailureKind::RedirectOrigin
                    | FailureKind::Redirect
                    | FailureKind::Url
                    | FailureKind::PrivateAddress
            ),
            "{target}"
        );
        assert_eq!(network.sent.lock().unwrap().len(), 1, "{target}");
        assert!(!failure.message.contains(target));
    }
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(
            307,
            &[("location", "https://other.example.invalid/collect")],
            vec![],
        )],
    );
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::RedirectOrigin
    );
    let network = MockNetwork::new(
        vec![addresses(); 4],
        (0..4)
            .map(|_| response(307, &[("location", "/next")], vec![]))
            .collect(),
    );
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::RedirectLimit
    );
    assert_eq!(network.sent.lock().unwrap().len(), 4);
}

#[test]
fn credentials_are_never_attached_to_a_different_origin() {
    let original = validate_url("https://source.example.com/subscription?token=fixture").unwrap();
    let other = Url::parse("https://other.example.com/collect").unwrap();
    assert_eq!(
        same_origin(&original, &other).unwrap_err().kind,
        FailureKind::RedirectOrigin
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_static("/next"));
    let next = redirect_url(&original, &original, &headers, 2).unwrap();
    assert_eq!(next.as_str(), "https://source.example.com/next");
    assert!(same_origin(&original, &next).is_ok());
    assert_eq!(
        redirect_url(&original, &original, &headers, 3)
            .unwrap_err()
            .kind,
        FailureKind::RedirectLimit
    );
}

#[tokio::test]
async fn redirects_recheck_dns_and_block_rebinding() {
    let network = MockNetwork::new(
        vec![addresses(), vec!["169.254.169.254:443".parse().unwrap()]],
        vec![response(302, &[("location", "/next")], vec![])],
    );
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::PrivateAddress
    );
    assert_eq!(network.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_failures_have_distinct_classes_without_response_or_url_content() {
    for status in [403, 429, 500, 300, 305] {
        let network = MockNetwork::new(
            vec![addresses()],
            vec![response(
                status,
                &[("location", "/next")],
                vec![b"private-marker password secret".to_vec()],
            )],
        );
        let failure = error(run(&config(), &network).await);
        assert_eq!(failure.kind, FailureKind::Http);
        assert_eq!(failure.http_status, Some(status));
        assert_eq!(network.sent.lock().unwrap().len(), 1);
        for secret in [
            "private-marker",
            "password",
            "download.example.invalid",
            "subscription?",
            "secret",
        ] {
            assert!(!failure.message.contains(secret));
        }
    }
    for content_type in [
        "text/html; charset=utf-8",
        "TEXT/HTML",
        "application/xhtml+xml",
        "application/octet-stream, text/html",
    ] {
        let network = MockNetwork::new(
            vec![addresses()],
            vec![response(
                200,
                &[("content-type", content_type)],
                vec![b"<html>private-marker</html>".to_vec()],
            )],
        );
        assert_eq!(
            error(run(&config(), &network).await).kind,
            FailureKind::Html,
            "{content_type}"
        );
    }
}

#[tokio::test]
async fn conditional_304_requires_existing_cache_and_returns_no_new_body() {
    let network = MockNetwork::new(vec![addresses()], vec![response(304, &[], vec![])]);
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::UnexpectedNotModified
    );
    let mut config = config();
    config.etag = Some("\"old\"".into());
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(
            304,
            &[("etag", "\"new\""), ("subscription-userinfo", "total=10")],
            vec![],
        )],
    );
    assert!(matches!(
        success(run(&config, &network).await),
        Outcome::NotModified { etag: Some(ref v), traffic: Some(ref t), .. }
            if v == "\"new\"" && t == "total=10"
    ));
}

#[tokio::test]
async fn total_deadline_covers_dns_and_body_waiting() {
    let mut dns = MockNetwork::new(vec![], vec![]);
    dns.dns_pending = true;
    assert_eq!(
        error(
            fetch_with_deadline(
                &config().request(),
                &dns,
                Instant::now() + Duration::from_millis(10)
            )
            .await
        )
        .kind,
        FailureKind::Timeout
    );
    let network = MockNetwork::new(vec![addresses()], vec![PlannedResponse::Pending]);
    assert_eq!(
        error(
            fetch_with_deadline(
                &config().request(),
                &network,
                Instant::now() + Duration::from_millis(10)
            )
            .await
        )
        .kind,
        FailureKind::Timeout
    );
    let body = MockNetwork::new(vec![addresses()], vec![PlannedResponse::PendingBody]);
    assert_eq!(
        error(
            fetch_with_deadline(
                &config().request(),
                &body,
                Instant::now() + Duration::from_millis(10)
            )
            .await
        )
        .kind,
        FailureKind::Timeout
    );
}

#[tokio::test]
async fn transport_failures_keep_typed_errors_and_do_not_retry() {
    for kind in [
        FailureKind::Connection,
        FailureKind::Read,
        FailureKind::Tls,
        FailureKind::Timeout,
    ] {
        let network = MockNetwork::new(vec![addresses()], vec![PlannedResponse::Failure(kind)]);
        assert_eq!(error(run(&config(), &network).await).kind, kind);
        assert_eq!(network.sent.lock().unwrap().len(), 1);
    }
}

fn gzip(input: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
}

fn deflate(input: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(input).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn wire_length_and_accumulated_chunks_are_bounded() {
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(
            200,
            &[("content-length", &(MAX_BODY_BYTES + 1).to_string())],
            vec![],
        )],
    );
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::BodyLimit
    );
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(200, &[("content-length", "many")], vec![])],
    );
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::InvalidLength
    );
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(
            200,
            &[],
            vec![vec![b'a'; MAX_BODY_BYTES], vec![b'b']],
        )],
    );
    assert_eq!(
        error(run(&config(), &network).await).kind,
        FailureKind::BodyLimit
    );
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(200, &[], vec![vec![b'a'; MAX_BODY_BYTES]])],
    );
    assert!(
        matches!(success(run(&config(), &network).await), Outcome::Modified { ref body, .. } if body.len() == MAX_BODY_BYTES)
    );
    let network = MockNetwork::new(
        vec![addresses()],
        vec![response(
            200,
            &[("content-encoding", "deflate")],
            vec![deflate(b"trojan://a@b.example:443")],
        )],
    );
    assert!(
        matches!(success(run(&config(), &network).await), Outcome::Modified { ref body, .. } if body == b"trojan://a@b.example:443")
    );
}

#[test]
fn decompression_checks_output_members_encoding_and_deadline() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let input = b"trojan://example@proxy.example.invalid:443";
    assert_eq!(
        success(decode_body(gzip(input), Some("gzip"), deadline)),
        input
    );
    assert_eq!(
        success(decode_body(deflate(input), Some(" Deflate "), deadline)),
        input
    );
    assert_eq!(
        success(decode_body(b"fixture".to_vec(), Some("identity"), deadline)),
        b"fixture"
    );
    let mut members = gzip(b"first");
    members.extend(gzip(b"second"));
    assert_eq!(
        success(decode_body(members, Some("gzip"), deadline)),
        b"firstsecond"
    );
    let large = gzip(&vec![b'a'; MAX_BODY_BYTES + 1]);
    assert!(large.len() < MAX_BODY_BYTES);
    assert_eq!(
        error(decode_body(large.clone(), Some("gzip"), deadline)).kind,
        FailureKind::DecompressedLimit
    );
    // A valid first member cannot smuggle an oversized second member.
    let mut smuggled = gzip(b"first-member");
    smuggled.extend(large);
    assert_eq!(
        error(decode_body(smuggled, Some("gzip"), deadline)).kind,
        FailureKind::DecompressedLimit
    );
    assert_eq!(
        error(decode_body(
            deflate(&vec![b'a'; MAX_BODY_BYTES + 1]),
            Some("deflate"),
            deadline
        ))
        .kind,
        FailureKind::DecompressedLimit
    );
    for (bytes, encoding) in [
        (b"not-gzip".to_vec(), "gzip"),
        (b"not-deflate".to_vec(), "deflate"),
    ] {
        assert_eq!(
            error(decode_body(bytes, Some(encoding), deadline)).kind,
            FailureKind::CorruptBody
        );
    }
    assert_eq!(
        error(decode_body(gzip(input), Some("br"), deadline)).kind,
        FailureKind::UnsupportedEncoding
    );
    assert_eq!(
        error(decode_body(
            vec![],
            None,
            Instant::now() - Duration::from_secs(1)
        ))
        .kind,
        FailureKind::Timeout
    );
    let mut truncated = gzip(input);
    truncated.truncate(truncated.len() - 4);
    assert_eq!(
        error(decode_body(truncated, Some("gzip"), deadline)).kind,
        FailureKind::CorruptBody
    );
}

#[tokio::test]
async fn real_tls_transport_failure_is_classified_without_exposing_the_url() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 2048];
        let _ = stream.read(&mut hello).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
    });
    // Exercise only the private TLS transport. The public fetch path rejects
    // this loopback target before connecting, as independently asserted above.
    let url = Url::parse(&format!(
        "https://tls.example.invalid:{}/private-marker",
        address.port()
    ))
    .unwrap();
    let failure = error(
        PublicNetwork
            .get(
                &url,
                &[address],
                HeaderMap::new(),
                Instant::now() + Duration::from_secs(2),
            )
            .await,
    );
    server.await.unwrap();
    assert_eq!(failure.kind, FailureKind::Tls);
    assert!(!failure.message.contains("private-marker"));
}
