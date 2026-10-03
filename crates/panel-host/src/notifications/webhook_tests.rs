use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn config() -> Config {
    Config {
        enabled: true,
        preset: Preset::Custom,
        url: "https://example.invalid/notify?key=TEST_ONLY_SECRET".into(),
        headers: "Authorization: Bearer TEST_ONLY_SECRET".into(),
        body: DEFAULT_BODY.into(),
    }
}

#[test]
fn templates_escape_json_and_do_not_expand_inserted_values() {
    let message = Message {
        title: "quoted \"title\"",
        server: "{{message}}",
        message: "line\n\\end",
        time: "time",
        event: "offline",
        event_id: "123",
        category: "offline",
    };
    let text = render(DEFAULT_BODY, &message).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["title"], message.title);
    assert_eq!(value["node"], "{{message}}");
    assert_eq!(value["message"], message.message);
    assert!(validate(&config()).is_ok());
    for body in [
        r#"{"text":{{message}}}"#,
        r#"{"text":"{{secret}}"}"#,
        r#"{"text":"{{title"}"#,
        r#"{"{{title}}":"value"}"#,
    ] {
        assert!(
            validate(&Config {
                body: body.into(),
                ..config()
            })
            .is_err()
        );
    }
    let long = "A".repeat(64 * 1024);
    assert!(
        render(
            r#"{"text":"{{message}}"}"#,
            &Message {
                message: &long,
                ..message
            }
        )
        .is_err()
    );
}

#[test]
fn targets_and_headers_are_validated_without_echoing_credentials() {
    for url in [
        "file:///tmp/config",
        "https://name:TEST_ONLY_SECRET@example.invalid",
        "https://example.invalid/#TEST_ONLY_SECRET",
        "https://example.invalid/a b",
    ] {
        let error = validate(&Config {
            url: url.into(),
            ..config()
        })
        .unwrap_err();
        assert!(!error.contains("TEST_ONLY_SECRET"));
    }
    for headers in [
        "Host: example.invalid",
        "Content-Length: 1",
        "Transfer-Encoding: chunked",
        "Proxy-Authorization: TEST_ONLY_SECRET",
        "bad header: TEST_ONLY_SECRET",
        "Authorization: ok\rInjected: bad",
    ] {
        assert!(
            validate(&Config {
                headers: headers.into(),
                ..config()
            })
            .is_err()
        );
    }
}

#[test]
fn every_preset_requires_its_own_acknowledgement_and_rejects_ambiguous_success() {
    for (preset, response, body, accepted) in [
        (Preset::Custom, "", "{}", true),
        (Preset::Slack, "ok\n", "{}", true),
        (Preset::Slack, "invalid_payload", "{}", false),
        (Preset::Slack, r#"{"ok":true}"#, "{}", false),
        (Preset::Discord, r#"{"id":"123456789"}"#, "{}", true),
        (Preset::Discord, "", "{}", false),
        (
            Preset::Discord,
            r#"{"code":500,"message":"TEST_ONLY_SECRET"}"#,
            "{}",
            false,
        ),
        (Preset::Discord, r#"{"id":"0"}"#, "{}", false),
        (Preset::Bark, r#"{"code":200}"#, "{}", true),
        (Preset::Bark, r#"{"code":500}"#, "{}", false),
        (Preset::Wecom, r#"{"errcode":0}"#, "{}", true),
        (Preset::Dingtalk, r#"{"errcode":"0"}"#, "{}", false),
        (Preset::Feishu, r#"{"code":0}"#, "{}", true),
        (Preset::Feishu, r#"{"StatusCode":0}"#, "{}", true),
        (Preset::Feishu, r#"{"code":0,"StatusCode":1}"#, "{}", false),
        (Preset::Gotify, r#"{"id":1}"#, "{}", true),
        (
            Preset::Gotify,
            r#"{"error":"TEST_ONLY_SECRET"}"#,
            "{}",
            false,
        ),
        (Preset::Gotify, r#"{"id":"1"}"#, "{}", false),
        (
            Preset::Ntfy,
            r#"{"id":"fixture123","event":"message","topic":"fixture"}"#,
            r#"{"topic":"fixture"}"#,
            true,
        ),
        (
            Preset::Ntfy,
            r#"{"id":"fixture123","event":"message","topic":"other"}"#,
            r#"{"topic":"fixture"}"#,
            false,
        ),
        (
            Preset::Ntfy,
            r#"{"error":"TEST_ONLY_SECRET"}"#,
            r#"{"topic":"fixture"}"#,
            false,
        ),
    ] {
        assert_eq!(acknowledged(preset, response.as_bytes(), body), accepted);
    }
}

async fn receiver(
    status: u16,
    extra: &str,
    body: &str,
) -> (String, tokio::task::JoinHandle<(String, Value)>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/TEST_ONLY_SECRET", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status} Fixture\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let worker = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let (headers, body) = loop {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0 && request.len() + count < 128 * 1024);
            request.extend_from_slice(&buffer[..count]);
            if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if request.len() >= end + 4 + length {
                    break (
                        headers,
                        serde_json::from_slice(&request[end + 4..end + 4 + length]).unwrap(),
                    );
                }
            }
        };
        stream.write_all(response.as_bytes()).await.unwrap();
        (headers, body)
    });
    (url, worker)
}

#[tokio::test]
async fn rate_limits_redirects_business_errors_and_success_are_bounded_and_private() {
    for (status, extra, body, preset, succeeds, retry) in [
        (
            429,
            "Retry-After: 123\r\n",
            "TEST_ONLY_SECRET",
            Preset::Custom,
            false,
            Some(123),
        ),
        (
            302,
            "Location: http://127.0.0.1:1/TEST_ONLY_SECRET\r\n",
            "",
            Preset::Custom,
            false,
            None,
        ),
        (
            200,
            "",
            r#"{"errcode":400,"errmsg":"TEST_ONLY_SECRET"}"#,
            Preset::Wecom,
            false,
            None,
        ),
        (200, "", r#"{"errcode":0}"#, Preset::Dingtalk, true, None),
        (200, "", r#"{"code":200}"#, Preset::Bark, true, None),
        (200, "", r#"{"StatusCode":0}"#, Preset::Feishu, true, None),
        (204, "", "", Preset::Custom, true, None),
    ] {
        let (url, worker) = receiver(status, extra, body).await;
        let result = send(
            &Config {
                url,
                preset,
                ..config()
            },
            r#"{"text":"测试"}"#,
        )
        .await;
        assert_eq!(result.is_ok(), succeeds);
        if let Err(error) = result {
            assert_eq!(error.retry_after, retry);
            assert!(!error.message.contains("TEST_ONLY_SECRET"));
        }
        let (headers, value) = worker.await.unwrap();
        assert!(headers.contains("authorization: bearer test_only_secret"));
        assert_eq!(value["text"], "测试");
    }
    let (url, worker) = receiver(200, "", &"X".repeat(65 * 1024)).await;
    assert!(send(&Config { url, ..config() }, "{}").await.is_err());
    worker.await.unwrap();
}

#[tokio::test]
async fn discord_wait_is_forced_once_and_an_empty_response_is_not_an_acknowledgement() {
    for (status, body, accepted) in [(200, r#"{"id":"123456789"}"#, true), (204, "", false)] {
        let (url, worker) = receiver(status, "", body).await;
        let result = send(
            &Config {
                url: format!("{url}?wait=false&thread_id=42&wait=false"),
                preset: Preset::Discord,
                ..config()
            },
            "{}",
        )
        .await;
        assert_eq!(result.is_ok(), accepted);
        let (request, _) = worker.await.unwrap();
        let target = request.lines().next().unwrap();
        assert!(target.contains("thread_id=42"));
        assert_eq!(target.matches("wait=true").count(), 1);
        assert!(!target.contains("wait=false"));
    }
}
