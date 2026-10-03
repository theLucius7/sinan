use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response, StatusCode},
};
use std::sync::{Arc, Mutex};
use tokio::{net::TcpListener, task::JoinHandle};

#[derive(Default)]
pub(super) struct Data {
    pub records: Vec<Value>,
    pub requests: Vec<(String, String, Value)>,
    pub reply: Option<(u16, String)>,
    pub pages: u64,
    pub list_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    pub write_pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

pub(super) struct Mock {
    pub data: Arc<Mutex<Data>>,
    pub client: Providers,
    task: JoinHandle<()>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mock {
    pub async fn start() -> Self {
        let data = Arc::new(Mutex::new(Data {
            pages: 1,
            ..Data::default()
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Providers::local(&format!("http://{}/", listener.local_addr().unwrap()));
        let router = Router::new().fallback(handle).with_state(data.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { data, client, task }
    }
    pub fn writes(&self) -> usize {
        self.data
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.0 != "GET")
            .count()
    }
}

async fn handle(State(data): State<Arc<Mutex<Data>>>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    assert_eq!(parts.headers["authorization"], format!("Bearer {TOKEN}"));
    assert!(!parts.headers.contains_key("cookie"));
    let bytes = to_bytes(body, 16384).await.unwrap();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    let path = parts.uri.path();
    let (result, pause) = {
        let mut data = data.lock().unwrap();
        data.requests.push((
            parts.method.to_string(),
            parts.uri.to_string(),
            body.clone(),
        ));
        if let Some((status, text)) = &data.reply {
            return Response::builder()
                .status(*status)
                .header("content-type", "application/json")
                .header("retry-after", "900")
                .header("location", "/secret-sink")
                .body(Body::from(text.clone()))
                .unwrap();
        }
        let result = if path == format!("/zones/{ZONE}") {
            json!({"success":true,"result":{"id":ZONE,"name":"example.com","status":"active"}})
        } else if parts.method == "GET" {
            assert!(parts.uri.query().unwrap().contains("name.exact="));
            json!({"success":true,"result":data.records,"result_info":{"total_count":data.records.len(),"total_pages":data.pages}})
        } else if parts.method == "POST" {
            let mut record = body;
            record["id"] = RECORD.into();
            data.records.push(record.clone());
            json!({"success":true,"result":record})
        } else {
            assert_eq!(parts.method, "PATCH");
            assert!(path.ends_with(RECORD));
            assert_eq!(body.as_object().unwrap().len(), 5);
            assert_eq!(body["name"], data.records[0]["name"]);
            assert_eq!(body["type"], data.records[0]["type"]);
            assert!(body.get("comment").is_none() && body.get("tags").is_none());
            let record = &mut data.records[0];
            for (name, value) in body.as_object().unwrap() {
                record[name] = value.clone();
            }
            json!({"success":true,"result":record})
        };
        let pause = if parts.method == "GET" && path.ends_with("/dns_records") {
            data.list_pause.clone()
        } else if parts.method != "GET" {
            data.write_pause.clone()
        } else {
            None
        };
        (result, pause)
    };
    if let Some((entered, release)) = pause {
        entered.notify_one();
        release.notified().await;
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(result.to_string()))
        .unwrap()
}

pub(super) fn record() -> Value {
    json!({"id":RECORD,"name":"node.example.com","type":"A","content":"192.0.2.10","ttl":300,"proxied":false,"comment":"TEST_ONLY keep comment","tags":["owner:test"]})
}

#[tokio::test]
async fn create_recovers_lost_receipt_then_updates_only_owned_fields() {
    let mock = Mock::start().await;
    let rule = rule();
    let ip = "192.0.2.10".parse().unwrap();
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.unwrap().status,
        "updated"
    );
    assert_eq!(mock.writes(), 1);
    // The same rule has no persisted record ID: its remote marker recovers
    // a create that completed before a database failure or process restart.
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.unwrap().status,
        "unchanged"
    );
    assert_eq!(mock.writes(), 1);
    mock.data.lock().unwrap().records[0]["tags"] = json!(["owner:test"]);
    assert_eq!(
        mock.client
            .reconcile(&rule, "192.0.2.11".parse().unwrap())
            .await
            .unwrap()
            .status,
        "updated"
    );
    let data = mock.data.lock().unwrap();
    assert_eq!(data.records.len(), 1);
    assert_eq!(data.records[0]["tags"], json!(["owner:test"]));
    assert_eq!(
        data.records[0]["comment"],
        format!("sinan-ddns:{}", rule.id)
    );
}

#[tokio::test]
async fn adoption_is_explicit_and_duplicate_cname_or_incomplete_lists_never_write() {
    let mock = Mock::start().await;
    mock.data.lock().unwrap().records.push(record());
    let mut rule = rule();
    let ip = "192.0.2.11".parse().unwrap();
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.err().unwrap().code,
        "record_not_owned"
    );
    rule.config.adopt_existing = true;
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.unwrap().status,
        "updated"
    );
    assert_eq!(
        mock.data.lock().unwrap().records[0]["comment"],
        "TEST_ONLY keep comment"
    );
    let writes = mock.writes();
    mock.data.lock().unwrap().records.push(record());
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.err().unwrap().code,
        "record_conflict"
    );
    mock.data.lock().unwrap().records[1]["type"] = "CNAME".into();
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.err().unwrap().code,
        "record_conflict"
    );
    mock.data.lock().unwrap().records.pop();
    mock.data.lock().unwrap().pages = 2;
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.err().unwrap().code,
        "record_conflict"
    );
    assert_eq!(mock.writes(), writes);
    rule.config.record_name = "not-example.com".into();
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.err().unwrap().code,
        "zone_mismatch"
    );
    assert_eq!(mock.writes(), writes);
}

#[tokio::test]
async fn ipv6_is_semantic_and_proxy_ttl_is_automatic() {
    let mock = Mock::start().await;
    let mut rule = rule();
    rule.config.record_type = "AAAA".into();
    rule.config.proxied = true;
    rule.config.normalize().unwrap();
    let ip = "2001:db8::12".parse().unwrap();
    mock.client.reconcile(&rule, ip).await.unwrap();
    mock.data.lock().unwrap().records[0]["content"] =
        "2001:0db8:0000:0000:0000:0000:0000:0012".into();
    assert_eq!(
        mock.client.reconcile(&rule, ip).await.unwrap().status,
        "unchanged"
    );
    assert_eq!(mock.writes(), 1);
    assert_eq!(mock.data.lock().unwrap().records[0]["ttl"], 1);
}

#[tokio::test]
async fn untrusted_provider_responses_are_bounded_redacted_and_never_redirected() {
    let mock = Mock::start().await;
    let rule = rule();
    for (status, body, expected) in [
        (403, TOKEN.to_owned(), "authentication_failed"),
        (302, TOKEN.to_owned(), "redirect_refused"),
        (
            200,
            json!({"success":false,"errors":[{"message":TOKEN}]}).to_string(),
            "provider_rejected",
        ),
        (
            200,
            json!({"success":true,"errors":[{"code":1,"message":TOKEN}],"result":{}}).to_string(),
            "provider_rejected",
        ),
        (200, "{".into(), "invalid_response"),
        (200, "x".repeat(262145), "response_too_large"),
        (429, TOKEN.to_owned(), "rate_limited"),
    ] {
        mock.data.lock().unwrap().reply = Some((status, body));
        let before = mock.data.lock().unwrap().requests.len();
        let error = mock
            .client
            .reconcile(&rule, "192.0.2.10".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, expected);
        assert!(!format!("{error:?}").contains(TOKEN));
        assert_eq!(mock.data.lock().unwrap().requests.len(), before + 1);
        if status == 429 {
            assert_eq!(error.retry_after, 900);
        }
    }
    assert_eq!(mock.writes(), 0);
}

#[test]
fn rate_limit_accepts_unsigned_seconds_and_http_date_without_shortening_fractional_waits() {
    let now = httpdate::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
    for (input, expected) in [
        ("900", Some(900)),
        ("0", Some(60)),
        ("99999", Some(3600)),
        ("Sun, 06 Nov 1994 09:04:37 GMT", Some(900)),
        ("-1", None),
        ("+1", None),
        ("", None),
        ("1.5", None),
    ] {
        assert_eq!(crate::cloudflare::retry_after(input, now), expected);
    }
    assert_eq!(
        crate::cloudflare::retry_after(
            "Sun, 06 Nov 1994 09:04:37 GMT",
            now + std::time::Duration::from_millis(1)
        ),
        Some(900)
    );
}
