use super::*;
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use reqwest::dns::{self, Resolve};
use serde_json::json;
use std::{error::Error as StdError, io};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn local_client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
}

#[test]
fn old_quality_payload_is_readable_without_inventing_attempts_or_error_types() {
    let old = json!({
        "ip":"192.0.2.1", "checked_at":1, "expires_at":2, "status":"partial",
        "databases":[
            {"database":"ipqualityscore", "label":"IPQualityScore", "status":"succeeded",
             "fields":[{"label":"风险", "value":0}, {"label":"代理", "value":false}], "error":null},
            {"database":"ipapi", "label":"IPAPI", "status":"failed",
             "fields":[], "error":"旧错误"}
        ]
    });
    let parsed: IpQuality = serde_json::from_value(old).unwrap();
    for entry in &parsed.databases {
        assert_eq!(entry.provider, "check-place");
        assert_eq!(entry.attempted_at, None);
        assert_eq!(entry.elapsed_ms, None);
        assert_eq!(entry.target_ip, None);
        assert_eq!(entry.error_kind, None);
        assert_eq!(entry.http_status, None);
    }
    assert_eq!(parsed.databases[0].fields[0].value, json!(0));
    assert_eq!(parsed.databases[0].fields[1].value, json!(false));
    assert_eq!(parsed.databases[1].error.as_deref(), Some("旧错误"));
}

#[tokio::test]
async fn real_http_sources_record_categories_target_time_and_duration() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route("/{ip}", get(|axum::extract::Query(query): axum::extract::Query<BTreeMap<String, String>>| async move {
        match query.get("db").map(String::as_str) {
            None => (StatusCode::FORBIDDEN, "denied").into_response(),
            Some("ipapi") => (StatusCode::TOO_MANY_REQUESTS, "limited").into_response(),
            Some("scamalytics") => (StatusCode::OK, "<html>unavailable</html>").into_response(),
            Some("abuseipdb") => Json(json!({"unexpected":"shape"})).into_response(),
            Some("ip2location") => (StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response(),
            Some("ipdata") => Json(json!({"threat":{"is_proxy":false}})).into_response(),
            _ => Json(json!({"fraud_score":0,"proxy":false})).into_response(),
        }
    }));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let started_at = now_timestamp();
    let values = query_all(
        &local_client(),
        &format!("http://{address}"),
        &["192.0.2.1".into()],
        true,
    )
    .await;
    task.abort();
    let entry = &values[0];
    assert_eq!(entry.status, "partial");
    let expected = [
        Some(QueryErrorKind::Http403),
        Some(QueryErrorKind::Http429),
        Some(QueryErrorKind::NonJson),
        Some(QueryErrorKind::SchemaMismatch),
        Some(QueryErrorKind::HttpOther),
        None,
        None,
    ];
    for (database, kind) in entry.databases.iter().zip(expected) {
        assert_eq!(database.provider, "check-place");
        assert_eq!(database.target_ip.as_deref(), Some("192.0.2.1"));
        assert!(database.attempted_at.unwrap() >= started_at);
        assert!(database.elapsed_ms.unwrap() < 2000);
        assert_eq!(database.error_kind, kind);
        if kind.is_some() {
            assert!(database.fields.is_empty());
            assert!(database.error.is_some());
        }
    }
    assert_eq!(entry.databases[0].http_status, Some(403));
    assert_eq!(entry.databases[1].http_status, Some(429));
    assert_eq!(entry.databases[4].http_status, Some(503));
    assert_eq!(entry.databases[6].fields[0].value, json!(0));
    assert_eq!(entry.databases[6].fields[1].value, json!(false));
    let encoded = serde_json::to_value(entry).unwrap();
    assert_eq!(encoded["databases"][0]["error_kind"], "http_403");
    assert_eq!(encoded["databases"][1]["error_kind"], "http_429");
}

struct FailingResolver;

impl dns::Resolve for FailingResolver {
    fn resolve(&self, _: dns::Name) -> dns::Resolving {
        Box::pin(async {
            Err(Box::new(errors::DnsLookupError(io::Error::new(
                io::ErrorKind::NotFound,
                "fixture name has no address",
            ))) as Box<dyn StdError + Send + Sync>)
        })
    }
}

#[tokio::test]
async fn typed_dns_failure_is_distinct_from_a_refused_connection() {
    let client = Client::builder()
        .no_proxy()
        .dns_resolver(Arc::new(FailingResolver))
        .build()
        .unwrap();
    let error = query_database(&client, "http://source.invalid", "192.0.2.1", "maxmind")
        .await
        .unwrap_err();
    assert_eq!(error.kind, QueryErrorKind::Dns);
    let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = unused.local_addr().unwrap();
    drop(unused);
    let error = query_database(
        &local_client(),
        &format!("http://{address}"),
        "192.0.2.1",
        "maxmind",
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, QueryErrorKind::Connect);
}

#[tokio::test]
async fn system_dns_adapter_preserves_loopback_resolution() {
    let addresses: Vec<_> = QualityDnsResolver
        .resolve("localhost".parse().unwrap())
        .await
        .unwrap()
        .collect();
    assert!(!addresses.is_empty());
    assert!(
        addresses
            .iter()
            .all(|address| address.ip().is_loopback() && address.port() == 0)
    );
}

#[tokio::test]
async fn invalid_tls_records_are_classified_from_the_rustls_source_type() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut hello = [0u8; 4096];
        assert!(socket.read(&mut hello).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    });
    let error = query_database(
        &local_client(),
        &format!("https://{address}"),
        "192.0.2.1",
        "maxmind",
    )
    .await
    .unwrap_err();
    task.await.unwrap();
    assert_eq!(error.kind, QueryErrorKind::Tls);
}

#[tokio::test]
async fn timeout_and_a_truncated_http_body_have_distinct_categories() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/{ip}",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Json(json!({"ASN":{"AutonomousSystemNumber":64500}}))
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    let error = query_database(
        &client,
        &format!("http://{address}"),
        "192.0.2.1",
        "maxmind",
    )
    .await
    .unwrap_err();
    task.abort();
    assert_eq!(error.kind, QueryErrorKind::Timeout);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        assert!(socket.read(&mut request).await.unwrap() > 0);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
    });
    let error = query_database(
        &local_client(),
        &format!("http://{address}"),
        "192.0.2.1",
        "maxmind",
    )
    .await
    .unwrap_err();
    task.await.unwrap();
    assert_eq!(error.kind, QueryErrorKind::BodyError);
}

#[tokio::test]
async fn batch_timeout_preserves_started_attempts_and_marks_waiting_requests() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/{ip}",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Json(json!({}))
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let values = query_all_with_limit(
        &local_client(),
        &format!("http://{address}"),
        &["192.0.2.1".into(), "2001:db8::1".into()],
        true,
        Duration::from_millis(50),
    )
    .await;
    task.abort();
    assert_eq!(values[0].status, "failed");
    let attempted: Vec<_> = values[0]
        .databases
        .iter()
        .filter(|entry| entry.attempted_at.is_some())
        .collect();
    assert_eq!(attempted.len(), 4);
    assert!(
        attempted
            .iter()
            .all(|entry| entry.error_kind == Some(QueryErrorKind::Timeout)
                && entry.elapsed_ms.unwrap() >= 40)
    );
    let waiting: Vec<_> = values[0]
        .databases
        .iter()
        .filter(|entry| entry.attempted_at.is_none())
        .collect();
    assert_eq!(waiting.len(), 3);
    assert!(waiting.iter().all(
        |entry| entry.error_kind == Some(QueryErrorKind::NotAttempted)
            && entry.elapsed_ms.is_none()
    ));
    assert!(values[0].last_attempt_at.is_some());
    assert_eq!(values[1].last_attempt_at, None);
    assert!(values[1].databases.iter().all(|entry| {
        entry.attempted_at.is_none()
            && entry.elapsed_ms.is_none()
            && entry.error_kind == Some(QueryErrorKind::NotAttempted)
    }));
}
