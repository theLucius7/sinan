use super::*;
use crate::plugins::ddns::{model::Provider, providers::RecordClient};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request as HttpRequest, Response, StatusCode},
};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const ZONE: &str = "00000000000000000000000000000001";
const ID: &str = "00000000000000000000000000000002";
#[derive(Default)]
pub(super) struct Data {
    pub(super) requests: usize,
    pub(super) record: Option<Value>,
    pub(super) writes: usize,
    pub(super) fail_write: bool,
}
pub(super) async fn handle(
    State(data): State<Arc<Mutex<Data>>>,
    request: HttpRequest<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    assert_eq!(
        parts.headers["authorization"],
        "Bearer TEST_ONLY_TOKEN_VALUE"
    );
    let bytes = to_bytes(body, 16384).await.unwrap();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    let mut data = data.lock().unwrap();
    data.requests += 1;
    let result = if parts.uri.path() == format!("/zones/{ZONE}") {
        json!({"id":ZONE,"name":"example.com","status":"active"})
    } else if parts.method == reqwest::Method::GET && parts.uri.path().ends_with(ID) {
        data.record.clone().unwrap_or(Value::Null)
    } else if parts.method == reqwest::Method::GET {
        let records = data.record.clone().into_iter().collect::<Vec<_>>();
        return Response::builder().status(200).header("content-type","application/json").body(Body::from(json!({"success":true,"result":records,"result_info":{"total_count":records.len(),"total_pages":1}}).to_string())).unwrap();
    } else {
        data.writes += 1;
        if data.fail_write {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("TEST_ONLY provider failure"))
                .unwrap();
        }
        if parts.method == reqwest::Method::DELETE {
            data.record = None;
            json!({"id":ID})
        } else {
            let mut record = if parts.method == reqwest::Method::PATCH {
                data.record.clone().unwrap()
            } else {
                json!({"id":ID})
            };
            for (key, value) in body.as_object().unwrap() {
                record[key] = value.clone();
            }
            data.record = Some(record.clone());
            record
        }
    };
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"success":true,"result":result}).to_string(),
        ))
        .unwrap()
}

pub(super) fn account() -> Account {
    Account {
        id: Uuid::new_v4(),
        config: dns_accounts::Config {
            name: "TEST_ONLY account".into(),
            provider: Provider::Cloudflare,
            credential_id: Uuid::new_v4(),
            zone_ids: vec![ZONE.into()],
            server_ids: vec![],
            enabled: true,
        },
        revision: 1,
        checked_at: None,
        error_code: None,
        created_at: 0,
        updated_at: 0,
    }
}
pub(super) fn request() -> Request {
    Request {
        operation: "create".into(),
        zone_id: ZONE.into(),
        record_id: None,
        record: json!({"name":"_service.example.com","type":"TXT","content":"TEST_ONLY value","ttl":300}),
    }
}

#[sqlx::test]
async fn official_record_executor_creates_updates_deletes_and_blocks_changed_remote_snapshot(
    pool: sqlx::PgPool,
) {
    let data = Arc::new(Mutex::new(Data::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new().fallback(handle).with_state(data.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = RecordClient::local(Provider::Cloudflare, &endpoint);
    let account = account();
    let mut request = request();
    let mut write_started = false;
    let created = execute_with_client(
        &pool,
        &account,
        &request,
        &Value::Null,
        &mut write_started,
        &client,
    )
    .await
    .unwrap();
    assert!(write_started);
    assert_eq!(created["content"], "TEST_ONLY value");
    request.operation = "update".into();
    request.record_id = Some(ID.into());
    request.record["content"] = "TEST_ONLY changed".into();
    write_started = false;
    data.lock().unwrap().record.as_mut().unwrap()["ttl"] = 600.into();
    assert!(
        execute_with_client(
            &pool,
            &account,
            &request,
            &created,
            &mut write_started,
            &client
        )
        .await
        .is_err()
    );
    assert!(!write_started);
    assert_eq!(data.lock().unwrap().writes, 1);
    data.lock().unwrap().record.as_mut().unwrap()["ttl"] = 300.into();
    let updated = execute_with_client(
        &pool,
        &account,
        &request,
        &created,
        &mut write_started,
        &client,
    )
    .await
    .unwrap();
    assert_eq!(updated["content"], "TEST_ONLY changed");
    request.operation = "delete".into();
    request.record = Value::Null;
    let deleted = execute_with_client(
        &pool,
        &account,
        &request,
        &updated,
        &mut write_started,
        &client,
    )
    .await
    .unwrap();
    assert!(deleted.is_null());
    assert_eq!(data.lock().unwrap().writes, 3);
    task.abort();
}

#[sqlx::test]
async fn provider_failure_after_write_start_is_distinguished_from_precondition_rejection(
    pool: sqlx::PgPool,
) {
    let data = Arc::new(Mutex::new(Data {
        fail_write: true,
        ..Data::default()
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new().fallback(handle).with_state(data);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = RecordClient::local(Provider::Cloudflare, &endpoint);
    let mut started = false;
    assert!(
        execute_with_client(
            &pool,
            &account(),
            &request(),
            &Value::Null,
            &mut started,
            &client
        )
        .await
        .is_err()
    );
    assert!(started);
    task.abort();
}
