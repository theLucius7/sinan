use super::*;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::get,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

const TOKEN: &str = "fixture-token-without-real-credentials";

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: String,
    location: Option<String>,
    stream_body: bool,
}

impl Reply {
    fn json(value: Value) -> Self {
        Self {
            status: StatusCode::OK,
            body: value.to_string(),
            location: None,
            stream_body: false,
        }
    }
}

#[derive(Clone, Debug)]
struct Request {
    page: Option<u64>,
    per_page: Option<u64>,
    authorized: bool,
}

#[derive(Clone)]
struct FixtureState {
    replies: Arc<Vec<Reply>>,
    requests: Arc<Mutex<Vec<Request>>>,
}

struct Fixture {
    address: SocketAddr,
    state: FixtureState,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        let state = FixtureState {
            replies: Arc::new(replies),
            requests: Arc::default(),
        };
        let app = Router::new()
            .route("/v1/servers", get(reply))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            address,
            state,
            server,
        }
    }

    fn endpoint(&self) -> String {
        assert!(self.address.ip().is_loopback());
        format!("http://{}/v1/servers", self.address)
    }

    fn requests(&self) -> Vec<Request> {
        self.state.requests.lock().unwrap().clone()
    }

    async fn fetch(&self, token: &str) -> Inventory {
        let client = client_builder().no_proxy().build().unwrap();
        fetch_with_client(&client, &self.endpoint(), token).await
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn reply(State(state): State<FixtureState>, uri: Uri, headers: HeaderMap) -> Response {
    let parameter = |name: &str| {
        uri.query().unwrap_or_default().split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.parse::<u64>().ok()).flatten()
        })
    };
    let request = Request {
        page: parameter("page"),
        per_page: parameter("per_page"),
        authorized: headers
            .get("authorization")
            .and_then(|header| header.to_str().ok())
            == Some(format!("Bearer {TOKEN}").as_str()),
    };
    let index = {
        let mut requests = state.requests.lock().unwrap();
        let index = requests.len();
        requests.push(request);
        index
    };
    let Some(reply) = state.replies.get(index) else {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap();
    };
    let mut response = Response::builder().status(reply.status);
    if let Some(location) = &reply.location {
        response = response.header("location", location);
    }
    let body = if reply.stream_body {
        Body::from_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
            reply.body.clone(),
        )]))
    } else {
        Body::from(reply.body.clone())
    };
    response.body(body).unwrap()
}

fn server(id: u64) -> Value {
    json!({
        "id": id,
        "name": format!("fixture-{id}"),
        "status": "running",
        "created": "2026-01-01T00:00:00Z",
        "public_net": {"ipv4": {"ip": "192.0.2.1"}, "ipv6": {"ip": "2001:db8::/64"}},
        "server_type": {"id": 1, "name": "fixture-type", "cores": 2, "memory": 4.0, "disk": 40, "architecture": "x86"},
        "datacenter": {"id": 1, "name": "fixture-dc", "location": {"id": 1, "name": "fixture-location", "country": "DE", "city": "fixture-city"}},
        "included_traffic": 9007199254740993_u64,
        "ingoing_traffic": 42,
        "outgoing_traffic": 81,
        "protection": {"delete": true, "rebuild": false},
    })
}

fn page(current: u64, total: u64) -> Value {
    let first = (current - 1) * PAGE_SIZE + 1;
    let last_id = (current * PAGE_SIZE).min(total);
    let servers: Vec<Value> = (first..=last_id).map(server).collect();
    let last_page = total.div_ceil(PAGE_SIZE).max(1);
    json!({
        "servers": servers,
        "meta": {"pagination": {
            "current_page": current,
            "per_page": PAGE_SIZE,
            "previous_page": if current == 1 { None } else { Some(current - 1) },
            "next_page": if current < last_page { Some(current + 1) } else { None },
            "last_page": last_page,
            "total_entries": total,
        }},
    })
}

#[tokio::test]
async fn combines_only_consistent_pages_and_preserves_integer_traffic() {
    let fixture = Fixture::start(vec![Reply::json(page(1, 51)), Reply::json(page(2, 51))]).await;
    let inventory = fixture.fetch(TOKEN).await;
    assert!(inventory.complete);
    assert_eq!(inventory.error_code, None);
    assert_eq!(inventory.pages, 2);
    assert_eq!(inventory.servers.len(), 51);
    assert_eq!(inventory.servers[50].cloud_id, "51");
    assert_eq!(
        inventory.servers[0].snapshot["traffic"]["included_bytes"],
        "9007199254740993"
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].page, Some(1));
    assert_eq!(requests[1].page, Some(2));
    assert!(
        requests
            .iter()
            .all(|request| request.per_page == Some(PAGE_SIZE) && request.authorized)
    );
}

#[tokio::test]
async fn failed_second_page_retains_first_page_without_claiming_complete_inventory() {
    let failure = Reply {
        status: StatusCode::SERVICE_UNAVAILABLE,
        body: "sensitive-provider-error-body".into(),
        location: None,
        stream_body: false,
    };
    let fixture = Fixture::start(vec![Reply::json(page(1, 51)), failure]).await;
    let inventory = fixture.fetch(TOKEN).await;
    assert!(!inventory.complete);
    assert_eq!(inventory.error_code.as_deref(), Some("http_5xx"));
    assert_eq!(inventory.pages, 1);
    assert_eq!(inventory.servers.len(), 50);
    assert!(!format!("{inventory:?}").contains("sensitive-provider-error-body"));
}

#[tokio::test]
async fn http_failures_return_only_bounded_codes() {
    for (status, code) in [
        (StatusCode::UNAUTHORIZED, "http_401"),
        (StatusCode::FORBIDDEN, "http_403"),
        (StatusCode::TOO_MANY_REQUESTS, "http_429"),
        (StatusCode::INTERNAL_SERVER_ERROR, "http_5xx"),
        (StatusCode::BAD_REQUEST, "http_other"),
    ] {
        let failure = Reply {
            status,
            body: "provider-credential-error-detail".into(),
            location: None,
            stream_body: false,
        };
        let fixture = Fixture::start(vec![failure]).await;
        let inventory = fixture.fetch(TOKEN).await;
        assert_eq!(inventory.error_code.as_deref(), Some(code));
        assert!(inventory.servers.is_empty());
        assert!(!inventory.complete);
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_authorization_does_not_reach_the_destination() {
    let destination = Fixture::start(vec![Reply::json(page(1, 1))]).await;
    let redirect = Reply {
        status: StatusCode::TEMPORARY_REDIRECT,
        body: String::new(),
        location: Some(destination.endpoint()),
        stream_body: false,
    };
    let source = Fixture::start(vec![redirect]).await;
    let inventory = source.fetch(TOKEN).await;
    assert!(!inventory.complete);
    assert_eq!(inventory.error_code.as_deref(), Some("http_other"));
    assert!(destination.requests().is_empty());
    assert_eq!(source.requests().len(), 1);
    assert!(source.requests()[0].authorized);
}

#[tokio::test]
async fn inventory_limit_keeps_at_most_ten_pages_and_five_hundred_servers() {
    let fixture = Fixture::start(
        (1..=11)
            .map(|current| Reply::json(page(current, 501)))
            .collect(),
    )
    .await;
    let inventory = fixture.fetch(TOKEN).await;
    assert!(!inventory.complete);
    assert_eq!(inventory.error_code.as_deref(), Some("inventory_limit"));
    assert_eq!(inventory.pages, MAX_PAGES);
    assert_eq!(inventory.servers.len(), MAX_SERVERS);
    assert_eq!(fixture.requests().len(), MAX_PAGES);
}

#[tokio::test]
async fn pagination_contradictions_and_duplicates_never_commit_an_invalid_page() {
    let mut wrong_next = page(1, 51);
    wrong_next["meta"]["pagination"]["next_page"] = json!(3);
    let mut changed_total = page(2, 52);
    changed_total["servers"].as_array_mut().unwrap().truncate(1);
    let mut duplicate = page(2, 51);
    duplicate["servers"][0]["id"] = json!(1);
    let cases = [
        (vec![Reply::json(wrong_next)], 0),
        (
            vec![Reply::json(page(1, 51)), Reply::json(changed_total)],
            50,
        ),
        (vec![Reply::json(page(1, 51)), Reply::json(duplicate)], 50),
    ];
    for (replies, known) in cases {
        let fixture = Fixture::start(replies).await;
        let inventory = fixture.fetch(TOKEN).await;
        assert!(!inventory.complete);
        assert_eq!(
            inventory.error_code.as_deref(),
            Some("pagination_inconsistent")
        );
        assert_eq!(inventory.servers.len(), known);
    }
    let mut duplicate_page = page(1, 2);
    duplicate_page["servers"][1]["id"] = json!(1);
    let fixture = Fixture::start(vec![Reply::json(duplicate_page)]).await;
    let inventory = fixture.fetch(TOKEN).await;
    assert_eq!(
        inventory.error_code.as_deref(),
        Some("pagination_inconsistent")
    );
    assert_eq!(inventory.pages, 0);
}

#[tokio::test]
async fn secret_fields_are_discarded_and_names_and_strings_are_bounded() {
    let mut document = page(1, 1);
    let raw = &mut document["servers"][0];
    raw["name"] = json!("界".repeat(300));
    raw["status"] = json!("x".repeat(700));
    raw["user_data"] = json!("sensitive-user-data");
    raw["ssh_keys"] = json!([{"public_key": "sensitive-ssh-key"}]);
    raw["labels"] = json!({"secret": "sensitive-label"});
    raw["server_type"]["description"] = json!("sensitive-description");
    let fixture = Fixture::start(vec![Reply::json(document)]).await;
    let inventory = fixture.fetch(TOKEN).await;
    assert!(inventory.complete);
    let server = &inventory.servers[0];
    assert_eq!(server.name.chars().count(), 200);
    assert_eq!(
        server.snapshot["status"].as_str().unwrap().chars().count(),
        512
    );
    assert_eq!(server.snapshot.as_object().unwrap().len(), 9);
    assert!(!server.snapshot.to_string().contains("sensitive-"));
    assert!(server.snapshot.get("labels").is_none());
    assert_eq!(server.snapshot["server_type"]["id"], 1);
}

#[tokio::test]
async fn invalid_tokens_are_rejected_before_sending_any_request() {
    let fixture = Fixture::start(vec![Reply::json(page(1, 1))]).await;
    for token in [
        "short",
        "fixture-token-with\r\nheader-injection",
        "fixture-token-with a-space",
    ] {
        let inventory = fixture.fetch(token).await;
        assert_eq!(inventory.error_code.as_deref(), Some("credential_invalid"));
        assert!(inventory.servers.is_empty());
    }
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn chunked_response_body_is_bounded_without_relying_on_content_length() {
    let reply = Reply {
        status: StatusCode::OK,
        body: "x".repeat(MAX_BODY_BYTES + 1),
        location: None,
        stream_body: true,
    };
    let fixture = Fixture::start(vec![reply]).await;
    let inventory = fixture.fetch(TOKEN).await;
    assert_eq!(inventory.error_code.as_deref(), Some("invalid_response"));
    assert!(!inventory.complete);
    assert_eq!(inventory.pages, 0);
}

#[tokio::test]
async fn empty_inventory_is_complete_and_unknown_optional_fields_remain_null() {
    let empty = Fixture::start(vec![Reply::json(page(1, 0))]).await;
    let inventory = empty.fetch(TOKEN).await;
    assert!(inventory.complete);
    assert_eq!(inventory.pages, 1);
    assert!(inventory.servers.is_empty());
    let mut document = page(1, 1);
    document["servers"][0]
        .as_object_mut()
        .unwrap()
        .remove("public_net");
    document["servers"][0]
        .as_object_mut()
        .unwrap()
        .remove("ingoing_traffic");
    let fixture = Fixture::start(vec![Reply::json(document)]).await;
    let inventory = fixture.fetch(TOKEN).await;
    assert!(inventory.complete);
    assert!(inventory.servers[0].snapshot["ipv4"].is_null());
    assert!(inventory.servers[0].snapshot["traffic"]["ingoing_bytes"].is_null());
}
