use super::super::{Adapter, ProviderRegistry};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    routing::get,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

pub(super) const FIXTURE_KEY: &str = "PUBLIC_TEST_ONLY_API_KEY";

#[derive(Clone)]
pub(super) struct Observation {
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub raw_query: String,
    pub headers: HeaderMap,
    pub method: Method,
}

#[derive(Clone, Default)]
struct SourceState {
    mode: Arc<AtomicUsize>,
    aggregate_mode: Arc<AtomicUsize>,
    observations: Arc<Mutex<Vec<Observation>>>,
}

pub(super) struct Source {
    pub origin: String,
    state: SourceState,
    task: tokio::task::JoinHandle<()>,
}

impl Source {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let state = SourceState::default();
        let app = Router::new()
            .route("/{ip}", get(aggregate))
            .route("/api/v2/check", get(official))
            .route("/unexpected", get(unexpected))
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            origin,
            state,
            task,
        }
    }
    pub fn mode(&self, mode: usize) {
        self.state.mode.store(mode, Ordering::SeqCst);
    }
    pub fn aggregate_mode(&self, mode: usize) {
        self.state.aggregate_mode.store(mode, Ordering::SeqCst);
    }
    pub fn observations(&self) -> Vec<Observation> {
        self.state.observations.lock().unwrap().clone()
    }
    pub fn registry(&self, configured: bool) -> ProviderRegistry {
        let mut registry = ProviderRegistry::configured(configured.then_some(FIXTURE_KEY));
        for provider in &mut registry.providers {
            match provider.adapter.as_mut() {
                Some(Adapter::CheckPlace { origin }) => *origin = self.origin.clone(),
                Some(Adapter::AbuseIpDb { endpoint, .. }) => {
                    *endpoint = format!("{}/api/v2/check", self.origin)
                }
                None => (),
            }
        }
        registry
    }
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap()
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn aggregate(
    State(state): State<SourceState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> axum::response::Response {
    state.observations.lock().unwrap().push(Observation {
        path: uri.path().into(),
        raw_query: uri.query().unwrap_or_default().into(),
        method,
        query,
        headers,
    });
    match state.aggregate_mode.load(Ordering::SeqCst) {
        1 => (StatusCode::FORBIDDEN,"fixture denied").into_response(),
        2 => { tokio::time::sleep(Duration::from_millis(300)).await; Json(json!({})).into_response() },
        _ => Json(json!({"ASN":{"AutonomousSystemNumber":64500},"company":{"abuser_score":0},"scamalytics":{"scamalytics_score":0},"data":{"abuseConfidenceScore":0},"fraud_score":0,"proxy":false,"is_proxy":false,"threat":{"is_proxy":false}})).into_response(),
    }
}

async fn official(
    State(state): State<SourceState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> axum::response::Response {
    let ip = query.get("ipAddress").cloned().unwrap_or_default();
    state.observations.lock().unwrap().push(Observation {
        path: uri.path().into(),
        raw_query: uri.query().unwrap_or_default().into(),
        method,
        query,
        headers,
    });
    match state.mode.load(Ordering::SeqCst) {
        1 => (StatusCode::FORBIDDEN,"fixture denied").into_response(),
        2 => (StatusCode::TOO_MANY_REQUESTS,"fixture limited").into_response(),
        3 => {tokio::time::sleep(Duration::from_millis(300)).await; Json(json!({})).into_response()},
        4 => (StatusCode::OK,"<html>fixture page</html>").into_response(),
        5 => Json(json!({"data":{"ipAddress":"192.0.2.254","isPublic":true,"ipVersion":4,"abuseConfidenceScore":0,"isTor":false}})).into_response(),
        6 => Json(json!({"success":false,"data":{"ipAddress":ip,"isPublic":true,"ipVersion":4,"abuseConfidenceScore":0,"isTor":false}})).into_response(),
        7 => (StatusCode::FOUND,[("location","/unexpected")],"").into_response(),
        8 => (StatusCode::OK,"x".repeat(super::super::super::RESPONSE_LIMIT + 1)).into_response(),
        9 => Json(Value::Null).into_response(),
        _ => Json(official_body(&ip)).into_response(),
    }
}

async fn unexpected(
    State(state): State<SourceState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> String {
    state.observations.lock().unwrap().push(Observation {
        path: uri.path().into(),
        raw_query: uri.query().unwrap_or_default().into(),
        method,
        query,
        headers,
    });
    "must not follow redirect".into()
}

pub(super) fn official_body(ip: &str) -> Value {
    json!({"data":{"ipAddress":ip,"isPublic":true,"ipVersion":if ip.contains(':'){6}else{4},"usageType":"Data Center/Web Hosting/Transit","countryCode":"ZZ","isp":"fixture","isTor":false,"isWhitelisted":null,"abuseConfidenceScore":0}})
}
