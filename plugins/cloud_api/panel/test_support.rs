use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, Response},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, task::JoinHandle};

pub struct Reply {
    pub action: String,
    pub value: Value,
    pub status: u16,
}
impl Reply {
    pub fn ok(action: &str, value: Value) -> Self {
        Self {
            action: action.into(),
            value,
            status: 200,
        }
    }
}
#[derive(Clone)]
pub struct RequestData {
    pub action: String,
    pub headers: HeaderMap,
    pub body: Value,
    pub params: BTreeMap<String, String>,
}
struct Data {
    replies: VecDeque<Reply>,
    requests: Vec<RequestData>,
}
pub struct Mock {
    pub endpoint: String,
    data: Arc<Mutex<Data>>,
    task: JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mock {
    pub async fn start(replies: Vec<Reply>) -> Self {
        let data = Arc::new(Mutex::new(Data {
            replies: replies.into(),
            requests: Vec::new(),
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let app = Router::new().fallback(handle).with_state(data.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            endpoint,
            data,
            task,
        }
    }
    pub fn requests(&self) -> Vec<RequestData> {
        self.data.lock().unwrap().requests.clone()
    }
    pub fn exhausted(&self) {
        assert!(self.data.lock().unwrap().replies.is_empty());
    }
}
async fn handle(State(data): State<Arc<Mutex<Data>>>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 32768).await.unwrap();
    assert!(!parts.headers.contains_key("cookie"));
    assert!(!parts.uri.to_string().contains("TEST_ONLY"));
    let mut params = BTreeMap::new();
    let body = if parts
        .headers
        .get("content-type")
        .is_some_and(|v| v == "application/x-www-form-urlencoded")
    {
        assert!(parts.uri.query().is_none());
        let url = reqwest::Url::parse(&format!(
            "http://example.invalid/?{}",
            String::from_utf8(bytes.to_vec()).unwrap()
        ))
        .unwrap();
        params = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Value::Null
    } else if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    let action = parts
        .headers
        .get("x-tc-action")
        .map(|v| v.to_str().unwrap().to_owned())
        .or_else(|| params.get("Action").cloned())
        .unwrap_or_else(|| format!("{} {}", parts.method, parts.uri.path()));
    let mut data = data.lock().unwrap();
    data.requests.push(RequestData {
        action: action.clone(),
        headers: parts.headers,
        body,
        params,
    });
    let reply = data.replies.pop_front().expect("unexpected cloud request");
    assert_eq!(reply.action, action);
    Response::builder()
        .status(reply.status)
        .header("content-type", "application/json")
        .body(Body::from(reply.value.to_string()))
        .unwrap()
}
