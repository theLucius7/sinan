use super::{dns_accounts, dns_wire};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub zone_id: String,
    pub name: String,
    pub kind: String,
    pub resolver_ip: IpAddr,
    #[serde(default = "port")]
    pub resolver_port: u16,
    #[serde(default)]
    pub expected: Vec<String>,
}
fn port() -> u16 {
    53
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/accounts/{id}/resolve", post(resolve))
        .route("/api/plugins/ddns/accounts/{id}/observations", get(history))
}

async fn resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(mut input): Json<Request>,
) -> ApiResult<Json<Value>> {
    let account = dns_accounts::load(&state.pool, id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:read").await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    if !account.config.enabled || !account.config.zone_ids.contains(&input.zone_id) {
        return Err(ApiError::Forbidden("账号已停用或区域未授权".into()));
    }
    let client = dns_accounts::client(&state.pool, &account).await?;
    let zone = dns_accounts::zone(&client, &account, &input.zone_id).await?;
    input.name = super::dns_record_spec::name(&input.name)
        .ok_or_else(|| ApiError::BadRequest("DNS 查询名称无效".into()))?;
    if input.name != zone && !input.name.ends_with(&format!(".{zone}")) {
        return Err(ApiError::BadRequest("查询名称不属于授权区域".into()));
    }
    if input.resolver_port == 0
        || input.resolver_ip.is_unspecified()
        || input.resolver_ip.is_multicast()
        || input.expected.len() > 32
        || input.expected.iter().any(|value| value.len() > 4096)
    {
        return Err(ApiError::BadRequest("解析器地址、端口或预期值无效".into()));
    }
    let kind = dns_wire::kind(&input.kind)
        .ok_or_else(|| ApiError::BadRequest("此 DNS 查询类型不可用".into()))?;
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(5), query(&input, kind)).await;
    let now = sinan_protocol::now_timestamp();
    let result = match result {
        Ok(Ok(mut value)) => {
            let expected: BTreeSet<_> = input.expected.iter().cloned().collect();
            let observed: BTreeSet<_> = value["answers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|answer| answer["kind"] == input.kind)
                .filter_map(|answer| answer["value"].as_str().map(str::to_owned))
                .collect();
            value["expected_match"] = if expected.is_empty() {
                Value::Null
            } else {
                (value["rcode"] == 0 && expected == observed).into()
            };
            value
        }
        Ok(Err(code)) => json!({"status":"error","error_code":code,"expected_match":null}),
        Err(_) => json!({"status":"error","error_code":"resolver_timeout","expected_match":null}),
    };
    let mut result = result;
    result["elapsed_ms"] = (started.elapsed().as_secs_f64() * 1000.0).into();
    result["checked_at"] = now.into();
    result["source"] = "panel".into();
    result["resolver"] = SocketAddr::new(input.resolver_ip, input.resolver_port)
        .to_string()
        .into();
    result["provider_accepted"] = Value::Null;
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO dns_resolver_observations(id,account_id,request,result,occurred_at) VALUES($1,$2,$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(id).bind(json!(input)).bind(&result).bind(now).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM dns_resolver_observations WHERE account_id=$1 AND id IN (SELECT id FROM dns_resolver_observations WHERE account_id=$1 ORDER BY occurred_at DESC,id DESC OFFSET 256)")
        .bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub(super) async fn query(input: &Request, kind: u16) -> Result<Value, &'static str> {
    let id = u16::from_be_bytes([Uuid::new_v4().as_bytes()[0], Uuid::new_v4().as_bytes()[1]]);
    let packet = dns_wire::request(id, &input.name, kind).ok_or("invalid_dns_name")?;
    let target = SocketAddr::new(input.resolver_ip, input.resolver_port);
    let bind = if input.resolver_ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| "resolver_network_error")?;
    socket
        .connect(target)
        .await
        .map_err(|_| "resolver_network_error")?;
    socket
        .send(&packet)
        .await
        .map_err(|_| "resolver_network_error")?;
    let mut response = vec![0u8; 4096];
    let length = socket
        .recv(&mut response)
        .await
        .map_err(|_| "resolver_network_error")?;
    response.truncate(length);
    let tcp = response.get(2).is_some_and(|flags| *flags & 2 != 0);
    if tcp {
        let mut stream = TcpStream::connect(target)
            .await
            .map_err(|_| "resolver_tcp_error")?;
        stream
            .write_all(&(packet.len() as u16).to_be_bytes())
            .await
            .map_err(|_| "resolver_tcp_error")?;
        stream
            .write_all(&packet)
            .await
            .map_err(|_| "resolver_tcp_error")?;
        let length = stream.read_u16().await.map_err(|_| "resolver_tcp_error")? as usize;
        if !(12..=16384).contains(&length) {
            return Err("resolver_response_too_large");
        }
        response.resize(length, 0);
        stream
            .read_exact(&mut response)
            .await
            .map_err(|_| "resolver_tcp_error")?;
    }
    let mut result = dns_wire::response(&response, id, &input.name, kind)?;
    result["transport"] = if tcp { "tcp_fallback" } else { "udp" }.into();
    Ok(result)
}

async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    let account = dns_accounts::load(&state.pool, id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:read").await?;
    Ok(Json(sqlx::query_scalar("SELECT to_jsonb(o) FROM dns_resolver_observations o WHERE account_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 256").bind(id).fetch_all(&state.pool).await?))
}
