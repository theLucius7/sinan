use crate::{
    AppState,
    error::{ApiError, ApiResult},
    probes,
    servers::{SERVER_COLUMNS, Server},
    settings, telemetry,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, header},
    routing::get,
};
use serde_json::{Value, json};
use sinan_protocol::{ProbeResult, ProbeSpec, now_timestamp};
use tower_http::set_header::SetResponseHeaderLayer;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/dashboard/access", get(access))
        .route("/api/dashboard/servers", get(list))
        .route("/api/dashboard/live", get(live))
        .route("/api/dashboard/exchange-rates", get(exchange_rates))
        .route("/api/dashboard/servers/{id}", get(detail))
        .route("/api/dashboard/servers/{id}/metrics", get(metrics))
        .route("/api/dashboard/servers/{id}/history", get(history))
        .route("/api/dashboard/servers/{id}/probes", get(probe_list))
        .route(
            "/api/dashboard/servers/{id}/probe-results",
            get(probe_history),
        )
        .route("/api/dashboard/probes/overview", get(probe_overview))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

async fn administrator(state: &AppState, headers: &HeaderMap) -> ApiResult<bool> {
    match crate::control_center::authenticate(state, headers).await {
        Ok(_) => Ok(true),
        Err(ApiError::Unauthorized) => Ok(false),
        Err(error) => Err(error),
    }
}

async fn access(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({"authenticated":administrator(&state,&headers).await?, "public_dashboard":settings::read(&state.pool).await?.public_dashboard}),
    ))
}

async fn allowed(state: &AppState, headers: &HeaderMap, id: Option<i64>) -> ApiResult<bool> {
    allowed_for(state, headers, id, "servers:read").await
}

async fn allowed_for(
    state: &AppState,
    headers: &HeaderMap,
    id: Option<i64>,
    private_capability: &str,
) -> ApiResult<bool> {
    let private = match crate::control_center::authenticate(state, headers).await {
        Ok(actor) => {
            if !actor.allows("monitoring:read")
                || id.is_some_and(|id| !actor.allows_server(id))
                || id.is_none() && !actor.global_servers()
            {
                return Err(ApiError::Forbidden(
                    "当前管理员或 API 令牌没有此看板监控范围的读取权限".into(),
                ));
            }
            actor.allows(private_capability)
        }
        Err(ApiError::Unauthorized) => {
            if !settings::read(&state.pool).await?.public_dashboard {
                return Err(ApiError::Unauthorized);
            }
            false
        }
        Err(error) => return Err(error),
    };
    if let Some(id) = id {
        let visible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL AND COALESCE(asset_settings->>'hidden','false')<>'true')")
            .bind(id).fetch_one(&state.pool).await?;
        if !visible {
            return Err(ApiError::NotFound);
        }
    }
    Ok(private)
}

fn select(value: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .filter_map(|key| value.get(*key).map(|v| ((*key).into(), v.clone())))
            .collect(),
    )
}

pub(crate) fn public_metrics_for_asset(value: &Value, asset: &Value) -> Value {
    let mut scoped = value.clone();
    if let Ok(settings) =
        serde_json::from_value::<crate::server_assets::AssetSettings>(asset.clone())
        && let Some(interfaces) = scoped
            .get_mut("network_interfaces")
            .and_then(Value::as_object_mut)
    {
        interfaces.retain(|name, _| settings.includes(name));
    }
    public_metrics(&scoped)
}

pub(crate) fn public_metrics(value: &Value) -> Value {
    let mut result = select(
        value,
        &[
            "cpu_percent",
            "memory_used",
            "memory_total",
            "disk_used",
            "disk_total",
            "swap_used",
            "swap_total",
            "processes",
            "uptime_secs",
            "tcp_connections",
            "udp_connections",
            "load_1",
            "load_5",
            "load_15",
        ],
    );
    // Capacities are optional extension fields, including in older stored JSON.
    // A whitelisted name must never make an object or secret string public.
    result.as_object_mut().unwrap().retain(|_, value| {
        value.is_null()
            || value
                .as_f64()
                .is_some_and(|number| number.is_finite() && number >= 0.0)
    });
    let mut networks = serde_json::Map::new();
    if let Some(interfaces) = value.get("network_interfaces").and_then(Value::as_object) {
        for (index, metric) in interfaces.values().enumerate() {
            let mut metric = select(
                metric,
                &[
                    "received_bytes",
                    "transmitted_bytes",
                    "receive_bytes_per_sec",
                    "transmit_bytes_per_sec",
                ],
            );
            metric.as_object_mut().unwrap().retain(|_, value| {
                value.is_null()
                    || value
                        .as_f64()
                        .is_some_and(|number| number.is_finite() && number >= 0.0)
            });
            networks.insert(format!("网卡 {}", index + 1), metric);
        }
    }
    result["network_interfaces"] = Value::Object(networks);
    result
}

fn server_view(server: Server, admin: bool) -> ApiResult<Value> {
    let registered = server.device_public_key.is_some();
    let value = serde_json::to_value(server).map_err(anyhow::Error::from)?;
    if admin {
        return Ok(value);
    }
    let mut result = select(
        &value,
        &[
            "id",
            "name",
            "online",
            "metrics_stale",
            "last_seen",
            "last_heartbeat_at",
            "metrics_sampled_at",
            "metrics_received_at",
            "metrics_persisted_at",
            "served_at",
            "telemetry_settings",
        ],
    );
    result["registered"] = json!(registered);
    result["public_view"] = json!(true);
    result["agent_settings"] = select(
        &value["agent_settings"],
        &["sample_interval_secs", "upload_interval_secs"],
    );
    result["static_info"] = select(
        &value["static_info"],
        &[
            "system",
            "arch",
            "cpu_model",
            "cpu_cores",
            "memory_total",
            "disk_total",
            "virtualization",
        ],
    );
    result["latest_metrics"] =
        public_metrics_for_asset(&value["latest_metrics"], &value["asset_settings"]);
    result["asset_settings"] = select(
        &value["asset_settings"],
        &[
            "region",
            "group_name",
            "tags",
            "traffic_limit",
            "traffic_limit_type",
            "reset_day",
        ],
    );
    result["traffic"] = if value["traffic"].is_null() {
        Value::Null
    } else {
        select(
            &value["traffic"],
            &[
                "cycle_start",
                "cycle_end",
                "uploaded",
                "downloaded",
                "used",
                "limit",
                "remaining",
                "percent",
                "exceeded",
                "observed_from",
                "last_sample_at",
                "incomplete",
                "corrected",
            ],
        )
    };
    Ok(result)
}

async fn read_servers(state: &AppState, id: Option<i64>) -> ApiResult<Vec<Server>> {
    let query = format!(
        "SELECT {SERVER_COLUMNS} FROM servers WHERE deleted_at IS NULL AND COALESCE(asset_settings->>'hidden','false')<>'true' AND ($1::bigint IS NULL OR id=$1) ORDER BY id"
    );
    let mut servers: Vec<_> = sqlx::query_as::<_, Server>(&query)
        .bind(id)
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(Server::with_online)
        .collect();
    crate::server_traffic::attach(&state.pool, &mut servers, now_timestamp()).await?;
    telemetry::attach_live(state, &mut servers).await?;
    Ok(servers)
}

async fn live(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let admin = allowed(&state, &headers, None).await?;
    Ok(Json(telemetry::dashboard_live(&state, admin).await?))
}

async fn exchange_rates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<crate::exchange::ExchangeView>> {
    allowed(&state, &headers, None).await?;
    Ok(Json(crate::exchange::current(&state.pool).await?))
}

async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<telemetry::AggregateQuery>,
) -> ApiResult<Json<telemetry::AggregateHistory>> {
    let admin = allowed(&state, &headers, Some(id)).await?;
    let mut history = telemetry::read_aggregate(&state, id, query).await?;
    if !admin {
        for point in &mut history.0.points {
            point.metrics.retain(|key, _| {
                matches!(
                    key.as_str(),
                    "cpu_percent"
                        | "memory_used"
                        | "memory_total"
                        | "memory_percent"
                        | "disk_used"
                        | "disk_total"
                        | "disk_percent"
                        | "swap_used"
                        | "swap_total"
                        | "swap_percent"
                        | "processes"
                        | "uptime_secs"
                        | "tcp_connections"
                        | "udp_connections"
                        | "load_1"
                        | "load_5"
                        | "load_15"
                        | "network_receive_bytes_per_sec"
                        | "network_transmit_bytes_per_sec"
                )
            });
            point.network_counters = std::mem::take(&mut point.network_counters)
                .into_values()
                .enumerate()
                .map(|(index, counter)| (format!("网卡 {}", index + 1), counter))
                .collect();
        }
    }
    Ok(history)
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Value>>> {
    let admin = allowed(&state, &headers, None).await?;
    Ok(Json(
        read_servers(&state, None)
            .await?
            .into_iter()
            .map(|server| server_view(server, admin))
            .collect::<ApiResult<_>>()?,
    ))
}

async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let admin = allowed(&state, &headers, Some(id)).await?;
    let server = read_servers(&state, Some(id))
        .await?
        .pop()
        .ok_or(ApiError::NotFound)?;
    Ok(Json(server_view(server, admin)?))
}

async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<telemetry::HistoryQuery>,
) -> ApiResult<Json<Value>> {
    let admin = allowed(&state, &headers, Some(id)).await?;
    let mut value = serde_json::to_value(telemetry::read_history(&state, id, query).await?.0)
        .map_err(anyhow::Error::from)?;
    if !admin {
        let asset: Value = sqlx::query_scalar("SELECT asset_settings FROM servers WHERE id=$1")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
        for sample in value.as_array_mut().unwrap() {
            sample["metrics"] = public_metrics_for_asset(&sample["metrics"], &asset);
        }
    }
    Ok(Json(value))
}

fn sanitize_probe(probe: &mut ProbeSpec) {
    probe.target.clear();
    probe.port = None;
    if let Some(monitor) = &mut probe.monitor {
        monitor.authorization = None;
    }
}
fn sanitize_results(results: &mut [ProbeResult]) {
    for result in results {
        result.execution = None;
        if result.error.is_some() {
            result.error = Some("检测未完成".into());
        }
    }
}

async fn probe_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<ProbeSpec>>> {
    let admin = allowed_for(&state, &headers, Some(id), "network:read").await?;
    let mut probes = probes::read(&state, id).await?;
    if !admin {
        probes.0.iter_mut().for_each(sanitize_probe);
    }
    Ok(probes)
}

async fn probe_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<probes::HistoryQuery>,
) -> ApiResult<Json<Vec<ProbeResult>>> {
    let admin = allowed_for(&state, &headers, Some(id), "network:read").await?;
    let mut results = probes::read_history(&state, id, query).await?;
    if !admin {
        sanitize_results(&mut results.0);
    }
    Ok(results)
}

async fn probe_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<probes::Overview>>> {
    let admin = allowed_for(&state, &headers, None, "network:read").await?;
    let mut overview = probes::read_overview(&state, true).await?;
    if !admin {
        for row in &mut overview.0 {
            sanitize_probe(&mut row.probe);
            sanitize_results(&mut row.results);
        }
    }
    Ok(overview)
}
