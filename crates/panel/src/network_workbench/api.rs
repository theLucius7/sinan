use super::{engine, models::*};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

pub(super) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    plan: &Plan,
    write: bool,
) -> ApiResult<i64> {
    let scope = if write {
        "diagnostics:write"
    } else {
        "diagnostics:read"
    };
    let principal = control_center::authenticate(state, headers).await?;
    if write && principal.token_id.is_some() {
        return Err(ApiError::Conflict(
            "排队测试与定时方案要求管理员会话，限权API令牌不能转为后台全权限任务".into(),
        ));
    }
    let actor = control_center::require_capability(state, headers, scope).await?;
    let mut ids = Vec::new();
    for step in &plan.steps {
        ids.extend(step.source.servers());
        match &step.check {
            Check::Throughput {
                receiver_server, ..
            } => ids.push(*receiver_server),
            Check::Route {
                reverse_server: Some(id),
                ..
            } => ids.push(*id),
            _ => {}
        }
    }
    ids.sort();
    ids.dedup();
    for id in ids {
        control_center::require_server(state, headers, id, scope).await?;
    }
    Ok(actor)
}
pub async fn catalog(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    Ok(Json(
        json!({"engine_version":"1.0.0","sources":["panel","server","group"],"panel_methods":["tcp","http","ip_info"],"agent_methods":["tcp","icmp","http","dns","tls","udp","web_socket","quic","hardware_info","route","mtr","throughput","cpu","memory","disk","stability","exit","mail","speedtest"],"quic":{"available":true,"required_tool":"curl with HTTP3 feature in signed manifest","unavailable_semantics":"未供应HTTP3工具时明确未知，不以UDP无响应判断端口关闭"},"geekbench":{"execution_available":false,"import_available":true,"reason":"仅接收按许可取得的结构化报告；不同大版本分别比较"},"nodequality_full":{"available":false,"reason":crate::diagnostic_plugins::nodequality::FULL_START_DENIAL},"tool_artifact":"network-workbench","tool_artifact_version":"1.0.0","agent_capability":"diagnostic:network-workbench-v1","execution_release_state":"source_preparation","physical_acceptance":"pending","templates":[{"id":"quick","name":"快速验机","checks":["tcp","tls","exit"]},{"id":"hardware","name":"硬件验机","checks":["cpu","memory","disk"]},{"id":"network","name":"网络验机","checks":["tcp","icmp","route","throughput"]},{"id":"exit","name":"出口检查","checks":["exit","ip_info","dns"]},{"id":"stability","name":"长期稳定性","checks":["stability","throughput"]}]}),
    ))
}
pub async fn targets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Target>>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    let rows = sqlx::query("SELECT * FROM network_workbench_targets ORDER BY name,id")
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Target {
                id: r.get("id"),
                name: r.get("name"),
                host: r.get("host"),
                region: r.get("region"),
                carrier: r.get("carrier"),
                purpose: r.get("purpose"),
                authorization: r.get("authorization_snapshot"),
                authorized_until: r.get("authorized_until"),
            })
            .collect(),
    ))
}
fn valid_target(target: &Target) -> ApiResult<()> {
    if target.name.is_empty()
        || target.name.len() > 128
        || !valid_host(&target.host)
        || target.authorization.trim().is_empty()
        || target.authorization.len() > 1024
        || target.purpose.is_empty()
        || target.region.len() > 128
        || target.carrier.len() > 128
    {
        return Err(ApiError::BadRequest(
            "必须填写有效目标、用途与自有或授权依据".into(),
        ));
    }
    Ok(())
}
pub async fn save_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(target): Json<Target>,
) -> ApiResult<(StatusCode, Json<Target>)> {
    control_center::require_capability(&state, &headers, "diagnostics:write").await?;
    valid_target(&target)?;
    sqlx::query("INSERT INTO network_workbench_targets(id,name,host,region,carrier,purpose,authorization_snapshot,authorized_until,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)").bind(target.id).bind(&target.name).bind(&target.host).bind(&target.region).bind(&target.carrier).bind(&target.purpose).bind(&target.authorization).bind(target.authorized_until).bind(now_timestamp()).execute(&state.pool).await?;
    Ok((StatusCode::CREATED, Json(target)))
}
pub async fn update_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(target): Json<Target>,
) -> ApiResult<Json<Target>> {
    control_center::require_capability(&state, &headers, "diagnostics:write").await?;
    valid_target(&target)?;
    if id != target.id {
        return Err(ApiError::BadRequest("目标ID不匹配".into()));
    }
    let r=sqlx::query("UPDATE network_workbench_targets SET name=$2,host=$3,region=$4,carrier=$5,purpose=$6,authorization_snapshot=$7,authorized_until=$8,updated_at=$9 WHERE id=$1").bind(id).bind(&target.name).bind(&target.host).bind(&target.region).bind(&target.carrier).bind(&target.purpose).bind(&target.authorization).bind(target.authorized_until).bind(now_timestamp()).execute(&state.pool).await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(target))
}
pub async fn delete_target(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    control_center::require_capability(&state, &headers, "diagnostics:write").await?;
    sqlx::query("DELETE FROM network_workbench_targets WHERE id=$1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    pub version: String,
    pub license: String,
    pub source_url: String,
    pub licensed: bool,
    pub platforms: Vec<String>,
}
pub async fn tools(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Tool>>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    let rows = sqlx::query("SELECT * FROM network_workbench_tools ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Tool {
                id: r.get("id"),
                version: r.get("version"),
                license: r.get("license"),
                source_url: r.get("source_url"),
                licensed: r.get("licensed"),
                platforms: r.get("platforms"),
            })
            .collect(),
    ))
}
pub async fn save_tool(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(tool): Json<Tool>,
) -> ApiResult<Json<Tool>> {
    control_center::require_capability(&state, &headers, "diagnostics:write").await?;
    if ![
        "nexttrace",
        "traceroute",
        "mtr",
        "iperf3",
        "sysbench",
        "fio",
        "stress-ng",
        "speedtest",
        "curl",
        "smartctl",
        "ping",
    ]
    .contains(&tool.id.as_str())
        || tool.version.is_empty()
        || tool.version.len() > 128
        || tool.license.is_empty()
        || !valid_url(&tool.source_url, &["https"])
        || tool.platforms.is_empty()
    {
        return Err(ApiError::BadRequest(
            "工具必须有明确版本、许可、官方来源与平台清单".into(),
        ));
    }
    sqlx::query("INSERT INTO network_workbench_tools(id,version,license,source_url,licensed,platforms,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET version=EXCLUDED.version,license=EXCLUDED.license,source_url=EXCLUDED.source_url,licensed=EXCLUDED.licensed,platforms=EXCLUDED.platforms,updated_at=EXCLUDED.updated_at").bind(&tool.id).bind(&tool.version).bind(&tool.license).bind(&tool.source_url).bind(tool.licensed).bind(&tool.platforms).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(tool))
}
pub async fn plans(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    let rows =
        sqlx::query("SELECT * FROM network_workbench_plans ORDER BY updated_at DESC LIMIT 200")
            .fetch_all(&state.pool)
            .await?;
    let mut result = Vec::new();
    for row in rows {
        let definition: Value = row.get("definition");
        let plan: Plan =
            serde_json::from_value(definition["plan"].clone()).map_err(anyhow::Error::from)?;
        match authorize(&state,&headers,&plan,false).await {Ok(_)=>result.push(json!({"id":row.get::<Uuid,_>("id"),"definition":definition,"revision":row.get::<i64,_>("revision"),"enabled":row.get::<bool,_>("enabled"),"next_run_at":row.get::<Option<i64>,_>("next_run_at")})),Err(ApiError::Forbidden(_))=>{},Err(error)=>return Err(error)}
    }
    Ok(Json(result))
}
pub async fn save_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(plan): Json<Plan>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    plan.validate()?;
    let actor = authorize(&state, &headers, &plan, true).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO network_workbench_plans(id,name,definition,enabled,interval_secs,next_run_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)").bind(id).bind(&plan.name).bind(json!({"plan":plan,"actor":actor})).bind(plan.schedule.is_some()).bind(plan.schedule.as_ref().map(|s|i64::from(s.interval_secs))).bind(plan.schedule.as_ref().map(|s|s.first_run_at)).bind(now_timestamp()).execute(&state.pool).await?;
    Ok((StatusCode::CREATED, Json(json!({"id":id,"revision":1}))))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanUpdate {
    pub plan: Plan,
    pub expected_revision: i64,
    pub enabled: bool,
}
pub async fn update_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PlanUpdate>,
) -> ApiResult<Json<Value>> {
    input.plan.validate()?;
    let actor = authorize(&state, &headers, &input.plan, true).await?;
    let row=sqlx::query("UPDATE network_workbench_plans SET name=$2,definition=$3,enabled=$4,interval_secs=$5,next_run_at=$6,revision=revision+1,updated_at=$7 WHERE id=$1 AND revision=$8 RETURNING revision").bind(id).bind(&input.plan.name).bind(json!({"plan":input.plan,"actor":actor})).bind(input.enabled&&input.plan.schedule.is_some()).bind(input.plan.schedule.as_ref().map(|s|i64::from(s.interval_secs))).bind(input.plan.schedule.as_ref().map(|s|s.first_run_at)).bind(now_timestamp()).bind(input.expected_revision).fetch_optional(&state.pool).await?.ok_or_else(||ApiError::Conflict("方案已被修改，请重新读取并核对差异".into()))?;
    Ok(Json(
        json!({"id":id,"revision":row.get::<i64,_>("revision")}),
    ))
}
pub async fn start_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let definition: Value =
        sqlx::query_scalar("SELECT definition FROM network_workbench_plans WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let plan: Plan =
        serde_json::from_value(definition["plan"].clone()).map_err(anyhow::Error::from)?;
    let actor = authorize(&state, &headers, &plan, true).await?;
    let run = engine::enqueue(&state, Some(id), plan, actor).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":run,"status":"queued"})),
    ))
}
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(plan): Json<Plan>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    plan.validate()?;
    let actor = authorize(&state, &headers, &plan, true).await?;
    let id = engine::enqueue(&state, None, plan, actor).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"status":"queued"})),
    ))
}
pub async fn runs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    let rows=sqlx::query("SELECT id,snapshot,status,error,created_at,updated_at,current_step FROM network_workbench_runs ORDER BY created_at DESC LIMIT 100").fetch_all(&state.pool).await?;
    let mut result = vec![];
    for row in rows {
        let snapshot: Value = row.get("snapshot");
        let plan: Plan =
            serde_json::from_value(snapshot["plan"].clone()).map_err(anyhow::Error::from)?;
        match authorize(&state,&headers,&plan,false).await{Ok(_)=>result.push(json!({"id":row.get::<Uuid,_>("id"),"name":plan.name,"status":row.get::<String,_>("status"),"current_step":row.get::<i32,_>("current_step"),"error":row.get::<Option<String>,_>("error"),"created_at":row.get::<i64,_>("created_at"),"updated_at":row.get::<i64,_>("updated_at")})),Err(ApiError::Forbidden(_))=>{},Err(error)=>return Err(error)}
    }
    Ok(Json(result))
}
pub(super) async fn authorized_snapshot(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    write: bool,
) -> ApiResult<Value> {
    let snapshot: Value =
        sqlx::query_scalar("SELECT snapshot FROM network_workbench_runs WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let plan: Plan =
        serde_json::from_value(snapshot["plan"].clone()).map_err(anyhow::Error::from)?;
    authorize(state, headers, &plan, write).await?;
    Ok(snapshot)
}
pub async fn run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    authorized_snapshot(&state, &headers, id, false).await?;
    Ok(Json(engine::report(&state, id).await?))
}
pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    authorized_snapshot(&state, &headers, id, true).await?;
    let now = now_timestamp();
    sqlx::query("UPDATE network_workbench_runs SET status='cancel_requested',cancel_requested_at=$2,updated_at=$2 WHERE id=$1 AND status IN ('queued','running','paused','cleaning')").bind(id).bind(now).execute(&state.pool).await?;
    let jobs:Vec<(i64,Uuid)>=sqlx::query_as("SELECT server_id,job_id FROM network_workbench_results WHERE run_id=$1 AND job_id IS NOT NULL AND status NOT IN ('succeeded','failed','cancelled')").bind(id).fetch_all(&state.pool).await?;
    for (server, job) in jobs {
        let _ = crate::diagnostics::cancellation::request(
            State(state.clone()),
            headers.clone(),
            Path((server, job)),
        )
        .await?;
    }
    Ok(Json(
        json!({"id":id,"status":"cancel_requested","cleanup_confirmed":false}),
    ))
}
pub async fn resume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    authorized_snapshot(&state, &headers, id, true).await?;
    let result=sqlx::query("UPDATE network_workbench_runs SET status='queued',error=NULL,updated_at=$2 WHERE id=$1 AND status='paused'").bind(id).bind(now_timestamp()).execute(&state.pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict("只有暂停的方案可继续".into()));
    }
    Ok(Json(json!({"id":id,"status":"queued"})))
}
