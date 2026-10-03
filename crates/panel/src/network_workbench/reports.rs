use super::{api, engine, models::*, plugin};
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
use sha2::{Digest, Sha256};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: Uuid,
    pub name: String,
    pub endpoint: String,
    pub credential_ref: Option<String>,
    pub daily_quota: i32,
    pub cache_seconds: i32,
    pub disabled: bool,
}
pub async fn providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Provider>>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    let rows = sqlx::query("SELECT * FROM network_workbench_providers ORDER BY name")
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Provider {
                id: r.get("id"),
                name: r.get("name"),
                endpoint: r.get("endpoint"),
                credential_ref: r.get("credential_ref"),
                daily_quota: r.get("daily_quota"),
                cache_seconds: r.get("cache_seconds"),
                disabled: r.get("disabled"),
            })
            .collect(),
    ))
}
pub async fn save_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(provider): Json<Provider>,
) -> ApiResult<Json<Provider>> {
    control_center::require_capability(&state, &headers, "diagnostics:write").await?;
    if provider.name.is_empty()
        || provider.name.len() > 128
        || !provider.endpoint.contains("{ip}")
        || !valid_url(&provider.endpoint.replace("{ip}", "192.0.2.1"), &["https"])
        || !(1..=10000).contains(&provider.daily_quota)
        || !(60..=86400).contains(&provider.cache_seconds)
        || provider
            .credential_ref
            .as_ref()
            .is_some_and(|v| v.len() > 128)
    {
        return Err(ApiError::BadRequest(
            "资料源需有HTTPS接口、{ip}占位符、明确配额和缓存期限".into(),
        ));
    }
    sqlx::query("INSERT INTO network_workbench_providers(id,name,endpoint,credential_ref,daily_quota,cache_seconds,disabled,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,endpoint=EXCLUDED.endpoint,credential_ref=EXCLUDED.credential_ref,daily_quota=EXCLUDED.daily_quota,cache_seconds=EXCLUDED.cache_seconds,disabled=EXCLUDED.disabled,updated_at=EXCLUDED.updated_at").bind(provider.id).bind(&provider.name).bind(&provider.endpoint).bind(&provider.credential_ref).bind(provider.daily_quota).bind(provider.cache_seconds).bind(provider.disabled).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(provider))
}
pub(super) async fn query_ip(
    state: &AppState,
    execution: &Execution,
    address: &str,
    family: Family,
    providers: &[Uuid],
) -> ApiResult<Observation> {
    let mut evidence = vec![];
    for provider in providers {
        let row = sqlx::query("SELECT * FROM network_workbench_providers WHERE id=$1")
            .bind(provider)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
        let name: String = row.get("name");
        let source_key = format!("{provider}:{name}");
        let cached:Option<(String,Value,i64)>=sqlx::query_as("SELECT status,evidence,observed_at FROM network_workbench_ip_evidence WHERE address=$1 AND source=$2 AND expires_at>$3 ORDER BY observed_at DESC LIMIT 1").bind(address).bind(&source_key).bind(now_timestamp()).fetch_optional(&state.pool).await?;
        if let Some((status, result, time)) = cached {
            evidence.push(json!({"source":name,"status":status,"observed_at":time,"cached":true,"raw":result}));
            continue;
        }
        let now = now_timestamp();
        let quota=sqlx::query("UPDATE network_workbench_providers SET requests_today=CASE WHEN quota_day<>$2 THEN 1 ELSE requests_today+1 END,quota_day=$2 WHERE id=$1 AND NOT disabled AND (quota_day<>$2 OR requests_today<daily_quota) RETURNING requests_today").bind(provider).bind(now/86400).fetch_optional(&state.pool).await?;
        let result: Result<Value, String> = if row.get::<bool, _>("disabled") {
            Err("资料源已停用".into())
        } else if quota.is_none() {
            Err("资料源日配额已用完".into())
        } else {
            let endpoint = row.get::<String, _>("endpoint").replace("{ip}", address);
            if let Some(reference) = row.get::<Option<String>, _>("credential_ref") {
                match Uuid::parse_str(&reference) {
                    Err(_) => Err("资料源凭据引用ID无效".into()),
                    Ok(credential_id) => match control_center::credentials::resolve_reference(
                        state,
                        credential_id,
                        "external-api",
                        &format!("network-workbench:provider:{provider}"),
                    )
                    .await
                    {
                        Err(_) => Err("资料源凭据引用不可用或无法解密".into()),
                        Ok(credential) => {
                            fetch_json(state, *provider, &endpoint, Some(&credential)).await
                        }
                    },
                }
            } else {
                fetch_json(state, *provider, &endpoint, None).await
            }
        };
        let (status, result) = match result {
            Ok(value) => ("observed", value),
            Err(error) => ("unknown", json!({"error":error})),
        };
        let expiry = now + i64::from(row.get::<i32, _>("cache_seconds"));
        sqlx::query("INSERT INTO network_workbench_ip_evidence(id,server_id,address,family,source,status,evidence,observed_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(Uuid::new_v4()).bind(execution.source_server).bind(address).bind(if family==Family::Ipv4{"ipv4"}else{"ipv6"}).bind(&source_key).bind(status).bind(&result).bind(now).bind(expiry).execute(&state.pool).await?;
        evidence.push(
            json!({"source":name,"status":status,"observed_at":now,"cached":false,"raw":result}),
        );
    }
    Ok(Observation {
        schema: 1,
        source: "面板资料查询".into(),
        target: address.into(),
        method: "ip_info".into(),
        tool: "provider_api".into(),
        tool_version: "per_source".into(),
        parameters: json!(execution.check),
        collected_at: now_timestamp(),
        status: if evidence.iter().any(|v| v["status"] == "observed") {
            "succeeded"
        } else {
            "failed"
        }
        .into(),
        data: json!({"address":address,"family":family,"sources":evidence,"consensus":null,"risk_verdict":"unknown_until_interpreted","semantics":"供应方原始证据分别保存，错误和未知不会变成干净或真家宽"}),
        raw_output: String::new(),
        error: None,
        cleanup: Cleanup {
            process_stopped: true,
            files_removed: true,
            listeners_closed: true,
        },
    })
}
async fn fetch_json(
    state: &AppState,
    provider: Uuid,
    endpoint: &str,
    credential: Option<&Value>,
) -> Result<Value, String> {
    let mut last = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            let reserved=sqlx::query("UPDATE network_workbench_providers SET requests_today=requests_today+1 WHERE id=$1 AND NOT disabled AND quota_day=$2 AND requests_today<daily_quota RETURNING requests_today").bind(provider).bind(now_timestamp()/86400).fetch_optional(&state.pool).await.map_err(|_|"资料源配额读取失败".to_string())?;
            if reserved.is_none() {
                return Err("资料源重试受日配额限制".into());
            }
        }
        match fetch_json_once(endpoint, credential).await {
            Ok(value) => return Ok(value),
            Err(error) => {
                let retry = error.contains("连接失败")
                    || error.contains("读取失败")
                    || error.contains("429")
                    || error.contains("503");
                last = error;
                if !retry {
                    break;
                }
            }
        }
    }
    Err(last)
}
async fn fetch_json_once(endpoint: &str, credential: Option<&Value>) -> Result<Value, String> {
    use futures_util::StreamExt;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.get(endpoint);
    if let Some(token) = credential.and_then(|value| value["token"].as_str()) {
        request = request.bearer_auth(token);
    }
    if let Some(query) = credential.and_then(|value| value["query"].as_object()) {
        let mut parameters = std::collections::BTreeMap::new();
        for (key, value) in query {
            let value = value
                .as_str()
                .ok_or_else(|| "资料源凭据查询参数格式无效".to_string())?;
            if key.is_empty() || key.len() > 64 || value.len() > 4096 {
                return Err("资料源凭据查询参数超出上限".into());
            }
            parameters.insert(key, value);
        }
        request = request.query(&parameters);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "资料源连接失败".to_string())?;
    if !response.status().is_success() {
        return Err(format!("资料源HTTP状态 {}", response.status().as_u16()));
    }
    let mut bytes = vec![];
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "资料源响应读取失败".to_string())?;
        if bytes.len() + chunk.len() > 64 * 1024 {
            return Err("资料源响应超过64KiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "资料源未返回有效JSON".into())
}
pub async fn ip_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(address): Path<String>,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "diagnostics:read").await?;
    if address.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::BadRequest("IP地址无效".into()));
    }
    let rows=sqlx::query("SELECT * FROM network_workbench_ip_evidence WHERE address=$1 ORDER BY observed_at DESC LIMIT 100").bind(address).fetch_all(&state.pool).await?;
    let mut evidence = vec![];
    for row in rows {
        if let Some(server) = row.get::<Option<i64>, _>("server_id") {
            match control_center::require_server(&state, &headers, server, "diagnostics:read").await
            {
                Ok(_) => {}
                Err(ApiError::Forbidden(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        evidence.push(json!({"source":row.get::<String,_>("source"),"status":row.get::<String,_>("status"),"family":row.get::<String,_>("family"),"evidence":row.get::<Value,_>("evidence"),"observed_at":row.get::<i64,_>("observed_at"),"expires_at":row.get::<i64,_>("expires_at")}));
    }
    Ok(Json(evidence))
}
pub async fn exit_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_server(&state, &headers, server, "diagnostics:read").await?;
    let rows=sqlx::query("SELECT address,family,source,status,evidence,observed_at,expires_at FROM network_workbench_ip_evidence WHERE server_id=$1 AND source LIKE $2 ORDER BY observed_at DESC LIMIT 100").bind(server).bind(format!("agent_exit:{server}:%")).fetch_all(&state.pool).await?;
    Ok(Json(rows.into_iter().map(|r|json!({"address":r.get::<String,_>("address"),"family":r.get::<String,_>("family"),"source":r.get::<String,_>("source"),"status":r.get::<String,_>("status"),"evidence":r.get::<Value,_>("evidence"),"observed_at":r.get::<i64,_>("observed_at"),"expires_at":r.get::<i64,_>("expires_at")})).collect()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub step_index: i32,
    pub role: String,
    pub observation: Observation,
    pub authorized_source: String,
    pub license_acknowledged: bool,
}
pub async fn import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Import>,
) -> ApiResult<Json<Value>> {
    let snapshot = api::authorized_snapshot(&state, &headers, id, true).await?;
    let snapshot: engine::Snapshot =
        serde_json::from_value(snapshot).map_err(anyhow::Error::from)?;
    if serde_json::to_vec(&input.observation).map_or(true, |encoded| encoded.len() > 64 * 1024)
        || input.observation.schema != 1
        || !["succeeded", "failed", "unknown"].contains(&input.observation.status.as_str())
        || input.authorized_source.is_empty()
        || !input.license_acknowledged
        || input.observation.raw_output.len() > 64 * 1024
        || input.observation.collected_at <= 0
        || input.observation.collected_at > now_timestamp() + 60
        || input.observation.tool_version.is_empty()
    {
        return Err(ApiError::BadRequest(
            "导入须提供授权来源、许可确认、工具版本与真实采集时间".into(),
        ));
    }
    let expected = snapshot
        .executions
        .get(input.step_index as usize)
        .and_then(|steps| steps.iter().find(|v| v.role == input.role))
        .ok_or(ApiError::NotFound)?;
    if let Check::GeekbenchImport {
        tool_version,
        major_version,
        ..
    } = &expected.check
        && (input.observation.tool != "geekbench"
            || input.observation.tool_version != *tool_version
            || input
                .observation
                .tool_version
                .split('.')
                .next()
                .and_then(|v| v.parse::<u16>().ok())
                != Some(*major_version))
    {
        return Err(ApiError::Conflict("Geekbench工具和大版本不匹配".into()));
    }
    if let Check::Speedtest { tool_version, .. } = &expected.check
        && (input.observation.tool != "speedtest"
            || input.observation.tool_version != *tool_version)
    {
        return Err(ApiError::Conflict("Speedtest报告工具版本不匹配".into()));
    }
    if input.observation.parameters != json!(expected.check) {
        return Err(ApiError::Conflict(
            "外部报告参数与该步骤不一致，拒绝合并".into(),
        ));
    }
    let result=sqlx::query("UPDATE network_workbench_results SET result=$4,status=$5,updated_at=$6 WHERE run_id=$1 AND step_index=$2 AND role=$3 AND job_id IS NULL AND status='queued'").bind(id).bind(input.step_index).bind(&input.role).bind(json!({"origin":"authorized_import","source_reference":input.authorized_source,"observation":input.observation})).bind(if input.observation.status=="succeeded"{"succeeded"}else{"failed"}).bind(now_timestamp()).execute(&state.pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::Conflict(
            "该步骤已有执行结果或已派发，导入不能覆盖真实设备记录".into(),
        ));
    }
    Ok(Json(json!({"imported":true,"physical_acceptance":false})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub left_run: Uuid,
    pub left_step: i32,
    pub left_role: String,
    pub right_run: Uuid,
    pub right_step: i32,
    pub right_role: String,
}
fn normalize_result(value: Value) -> ApiResult<Observation> {
    if let Some(text) = value["text"].as_str() {
        let parsed: Value = serde_json::from_str(text).map_err(anyhow::Error::from)?;
        plugin::observation(&parsed)
    } else if value.get("observation").is_some() {
        plugin::observation(&value["observation"])
    } else {
        plugin::observation(&value)
    }
}
fn comparison_conditions_match(
    left: &Observation,
    right: &Observation,
    left_budget: &super::models::Budget,
    right_budget: &super::models::Budget,
) -> bool {
    left.method == right.method
        && left.tool == right.tool
        && left.tool_version == right.tool_version
        && left.parameters == right.parameters
        && left.target == right.target
        && left_budget == right_budget
}
pub async fn compare(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Comparison>,
) -> ApiResult<Json<Value>> {
    let mut budgets = Vec::new();
    for run in [input.left_run, input.right_run] {
        let snapshot = api::authorized_snapshot(&state, &headers, run, false).await?;
        let budget: super::models::Budget =
            serde_json::from_value(snapshot["plan"]["budget"].clone())
                .map_err(|_| ApiError::Conflict("报告缺少可核对的执行资源预算".into()))?;
        budgets.push(budget);
    }
    let mut results = vec![];
    for (run, step, role) in [
        (input.left_run, input.left_step, &input.left_role),
        (input.right_run, input.right_step, &input.right_role),
    ] {
        let value:Option<Value>=sqlx::query_scalar("SELECT result FROM network_workbench_results WHERE run_id=$1 AND step_index=$2 AND role=$3").bind(run).bind(step).bind(role).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
        results.push(normalize_result(
            value.ok_or_else(|| ApiError::Conflict("测试尚无结构化结果".into()))?,
        )?);
    }
    let left = &results[0];
    let right = &results[1];
    let comparable = comparison_conditions_match(left, right, &budgets[0], &budgets[1]);
    let mut changes = vec![];
    if comparable {
        let old = left.data["hops"].as_array();
        let new = right.data["hops"].as_array();
        if let (Some(old), Some(new)) = (old, new) {
            for i in 0..old.len().max(new.len()) {
                if old.get(i).map(|v| (&v["ip"], &v["responders"]))
                    != new.get(i).map(|v| (&v["ip"], &v["responders"]))
                {
                    changes.push(json!({"hop":i+1,"before":old.get(i),"after":new.get(i),"change":if i>=old.len(){"added"}else if i>=new.len(){"removed"}else{"changed"}}));
                }
            }
        }
    }
    Ok(Json(
        json!({"comparable":comparable,"reason":if comparable{"相同工具、版本、参数、目标与资源预算，来源单独保留"}else{"工具、版本、目标、参数或资源预算不同，不计算统一速度/硬件分数"},"budgets":budgets,"resource_budget_match":budgets[0]==budgets[1],"sources":[left.source,right.source],"left":left,"right":right,"path_changes":changes,"external_as_path":null,"location_is_estimate":true}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub expires_at: i64,
    pub include_addresses: bool,
}
fn token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub async fn share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Share>,
) -> ApiResult<Json<Value>> {
    api::authorized_snapshot(&state, &headers, id, false).await?;
    control_center::require_capability(&state, &headers, "diagnostics:write").await?;
    if input.expires_at <= now_timestamp() || input.expires_at > now_timestamp() + 30 * 86400 {
        return Err(ApiError::BadRequest("分享期限应在未来30天内".into()));
    }
    let secret = token();
    let share = Uuid::new_v4();
    sqlx::query("INSERT INTO network_workbench_shares(id,run_id,token_hash,expires_at,redaction,created_at) VALUES($1,$2,$3,$4,$5,$6)").bind(share).bind(id).bind(hash(&secret)).bind(input.expires_at).bind(json!({"include_addresses":input.include_addresses,"include_raw":false})).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(
        json!({"id":share,"path":format!("/network-report/{secret}"),"expires_at":input.expires_at}),
    ))
}
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let run: Uuid = sqlx::query_scalar("SELECT run_id FROM network_workbench_shares WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    api::authorized_snapshot(&state, &headers, run, true).await?;
    sqlx::query("UPDATE network_workbench_shares SET revoked_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now_timestamp())
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn shared(
    State(state): State<AppState>,
    Path(secret): Path<String>,
) -> ApiResult<Json<Value>> {
    if secret.len() != 64 {
        return Err(ApiError::NotFound);
    }
    let row=sqlx::query("SELECT run_id,redaction FROM network_workbench_shares WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>$2").bind(hash(&secret)).bind(now_timestamp()).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let report = engine::report(&state, row.get("run_id")).await?;
    let addresses = row.get::<Value, _>("redaction")["include_addresses"] == true;
    let mut results = vec![];
    for result in report["results"].as_array().into_iter().flatten() {
        if let Some(value) = result["observation"].as_object()
            && let Ok(observation) = normalize_result(Value::Object(value.clone()))
        {
            results.push(json!({"step_index":result["step_index"],"execution_origin":value.get("origin").and_then(Value::as_str).unwrap_or(if result["job_id"].is_null(){"panel"}else{"agent"}),"cleanup_verified_by_platform":result["cleanup_confirmed"]==true&&result["cleanup_origin"]!="external_claim","status":observation.status,"method":observation.method,"tool":observation.tool,"version":observation.tool_version,"collected_at":observation.collected_at,"target":if addresses{observation.target}else{"已脱敏".into()},"data":redact(observation.data,addresses),"cleanup":observation.cleanup}));
        }
    }
    Ok(Json(
        json!({"status":report["status"],"results":results,"source":"受控分享","raw_output_included":false}),
    ))
}
fn redact(value: Value, addresses: bool) -> Value {
    match value {
        Value::Object(map) => {
            let map = map
                .into_iter()
                .filter(|(key, _)| {
                    let key = key.to_ascii_lowercase();
                    !key.contains("key")
                        && !key.contains("authorization")
                        && !key.contains("cookie")
                        && !key.contains("serial")
                        && !key.contains("secret")
                        && !key.contains("token")
                        && !key.contains("password")
                        && !key.contains("credential")
                        && !key.contains("raw")
                        && (addresses
                            || ![
                                "address", "ip", "host", "hops", "target", "url", "source",
                                "server", "sender", "receiver", "redirect",
                            ]
                            .iter()
                            .any(|v| key.contains(v)))
                })
                .map(|(key, value)| (key, redact(value, addresses)))
                .collect();
            Value::Object(map)
        }
        Value::Array(array) => {
            Value::Array(array.into_iter().map(|v| redact(v, addresses)).collect())
        }
        Value::String(text) => {
            if let Ok(mut url) = reqwest::Url::parse(&text)
                && matches!(url.scheme(), "http" | "https" | "ws" | "wss")
            {
                if !addresses {
                    return Value::String("已脱敏".into());
                }
                let _ = url.set_username("");
                let _ = url.set_password(None);
                url.set_query(None);
                url.set_fragment(None);
                return Value::String(url.into());
            }
            Value::String(text)
        }
        other => other,
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pairing {
    pub run_id: Uuid,
    pub step_index: i32,
    pub role: String,
    pub expires_at: i64,
}
pub async fn pairing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Pairing>,
) -> ApiResult<Json<Value>> {
    let snapshot = api::authorized_snapshot(&state, &headers, input.run_id, true).await?;
    if input.expires_at <= now_timestamp() || input.expires_at > now_timestamp() + 3600 {
        return Err(ApiError::BadRequest("本地配对凭据最多有效1小时".into()));
    }
    let snapshot: engine::Snapshot =
        serde_json::from_value(snapshot).map_err(anyhow::Error::from)?;
    let execution = snapshot
        .executions
        .get(input.step_index as usize)
        .and_then(|v| v.iter().find(|e| e.role == input.role))
        .ok_or(ApiError::NotFound)?;
    if !matches!(execution.check, Check::Throughput { .. }) {
        return Err(ApiError::BadRequest(
            "本地配对仅用于明确参数的吞吐步骤".into(),
        ));
    }
    let secret = token();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO network_workbench_pairings(id,run_id,token_hash,expires_at,definition,created_at) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(input.run_id).bind(hash(&secret)).bind(input.expires_at).bind(json!({"step_index":input.step_index,"role":input.role,"execution":execution})).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(
        json!({"id":id,"submit_path":format!("/network-pairing/{secret}"),"expires_at":input.expires_at,"instructions":"按execution参数在获准的本地客户端运行iperf3，保存JSON。提交结构化Observation；凭据仅授权一次报告配对，不开放服务器远程控制或代替iperf认证。", "execution":execution}),
    ))
}
pub async fn paired_result(
    State(state): State<AppState>,
    Path(secret): Path<String>,
    Json(observation): Json<Observation>,
) -> ApiResult<StatusCode> {
    if secret.len() != 64 {
        return Err(ApiError::NotFound);
    }
    let mut tx = state.pool.begin().await?;
    let row=sqlx::query("SELECT * FROM network_workbench_pairings WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2 FOR UPDATE").bind(hash(&secret)).bind(now_timestamp()).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let definition: Value = row.get("definition");
    if serde_json::to_vec(&observation).map_or(true, |encoded| encoded.len() > 64 * 1024)
        || observation.schema != 1
        || !["succeeded", "failed", "unknown"].contains(&observation.status.as_str())
        || observation.collected_at <= 0
        || observation.collected_at > now_timestamp() + 60
        || observation.parameters != definition["execution"]["check"]
        || observation.tool != "iperf3"
        || Some(observation.tool_version.as_str())
            != definition["execution"]["check"]["tool_version"].as_str()
        || observation.raw_output.len() > 64 * 1024
    {
        return Err(ApiError::BadRequest("配对报告工具或参数不一致".into()));
    }
    let paired=sqlx::query("UPDATE network_workbench_results SET result=$4,status=$5,updated_at=$6 WHERE run_id=$1 AND step_index=$2 AND role=$3 AND job_id IS NULL AND status='queued'").bind(row.get::<Uuid,_>("run_id")).bind(definition["step_index"].as_i64().ok_or(ApiError::NotFound)? as i32).bind(definition["role"].as_str().ok_or(ApiError::NotFound)?).bind(json!({"origin":"paired_local","observation":observation})).bind(if observation.status=="succeeded"{"succeeded"}else{"failed"}).bind(now_timestamp()).execute(&mut *tx).await?;
    if paired.rows_affected() != 1 {
        return Err(ApiError::Conflict(
            "此配对步骤已经执行或完成，拒绝覆盖".into(),
        ));
    }
    sqlx::query("UPDATE network_workbench_pairings SET used_at=$2 WHERE id=$1")
        .bind(row.get::<Uuid, _>("id"))
        .bind(now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn differing_cpu_hard_limits_are_not_comparable_even_with_identical_tool_parameters() {
        let observation: Observation = serde_json::from_value(json!({"schema":1,"source":"fixture","target":"","method":"cpu","tool":"sysbench","tool_version":"1.0",
            "parameters":{"kind":"cpu","threads":1,"duration_secs":10},"collected_at":1,"status":"succeeded","data":{},"raw_output":"","error":null,
            "cleanup":{"process_stopped":true,"files_removed":true,"listeners_closed":true}})).unwrap();
        let left = super::super::models::Budget::default();
        let mut right = left.clone();
        assert!(comparison_conditions_match(
            &observation,
            &observation,
            &left,
            &right
        ));
        right.cpu_percent = 40;
        assert!(!comparison_conditions_match(
            &observation,
            &observation,
            &left,
            &right
        ));
        right.cpu_percent = left.cpu_percent;
        right.cpu_weight = 40;
        assert!(!comparison_conditions_match(
            &observation,
            &observation,
            &left,
            &right
        ));
    }
    #[test]
    fn shared_http_phases_and_throughput_flows_do_not_disclose_addresses_or_credentials() {
        let value = json!({"phase_timings":{"dns_ms":1.0,"url":"https://example.com/path?token=private","resolved_address":"192.0.2.1"},
            "redirects":["https://example.com/next"],"flows":[{"sender":"服务器 1","receiver":"服务器 2"}],
            "nested":["https://account:password@example.com/private?token=private#fragment"]});
        let private = redact(value.clone(), false);
        let serialized = private.to_string();
        assert!(!serialized.contains("example.com"));
        assert!(!serialized.contains("192.0.2.1"));
        assert!(!serialized.contains("服务器"));
        assert!(!serialized.contains("password"));
        assert_eq!(private["phase_timings"]["dns_ms"], 1.0);
        let addresses = redact(value, true);
        assert_eq!(addresses["nested"][0], "https://example.com/private");
        assert!(!addresses.to_string().contains("password"));
        assert!(!addresses.to_string().contains("token=private"));
    }
}
