use super::{models::*, plugin::NetworkWorkbenchPlugin};
use crate::{
    AppState, control_center,
    diagnostics::service,
    error::{ApiError, ApiResult},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::time::{Duration, Instant};
use uuid::Uuid;
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub plan: Plan,
    pub executions: Vec<Vec<Execution>>,
}
pub(super) async fn enqueue(
    state: &AppState,
    plan_id: Option<Uuid>,
    plan: Plan,
    actor: i64,
) -> ApiResult<Uuid> {
    plan.validate()?;
    let mut executions = vec![];
    for step in &plan.steps {
        let target = if let Some(id) = step.check.target() {
            let row = sqlx::query("SELECT * FROM network_workbench_targets WHERE id=$1")
                .bind(id)
                .fetch_optional(&state.pool)
                .await?
                .ok_or(ApiError::NotFound)?;
            let target = Target {
                id,
                name: row.get("name"),
                host: row.get("host"),
                region: row.get("region"),
                carrier: row.get("carrier"),
                purpose: row.get("purpose"),
                authorization: row.get("authorization_snapshot"),
                authorized_until: row.get("authorized_until"),
            };
            if target
                .authorized_until
                .is_some_and(|end| end <= now_timestamp())
            {
                return Err(ApiError::Conflict("目标授权已到期".into()));
            }
            match &step.check {
                Check::Http { url, .. }
                | Check::WebSocket { url, .. }
                | Check::Quic { url, .. } => {
                    if reqwest::Url::parse(url)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_owned))
                        .as_deref()
                        != Some(target.host.as_str())
                    {
                        return Err(ApiError::BadRequest("URL必须属于选定的授权目标".into()));
                    }
                }
                Check::Mail { domain, .. } if domain != &target.host => {
                    return Err(ApiError::BadRequest("邮件域名必须属于选定授权目标".into()));
                }
                _ => {}
            }
            Some(target)
        } else {
            None
        };
        if let Some((tool, version)) = step.check.tool() {
            let ok:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_tools WHERE id=$1 AND version=$2 AND licensed)").bind(tool).bind(version).fetch_one(&state.pool).await?;
            if !ok {
                return Err(ApiError::Conflict(format!(
                    "{tool}尚未登记该版本与许可条件"
                )));
            }
        }
        if let Check::Throughput {
            receiver_server,
            receiver_host,
            latency_target,
            ..
        } = &step.check
        {
            let info: Value = sqlx::query_scalar(
                "SELECT static_info FROM servers WHERE id=$1 AND deleted_at IS NULL",
            )
            .bind(receiver_server)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
            if !info["ip_addresses"]
                .as_array()
                .is_some_and(|ips| ips.iter().any(|ip| ip.as_str() == Some(receiver_host)))
            {
                return Err(ApiError::Conflict(
                    "接收方监听地址必须是该服务器已上报的网卡地址，NAT公开入口需先明确映射".into(),
                ));
            }
            if let Some(host) = latency_target {
                let authorized:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_targets WHERE host=$1 AND (authorized_until IS NULL OR authorized_until>$2))").bind(host).bind(now_timestamp()).fetch_one(&state.pool).await?;
                if !authorized {
                    return Err(ApiError::Conflict(
                        "负载延迟目标必须属于仍有效的授权目标集".into(),
                    ));
                }
            }
        }
        let source_ids = step.source.servers();
        let mut entries = vec![];
        let source_list: Vec<Option<i64>> = if source_ids.is_empty() {
            vec![None]
        } else {
            source_ids.into_iter().map(Some).collect()
        };
        for source in source_list {
            if let Some(id) = source {
                let _: i64 =
                    sqlx::query_scalar("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL")
                        .bind(id)
                        .fetch_optional(&state.pool)
                        .await?
                        .ok_or(ApiError::NotFound)?;
            }
            entries.push(Execution {
                schema: 1,
                source_server: source,
                target: target.clone(),
                check: step.check.clone(),
                budget: plan.budget.clone(),
                role: format!(
                    "source:{}",
                    source.map_or("panel".into(), |v| v.to_string())
                ),
                source_label: source.map_or("面板".into(), |v| format!("服务器 {v}")),
            });
        }
        if let Check::Throughput {
            receiver_server, ..
        } = &step.check
        {
            entries.insert(
                0,
                Execution {
                    schema: 1,
                    source_server: Some(*receiver_server),
                    target: None,
                    check: step.check.clone(),
                    budget: plan.budget.clone(),
                    role: format!("listener:{receiver_server}"),
                    source_label: format!("服务器 {receiver_server}"),
                },
            );
        }
        if let Check::Route {
            reverse_server: Some(reverse),
            ..
        } = &step.check
        {
            let source = entries
                .first()
                .and_then(|v| v.source_server)
                .ok_or_else(|| ApiError::BadRequest("双向路径需要两个明确Agent来源".into()))?;
            let info: Value = sqlx::query_scalar(
                "SELECT static_info FROM servers WHERE id=$1 AND deleted_at IS NULL",
            )
            .bind(source)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
            let family = match &step.check {
                Check::Route { family, .. } => *family,
                _ => unreachable!(),
            };
            let host = info["ip_addresses"]
                .as_array()
                .and_then(|addresses| {
                    addresses.iter().filter_map(Value::as_str).find(|address| {
                        address.parse::<std::net::IpAddr>().is_ok_and(|ip| {
                            matches!(
                                (ip, family),
                                (std::net::IpAddr::V4(_), Family::Ipv4)
                                    | (std::net::IpAddr::V6(_), Family::Ipv6)
                            )
                        })
                    })
                })
                .ok_or_else(|| ApiError::Conflict("正向来源缺少相应地址，无法反向采集".into()))?;
            let mut check = step.check.clone();
            if let Check::Route { reverse_server, .. } = &mut check {
                *reverse_server = None;
            }
            entries.push(Execution {
                schema: 1,
                source_server: Some(*reverse),
                target: Some(Target {
                    id: Uuid::new_v4(),
                    name: "反向来源".into(),
                    host: host.into(),
                    region: String::new(),
                    carrier: String::new(),
                    purpose: "双向实际路径".into(),
                    authorization: "受管服务器反向采集".into(),
                    authorized_until: None,
                }),
                check,
                budget: plan.budget.clone(),
                role: format!("reverse:{reverse}"),
                source_label: format!("服务器 {reverse}"),
            });
        }
        executions.push(entries);
    }
    let snapshot = Snapshot { plan, executions };
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO network_workbench_runs(id,plan_id,snapshot,status,actor,created_at,updated_at) VALUES($1,$2,$3,'queued',$4,$5,$5)").bind(id).bind(plan_id).bind(serde_json::to_value(&snapshot).map_err(anyhow::Error::from)?).bind(actor.to_string()).bind(now_timestamp()).execute(&mut *tx).await?;
    for (index, values) in snapshot.executions.iter().enumerate() {
        for execution in values {
            sqlx::query("INSERT INTO network_workbench_results(id,run_id,step_index,server_id,role,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'queued',$6,$6)").bind(Uuid::new_v4()).bind(id).bind(index as i32).bind(execution.source_server).bind(&execution.role).bind(now_timestamp()).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(id)
}
pub async fn tick(state: &AppState) -> ApiResult<()> {
    // Each run row remains locked during dispatch. A second executor cannot repeat a step.
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM network_workbench_runs WHERE status IN ('queued','running','cleaning','cancel_requested') ORDER BY created_at LIMIT 8").fetch_all(&state.pool).await?;
    for id in ids {
        if let Err(error) = advance(state, id).await {
            tracing::warn!(%id,%error,"workbench advance failed");
        }
    }
    schedule(state).await?;
    Ok(())
}
async fn schedule(state: &AppState) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    let rows=sqlx::query("SELECT id,definition,interval_secs,next_run_at FROM network_workbench_plans WHERE enabled AND next_run_at<=$1 ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 4").bind(now_timestamp()).fetch_all(&mut *tx).await?;
    for row in rows {
        let definition: Value = row.get("definition");
        let plan: Plan =
            serde_json::from_value(definition["plan"].clone()).map_err(anyhow::Error::from)?;
        let actor = definition["actor"]
            .as_i64()
            .ok_or_else(|| ApiError::Conflict("定时计划缺少发起人".into()))?;
        control_center::require_actor_capability(state, actor, "diagnostics:write").await?;
        for step in &plan.steps {
            for server in step.source.servers() {
                control_center::require_actor_server(state, actor, server, "diagnostics:write")
                    .await?;
            }
            if let Check::Throughput {
                receiver_server, ..
            } = &step.check
            {
                control_center::require_actor_server(
                    state,
                    actor,
                    *receiver_server,
                    "diagnostics:write",
                )
                .await?;
            }
        }
        let now = now_timestamp();
        let next: i64 = row.get("next_run_at");
        let interval: i64 = row.get("interval_secs");
        if plan
            .schedule
            .as_ref()
            .is_some_and(|s| s.missed_window == "run_once")
            || now - next < 60
        {
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_runs WHERE plan_id=$1 AND status IN ('queued','running','cleaning','paused','cancel_requested'))").bind(row.get::<Uuid,_>("id")).fetch_one(&mut *tx).await?;
            if !active {
                let _ = enqueue(state, Some(row.get("id")), plan, actor).await?;
            }
        }
        sqlx::query("UPDATE network_workbench_plans SET next_run_at=$2,updated_at=$3 WHERE id=$1")
            .bind(row.get::<Uuid, _>("id"))
            .bind(next + ((now - next) / interval + 1) * interval)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn advance(state: &AppState, id: Uuid) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    let Some(row)=sqlx::query("SELECT snapshot,status,current_step,created_at,actor FROM network_workbench_runs WHERE id=$1 FOR UPDATE SKIP LOCKED").bind(id).fetch_optional(&mut *tx).await? else {return Ok(());};
    let snapshot: Snapshot =
        serde_json::from_value(row.get("snapshot")).map_err(anyhow::Error::from)?;
    let actor = row
        .get::<String, _>("actor")
        .parse::<i64>()
        .map_err(anyhow::Error::from)?;
    let status: String = row.get("status");
    let index = row.get::<i32, _>("current_step") as usize;
    sqlx::query("UPDATE network_workbench_results r SET job_id=j.id FROM diagnostic_jobs j WHERE r.run_id=$1 AND r.job_id IS NULL AND j.job->'workbench'->>'run_id'=$2 AND (j.job->'workbench'->>'step_index')::integer=r.step_index AND j.job->'workbench'->>'role'=r.role").bind(id).bind(id.to_string()).execute(&mut *tx).await?;
    sqlx::query("UPDATE network_workbench_results r SET status=j.status,result=CASE WHEN j.report IS NOT NULL THEN j.report ELSE r.result END,updated_at=$2 FROM diagnostic_jobs j WHERE r.run_id=$1 AND r.job_id=j.id").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
    let unconfirmed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_results r JOIN diagnostic_jobs j ON j.id=r.job_id WHERE r.run_id=$1 AND (j.status IN ('queued','running','cleaning','cancel_requested') OR NOT j.agent_completed))").bind(id).fetch_one(&mut *tx).await?;
    if status == "cancel_requested" {
        if !unconfirmed {
            sqlx::query(
                "UPDATE network_workbench_runs SET status='cancelled',updated_at=$2 WHERE id=$1",
            )
            .bind(id)
            .bind(now_timestamp())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    if index >= snapshot.plan.steps.len() {
        let any_failed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_results WHERE run_id=$1 AND status='failed')").bind(id).fetch_one(&mut *tx).await?;
        sqlx::query("UPDATE network_workbench_runs SET status=$2,updated_at=$3 WHERE id=$1")
            .bind(id)
            .bind(if unconfirmed {
                "cleaning"
            } else if any_failed {
                "failed"
            } else {
                "succeeded"
            })
            .bind(now_timestamp())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(());
    }
    let results=sqlx::query("SELECT id,role,status,result,job_id FROM network_workbench_results WHERE run_id=$1 AND step_index=$2 ORDER BY role").bind(id).bind(index as i32).fetch_all(&mut *tx).await?;
    let failed = results
        .iter()
        .any(|r| r.get::<String, _>("status") == "failed");
    if failed && snapshot.plan.steps[index].stop_on_failure && !unconfirmed {
        sqlx::query("UPDATE network_workbench_runs SET status='failed',error='步骤失败；已按方案终止',updated_at=$2 WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(());
    }
    if results.iter().all(|r| {
        matches!(
            r.get::<String, _>("status").as_str(),
            "succeeded" | "failed" | "cancelled"
        )
    }) && !unconfirmed
    {
        sqlx::query("UPDATE network_workbench_runs SET current_step=current_step+1,status='queued',updated_at=$2 WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(());
    }
    let authorization = async {
        control_center::require_actor_capability(state, actor, "diagnostics:write").await?;
        for entries in &snapshot.executions {
            for execution in entries {
                if let Some(server) = execution.source_server {
                    control_center::require_actor_server(state, actor, server, "diagnostics:write")
                        .await?;
                }
            }
        }
        Ok::<(), ApiError>(())
    }
    .await;
    match authorization {
        Ok(()) => {}
        Err(error @ (ApiError::Forbidden(_) | ApiError::Unauthorized)) => {
            sqlx::query("UPDATE network_workbench_runs SET status='paused',error=$2,updated_at=$3 WHERE id=$1").bind(id).bind(format!("发起人授权已不可用：{error}")).bind(now_timestamp()).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    let listener = results
        .iter()
        .find(|r| r.get::<String, _>("role").starts_with("listener:"));
    let listener_ready = if let Some(listener) = listener {
        if let Some(job) = listener.get::<Option<Uuid>, _>("job_id") {
            sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM diagnostic_report_sections WHERE job_id=$1 AND name='workbench_scope' AND text::jsonb->>'listener_ready'='true')").bind(job).fetch_one(&mut *tx).await?
        } else {
            false
        }
    } else {
        true
    };
    let mut dispatches = results
        .iter()
        .filter(|r| {
            !r.get::<String, _>("role").starts_with("listener:")
                && r.get::<Option<Uuid>, _>("job_id").is_some()
                && matches!(
                    r.get::<String, _>("status").as_str(),
                    "queued" | "running" | "cleaning" | "cancel_requested"
                )
        })
        .count();
    for execution in &snapshot.executions[index] {
        let result = results
            .iter()
            .find(|r| r.get::<String, _>("role") == execution.role)
            .ok_or(ApiError::NotFound)?;
        if result.get::<String, _>("status") != "queued"
            || result.get::<Option<Uuid>, _>("job_id").is_some()
        {
            continue;
        }
        if execution.role.starts_with("source:") && !listener_ready {
            continue;
        }
        if dispatches >= usize::from(snapshot.plan.budget.concurrency) {
            break;
        }
        dispatches += 1;
        if matches!(&execution.check,Check::Throughput{client_mode,..} if client_mode=="local")
            && execution.role.starts_with("source:")
        {
            sqlx::query("UPDATE network_workbench_runs SET status='paused',error='临时监听已就绪，等待本地客户端凭据配对报告',updated_at=$2 WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
            break;
        }
        if matches!(
            execution.check,
            Check::Speedtest { .. } | Check::GeekbenchImport { .. }
        ) {
            sqlx::query("UPDATE network_workbench_runs SET status='paused',error='此步骤等待满足许可的外部报告导入，未启动Agent工具',updated_at=$2 WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
            break;
        }
        if execution
            .target
            .as_ref()
            .is_some_and(|t| t.authorized_until.is_some_and(|end| end <= now_timestamp()))
        {
            sqlx::query("UPDATE network_workbench_runs SET status='paused',error='目标授权已到期',updated_at=$2 WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
            break;
        }
        if let Some(server) = execution.source_server {
            match service::create_job(
                state,
                server,
                &NetworkWorkbenchPlugin,
                json!({"run_id":id,"step_index":index,"role":execution.role}),
            )
            .await
            {
                Ok(job) => {
                    sqlx::query("UPDATE network_workbench_results SET job_id=$2,status='queued',updated_at=$3 WHERE id=$1").bind(result.get::<Uuid,_>("id")).bind(job.id).bind(now_timestamp()).execute(&mut *tx).await?;
                }
                Err(error) => {
                    sqlx::query("UPDATE network_workbench_runs SET status='paused',error=$2,updated_at=$3 WHERE id=$1").bind(id).bind(error.to_string()).bind(now_timestamp()).execute(&mut *tx).await?;
                    break;
                }
            }
        } else {
            let result_uuid: Uuid = result.get("id");
            let observation = panel(state, execution).await;
            let (status, result) = match observation {
                Ok(v) => (v.status.clone(), json!(v)),
                Err(error) => (
                    "failed".into(),
                    json!({"error":error.to_string(),"status":"failed","source":"面板","collected_at":now_timestamp()}),
                ),
            };
            sqlx::query("UPDATE network_workbench_results SET status=$2,result=$3,updated_at=$4 WHERE id=$1").bind(result_uuid).bind(status).bind(result).bind(now_timestamp()).execute(&mut *tx).await?;
        }
    }
    sqlx::query("UPDATE network_workbench_runs SET status=CASE WHEN status='paused' THEN status ELSE 'running' END,updated_at=$2 WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn panel(state: &AppState, execution: &Execution) -> ApiResult<Observation> {
    let target = execution.target.as_ref();
    let mut raw = String::new();
    let data = match &execution.check {
        Check::Tcp {
            port,
            family,
            samples,
            ..
        } => {
            let host = &target.ok_or(ApiError::NotFound)?.host;
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), *port))
                .await
                .map_err(anyhow::Error::from)?
                .filter(|addr| match family {
                    Family::Ipv4 => addr.is_ipv4(),
                    Family::Ipv6 => addr.is_ipv6(),
                })
                .collect();
            if addresses.is_empty() {
                return Err(ApiError::Conflict("目标没有选定地址族".into()));
            }
            let mut results = vec![];
            for _ in 0..*samples {
                let timer = Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(addresses.as_slice()),
                )
                .await;
                results.push(match result{Ok(Ok(stream))=>{let peer=stream.peer_addr().map_err(anyhow::Error::from)?;drop(stream);json!({"connected":true,"elapsed_ms":timer.elapsed().as_secs_f64()*1000.0,"address":peer.ip().to_string()})},Ok(Err(e))=>json!({"connected":false,"failure":e.to_string()}),Err(_)=>json!({"connected":false,"failure":"连接超时"})});
            }
            json!({"samples":results,"port":port,"family":family,"method":"tcp_connect"})
        }
        Check::Http { .. } => {
            let (data, body) = super::http_probe::probe(execution).await?;
            raw = body;
            data
        }
        Check::IpInfo {
            address,
            family,
            provider_ids,
        } => {
            return super::reports::query_ip(state, execution, address, *family, provider_ids)
                .await;
        }
        _ => return Err(ApiError::Conflict("此检测不可从面板执行".into())),
    };
    let valid = match &execution.check {
        Check::Tcp { .. } => data["samples"]
            .as_array()
            .is_some_and(|v| v.iter().all(|s| s["connected"] == true)),
        Check::Http {
            expected_status, ..
        } => data["status_code"] == *expected_status && data["content_match"] == true,
        _ => true,
    };
    Ok(Observation {
        schema: 1,
        source: "面板".into(),
        target: target.map_or(String::new(), |v| v.host.clone()),
        method: execution.check.name().into(),
        tool: "sinan-panel".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        parameters: json!(execution.check),
        collected_at: now_timestamp(),
        status: if valid { "succeeded" } else { "failed" }.into(),
        data,
        raw_output: raw,
        error: None,
        cleanup: Cleanup {
            process_stopped: true,
            files_removed: true,
            listeners_closed: true,
        },
    })
}
pub(super) async fn report(state: &AppState, id: Uuid) -> ApiResult<Value> {
    let row = sqlx::query("SELECT * FROM network_workbench_runs WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let rows=sqlx::query("SELECT r.*,COALESCE(j.status,r.status) AS current_status,COALESCE(j.report,r.result) AS current_result,j.agent_completed,j.cancel_requested_at,j.cancel_error,j.error AS job_error,j.expected_sections,j.report_completeness,COALESCE((SELECT jsonb_agg(jsonb_build_object('name',s.name,'text',s.text,'complete',s.complete,'collected_at',s.collected_at) ORDER BY s.name) FROM diagnostic_report_sections s WHERE s.job_id=j.id),'[]'::jsonb) AS sections FROM network_workbench_results r LEFT JOIN diagnostic_jobs j ON j.id=r.job_id WHERE r.run_id=$1 ORDER BY r.step_index,r.role").bind(id).fetch_all(&state.pool).await?;
    let results:Vec<Value>=rows.into_iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"step_index":r.get::<i32,_>("step_index"),"source_server":r.get::<Option<i64>,_>("server_id"),"role":r.get::<String,_>("role"),"job_id":r.get::<Option<Uuid>,_>("job_id"),"status":r.get::<String,_>("current_status"),"observation":r.get::<Option<Value>,_>("current_result"),"cleanup_confirmed":r.get::<Option<bool>,_>("agent_completed").unwrap_or_else(||r.get::<Option<Value>,_>("current_result").is_none_or(|v|v.get("origin").is_none())),"cleanup_origin":if r.get::<Option<bool>,_>("agent_completed").is_some(){"agent"}else if r.get::<Option<Value>,_>("current_result").is_some_and(|v|v.get("origin").is_some()){"external_claim"}else{"panel"},"cancel_error":r.get::<Option<String>,_>("cancel_error"),"error":r.get::<Option<String>,_>("job_error"),"sections":r.get::<Value,_>("sections")})).collect();
    Ok(
        json!({"id":id,"status":row.get::<String,_>("status"),"snapshot":row.get::<Value,_>("snapshot"),"current_step":row.get::<i32,_>("current_step"),"error":row.get::<Option<String>,_>("error"),"created_at":row.get::<i64,_>("created_at"),"updated_at":row.get::<i64,_>("updated_at"),"summary":{"step_count":row.get::<Value,_>("snapshot")["plan"]["steps"].as_array().map_or(0,Vec::len),"result_count":results.len(),"succeeded":results.iter().filter(|v|v["status"]=="succeeded").count(),"failed":results.iter().filter(|v|v["status"]=="failed").count(),"cleanup_pending":results.iter().filter(|v|v["cleanup_origin"]=="agent"&&v["cleanup_confirmed"]==false).count()},"results":results,"physical_acceptance":"pending"}),
    )
}
