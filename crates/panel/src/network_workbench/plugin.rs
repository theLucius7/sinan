use super::{engine::Snapshot, models::Execution};
use crate::{
    diagnostics::service::{DiagnosticPlugin, JobPlan, PlanFuture, SectionContext, SectionFuture},
    error::{ApiError, ApiResult},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::{DiagnosticResourceBudget, DiagnosticSectionUpdate};
use std::collections::BTreeMap;
use uuid::Uuid;
pub struct NetworkWorkbenchPlugin;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub run_id: Uuid,
    pub step_index: usize,
    pub role: String,
}
impl DiagnosticPlugin for NetworkWorkbenchPlugin {
    fn id(&self) -> &'static str {
        "network-workbench"
    }
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    fn title(&self) -> &'static str {
        "网络与硬件工作台"
    }
    fn required_capabilities(&self) -> &'static [&'static str] {
        &["diagnostic:network-workbench-v1"]
    }
    fn record_section<'a>(
        &'a self,
        context: SectionContext<'a>,
        update: &'a DiagnosticSectionUpdate,
        connection: &'a mut sqlx::PgConnection,
    ) -> SectionFuture<'a> {
        Box::pin(async move {
            if update.name != "workbench_result" || !update.complete {
                return Ok(());
            }
            let Some(encoded) = context.job["options"]["execution"].as_str() else {
                return Err(ApiError::Conflict("任务执行来源快照缺失".into()));
            };
            let execution: Execution =
                serde_json::from_str(encoded).map_err(anyhow::Error::from)?;
            let report: super::models::Observation =
                serde_json::from_str(&update.text).map_err(anyhow::Error::from)?;
            if report.parameters
                != serde_json::to_value(&execution.check).map_err(anyhow::Error::from)?
            {
                return Err(ApiError::Conflict("观测参数与固定任务不同".into()));
            }
            if let super::models::Check::Exit {
                family, route_kind, ..
            } = &execution.check
                && report.status == "succeeded"
            {
                let address = report.data["address"]
                    .as_str()
                    .ok_or_else(|| ApiError::BadRequest("出口观测缺少实际地址".into()))?;
                let parsed: std::net::IpAddr = address.parse().map_err(anyhow::Error::from)?;
                if !matches!(
                    (parsed, family),
                    (std::net::IpAddr::V4(_), super::models::Family::Ipv4)
                        | (std::net::IpAddr::V6(_), super::models::Family::Ipv6)
                ) {
                    return Err(ApiError::BadRequest("出口观测地址族不匹配".into()));
                }
                let source = format!("agent_exit:{}:{route_kind}", context.server_id);
                sqlx::query("INSERT INTO network_workbench_ip_evidence(id,server_id,address,family,source,status,evidence,observed_at,expires_at) SELECT $1,$2,$3,$4,$5,'observed',$6,$7,$8 WHERE NOT EXISTS(SELECT 1 FROM network_workbench_ip_evidence WHERE server_id=$2 AND address=$3 AND source=$5 AND observed_at=$7)").bind(Uuid::new_v4()).bind(context.server_id).bind(address).bind(if *family==super::models::Family::Ipv4{"ipv4"}else{"ipv6"}).bind(source).bind(serde_json::to_value(&report).map_err(anyhow::Error::from)?).bind(report.collected_at).bind(report.collected_at+3600).execute(&mut *connection).await?;
            }
            Ok(())
        })
    }
    fn plan<'a>(
        &'a self,
        request: Value,
        server_id: i64,
        connection: &'a mut sqlx::PgConnection,
    ) -> PlanFuture<'a> {
        Box::pin(async move {
            let request: JobRequest = serde_json::from_value(request)
                .map_err(|_| ApiError::BadRequest("工作台任务参数无效".into()))?;
            let value:Value=sqlx::query_scalar("SELECT snapshot FROM network_workbench_runs WHERE id=$1 AND current_step=$2 AND status IN ('queued','running')").bind(request.run_id).bind(request.step_index as i32).fetch_optional(&mut *connection).await?.ok_or_else(||ApiError::Conflict("测试方案已停止或未登记".into()))?;
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_workbench_results WHERE run_id=$1 AND step_index=$2 AND role=$3 AND server_id=$4 AND status='queued' AND job_id IS NULL)").bind(request.run_id).bind(request.step_index as i32).bind(&request.role).bind(server_id).fetch_one(&mut *connection).await?;
            if !pending {
                return Err(ApiError::Conflict(
                    "此固定步骤已经派发或完成，不能重复启动".into(),
                ));
            }
            let snapshot: Snapshot = serde_json::from_value(value).map_err(anyhow::Error::from)?;
            let execution: Execution = snapshot
                .executions
                .get(request.step_index)
                .and_then(|values| {
                    values
                        .iter()
                        .find(|v| v.source_server == Some(server_id) && v.role == request.role)
                })
                .cloned()
                .ok_or_else(|| ApiError::BadRequest("此服务器不属于固定执行来源集合".into()))?;
            execution.check.validate(&execution.budget)?;
            if let Some(target) = &execution.target
                && target
                    .authorized_until
                    .is_some_and(|end| end <= sinan_protocol::now_timestamp())
            {
                return Err(ApiError::Conflict("探测目标授权已到期".into()));
            }
            if let Some((tool, version)) = execution.check.tool() {
                let row: Option<(String, bool)> = sqlx::query_as(
                    "SELECT version,licensed FROM network_workbench_tools WHERE id=$1",
                )
                .bind(tool)
                .fetch_optional(&mut *connection)
                .await?;
                if row.is_none_or(|(saved, licensed)| saved != version || !licensed) {
                    return Err(ApiError::Conflict("工具版本未固定或许可条件未确认".into()));
                }
            }
            let encoded = serde_json::to_string(&execution).map_err(anyhow::Error::from)?;
            Ok(JobPlan {
                timeout_secs: (u64::from(execution.budget.duration_secs) + 30).min(3600),
                budget: DiagnosticResourceBudget {
                    memory_max: execution.budget.memory_bytes,
                    tasks_max: 64,
                    cpu_weight: execution.budget.cpu_weight,
                    cpu_max_percent: Some(u32::from(execution.budget.cpu_percent)),
                    io_weight: 10,
                    oom_score_adjust: 500,
                },
                options: BTreeMap::from([
                    ("execution".into(), encoded),
                    ("environment_section".into(), "true".into()),
                ]),
                expected_sections: vec![
                    "workbench_scope".into(),
                    "workbench_result".into(),
                    "environment".into(),
                ],
                metadata: BTreeMap::from([(
                    "workbench".into(),
                    json!({"run_id":request.run_id,"step_index":request.step_index,"role":request.role,"method":execution.check.name(),"tool_version":execution.check.tool().map(|(_,version)|version)}),
                )]),
            })
        })
    }
}
pub(super) fn observation(value: &Value) -> ApiResult<super::models::Observation> {
    serde_json::from_value(value.clone())
        .map_err(|_| ApiError::BadRequest("结构化观测缺少来源、参数、环境、时间或清理状态".into()))
}
