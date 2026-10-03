use super::model::digest;
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    from: Option<i64>,
    until: Option<i64>,
}

#[derive(Default)]
struct Evidence {
    count: i64,
    first: Option<i64>,
    last: Option<i64>,
    hours: i64,
}
#[derive(Default)]
struct Supplier {
    servers: Vec<i64>,
    evidence: Evidence,
    costs: BTreeMap<String, (i128, i64)>,
    diagnostics: BTreeMap<String, DiagnosticGroup>,
}
struct DiagnosticGroup {
    condition: Value,
    records: Vec<Value>,
    successful_servers: BTreeSet<i64>,
    environment_known: bool,
}

pub async fn comparison(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<Window>,
) -> ApiResult<Json<Value>> {
    let actor = control_center::authenticate(&state, &headers).await?;
    if !actor.allows("cloud:read") || !actor.allows("servers:read") {
        return Err(ApiError::Forbidden(
            "供应商资产对照需要云资源及服务器读取授权；原云资源与账单仍可单独查看".into(),
        ));
    }
    let until = input.until.unwrap_or_else(now_timestamp);
    let from = input.from.unwrap_or(until - 30 * 86400);
    if from < 0 || until <= from || until > now_timestamp() + 60 || until - from > 365 * 86400 {
        return Err(ApiError::BadRequest(
            "供应商比较窗口须为最长365天的明确历史时间段".into(),
        ));
    }
    let permitted: Vec<i64> = actor
        .token_servers
        .as_ref()
        .unwrap_or(&actor.server_ids)
        .iter()
        .copied()
        .filter(|id| actor.allows_server(*id))
        .collect();
    let mut servers=sqlx::query("SELECT s.id,COALESCE(NULLIF(p.asset->>'provider',''),'未登记供应商') AS provider FROM servers s LEFT JOIN fleet_profiles p ON p.server_id=s.id WHERE s.deleted_at IS NULL AND ($1 OR s.id=ANY($2)) ORDER BY s.id LIMIT 257").bind(actor.global_servers()).bind(permitted).fetch_all(&state.pool).await?;
    let server_limit_reached = servers.len() > 256;
    servers.truncate(256);
    let mut suppliers: BTreeMap<String, Supplier> = BTreeMap::new();
    let mut owner = BTreeMap::new();
    for server in servers {
        let id: i64 = server.get("id");
        let provider = server
            .get::<String, _>("provider")
            .chars()
            .take(128)
            .collect::<String>();
        owner.insert(id, provider.clone());
        suppliers.entry(provider).or_default().servers.push(id);
    }
    let ids: Vec<i64> = owner.keys().copied().collect();
    let monitoring_allowed = actor.allows("monitoring:read");
    let diagnostics_allowed = actor.allows("diagnostics:read");
    if monitoring_allowed && !ids.is_empty() {
        // A received sample proves presence at its own instant. Count UTC hour
        // slots containing actual evidence; never interpolate gaps into uptime.
        let rows=sqlx::query("SELECT server_id,COALESCE(sum(CASE WHEN (summary->>'first_sampled_at')::bigint>=$2 THEN (summary->>'sample_count')::bigint ELSE 0 END),0)::bigint AS samples,count(DISTINCT ((summary->>'last_sampled_at')::bigint/3600000))::bigint AS hours,min(CASE WHEN (summary->>'first_sampled_at')::bigint>=$2 THEN (summary->>'first_sampled_at')::bigint ELSE (summary->>'last_sampled_at')::bigint END) AS first_at,max((summary->>'last_sampled_at')::bigint) AS last_at FROM telemetry_history WHERE server_id=ANY($1) AND bucket_at>=$2-3600000 AND bucket_at<$3 AND (summary->>'last_sampled_at')::bigint>=$2 AND (summary->>'last_sampled_at')::bigint<$3 GROUP BY server_id").bind(&ids).bind(from*1000).bind(until*1000).fetch_all(&state.pool).await?;
        for row in rows {
            if let Some(supplier) = owner
                .get(&row.get::<i64, _>("server_id"))
                .and_then(|provider| suppliers.get_mut(provider))
            {
                let value = &mut supplier.evidence;
                value.count += row.get::<i64, _>("samples");
                value.hours += row.get::<i64, _>("hours");
                let first: Option<i64> = row.get("first_at");
                let last: Option<i64> = row.get("last_at");
                if let Some(first) = first {
                    value.first = Some(value.first.map_or(first, |old| old.min(first)));
                }
                if let Some(last) = last {
                    value.last = Some(value.last.map_or(last, |old| old.max(last)));
                }
            }
        }
    }
    if !ids.is_empty() {
        let rows=sqlx::query("SELECT server_id,currency,sum(CASE WHEN kind='refund' THEN -amount_minor ELSE amount_minor END)::text AS amount_minor,count(*)::bigint AS records FROM fleet_cost_records WHERE server_id=ANY($1) AND occurred_at>=$2 AND occurred_at<$3 AND kind IN ('purchase','renewal','refund') GROUP BY server_id,currency").bind(&ids).bind(from).bind(until).fetch_all(&state.pool).await?;
        for row in rows {
            if let Some(supplier) = owner
                .get(&row.get::<i64, _>("server_id"))
                .and_then(|provider| suppliers.get_mut(provider))
            {
                let amount = row
                    .get::<String, _>("amount_minor")
                    .parse::<i128>()
                    .map_err(anyhow::Error::from)?;
                let cost = supplier.costs.entry(row.get("currency")).or_default();
                cost.0 = cost
                    .0
                    .checked_add(amount)
                    .ok_or_else(|| ApiError::Conflict("采购成本总额超出精确整数范围".into()))?;
                cost.1 += row.get::<i64, _>("records");
            }
        }
    }
    let mut diagnostics_limit_reached = false;
    if diagnostics_allowed && !ids.is_empty() {
        // Parameters are hashed rather than exposed. Historical environment
        // evidence comes from the job section, never today's machine profile.
        let mut rows=sqlx::query("SELECT j.id,j.server_id,j.status,j.updated_at,j.agent_completed,j.report IS NOT NULL AS report_available,jsonb_build_object('plugin',j.job->'plugin','version',j.job->'version','artifact_sha256',j.job->'artifact'->'sha256','timeout_secs',j.job->'timeout_secs','options',j.job->'options','resource_budget',j.job->'resource_budget') AS definition,(SELECT CASE WHEN length(s.text)<=16384 THEN s.text ELSE NULL END FROM diagnostic_report_sections s WHERE s.job_id=j.id AND s.name='environment' AND s.complete ORDER BY s.revision DESC LIMIT 1) AS environment FROM diagnostic_jobs j WHERE j.server_id=ANY($1) AND j.updated_at>=$2 AND j.updated_at<$3 ORDER BY j.updated_at DESC,j.id LIMIT 2001").bind(&ids).bind(from).bind(until).fetch_all(&state.pool).await?;
        diagnostics_limit_reached = rows.len() > 2000;
        rows.truncate(2000);
        for row in rows {
            let server: i64 = row.get("server_id");
            let id: Uuid = row.get("id");
            let definition: Value = row.get("definition");
            let environment: Option<String> = row.get("environment");
            let normalized = condition_parameters(&definition);
            let environment_known = environment
                .as_ref()
                .is_some_and(|text| !text.trim().is_empty())
                && ["plugin", "version"].iter().all(|field| {
                    definition[*field]
                        .as_str()
                        .is_some_and(|value| !value.is_empty())
                })
                && definition["artifact_sha256"].as_str().is_some_and(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                && definition["timeout_secs"]
                    .as_i64()
                    .is_some_and(|value| value > 0);
            let environment_digest = match &environment {
                Some(text) if environment_known => digest(
                    &json!({"preflight":text.lines().filter(|line|!line.starts_with("启动预检时间：")).collect::<Vec<_>>()}),
                )?,
                _ => digest(&json!({"unknown_environment_job":id}))?,
            };
            let condition = json!({"plugin":definition["plugin"],"version":definition["version"],"artifact_sha256":definition["artifact_sha256"],"timeout_secs":definition["timeout_secs"],"parameter_digest":digest(&normalized)?,"environment_digest":environment_digest});
            let key = digest(&condition)?;
            if let Some(supplier) = owner
                .get(&server)
                .and_then(|provider| suppliers.get_mut(provider))
            {
                let group = supplier
                    .diagnostics
                    .entry(key)
                    .or_insert_with(|| DiagnosticGroup {
                        condition,
                        records: Vec::new(),
                        successful_servers: BTreeSet::new(),
                        environment_known,
                    });
                let status: String = row.get("status");
                let report: bool = row.get("report_available");
                if status == "succeeded"
                    && report
                    && row.get::<bool, _>("agent_completed")
                    && environment_known
                {
                    group.successful_servers.insert(server);
                }
                group.records.push(json!({"id":id,"server_id":server,"status":status,"updated_at":row.get::<i64,_>("updated_at"),"report_available":report}));
            }
        }
    }
    let window_hours = (until - 1).div_euclid(3600) + 1 - from.div_euclid(3600);
    let values:Vec<Value>=suppliers.into_iter().map(|(provider,supplier)|{
        let expected=window_hours*supplier.servers.len() as i64;let evidence=supplier.evidence;let sufficient=evidence.hours>=24&&evidence.first.zip(evidence.last).is_some_and(|(first,last)|last-first>=86400*1000);
        let costs:Vec<Value>=supplier.costs.into_iter().map(|(currency,(amount,count))|json!({"currency":currency,"amount_minor":amount.to_string(),"record_count":count})).collect();
        let diagnostics:Vec<Value>=supplier.diagnostics.into_iter().map(|(key,group)|json!({"condition_digest":key,"condition":group.condition,"records":group.records,"state":if group.environment_known&&group.successful_servers.len()>=2{"comparable"}else{"insufficient"}})).collect();
        json!({"provider":provider,"server_count":supplier.servers.len(),"server_ids":supplier.servers,"observations":{"count":evidence.count,"first_at":evidence.first.map(|value|value/1000),"last_at":evidence.last.map(|value|value/1000),"observed_hours":evidence.hours,"unknown_hours":expected.saturating_sub(evidence.hours),"evidence_state":if sufficient{"observed"}else{"insufficient"},"availability_percent":null,"source":"本面板实际接收的Telemetry历史","permission_available":monitoring_allowed},"costs":costs,"diagnostics":diagnostics,"diagnostics_permission_available":diagnostics_allowed})
    }).collect();
    Ok(Json(
        json!({"from":from,"until":until,"suppliers":values,"limits":{"server_limit":256,"diagnostics_limit":2000,"server_limit_reached":server_limit_reached,"diagnostics_limit_reached":diagnostics_limit_reached},"semantics":{"missing_is_offline":false,"ranking":false,"currency_conversion":false,"attribution":"按当前资产供应商归组；历史供应商变更未冻结，迁移前证据不能自动归因当前供应商","costs":"仅采购、续费与退款最小货币单位；价格变化不是再次付款","diagnostics":"同工具制品、版本、参数与历史预检证据才能分组；机器硬件差异与原始结果仍需按报告核对，不产生统一质量分数"}}),
    ))
}

fn condition_parameters(definition: &Value) -> Value {
    if let Some(encoded) = definition["options"]["execution"].as_str()
        && let Ok(execution) = serde_json::from_str::<Value>(encoded)
    {
        json!({"check":execution["check"],"target":execution["target"],"budget":execution["budget"],"source_kind":"agent","resource_budget":definition["resource_budget"]})
    } else {
        json!({"options":definition["options"],"resource_budget":definition["resource_budget"]})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparison_keeps_parameters_but_does_not_confuse_host_identity_with_treatment() {
        let left = json!({"options":{"execution":json!({"source_server":1,"role":"source:1","check":{"kind":"cpu","threads":1},"budget":{"duration_secs":60}}).to_string()}});
        let right = json!({"options":{"execution":json!({"source_server":2,"role":"source:2","check":{"kind":"cpu","threads":1},"budget":{"duration_secs":60}}).to_string()}});
        assert_eq!(condition_parameters(&left), condition_parameters(&right));
        let changed = json!({"options":{"execution":json!({"source_server":2,"check":{"kind":"cpu","threads":8},"budget":{"duration_secs":60}}).to_string()}});
        assert_ne!(condition_parameters(&left), condition_parameters(&changed));
    }
}
