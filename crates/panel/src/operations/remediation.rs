use super::{
    api::{authorize, authorize_steps, history, materialize},
    model::{Plan, digest, label},
};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    name: String,
    incident_id: Uuid,
    plan: Plan,
    targets: Vec<i64>,
    cooldown_secs: i64,
    max_runs: i32,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Rule>,
) -> ApiResult<Json<Value>> {
    let actor = authorize(&state, &headers, &request.targets, true).await?;
    authorize_steps(&state, &headers, &request.targets, &request.plan).await?;
    control_center::require_recent_proof(&state, &headers).await?;
    super::incidents::authorize_incident(&state, &headers, request.incident_id, true).await?;
    request.plan.validate(&request.targets)?;
    if request.plan.steps.iter().any(|step| !step.is_fleet()) {
        return Err(ApiError::BadRequest(
            "服务故障自动处置只允许已授权服务步骤；完整面板备份和签名部署须单独预览确认".into(),
        ));
    }
    label(&request.name, 128)?;
    if !(300..=604800).contains(&request.cooldown_secs) || !(1..=100).contains(&request.max_runs) {
        return Err(ApiError::BadRequest("自动处置冷却期或最大次数无效".into()));
    }
    let incident = sqlx::query("SELECT source_key,server_id FROM operations_incidents WHERE id=$1")
        .bind(request.incident_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let source: String = incident.get("source_key");
    let server: Option<i64> = incident.get("server_id");
    if !source.starts_with("service:") || server.is_none_or(|v| !request.targets.contains(&v)) {
        return Err(ApiError::BadRequest(
            "当前自动处置仅支持有实际新观测的受管服务故障，且故障服务器必须在明确目标中".into(),
        ));
    }
    let id = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO operations_remediation_rules(id,name,requested_by,source_key,plan,targets,cooldown_secs,max_runs,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)").bind(id).bind(request.name).bind(actor).bind(source).bind(json!(request.plan)).bind(request.targets).bind(request.cooldown_secs).bind(request.max_runs).bind(now).execute(&state.pool).await?;
    Ok(Json(json!({"id":id,"status":"enabled"})))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "operations:read").await?;
    let rows=sqlx::query("SELECT targets,source_key,to_jsonb(r) AS value FROM operations_remediation_rules r ORDER BY created_at DESC LIMIT 100").fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    for row in rows {
        if authorize(&state, &headers, &row.get::<Vec<i64>, _>("targets"), false)
            .await
            .is_err()
        {
            continue;
        }
        let source: String = row.get("source_key");
        if let Some(server) = source
            .strip_prefix("service:")
            .and_then(|v| v.split(':').next())
            .and_then(|v| v.parse::<i64>().ok())
            && control_center::require_server(&state, &headers, server, "services:read")
                .await
                .is_err()
        {
            continue;
        }
        values.push(row.get("value"));
    }
    Ok(Json(values))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pause {
    paused: bool,
}

pub async fn pause(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Pause>,
) -> ApiResult<Json<Value>> {
    let row = sqlx::query("SELECT targets,plan FROM operations_remediation_rules WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let ids: Vec<i64> = row.get("targets");
    authorize(&state, &headers, &ids, true).await?;
    if !request.paused {
        let plan: Plan = serde_json::from_value(row.get("plan")).map_err(anyhow::Error::from)?;
        authorize_steps(&state, &headers, &ids, &plan).await?;
        control_center::require_recent_proof(&state, &headers).await?;
    }
    sqlx::query("UPDATE operations_remediation_rules SET paused=$2,updated_at=$3 WHERE id=$1")
        .bind(id)
        .bind(request.paused)
        .bind(now_timestamp())
        .execute(&state.pool)
        .await?;
    Ok(Json(json!({"id":id,"paused":request.paused})))
}

pub(super) async fn tick(state: &AppState) -> ApiResult<()> {
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let rules=sqlx::query("SELECT r.*,i.id AS incident_id,i.observed_at FROM operations_remediation_rules r JOIN operations_incidents i ON i.source_key=r.source_key AND i.status<>'resolved' WHERE NOT r.paused AND r.run_count<r.max_runs AND COALESCE(r.last_run_at,0)+r.cooldown_secs<=$1 AND i.observed_at BETWEEN $1-120 AND $1 AND (r.last_job IS NULL OR NOT EXISTS(SELECT 1 FROM operations_jobs j WHERE j.id=r.last_job AND j.status IN ('queued','running','paused','cancel_requested','uncertain'))) ORDER BY r.created_at LIMIT 8 FOR UPDATE OF r SKIP LOCKED").bind(now).fetch_all(&mut *tx).await?;
    for row in rules {
        let id: Uuid = row.get("id");
        let actor: i64 = row.get("requested_by");
        let ids: Vec<i64> = row.get("targets");
        let plan: Plan = serde_json::from_value(row.get("plan")).map_err(anyhow::Error::from)?;
        let mut allowed = plan.steps.iter().all(|step| step.is_fleet());
        for server in &ids {
            allowed &= control_center::actor_server_allowed(
                &state.pool,
                actor,
                *server,
                "operations:write",
            )
            .await?;
            for step in &plan.steps {
                allowed &= control_center::actor_server_allowed(
                    &state.pool,
                    actor,
                    *server,
                    step.permission(),
                )
                .await?;
            }
        }
        if !allowed {
            sqlx::query(
                "UPDATE operations_remediation_rules SET paused=true,updated_at=$2 WHERE id=$1",
            )
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            continue;
        }
        let job = Uuid::new_v4();
        let spec = json!({"plan":plan,"source":"remediation","rule_id":id,"incident_id":row.get::<Uuid,_>("incident_id"),"retry_side_effects":false});
        sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,$2,$3,$4,$5,'queued',$6,$6,$7,$8)").bind(job).bind(&plan.name).bind(actor).bind(&spec).bind(&ids).bind(now).bind(now+plan.max_duration_secs).bind(digest(&spec)?).execute(&mut *tx).await?;
        materialize(&mut tx, job, &ids, &plan, &spec).await?;
        history(&mut tx,job,None,"remediation_triggered",json!({"rule_id":id,"incident_id":row.get::<Uuid,_>("incident_id"),"observed_at":row.get::<i64,_>("observed_at"),"cooldown_secs":row.get::<i64,_>("cooldown_secs"),"attempt":row.get::<i32,_>("run_count")+1}),now).await?;
        sqlx::query("UPDATE operations_remediation_rules SET run_count=run_count+1,last_run_at=$2,last_job=$3,updated_at=$2 WHERE id=$1").bind(id).bind(now).bind(job).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
