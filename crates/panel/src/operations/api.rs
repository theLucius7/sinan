use super::model::{Plan, batch, digest, label};
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
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub plan: Plan,
    pub targets: Vec<i64>,
    pub template_id: Option<Uuid>,
}

pub(super) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    targets: &[i64],
    write: bool,
) -> ApiResult<i64> {
    let scope = if write {
        "operations:write"
    } else {
        "operations:read"
    };
    let mut actor = control_center::require_capability(state, headers, scope).await?;
    for server in targets {
        actor = control_center::require_server(state, headers, *server, scope).await?;
    }
    Ok(actor)
}

pub(super) async fn history(
    tx: &mut Transaction<'_, Postgres>,
    job: Uuid,
    actor: Option<i64>,
    action: &str,
    details: Value,
    now: i64,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO operations_history(job_id,actor,action,details,recorded_at) VALUES($1,$2,$3,$4,$5)")
        .bind(job).bind(actor).bind(action).bind(details).bind(now).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn targets(pool: &PgPool, id: Uuid) -> ApiResult<Vec<i64>> {
    sqlx::query_scalar("SELECT targets FROM operations_jobs WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "operations:read").await?;
    Ok(Json(sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'revision',revision,'steps',steps,'created_at',created_at) FROM operations_templates WHERE NOT archived ORDER BY created_at DESC LIMIT 200").fetch_all(&state.pool).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    name: String,
    steps: Vec<super::model::Step>,
}

pub async fn save_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Template>,
) -> ApiResult<Json<Value>> {
    let actor = control_center::require_capability(&state, &headers, "operations:write").await?;
    label(&request.name, 128)?;
    if !(1..=16).contains(&request.steps.len()) {
        return Err(ApiError::BadRequest("模板须包含 1–16 个固定步骤".into()));
    }
    for step in &request.steps {
        step.validate()?;
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_templates(id,name,steps,created_by,created_at) VALUES($1,$2,$3,$4,$5)")
        .bind(id).bind(request.name).bind(json!(request.steps)).bind(actor).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(json!({"id":id})))
}

pub async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> ApiResult<Json<Value>> {
    request.plan.validate(&request.targets)?;
    let actor = authorize(&state, &headers, &request.targets, true).await?;
    authorize_steps(&state, &headers, &request.targets, &request.plan).await?;
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    if let Some(template) = request.template_id {
        let steps: Value = sqlx::query_scalar(
            "SELECT steps FROM operations_templates WHERE id=$1 AND NOT archived",
        )
        .bind(template)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
        if steps != json!(request.plan.steps) {
            return Err(ApiError::Conflict(
                "模板步骤已变化，请重新选择并预览".into(),
            ));
        }
    }
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',s.id,'name',s.name,'capabilities',s.capabilities,'last_seen',s.last_seen,'allowed_services',COALESCE(p.policy->'services','[]'::jsonb)) FROM servers s LEFT JOIN fleet_profiles p ON p.server_id=s.id WHERE s.id=ANY($1) AND s.deleted_at IS NULL ORDER BY array_position($1,s.id)")
        .bind(&request.targets).fetch_all(&mut *tx).await?;
    if rows.len() != request.targets.len() {
        return Err(ApiError::Conflict("目标包含已删除或不存在的服务器".into()));
    }
    let unavailable: Vec<_> = rows
        .iter()
        .filter(|v| {
            request.plan.steps.iter().any(|step| step.is_fleet()) && !supported(&v["capabilities"])
        })
        .collect();
    if !unavailable.is_empty() {
        return Err(ApiError::ConflictReferences {
            message: "批量操作需要 Agent 独立日常运维能力".into(),
            references: json!(unavailable),
        });
    }
    for target in &rows {
        for step in &request.plan.steps {
            if let Some(service) = &step.service
                && !target["allowed_services"]
                    .as_array()
                    .is_some_and(|allowed| {
                        allowed.iter().any(|v| v.as_str() == Some(service.as_str()))
                    })
            {
                return Err(ApiError::Conflict(format!(
                    "服务器 {} 未授权服务 {service}",
                    target["id"]
                )));
            }
        }
    }
    let typed_steps =
        super::typed_steps::preview(&state, &mut tx, &request.targets, &request.plan).await?;
    let spec = json!({"plan":request.plan,"target_snapshot":rows,"typed_steps":typed_steps,"executor":"typed_fleet_runtime_and_panel_backup","platform":"Agent实际能力、本机服务授权、固定已签名失败部署及面板完整备份","retry_side_effects":false});
    let hash = digest(&spec)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,template_id,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,$2,$3,$4,$5,$6,'preview',$7,$7,$8,$9)")
        .bind(id).bind(&request.plan.name).bind(actor).bind(request.template_id).bind(&spec).bind(&request.targets).bind(now).bind(now+600).bind(&hash).execute(&mut *tx).await?;
    history(&mut tx,id,Some(actor),"preview",json!({"targets":request.targets,"operations":request.plan.steps,"impact":"面板完整恢复点至多执行一次；实际服务和失败部署首台完成后再按固定批次执行"}),now).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"digest":hash,"expires_at":now+600,"spec":spec}),
    ))
}

pub(super) fn supported(capabilities: &Value) -> bool {
    capabilities.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|v| v.as_str() == Some(sinan_protocol::fleet::OPERATIONS_CAPABILITY))
    })
}

pub async fn jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "operations:read").await?;
    let rows = sqlx::query("SELECT id,targets,jsonb_build_object('id',id,'name',name,'status',status,'targets',targets,'requested_by',requested_by,'created_at',created_at,'updated_at',updated_at,'failure_reason',failure_reason) AS value FROM operations_jobs ORDER BY created_at DESC LIMIT 100").fetch_all(&state.pool).await?;
    let mut visible = Vec::new();
    for row in rows {
        let targets: Vec<i64> = row.get("targets");
        if authorize(&state, &headers, &targets, false).await.is_ok() {
            visible.push(row.get("value"));
        }
    }
    Ok(Json(visible))
}

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let ids = targets(&state.pool, id).await?;
    authorize(&state, &headers, &ids, false).await?;
    let job: Value = sqlx::query_scalar("SELECT to_jsonb(j) FROM operations_jobs j WHERE id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    let plan: Plan =
        serde_json::from_value(job["spec"]["plan"].clone()).map_err(anyhow::Error::from)?;
    super::typed_steps::authorize(&state, &headers, &plan, true).await?;
    for server in &ids {
        for step in &plan.steps {
            if step.service.is_some() {
                control_center::require_server(&state, &headers, *server, "services:read").await?;
            } else if step.is_runtime() {
                control_center::require_server(&state, &headers, *server, "proxy:read").await?;
            }
        }
    }
    let steps: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)||jsonb_build_object('execution_state',COALESCE(c.status,t.state),'dispatched_at',COALESCE(c.dispatched_at,t.started_at),'running_cancel_supported',false,'execution_result',COALESCE(c.result,t.result)) FROM operations_target_steps t LEFT JOIN fleet_operations c ON c.id=t.fleet_operation_id WHERE t.job_id=$1 ORDER BY t.batch,t.server_id,t.position").bind(id).fetch_all(&state.pool).await?;
    let panel_steps: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(p) FROM operations_panel_steps p WHERE job_id=$1 ORDER BY position",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let history: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(h) FROM operations_history h WHERE job_id=$1 ORDER BY recorded_at,id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        json!({"job":job,"steps":steps,"panel_steps":panel_steps,"history":history}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    digest: String,
}

pub async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Confirmation>,
) -> ApiResult<Json<Value>> {
    let target_ids = targets(&state.pool, id).await?;
    let actor = authorize(&state, &headers, &target_ids, true).await?;
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM operations_jobs WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let spec: Value = row.get("spec");
    let plan: Plan = serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
    authorize_steps(&state, &headers, &target_ids, &plan).await?;
    control_center::require_recent_proof(&state, &headers).await?;
    if row.get::<String, _>("status") != "preview"
        || row.get::<i64, _>("expires_at") <= now
        || row.get::<String, _>("preview_digest") != request.digest
        || digest(&spec)? != request.digest
    {
        return Err(ApiError::Conflict("预览已过期、发生变化或已经采用".into()));
    }
    super::typed_steps::validate_frozen(&state, &mut tx, &target_ids, &plan, &spec).await?;
    materialize(&mut tx, id, &target_ids, &plan, &spec).await?;
    sqlx::query("UPDATE operations_jobs SET status='queued',expires_at=$2,updated_at=$3,requested_by=$4 WHERE id=$1").bind(id).bind(now+plan.max_duration_secs).bind(now).bind(actor).execute(&mut *tx).await?;
    history(
        &mut tx,
        id,
        Some(actor),
        "confirmed",
        json!({"digest":request.digest}),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"status":"queued"})))
}

pub(super) async fn materialize(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    targets: &[i64],
    plan: &Plan,
    spec: &Value,
) -> ApiResult<()> {
    super::typed_steps::materialize(tx, id, plan, spec).await?;
    for (index, server) in targets.iter().enumerate() {
        for position in 0..plan.steps.len() {
            sqlx::query("INSERT INTO operations_target_steps(job_id,server_id,position,batch) VALUES($1,$2,$3,$4)").bind(id).bind(server).bind(position as i32).bind(batch(index,plan.batch_size)).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let actor = authorize(&state, &headers, &targets(&state.pool, id).await?, true).await?;
    let spec: Value = sqlx::query_scalar("SELECT spec FROM operations_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    let plan: Plan = serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
    authorize_steps(&state, &headers, &targets(&state.pool, id).await?, &plan).await?;
    let mut tx = state.pool.begin().await?;
    let status: String =
        sqlx::query_scalar("SELECT status FROM operations_jobs WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if matches!(status.as_str(), "succeeded" | "failed" | "cancelled") {
        return Err(ApiError::Conflict("任务已结束".into()));
    }
    let now = now_timestamp();
    sqlx::query("UPDATE operations_jobs SET status=CASE WHEN status='preview' THEN 'cancelled' ELSE 'cancel_requested' END,cancel_requested_at=$2,updated_at=$2 WHERE id=$1").bind(id).bind(now).execute(&mut *tx).await?;
    history(
        &mut tx,
        id,
        Some(actor),
        "cancel_requested",
        json!({"process_stop":"等待设备回执；未确认前保留锁"}),
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"status":"cancel_requested"})))
}

pub async fn resume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let ids = targets(&state.pool, id).await?;
    let actor = authorize(&state, &headers, &ids, true).await?;
    let spec: Value = sqlx::query_scalar("SELECT spec FROM operations_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    let plan: Plan = serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
    authorize_steps(&state, &headers, &ids, &plan).await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let changed=sqlx::query("UPDATE operations_jobs j SET status='queued',updated_at=$2,approved_batch=(SELECT MIN(batch) FROM operations_target_steps WHERE job_id=j.id AND state<>'succeeded') WHERE id=$1 AND status='paused' AND expires_at>$2").bind(id).bind(now_timestamp()).execute(&mut *tx).await?.rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict("任务未暂停或已超出总时长预算".into()));
    }
    history(
        &mut tx,
        id,
        Some(actor),
        "batch_resumed",
        json!({"target_snapshot_unchanged":true}),
        now_timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"status":"queued"})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    server_id: i64,
    operation_id: Uuid,
    inspection_id: Uuid,
    process_stopped: bool,
    cleanup_confirmed: bool,
    observed_at: i64,
    evidence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    server_id: i64,
    operation_id: Uuid,
}

async fn authorize_reconciliation(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    server: i64,
    operation: Uuid,
) -> ApiResult<(i64, Vec<(Option<i64>, String)>)> {
    let ids = targets(&state.pool, id).await?;
    let actor = authorize(state, headers, &ids, true).await?;
    let spec: Value = sqlx::query_scalar("SELECT spec FROM operations_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    let plan: Plan = serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
    authorize_steps(state, headers, &ids, &plan).await?;
    let original: Value = sqlx::query_scalar("SELECT c.operation FROM fleet_operations c JOIN operations_target_steps t ON t.fleet_operation_id=c.id WHERE c.id=$1 AND c.automation_job_id=$2 AND c.server_id=$3 AND t.job_id=$2 AND t.server_id=$3")
        .bind(operation).bind(id).bind(server).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let original = serde_json::from_value(original).map_err(anyhow::Error::from)?;
    crate::fleet::reconciliation::authorize(state, headers, server, &original).await?;
    let mut permissions = crate::fleet::reconciliation::permissions(server, &original);
    for target in &ids {
        permissions.push((Some(*target), "operations:write".into()));
        for step in &plan.steps {
            if !step.is_panel() {
                permissions.push((Some(*target), step.permission().to_owned()));
            }
        }
    }
    if plan.steps.iter().any(|step| step.is_panel()) {
        permissions.push((None, "recovery:write".into()));
    }
    Ok((actor, permissions))
}

async fn lock_uncertain_operation(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: i64,
    operation: Uuid,
) -> ApiResult<()> {
    let status: String =
        sqlx::query_scalar("SELECT status FROM operations_jobs WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    if !matches!(status.as_str(), "uncertain" | "cancel_requested") {
        return Err(ApiError::Conflict(
            "只有执行结果未知的任务可人工核对".into(),
        ));
    }
    let eligible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_target_steps WHERE job_id=$1 AND server_id=$2 AND fleet_operation_id=$3 AND state='uncertain' AND runtime_operation_id IS NULL AND position NOT IN (SELECT position FROM operations_panel_steps WHERE job_id=$1))")
        .bind(id).bind(server).bind(operation).fetch_one(&mut **tx).await?;
    if !eligible {
        return Err(ApiError::Conflict(
            "须选择此作业的确切未知日常操作；部署和备份使用各自证据核对流程".into(),
        ));
    }
    sqlx::query("SELECT id FROM servers WHERE id=$1 FOR UPDATE")
        .bind(server)
        .fetch_one(&mut **tx)
        .await?;
    Ok(())
}

pub async fn inspect_reconciliation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Inspection>,
) -> ApiResult<Json<Value>> {
    let (actor, permissions) = authorize_reconciliation(
        &state,
        &headers,
        id,
        request.server_id,
        request.operation_id,
    )
    .await?;
    let mut tx = state.pool.begin().await?;
    crate::fleet::reconciliation::lock_authorization(&mut tx, &headers, actor, &permissions)
        .await?;
    lock_uncertain_operation(&mut tx, id, request.server_id, request.operation_id).await?;
    crate::fleet::reconciliation::lock_authorization(&mut tx, &headers, actor, &permissions)
        .await?;
    let value = crate::fleet::reconciliation::enqueue_inspection(
        &mut tx,
        request.operation_id,
        request.server_id,
        actor,
        Some(id),
    )
    .await?;
    history(&mut tx, id, Some(actor), "reconciliation_inspection_queued", json!({"server_id":request.server_id,"operation_id":request.operation_id,"inspection":value}), now_timestamp()).await?;
    tx.commit().await?;
    Ok(Json(value))
}

pub async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Reconciliation>,
) -> ApiResult<Json<Value>> {
    let (actor, permissions) = authorize_reconciliation(
        &state,
        &headers,
        id,
        request.server_id,
        request.operation_id,
    )
    .await?;
    label(&request.evidence, 4096)?;
    let now = now_timestamp();
    if !request.process_stopped
        || !request.cleanup_confirmed
        || request.observed_at > now
        || request.observed_at < now - 600
    {
        return Err(ApiError::BadRequest(
            "须确认目标上的进程已停止，并提供最近十分钟的核对证据".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    crate::fleet::reconciliation::lock_authorization(&mut tx, &headers, actor, &permissions)
        .await?;
    // Match the worker's job-before-server order for manual reconciliation.
    lock_uncertain_operation(&mut tx, id, request.server_id, request.operation_id).await?;
    crate::fleet::reconciliation::lock_authorization(&mut tx, &headers, actor, &permissions)
        .await?;
    let now = now_timestamp();
    if request.observed_at > now || request.observed_at < now - 600 {
        return Err(ApiError::Conflict(
            "等待期间人工观察证据已过期，请重新核对".into(),
        ));
    }
    let record = crate::fleet::reconciliation::reconcile_in(
        &mut tx,
        request.operation_id,
        request.server_id,
        actor,
        &crate::fleet::reconciliation::Conclusion {
            inspection_id: request.inspection_id,
            outcome: "unknown".into(),
            conclusion: request.evidence.clone(),
            processes_stopped: request.process_stopped,
            cleanup_confirmed: request.cleanup_confirmed,
        },
        Some(id),
    )
    .await?;
    sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND fleet_operation_id=$3 AND state='uncertain'")
        .bind(id).bind(request.server_id).bind(request.operation_id).bind(now).bind(json!({"manual_reconciliation":record,"success":null,"observed_at":request.observed_at,"original_result":"unknown"})).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM operations_server_locks l WHERE job_id=$1 AND server_id=$2 AND NOT EXISTS(SELECT 1 FROM operations_target_steps t WHERE t.job_id=l.job_id AND t.server_id=l.server_id AND t.state IN ('queued','running','cancel_requested','uncertain'))")
        .bind(id)
        .bind(request.server_id)
        .execute(&mut *tx)
        .await?;
    history(&mut tx,id,Some(actor),"process_stop_confirmed",json!({"server_id":request.server_id,"operation_id":request.operation_id,"reconciliation":record,"observed_at":request.observed_at,"original_result":"unknown"}),now).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"server_id":request.server_id,"process_stop":"manually_confirmed","original_result":"unknown","original_receipt_preserved":true,"replayed":false}),
    ))
}

pub use super::planning::{
    maintenance, pause_schedule, save_maintenance, save_schedule, schedules,
};

pub(super) async fn authorize_steps(
    state: &AppState,
    headers: &HeaderMap,
    targets: &[i64],
    plan: &Plan,
) -> ApiResult<()> {
    super::typed_steps::authorize(state, headers, plan, false).await?;
    for server in targets {
        for step in &plan.steps {
            if !step.is_panel() {
                control_center::require_server(state, headers, *server, step.permission()).await?;
            }
        }
    }
    Ok(())
}
