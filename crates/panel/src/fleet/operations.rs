use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::{
    fleet::{Job, JobResult, OPERATIONS_CAPABILITY, Operation, Work},
    now_timestamp,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

fn restrict_policy(
    mut original: sinan_protocol::fleet::AccessPolicy,
    current: &sinan_protocol::fleet::AccessPolicy,
) -> sinan_protocol::fleet::AccessPolicy {
    original
        .terminal_accounts
        .retain(|account| current.terminal_accounts.contains(account));
    original
        .services
        .retain(|unit| current.services.contains(unit));
    fn directories(original: &[String], current: &[String]) -> Vec<String> {
        let mut result = std::collections::BTreeSet::new();
        for left in original {
            for right in current {
                if std::path::Path::new(left).starts_with(right) {
                    result.insert(left.clone());
                } else if std::path::Path::new(right).starts_with(left) {
                    result.insert(right.clone());
                }
            }
        }
        result.into_iter().collect()
    }
    original.read_directories = directories(&original.read_directories, &current.read_directories);
    original.write_directories =
        directories(&original.write_directories, &current.write_directories);
    original.maximum_file_bytes = original.maximum_file_bytes.min(current.maximum_file_bytes);
    original.system_network &= current.system_network;
    original.port_forward &= current.port_forward;
    original.private_mesh &= current.private_mesh;
    original.reverse_tunnel &= current.reverse_tunnel;
    original.firewall &= current.firewall;
    original.certificate_deploy &= current.certificate_deploy;
    original.runtime_inspection &= current.runtime_inspection;
    original
}

pub(super) fn permission(operation: &Operation) -> &'static str {
    match operation {
        Operation::Snapshot {} => "operations:read",
        Operation::RuntimePermissions { .. } => "operations:read",
        Operation::Services {} => "services:read",
        Operation::Service { action, .. } => {
            if action == "status" {
                "services:read"
            } else {
                "services:write"
            }
        }
        Operation::Logs { .. } => "services:read",
        Operation::Ports {} => "monitoring:read",
        Operation::FileRead { .. } | Operation::FileInspect { .. } => "files:read",
        Operation::FileWrite { .. } | Operation::FileUpload { .. } => "files:write",
        Operation::SystemNetwork { operation } => {
            if [
                "inventory",
                "mesh_status",
                "tunnel_status",
                "firewall_status",
            ]
            .contains(&operation["action"].as_str().unwrap_or(""))
            {
                "network:read"
            } else {
                "network:write"
            }
        }
        Operation::PortForward { operation } => {
            if operation["action"] == "status" {
                "network:read"
            } else {
                "network:write"
            }
        }
        Operation::CertificateDeploy { .. } => "network:write",
        Operation::CertificateInspect { .. } => "network:read",
    }
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(operation): Json<Operation>,
) -> ApiResult<Json<Value>> {
    let principal = crate::control_center::authenticate(&state, &headers).await?;
    if principal.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "此异步设备操作需要管理员会话，API 令牌不支持延迟执行授权".into(),
        ));
    }
    let actor =
        crate::control_center::require_server(&state, &headers, id, permission(&operation)).await?;
    let high_risk = match &operation {
        Operation::FileWrite { .. } | Operation::FileUpload { .. } => true,
        Operation::Service { action, .. } => action != "status",
        Operation::SystemNetwork { operation } => ![
            "inventory",
            "mesh_status",
            "tunnel_status",
            "firewall_status",
        ]
        .contains(&operation["action"].as_str().unwrap_or("")),
        Operation::PortForward { operation } => operation["action"] != "status",
        Operation::CertificateDeploy { .. } => true,
        _ => false,
    };
    if high_risk {
        crate::control_center::require_recent_proof(&state, &headers).await?;
    }
    Ok(Json(
        json!({"id":enqueue_for_actor(&state,id,actor,operation).await?,"status":"queued"}),
    ))
}
pub(crate) async fn enqueue_for_actor(
    state: &AppState,
    id: i64,
    actor: i64,
    operation: Operation,
) -> ApiResult<Uuid> {
    let mut tx = state.pool.begin().await?;
    let result = enqueue_tx(&mut tx, id, None, Some(actor), operation).await?;
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn enqueue_readonly_for_actor_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    actor: i64,
    operation: Operation,
) -> ApiResult<Uuid> {
    if !matches!(
        operation,
        Operation::Ports {} | Operation::RuntimePermissions { .. }
    ) {
        return Err(ApiError::BadRequest(
            "此预检入口只接受端口或运行时权限只读观察".into(),
        ));
    }
    enqueue_tx(tx, id, None, Some(actor), operation).await
}
pub(crate) async fn enqueue_automation_tx(
    _state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    job_id: Uuid,
    operation: Operation,
) -> ApiResult<Uuid> {
    let actor: i64 = sqlx::query_scalar("SELECT requested_by FROM operations_jobs WHERE id=$1")
        .bind(job_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    enqueue_tx(tx, id, Some(job_id), Some(actor), operation).await
}
async fn enqueue_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    automation: Option<Uuid>,
    actor: Option<i64>,
    operation: Operation,
) -> ApiResult<Uuid> {
    if let Some(job_id) = automation {
        sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(ApiError::NotFound)?;
        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND (lifecycle IN ('draining','retired') OR (lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$3 AND (maintenance_until IS NULL OR maintenance_until>$3)))) OR EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) OR NOT EXISTS(SELECT 1 FROM operations_server_locks WHERE server_id=$1 AND job_id=$2) OR EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND block_new_tasks AND starts_at<=$3 AND ends_at>$3)")
            .bind(id).bind(job_id).bind(now_timestamp()).fetch_one(&mut **tx).await?;
        if blocked {
            return Err(ApiError::Conflict(
                "自动化锁已变化，或服务器正在维护/退役".into(),
            ));
        }
    } else {
        super::ensure_accepts_fleet_tasks_tx(tx, id).await?;
    }
    let conflicting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_commands WHERE server_id=$1 AND (state IN ('claimed','running','cancel_requested') OR (state='queued' AND (spec->>'expires_at')::BIGINT>$2))) OR EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND (status IN ('queued','running','cleaning','cancel_requested') OR (NOT agent_completed AND job ? 'id'))) OR EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND result IS NULL AND reconciled_at IS NULL AND dispatched_at IS NOT NULL)").bind(id).bind(now_timestamp()).fetch_one(&mut **tx).await?;
    if conflicting {
        return Err(ApiError::Conflict(
            "设备尚有命令、诊断清理或已交付运行时操作；待确认完成后再提交日常操作".into(),
        ));
    }
    let capabilities: Value = sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1")
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    if !capabilities.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| value.as_str() == Some(OPERATIONS_CAPABILITY))
    }) {
        return Err(ApiError::Conflict(
            "Agent 尚未提供独立日常运维能力，请先升级并在本机授权".into(),
        ));
    }
    let policy = super::policy(tx, id).await?;
    match &operation {
        Operation::RuntimePermissions { module } => {
            if module.is_empty()
                || module.len() > 64
                || !module
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(ApiError::BadRequest("运行时模块标识无效".into()));
            }
            if !policy.runtime_inspection
                || !capabilities.as_array().is_some_and(|items| {
                    items.iter().any(|item| {
                        item.as_str() == Some(sinan_protocol::fleet::RUNTIME_PREFLIGHT_CAPABILITY)
                    })
                })
            {
                return Err(ApiError::Conflict(
                    "运行时只读预检未获本机与面板授权，或 Agent 尚未提供能力".into(),
                ));
            }
        }
        Operation::FileRead { path }
        | Operation::FileInspect { path }
        | Operation::FileUpload { path, .. }
        | Operation::FileWrite { path, .. }
            if path.len() > 4096 || !path.starts_with('/') || path.contains('\0') =>
        {
            return Err(ApiError::BadRequest("文件路径无效".into()));
        }
        Operation::FileUpload {
            content,
            sha256,
            previous_sha256,
            ..
        } => {
            let bytes = STANDARD
                .decode(content)
                .map_err(|_| ApiError::BadRequest("上传内容编码无效".into()))?;
            if policy.maximum_file_bytes == 0
                || bytes.len() > policy.maximum_file_bytes.min(256 * 1024)
                || format!("{:x}", Sha256::digest(&bytes)) != *sha256
                || previous_sha256.as_ref().is_some_and(|hash| {
                    hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err(ApiError::BadRequest(
                    "上传大小、完整性或旧文件校验值无效".into(),
                ));
            }
            if !capabilities.as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.as_str() == Some("fleet:files:transfer:v1"))
            }) {
                return Err(ApiError::Conflict(
                    "Agent 尚未提供受限二进制上传和新文件创建能力".into(),
                ));
            }
        }
        Operation::FileWrite {
            content,
            sha256,
            previous_sha256,
            syntax,
            ..
        } => {
            let bytes = STANDARD
                .decode(content)
                .map_err(|_| ApiError::BadRequest("文件内容编码无效".into()))?;
            if bytes.len() > policy.maximum_file_bytes.min(256 * 1024)
                || format!("{:x}", Sha256::digest(&bytes)) != *sha256
                || previous_sha256.len() != 64
                || !["json", "toml", "text"].contains(&syntax.as_str())
            {
                return Err(ApiError::BadRequest(
                    "大小、完整性、旧版本或语法模式无效".into(),
                ));
            }
        }
        Operation::Service { unit, action } => {
            if !policy.services.contains(unit)
                || !["status", "start", "stop", "restart", "enable", "disable"]
                    .contains(&action.as_str())
            {
                return Err(ApiError::BadRequest("服务或操作不在授权范围内".into()));
            }
        }
        Operation::Logs {
            unit,
            search,
            priority,
            ..
        } => {
            if !policy.services.contains(unit)
                || search.len() > 256
                || priority.is_some_and(|v| v > 7)
            {
                return Err(ApiError::BadRequest("日志筛选无效或服务未授权".into()));
            }
        }
        Operation::SystemNetwork { operation } => {
            let action = operation["action"].as_str().unwrap_or("");
            let granted = if action.starts_with("mesh_") {
                policy.private_mesh
            } else if action.starts_with("tunnel_") {
                policy.reverse_tunnel
            } else if action.starts_with("firewall_") {
                policy.firewall
            } else {
                action == "inventory" || policy.system_network
            };
            if !granted {
                return Err(ApiError::Conflict("所请求的网络能力未获授权".into()));
            }
        }
        Operation::PortForward { .. } if !policy.port_forward => {
            return Err(ApiError::Conflict("端口转发未授权".into()));
        }
        Operation::CertificateDeploy { .. } | Operation::CertificateInspect { .. }
            if !policy.certificate_deploy
                || !capabilities.as_array().is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item.as_str() == Some("system:certificate-deploy:v1"))
                }) =>
        {
            return Err(ApiError::Conflict(
                "证书部署未获本机与面板授权或 Agent 未提供此能力".into(),
            ));
        }
        _ => {}
    }
    let outstanding:i64=sqlx::query_scalar("SELECT count(*) FROM fleet_operations WHERE server_id=$1 AND status IN ('queued','dispatched','unknown') AND reconciled_at IS NULL").bind(id).fetch_one(&mut **tx).await?;
    if outstanding >= 16 {
        return Err(ApiError::Conflict(
            "服务器尚有未完成或未知结果操作，请先核对".into(),
        ));
    }
    let operation_id = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO fleet_operations(id,server_id,operation,policy,requested_at,expires_at,automation_job_id,requested_by,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'queued')")
        .bind(operation_id).bind(id).bind(json!(operation)).bind(json!(policy)).bind(now).bind(now+300).bind(automation).bind(actor).execute(&mut **tx).await?;
    let mut detail = json!({"id":operation_id,"operation":operation});
    if let Some(content) = detail["operation"].as_object_mut() {
        content.remove("content");
    }
    super::record(tx, id, "operation_queued", detail).await?;
    Ok(operation_id)
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<Value>>> {
    crate::control_center::require_server(&state, &headers, id, "operations:read").await?;
    let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'operation',operation-'content','requested_at',requested_at,'expires_at',expires_at,'status',CASE WHEN reconciled_at IS NOT NULL AND status IN ('dispatched','unknown') THEN 'reconciled' WHEN status='dispatched' AND expires_at<$2 THEN 'unknown' ELSE status END,'reconciled_at',reconciled_at,'reconciliation',reconciliation,'reconciliation_of',reconciliation_of,'result',NULL) FROM fleet_operations WHERE server_id=$1 ORDER BY requested_at DESC,id LIMIT 100")
        .bind(id).bind(now_timestamp()).fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

pub async fn work(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Work>> {
    let id = auth::require_agent(&state, &headers).await?;
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE fleet_operations SET status='expired' WHERE server_id=$1 AND status='queued' AND expires_at<=$2").bind(id).bind(now).execute(&mut *tx).await?;
    let lifecycle_blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND (lifecycle IN ('draining','retired') OR (lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$2 AND (maintenance_until IS NULL OR maintenance_until>$2)))) OR EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) OR EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND block_new_tasks AND starts_at<=$2 AND ends_at>$2)").bind(id).bind(now).fetch_one(&mut *tx).await?;
    let conflicting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_commands WHERE server_id=$1 AND (state IN ('claimed','running','cancel_requested') OR (state='queued' AND (spec->>'expires_at')::BIGINT>$2))) OR EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND (status IN ('queued','running','cleaning','cancel_requested') OR (NOT agent_completed AND job ? 'id'))) OR EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND result IS NULL AND reconciled_at IS NULL AND dispatched_at IS NOT NULL)").bind(id).bind(now).fetch_one(&mut *tx).await?;
    let allowed = !lifecycle_blocked && !conflicting;
    let rows = if allowed {
        sqlx::query("UPDATE fleet_operations SET status='dispatched',dispatched_at=$2 WHERE id IN (SELECT f.id FROM fleet_operations f WHERE f.server_id=$1 AND f.status='queued' AND NOT EXISTS(SELECT 1 FROM fleet_operations running WHERE running.server_id=$1 AND running.status IN ('dispatched','unknown') AND running.reconciled_at IS NULL AND (f.reconciliation_of IS NULL OR (running.id<>f.reconciliation_of AND (running.reconciliation_of IS NULL OR running.expires_at>$2)))) AND (NOT EXISTS(SELECT 1 FROM operations_server_locks l WHERE l.server_id=$1) OR EXISTS(SELECT 1 FROM operations_server_locks l WHERE l.server_id=$1 AND l.job_id=f.automation_job_id) OR EXISTS(SELECT 1 FROM operations_server_locks l JOIN fleet_operations original ON original.id=f.reconciliation_of AND original.server_id=l.server_id WHERE l.server_id=$1 AND l.job_id=original.automation_job_id)) ORDER BY f.requested_at,f.id LIMIT 1) RETURNING id,operation,policy,expires_at,requested_by,automation_job_id,reconciliation_of").bind(id).bind(now).fetch_all(&mut *tx).await?
    } else {
        Vec::new()
    };
    let mut jobs = Vec::new();
    let current_policy = super::policy(&mut tx, id).await?;
    for row in rows {
        let operation: Operation =
            serde_json::from_value(row.get("operation")).map_err(anyhow::Error::from)?;
        if let Some(job) = row.get::<Option<Uuid>, _>("automation_job_id") {
            let parent = sqlx::query("SELECT requested_by,status FROM operations_jobs WHERE id=$1")
                .bind(job)
                .fetch_optional(&mut *tx)
                .await?;
            let parent_allowed = if let Some(parent) = parent {
                parent.get::<String, _>("status") == "running"
                    && crate::control_center::actor_server_allowed(
                        &state.pool,
                        parent.get("requested_by"),
                        id,
                        "operations:write",
                    )
                    .await?
            } else {
                false
            };
            if !parent_allowed {
                sqlx::query("UPDATE fleet_operations SET status='cancelled' WHERE id=$1")
                    .bind(row.get::<Uuid, _>("id"))
                    .execute(&mut *tx)
                    .await?;
                continue;
            }
        }
        if let Some(actor) = row.get::<Option<i64>, _>("requested_by")
            && !crate::control_center::actor_server_allowed(
                &state.pool,
                actor,
                id,
                permission(&operation),
            )
            .await?
        {
            sqlx::query("UPDATE fleet_operations SET status='cancelled' WHERE id=$1")
                .bind(row.get::<Uuid, _>("id"))
                .execute(&mut *tx)
                .await?;
            continue;
        }
        if let Some(original) = row.get::<Option<Uuid>, _>("reconciliation_of") {
            let source = sqlx::query(
                "SELECT operation,reconciled_at FROM fleet_operations WHERE id=$1 AND server_id=$2",
            )
            .bind(original)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
            let source_operation: Operation =
                serde_json::from_value(source.get("operation")).map_err(anyhow::Error::from)?;
            let authorized = if let Some(actor) = row.get::<Option<i64>, _>("requested_by") {
                crate::control_center::actor_server_allowed(
                    &state.pool,
                    actor,
                    id,
                    "operations:write",
                )
                .await?
                    && crate::control_center::actor_server_allowed(
                        &state.pool,
                        actor,
                        id,
                        permission(&source_operation),
                    )
                    .await?
            } else {
                false
            };
            if !authorized || source.get::<Option<i64>, _>("reconciled_at").is_some() {
                sqlx::query("UPDATE fleet_operations SET status='cancelled' WHERE id=$1")
                    .bind(row.get::<Uuid, _>("id"))
                    .execute(&mut *tx)
                    .await?;
                continue;
            }
        }
        jobs.push(Job {
            id: row.get("id"),
            operation,
            policy: restrict_policy(
                serde_json::from_value(row.get("policy")).map_err(anyhow::Error::from)?,
                &current_policy,
            ),
            expires_at: row.get("expires_at"),
        });
    }
    let terminals = super::terminal::controls(&state, &mut tx, id, !lifecycle_blocked).await?;
    tx.commit().await?;
    Ok(Json(Work { jobs, terminals }))
}

pub async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(result): Json<JobResult>,
) -> ApiResult<Json<Value>> {
    let id = auth::require_agent(&state, &headers).await?;
    let encoded = serde_json::to_vec(&result).map_err(anyhow::Error::from)?;
    if encoded.len() > 768 * 1024 || result.completed_at > now_timestamp() + 60 {
        return Err(ApiError::BadRequest("操作结果大小或时间无效".into()));
    }
    let digest = format!("{:x}", Sha256::digest(encoded));
    let mut tx = state.pool.begin().await?;
    let row=sqlx::query("SELECT operation,status,result_digest,dispatched_at,requested_at FROM fleet_operations WHERE id=$1 AND server_id=$2 FOR UPDATE").bind(result.id).bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    if let Some(previous) = row.get::<Option<String>, _>("result_digest") {
        if previous != digest {
            return Err(ApiError::Conflict("已完成结果不可修改".into()));
        }
    } else {
        if !["dispatched", "unknown"].contains(&row.get::<String, _>("status").as_str())
            || row.get::<Option<i64>, _>("dispatched_at").is_none()
        {
            return Err(ApiError::Conflict("操作尚未交付设备".into()));
        }
        sqlx::query("UPDATE fleet_operations SET status=$2,result=$3,result_digest=$4 WHERE id=$1")
            .bind(result.id)
            .bind(if result.succeeded {
                "succeeded"
            } else {
                "failed"
            })
            .bind(json!(result))
            .bind(digest)
            .execute(&mut *tx)
            .await?;
        let operation: Operation =
            serde_json::from_value(row.get("operation")).map_err(anyhow::Error::from)?;
        super::monitoring::observe_service_result(&mut tx, id, &operation, &result).await?;
        if result.succeeded
            && let Operation::FileWrite {
                path,
                content,
                sha256,
                previous_sha256,
                ..
            } = operation
        {
            if STANDARD
                .decode(&content)
                .is_ok_and(|bytes| format!("{:x}", Sha256::digest(bytes)) == sha256)
            {
                sqlx::query("INSERT INTO fleet_config_history(id,server_id,path,operation_id,previous_sha256,sha256,content,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                    .bind(Uuid::new_v4()).bind(id).bind(path).bind(result.id).bind(previous_sha256).bind(sha256).bind(content).bind(result.completed_at).execute(&mut *tx).await?;
            } else {
                super::record(
                    &mut tx,
                    id,
                    "config_history_payload_unavailable",
                    json!({"operation_id":result.id,"reason":"retention_or_payload_mismatch"}),
                )
                .await?;
            }
        }
        super::record(
            &mut tx,
            id,
            "operation_completed",
            json!({"id":result.id,"succeeded":result.succeeded,"error":result.error}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"acknowledged":result.id})))
}

pub async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<Value>>> {
    crate::control_center::require_server(&state, &headers, id, "files:read").await?;
    let rows=sqlx::query_scalar("SELECT to_jsonb(h)-'content'-'server_id' FROM fleet_config_history h WHERE server_id=$1 ORDER BY created_at DESC LIMIT 100").bind(id).fetch_all(&state.pool).await?;
    Ok(Json(rows))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(operation_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let row=sqlx::query("SELECT server_id,operation,reconciliation_of,CASE WHEN reconciled_at IS NOT NULL AND status IN ('dispatched','unknown') THEN 'reconciled' WHEN status='dispatched' AND expires_at<$2 THEN 'unknown' ELSE status END AS status,result,reconciliation FROM fleet_operations WHERE id=$1").bind(operation_id).bind(now_timestamp()).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let operation: Operation =
        serde_json::from_value(row.get("operation")).map_err(anyhow::Error::from)?;
    crate::control_center::require_server(
        &state,
        &headers,
        row.get("server_id"),
        permission(&operation),
    )
    .await?;
    Ok(Json(
        json!({"id":operation_id,"server_id":row.get::<i64,_>("server_id"),"reconciliation_of":row.get::<Option<Uuid>,_>("reconciliation_of"),"status":row.get::<String,_>("status"),"result":row.get::<Option<Value>,_>("result"),"reconciliation":row.get::<Option<Value>,_>("reconciliation")}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sinan_protocol::fleet::AccessPolicy;
    #[test]
    fn dispatch_policy_cannot_expand_a_queued_grant() {
        let previous = AccessPolicy {
            read_directories: vec!["/srv/example".into()],
            services: vec!["example.service".into()],
            maximum_file_bytes: 4096,
            certificate_deploy: true,
            ..AccessPolicy::default()
        };
        let current = AccessPolicy {
            read_directories: vec!["/srv/example/config".into()],
            services: vec!["different.service".into()],
            maximum_file_bytes: 1024,
            ..AccessPolicy::default()
        };
        let effective = restrict_policy(previous, &current);
        assert_eq!(effective.read_directories, vec!["/srv/example/config"]);
        assert!(effective.services.is_empty());
        assert_eq!(effective.maximum_file_bytes, 1024);
        assert!(!effective.certificate_deploy);
    }
}
