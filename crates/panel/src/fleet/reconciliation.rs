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
use sinan_protocol::{fleet::Operation, now_timestamp};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

fn observation(operation: &Operation) -> Operation {
    match operation {
        Operation::FileRead { path }
        | Operation::FileInspect { path }
        | Operation::FileWrite { path, .. }
        | Operation::FileUpload { path, .. } => Operation::FileInspect { path: path.clone() },
        Operation::Service { unit, .. } | Operation::Logs { unit, .. } => Operation::Service {
            unit: unit.clone(),
            action: "status".into(),
        },
        Operation::Snapshot {} => Operation::Snapshot {},
        Operation::Services {} => Operation::Services {},
        Operation::Ports {} => Operation::Ports {},
        Operation::RuntimePermissions { module } => Operation::RuntimePermissions {
            module: module.clone(),
        },
        Operation::SystemNetwork { operation } => {
            let mut operation = operation.clone();
            let action = operation["action"].as_str().unwrap_or("").to_owned();
            operation["action"] = json!(if action.starts_with("mesh_") {
                "mesh_status"
            } else if action.starts_with("tunnel_") {
                "tunnel_status"
            } else if action.starts_with("firewall_") {
                "firewall_status"
            } else {
                "inventory"
            });
            Operation::SystemNetwork { operation }
        }
        Operation::PortForward { operation } => {
            let mut operation = operation.clone();
            operation["action"] = json!("status");
            Operation::PortForward { operation }
        }
        Operation::CertificateDeploy { deployment_id }
        | Operation::CertificateInspect { deployment_id } => Operation::CertificateInspect {
            deployment_id: *deployment_id,
        },
    }
}

pub(super) fn is_read_only(operation: &Operation) -> bool {
    match operation {
        Operation::Snapshot {}
        | Operation::Services {}
        | Operation::Ports {}
        | Operation::RuntimePermissions { .. }
        | Operation::FileRead { .. }
        | Operation::FileInspect { .. }
        | Operation::Logs { .. }
        | Operation::CertificateInspect { .. } => true,
        Operation::Service { action, .. } => action == "status",
        Operation::SystemNetwork { operation } => [
            "inventory",
            "mesh_status",
            "tunnel_status",
            "firewall_status",
        ]
        .contains(&operation["action"].as_str().unwrap_or("")),
        Operation::PortForward { operation } => operation["action"] == "status",
        _ => false,
    }
}
async fn source(state: &AppState, id: Uuid) -> ApiResult<(i64, Operation)> {
    let row = sqlx::query("SELECT server_id,operation FROM fleet_operations WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok((
        row.get("server_id"),
        serde_json::from_value(row.get("operation")).map_err(anyhow::Error::from)?,
    ))
}
pub(crate) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    server: i64,
    operation: &Operation,
) -> ApiResult<i64> {
    let principal = control_center::authenticate(state, headers).await?;
    if principal.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "人工核对需要管理员会话，API 令牌不能提交此操作".into(),
        ));
    }
    let actor = control_center::require_server(state, headers, server, "operations:write").await?;
    control_center::require_server(
        state,
        headers,
        server,
        super::operations::permission(operation),
    )
    .await?;
    control_center::require_server(
        state,
        headers,
        server,
        super::operations::permission(&observation(operation)),
    )
    .await?;
    control_center::require_recent_proof(state, headers).await?;
    Ok(actor)
}

pub(crate) fn permissions(server: i64, operation: &Operation) -> Vec<(Option<i64>, String)> {
    [
        "operations:write",
        super::operations::permission(operation),
        super::operations::permission(&observation(operation)),
    ]
    .into_iter()
    .map(|capability| (Some(server), capability.to_owned()))
    .collect()
}

fn auth_lock<T>(result: Result<T, sqlx::Error>) -> ApiResult<T> {
    result.map_err(|error| {
        if error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("55P03")
        {
            ApiError::Conflict("管理员会话、授权或再次验证正在变更，请刷新后重新核对".into())
        } else {
            error.into()
        }
    })
}

pub(crate) async fn lock_authorization(
    tx: &mut Transaction<'_, Postgres>,
    headers: &HeaderMap,
    actor: i64,
    requirements: &[(Option<i64>, String)],
) -> ApiResult<()> {
    let hash = crate::auth::security::session_hash(headers)?;
    // Pin authorization before job/server locks. NOWAIT avoids a lock cycle
    // with administrator changes or reauthentication taking the reverse order.
    let profile = auth_lock(sqlx::query("SELECT role,all_servers,capabilities FROM administrator_profiles WHERE admin_id=$1 AND enabled FOR SHARE NOWAIT")
        .bind(actor).fetch_optional(&mut **tx).await)?.ok_or(ApiError::Unauthorized)?;
    let now = now_timestamp();
    auth_lock(sqlx::query("SELECT token_hash FROM sessions WHERE token_hash=$1 AND admin_id=$2 AND expires_at>$3 FOR SHARE NOWAIT")
        .bind(&hash).bind(actor).bind(now).fetch_optional(&mut **tx).await)?.ok_or(ApiError::Unauthorized)?;
    auth_lock(sqlx::query("SELECT session_hash FROM administrator_reauth WHERE session_hash=$1 AND expires_at>$2 FOR SHARE NOWAIT")
        .bind(hash).bind(now).fetch_optional(&mut **tx).await)?.ok_or_else(||ApiError::Forbidden("人工核对需要当前管理员会话的有效再次验证".into()))?;
    let role: String = profile.get("role");
    let all_servers: bool = profile.get("all_servers");
    let capabilities: Value = profile.get("capabilities");
    let grants: Vec<i64> =
        sqlx::query_scalar("SELECT server_id FROM administrator_server_grants WHERE admin_id=$1")
            .bind(actor)
            .fetch_all(&mut **tx)
            .await?;
    for (server, capability) in requirements {
        if (role != "owner"
            && !capabilities.as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.as_str() == Some(capability.as_str()))
            }))
            || (role == "viewer" && capability.ends_with(":write"))
            || (!all_servers && server.is_none_or(|server| !grants.contains(&server)))
        {
            return Err(ApiError::Forbidden(
                "管理员已失去此冻结方案或服务器的核对权限".into(),
            ));
        }
    }
    Ok(())
}
async fn unresolved(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: i64,
    expected_job: Option<Uuid>,
) -> ApiResult<sqlx::postgres::PgRow> {
    let row=sqlx::query("SELECT operation,status,expires_at,automation_job_id,reconciliation_of,reconciled_at,dispatched_at FROM fleet_operations WHERE id=$1 AND server_id=$2 FOR UPDATE").bind(id).bind(server).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)?;
    if row.get::<Option<Uuid>, _>("automation_job_id") != expected_job {
        return Err(ApiError::Conflict(
            "此操作属于自动化作业，请在作业证据核对流程处理".into(),
        ));
    }
    if row.get::<Option<i64>, _>("dispatched_at").is_none()
        || row.get::<Option<Uuid>, _>("reconciliation_of").is_some()
        || row.get::<Option<i64>, _>("reconciled_at").is_some()
        || !(row.get::<String, _>("status") == "unknown"
            || (row.get::<String, _>("status") == "dispatched"
                && row.get::<i64, _>("expires_at") <= now_timestamp()))
    {
        return Err(ApiError::Conflict(
            "只有已交付并过期、尚未人工核对的独立未知操作可以处理".into(),
        ));
    }
    Ok(row)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
pub async fn inspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(_input): Json<Empty>,
) -> ApiResult<Json<Value>> {
    let (server, original) = source(&state, id).await?;
    let actor = authorize(&state, &headers, server, &original).await?;
    let mut tx = state.pool.begin().await?;
    let permissions = permissions(server, &original);
    lock_authorization(&mut tx, &headers, actor, &permissions).await?;
    super::ensure_terminal_input_tx(&mut tx, server).await?;
    lock_authorization(&mut tx, &headers, actor, &permissions).await?;
    let response = enqueue_inspection(&mut tx, id, server, actor, None).await?;
    tx.commit().await?;
    Ok(Json(response))
}

pub(crate) async fn enqueue_inspection(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: i64,
    actor: i64,
    expected_job: Option<Uuid>,
) -> ApiResult<Value> {
    let original = unresolved(tx, id, server, expected_job).await?;
    let original: Operation =
        serde_json::from_value(original.get("operation")).map_err(anyhow::Error::from)?;
    let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM fleet_operations WHERE reconciliation_of=$1 AND status IN ('queued','dispatched') AND expires_at>$2)").bind(id).bind(now_timestamp()).fetch_one(&mut **tx).await?;
    if pending {
        return Err(ApiError::Conflict(
            "已有新的只读检查在排队或执行，请等待该检查回执".into(),
        ));
    }
    let operation = observation(&original);
    let policy = super::policy(tx, server).await?;
    let capabilities: Value = sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&mut **tx)
        .await?;
    let required = match &operation {
        Operation::FileInspect { .. } => "fleet:files:transfer:v1",
        Operation::CertificateInspect { .. } => "system:certificate-deploy:v1",
        _ => sinan_protocol::fleet::OPERATIONS_CAPABILITY,
    };
    if !capabilities
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(required)))
    {
        return Err(ApiError::Conflict("Agent 尚未提供此只读核对能力".into()));
    }
    let inspection = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO fleet_operations(id,server_id,operation,policy,requested_by,requested_at,expires_at,status,reconciliation_of) VALUES($1,$2,$3,$4,$5,$6,$7,'queued',$8)").bind(inspection).bind(server).bind(json!(operation)).bind(json!(policy)).bind(actor).bind(now).bind(now+300).bind(id).execute(&mut **tx).await?;
    super::record(
        tx,
        server,
        "operation_inspection_queued",
        json!({"operation_id":id,"inspection_id":inspection,"actor":actor,"read_only":true}),
    )
    .await?;
    Ok(json!({"id":inspection,"status":"queued","reconciliation_of":id,"read_only":true}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conclusion {
    pub(crate) inspection_id: Uuid,
    pub(crate) outcome: String,
    pub(crate) conclusion: String,
    pub(crate) processes_stopped: bool,
    pub(crate) cleanup_confirmed: bool,
}
pub async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Conclusion>,
) -> ApiResult<Json<Value>> {
    let (server, original) = source(&state, id).await?;
    let actor = authorize(&state, &headers, server, &original).await?;
    let mut tx = state.pool.begin().await?;
    let permissions = permissions(server, &original);
    lock_authorization(&mut tx, &headers, actor, &permissions).await?;
    super::ensure_terminal_input_tx(&mut tx, server).await?;
    lock_authorization(&mut tx, &headers, actor, &permissions).await?;
    let record = reconcile_in(&mut tx, id, server, actor, &input, None).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"status":"reconciled","reconciliation":record,"original_receipt_preserved":true,"replayed":false}),
    ))
}

pub(crate) async fn reconcile_in(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: i64,
    actor: i64,
    input: &Conclusion,
    expected_job: Option<Uuid>,
) -> ApiResult<Value> {
    let conclusion = input.conclusion.trim();
    if !["failed", "unknown"].contains(&input.outcome.as_str())
        || !(32..=4096).contains(&conclusion.len())
        || conclusion.contains('\0')
        || !input.processes_stopped
        || !input.cleanup_confirmed
    {
        return Err(ApiError::BadRequest("请写明失败或未知的人工结论、实际核对步骤与依据，并明确确认已停止相关进程和清理临时资源".into()));
    }
    let original = unresolved(tx, id, server, expected_job).await?;
    let check=sqlx::query("SELECT operation,status,result,result_digest,requested_at,dispatched_at FROM fleet_operations WHERE id=$1 AND server_id=$2 AND reconciliation_of=$3 FOR UPDATE").bind(input.inspection_id).bind(server).bind(id).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)?;
    let check_operation: Operation =
        serde_json::from_value(check.get("operation")).map_err(anyhow::Error::from)?;
    let result: Value = check
        .get::<Option<Value>, _>("result")
        .ok_or_else(|| ApiError::Conflict("新的只读检查还没有真实设备回执".into()))?;
    let now = now_timestamp();
    let completed = result["completed_at"]
        .as_i64()
        .ok_or_else(|| ApiError::Conflict("只读证据没有有效采样时间".into()))?;
    if !is_read_only(&check_operation)
        || check.get::<String, _>("status") != "succeeded"
        || result["succeeded"] != true
        || check.get::<Option<String>, _>("result_digest").is_none()
        || check.get::<Option<i64>, _>("dispatched_at").is_none()
        || completed < now - 300
        || completed > now + 60
        || completed < check.get::<i64, _>("requested_at")
        || check.get::<i64, _>("requested_at") < original.get::<i64, _>("expires_at")
    {
        return Err(ApiError::Conflict("只读检查失败、未回报或证据已过期，未知状态继续保留；请重新取得成功的实际观测，不重复原副作用动作".into()));
    }
    let record = json!({"actor":actor,"inspection_id":input.inspection_id,"inspection_completed_at":completed,"inspection_result_digest":check.get::<Option<String>,_>("result_digest"),"conclusion":conclusion,"outcome":input.outcome,"human_process_stop_confirmation":true,"human_cleanup_confirmation":true,"agent_completion_confirmed":false,"recorded_at":now});
    sqlx::query("UPDATE fleet_operations SET reconciled_at=$2,reconciliation=$3 WHERE id=$1")
        .bind(id)
        .bind(now)
        .bind(&record)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE fleet_operations SET reconciled_at=$2,reconciliation=$3 WHERE reconciliation_of=$1 AND status='dispatched' AND expires_at<=$2 AND reconciled_at IS NULL").bind(id).bind(now).bind(json!({"superseded_by":input.inspection_id,"original_receipt_preserved":true,"read_only":true,"actor":actor})).execute(&mut **tx).await?;
    sqlx::query("UPDATE fleet_operations SET status='cancelled' WHERE reconciliation_of=$1 AND status='queued'").bind(id).execute(&mut **tx).await?;
    super::record(
        tx,
        server,
        "operation_manually_reconciled",
        json!({"operation_id":id,"reconciliation":record}),
    )
    .await?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observations_cannot_repeat_the_original_side_effect() {
        let original = Operation::FileUpload {
            path: "/srv/example/data.bin".into(),
            content: "AA==".into(),
            sha256: "0".repeat(64),
            previous_sha256: None,
        };
        assert!(matches!(
            observation(&original),
            Operation::FileInspect { .. }
        ));
        assert!(!is_read_only(&original));
        assert!(
            matches!(observation(&Operation::Service{unit:"example.service".into(),action:"restart".into()}),Operation::Service{action,..}if action=="status")
        );
        assert!(is_read_only(&observation(&Operation::CertificateDeploy {
            deployment_id: Uuid::nil()
        })));
    }
}
