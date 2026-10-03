use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sinan_protocol::{
    RUNTIME_OPERATIONS_CAPABILITY, RuntimeOperation, RuntimeOperationRequest,
    RuntimeOperationResult, now_timestamp,
};
use sqlx::{FromRow, Row};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub operation: RuntimeOperation,
    pub expected_revision: Option<u64>,
}

#[derive(Serialize)]
pub struct OperationView {
    pub spec: RuntimeOperationRequest,
    pub result: Option<RuntimeOperationResult>,
    pub dispatched_at: Option<i64>,
}

#[derive(Serialize)]
pub struct View {
    pub supported: bool,
    pub online: bool,
    pub retiring: bool,
    pub operations: Vec<OperationView>,
}

#[derive(FromRow)]
struct Deployment {
    target_rev: i64,
    applied_rev: i64,
    last_result_rev: i64,
    last_error: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<View>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    super::business::lock_server(&mut tx, server).await?;
    super::settings::require_enabled(&mut tx, server).await?;
    let row = sqlx::query("SELECT capabilities,last_seen,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) AS retiring FROM servers WHERE id=$1").bind(server).fetch_one(&mut *tx).await?;
    let capabilities: Value = row.get("capabilities");
    let supported = capabilities
        .as_array()
        .is_some_and(|caps| caps.iter().any(|cap| cap == RUNTIME_OPERATIONS_CAPABILITY));
    let rows = sqlx::query("SELECT spec,result,dispatched_at FROM runtime_operations WHERE server_id=$1 AND module='singbox' ORDER BY requested_at DESC,id DESC LIMIT 20").bind(server).fetch_all(&mut *tx).await?;
    let operations = rows
        .into_iter()
        .map(|row| {
            Ok(OperationView {
                spec: serde_json::from_value(row.get("spec"))?,
                result: row
                    .get::<Option<Value>, _>("result")
                    .map(serde_json::from_value)
                    .transpose()?,
                dispatched_at: row.get("dispatched_at"),
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()
        .map_err(anyhow::Error::from)?;
    tx.commit().await?;
    Ok(Json(View {
        supported,
        online: row
            .get::<Option<i64>, _>("last_seen")
            .is_some_and(|at| now_timestamp().saturating_sub(at) <= 60),
        retiring: row.get("retiring"),
        operations,
    }))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(body): Json<Create>,
) -> ApiResult<Json<RuntimeOperationRequest>> {
    auth::require_admin(&state, &headers).await?;
    let now = now_timestamp();
    let request = RuntimeOperationRequest {
        id: Uuid::new_v4(),
        module: "singbox".into(),
        operation: body.operation,
        expected_revision: body.expected_revision,
        requested_at: now,
        expires_at: now + 600,
    };
    if !request.valid() {
        return Err(ApiError::BadRequest("运行时操作或期望版本无效".into()));
    }
    let mut tx = state.pool.begin().await?;
    super::business::lock_server(&mut tx, server).await?;
    super::settings::require_enabled(&mut tx, server).await?;
    crate::fleet::ensure_accepts_tasks_tx(&mut tx, server).await?;
    let row = sqlx::query("SELECT capabilities,last_seen,dirty_at,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) AS retiring FROM servers WHERE id=$1").bind(server).fetch_one(&mut *tx).await?;
    let capabilities: Value = row.get("capabilities");
    if !capabilities
        .as_array()
        .is_some_and(|caps| caps.iter().any(|cap| cap == RUNTIME_OPERATIONS_CAPABILITY))
    {
        return Err(ApiError::Conflict(
            "Agent 尚不支持运行时运维，请先升级 Agent".into(),
        ));
    }
    if row.get::<bool, _>("retiring") {
        return Err(ApiError::Conflict(
            "服务器正在退役，不能执行运行时操作".into(),
        ));
    }
    if !row
        .get::<Option<i64>, _>("last_seen")
        .is_some_and(|at| now.saturating_sub(at) <= 60)
    {
        return Err(ApiError::Conflict(
            "设备离线，恢复连接后再执行运行时操作".into(),
        ));
    }
    let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND module='singbox' AND result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL)").bind(server).fetch_one(&mut *tx).await?;
    if busy {
        return Err(ApiError::Conflict(
            "已有运行时操作等待确认，请等待设备回报".into(),
        ));
    }
    let latest: Option<i64> =
        sqlx::query_scalar("SELECT MAX(requested_at) FROM runtime_operations WHERE server_id=$1")
            .bind(server)
            .fetch_one(&mut *tx)
            .await?;
    if latest.is_some_and(|at| now.saturating_sub(at) < 10) {
        return Err(ApiError::Busy);
    }
    if request.operation != RuntimeOperation::Inspect {
        let deployment: Deployment = sqlx::query_as("SELECT target_rev,applied_rev,last_result_rev,last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'").bind(server).fetch_optional(&mut *tx).await?.ok_or_else(|| ApiError::Conflict("尚无可操作的运行时部署".into()))?;
        if row.get::<Option<i64>, _>("dirty_at").is_some()
            || request.expected_revision != u64::try_from(deployment.target_rev).ok()
        {
            return Err(ApiError::Conflict(
                "期望版本已改变或正在发布，请刷新后重试".into(),
            ));
        }
        match request.operation {
            RuntimeOperation::Restart if deployment.applied_rev != deployment.target_rev => {
                return Err(ApiError::Conflict("目标版本尚未应用，请先完成部署".into()));
            }
            RuntimeOperation::RetryDeployment
                if deployment.last_result_rev != deployment.target_rev
                    || deployment.last_error.is_none() =>
            {
                return Err(ApiError::Conflict("当前期望版本没有失败部署可重试".into()));
            }
            _ => {}
        }
    }
    sqlx::query("INSERT INTO runtime_operations(id,server_id,module,requested_at,spec) VALUES($1,$2,'singbox',$3,$4)").bind(request.id).bind(server).bind(now).bind(serde_json::to_value(&request).map_err(anyhow::Error::from)?).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM runtime_operations WHERE server_id=$1 AND automation_job_id IS NULL AND result IS NOT NULL AND id NOT IN (SELECT id FROM runtime_operations WHERE server_id=$1 ORDER BY requested_at DESC,id DESC LIMIT 100)").bind(server).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(request))
}
