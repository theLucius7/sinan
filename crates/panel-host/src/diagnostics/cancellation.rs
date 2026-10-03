use super::*;
use sinan_protocol::{DiagnosticCancelRequest, DiagnosticCancelResult, Envelope};

pub(super) fn supported(capabilities: &Value) -> bool {
    capabilities.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| value.as_str() == Some(sinan_protocol::DIAGNOSTIC_CANCEL_CAPABILITY))
    })
}

pub async fn request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((server_id, id)): Path<(i64, Uuid)>,
) -> ApiResult<(StatusCode, Json<ReportRecord>)> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let capabilities: Value = sqlx::query_scalar(
        "SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let row = sqlx::query("SELECT status,job,agent_completed FROM diagnostic_jobs WHERE id=$1 AND server_id=$2 FOR UPDATE")
        .bind(id).bind(server_id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let status: String = row.get("status");
    if status == "cancelled" {
        let record = sqlx::query_as(RECORD_QUERY)
            .bind(id)
            .bind(server_id)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok((StatusCode::OK, Json(record)));
    }
    if !supported(&capabilities) {
        return Err(ApiError::Conflict(
            "此 Agent 或服务后端不支持确认式取消，请先升级到支持清理确认的 Agent".into(),
        ));
    }
    if row.get::<bool, _>("agent_completed") && status != "cancel_requested" {
        return Err(ApiError::Conflict(
            "任务已由设备完成，不能再请求取消".into(),
        ));
    }
    let job = saved_job(row.get("job"), id)?;
    if job.id != id {
        return Err(ApiError::Conflict("任务记录编号不一致，拒绝取消".into()));
    }
    sqlx::query("UPDATE diagnostic_jobs SET status='cancel_requested',cancel_requested_at=COALESCE(cancel_requested_at,$3),updated_at=$3 WHERE id=$1 AND server_id=$2")
        .bind(id).bind(server_id).bind(now_timestamp()).execute(&mut *tx).await?;
    let record = sqlx::query_as(RECORD_QUERY)
        .bind(id)
        .bind(server_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    crate::agent_api::notify(
        &state,
        server_id,
        Envelope::new(
            "diagnostic.cancel.request",
            DiagnosticCancelRequest { server_id, job },
        )
        .map_err(anyhow::Error::from)?,
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(record)))
}

pub async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<DiagnosticCancelRequest>>> {
    let server_id = auth::require_agent(&state, &headers).await?;
    let jobs: Vec<(Uuid, Value)> = sqlx::query_as("SELECT id,job FROM diagnostic_jobs WHERE server_id=$1 AND status='cancel_requested' ORDER BY cancel_requested_at,id LIMIT 64")
        .bind(server_id).fetch_all(&state.pool).await?;
    let requests = jobs
        .into_iter()
        .map(|(id, job)| saved_job(job, id).map(|job| DiagnosticCancelRequest { server_id, job }))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(requests))
}

pub async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(result): Json<DiagnosticCancelResult>,
) -> ApiResult<StatusCode> {
    let server_id = auth::require_agent(&state, &headers).await?;
    if id != result.id {
        return Err(ApiError::BadRequest("任务编号不一致".into()));
    }
    record_result(&state, server_id, result).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn record_result(
    state: &AppState,
    server_id: i64,
    result: DiagnosticCancelResult,
) -> ApiResult<()> {
    if result.server_id != server_id || (result.confirmed && result.error.is_some()) {
        return Err(ApiError::BadRequest("取消确认的设备或状态不一致".into()));
    }
    if let Some(report) = &result.report {
        validate_report(report)?;
    }
    let mut tx = state.pool.begin().await?;
    let _: i64 = sqlx::query_scalar("SELECT id FROM servers WHERE id=$1 FOR UPDATE")
        .bind(server_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT status,job FROM diagnostic_jobs WHERE id=$1 AND server_id=$2 FOR UPDATE",
    )
    .bind(result.id)
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if let Some(report) = &result.report {
        super::service::validate_plugin_report(&row.get::<Value, _>("job"), report)?;
    }
    let job = saved_job(row.get("job"), result.id)?;
    if job.id != result.id || job.plugin != result.plugin {
        return Err(ApiError::BadRequest(
            "取消确认与已知任务或插件不一致".into(),
        ));
    }
    let status: String = row.get("status");
    if status == "cancelled" {
        tx.commit().await?;
        return Ok(());
    }
    if status != "cancel_requested" {
        return Err(ApiError::Conflict("任务没有待确认的取消请求".into()));
    }
    let report = result
        .report
        .map(serde_json::to_value)
        .transpose()
        .map_err(anyhow::Error::from)?;
    if result.confirmed {
        sqlx::query("UPDATE diagnostic_jobs SET status='cancelled',cancel_confirmed_at=$2,cancel_error=NULL,error=NULL,agent_completed=TRUE,report=COALESCE(report,$3),report_completeness=CASE WHEN cardinality(expected_sections)=0 AND COALESCE(report,$3) IS NOT NULL THEN 'legacy' ELSE report_completeness END,updated_at=$2 WHERE id=$1")
            .bind(result.id).bind(now_timestamp()).bind(report).execute(&mut *tx).await?;
    } else {
        let error: String = result
            .error
            .unwrap_or_else(|| "设备尚未确认进程和挂载已清理，将继续重试".into())
            .chars()
            .take(4096)
            .collect();
        sqlx::query("UPDATE diagnostic_jobs SET cancel_error=$2,report=COALESCE($3,report),report_completeness=CASE WHEN cardinality(expected_sections)=0 AND COALESCE($3,report) IS NOT NULL THEN 'legacy' ELSE report_completeness END,updated_at=$4 WHERE id=$1")
            .bind(result.id).bind(error).bind(report).bind(now_timestamp()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
