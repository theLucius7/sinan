use crate::{
    AppState, artifacts, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Serialize;
use serde_json::Value;
use sinan_protocol::{
    DiagnosticJob, DiagnosticReport, DiagnosticSectionUpdate, DiagnosticStatus, DiagnosticUpdate,
    now_timestamp,
};
use sqlx::{FromRow, Row};
use uuid::Uuid;

pub const REPORT_LIMIT: usize = 512 * 1024;
pub mod service;
pub use crate::diagnostic_plugins::nodequality::{
    LegacyNodeQualityView, NodeQualityView, PLUGIN_VERSION, ReportRequest, create, get, legacy_get,
    safe_report_url,
};
mod sections;
pub(super) const HISTORY_QUERY: &str = "SELECT j.id,j.status,j.job,j.report,j.error,j.created_at,j.updated_at,j.expires_at,j.agent_completed,(j.status IN ('queued','running','cleaning','cancel_requested') OR (NOT j.agent_completed AND j.job ? 'id')) AS cleanup_pending,j.cancel_requested_at,j.cancel_error,j.expected_sections,j.report_completeness,COALESCE((SELECT jsonb_agg(jsonb_build_object('name',s.name,'text',s.text,'complete',s.complete,'revision',s.revision,'collected_at',s.collected_at) ORDER BY array_position(j.expected_sections,s.name),s.name) FROM diagnostic_report_sections s WHERE s.job_id=j.id),'[]'::jsonb) AS sections FROM diagnostic_jobs j WHERE j.server_id=$1 ORDER BY cleanup_pending DESC,j.created_at DESC,j.id DESC LIMIT 10";
pub(super) const RECORD_QUERY: &str = "SELECT j.id,j.status,j.job,j.report,j.error,j.created_at,j.updated_at,j.expires_at,j.agent_completed,(j.status IN ('queued','running','cleaning','cancel_requested') OR (NOT j.agent_completed AND j.job ? 'id')) AS cleanup_pending,j.cancel_requested_at,j.cancel_error,j.expected_sections,j.report_completeness,COALESCE((SELECT jsonb_agg(jsonb_build_object('name',s.name,'text',s.text,'complete',s.complete,'revision',s.revision,'collected_at',s.collected_at) ORDER BY array_position(j.expected_sections,s.name),s.name) FROM diagnostic_report_sections s WHERE s.job_id=j.id),'[]'::jsonb) AS sections FROM diagnostic_jobs j WHERE j.id=$1 AND j.server_id=$2";
pub(super) const UNRESOLVED_QUERY: &str = "SELECT EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND ($2::uuid IS NULL OR id<>$2) AND (status IN ('queued','running','cleaning','cancel_requested') OR (NOT agent_completed AND job ? 'id')))";

pub(super) fn saved_job(mut job: Value, expected: Uuid) -> ApiResult<DiagnosticJob> {
    if let Some(object) = job.as_object_mut()
        && object.get("plugin").is_none_or(Value::is_null)
    {
        // Normalize only the wire task; retain the exact historical JSON.
        object.insert("plugin".into(), Value::String("nodequality".into()));
    }
    let job: DiagnosticJob = serde_json::from_value(job)
        .map_err(|_| ApiError::Conflict("任务记录无效，拒绝执行设备操作".into()))?;
    if job.id != expected {
        return Err(ApiError::Conflict(
            "任务记录编号不一致，拒绝执行设备操作".into(),
        ));
    }
    Ok(job)
}

pub mod cancellation;

#[derive(Serialize, FromRow)]
pub struct ReportRecord {
    pub id: Uuid,
    pub status: String,
    pub job: Value,
    pub report: Option<Value>,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub agent_completed: bool,
    pub cleanup_pending: bool,
    pub cancel_requested_at: Option<i64>,
    pub cancel_error: Option<String>,
    pub expected_sections: Vec<String>,
    pub report_completeness: String,
    pub sections: Value,
}

pub async fn expire(state: &AppState) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE diagnostic_jobs SET status='failed',error='任务超时或设备未及时回报，请检查设备后重新运行',updated_at=$1 WHERE status IN ('queued','running') AND expires_at<=$1")
        .bind(now_timestamp()).execute(&state.pool).await?;
    Ok(())
}

pub async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<DiagnosticJob>>> {
    let server_id = auth::require_agent(&state, &headers).await?;
    artifacts::require_signed_agent(&state, server_id).await?;
    expire(&state).await?;
    let mut tx = state.pool.begin().await?;
    let capabilities: Value = sqlx::query_scalar(
        "SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    match crate::fleet::ensure_accepts_tasks_tx(&mut tx, server_id).await {
        Ok(()) => {}
        Err(ApiError::Conflict(_)) => {
            tx.commit().await?;
            return Ok(Json(Vec::new()));
        }
        Err(error) => return Err(error),
    }
    service::reject_queued(&mut tx, server_id).await?;
    if !capabilities.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| value.as_str() == Some(sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY))
    }) {
        // Existing device checkpoints still report and cancel through their own
        // endpoints; unconfirmed cleanup must never authorize a fresh start.
        tx.commit().await?;
        return Ok(Json(Vec::new()));
    }
    // A panel timeout or queue rejection cannot prove that a durable device
    // checkpoint never started. Only its completion or cancellation releases it.
    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND (status IN ('cleaning','cancel_requested') OR (status NOT IN ('queued','running') AND NOT agent_completed AND job ? 'id')))")
        .bind(server_id).fetch_one(&mut *tx).await?;
    if blocked {
        tx.commit().await?;
        return Ok(Json(Vec::new()));
    }
    let values: Vec<(Uuid, Value)> = sqlx::query_as("SELECT id,job FROM diagnostic_jobs WHERE server_id=$1 AND status IN ('queued','running') ORDER BY created_at,id")
        .bind(server_id).fetch_all(&mut *tx).await?;
    let jobs = values
        .into_iter()
        .filter(|(_, job)| {
            crate::diagnostic_plugins::for_job(job)
                .is_none_or(|plugin| plugin.can_dispatch(job, &capabilities))
        })
        .map(|(id, job)| saved_job(job, id))
        .collect::<ApiResult<_>>()?;
    tx.commit().await?;
    Ok(Json(jobs))
}

fn validate_report(report: &DiagnosticReport) -> ApiResult<()> {
    if report.text.trim().is_empty() || report.text.len() > REPORT_LIMIT {
        return Err(ApiError::BadRequest("报告文本为空或超过 512 KiB".into()));
    }
    Ok(())
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(update): Json<DiagnosticUpdate>,
) -> ApiResult<StatusCode> {
    let server_id = auth::require_agent(&state, &headers).await?;
    if id != update.id {
        return Err(ApiError::BadRequest("任务编号不一致".into()));
    }
    if let Some(report) = &update.report {
        validate_report(report)?;
    }
    if update.status == DiagnosticStatus::Succeeded && update.report.is_none() {
        return Err(ApiError::BadRequest("成功任务必须包含完整报告文本".into()));
    }
    if update.status == DiagnosticStatus::Running
        && (update.report.is_some() || update.error.is_some())
    {
        return Err(ApiError::BadRequest("进行中的任务不能回报最终结果".into()));
    }
    let mut tx = state.pool.begin().await?;
    // Creation and cancellation use this same lock order. A late cleanup
    // checkpoint cannot race a new task admitted after a panel-only timeout.
    let _: i64 = sqlx::query_scalar("SELECT id FROM servers WHERE id=$1 FOR UPDATE")
        .bind(server_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT status,expires_at,agent_completed,job FROM diagnostic_jobs WHERE id=$1 AND server_id=$2 FOR UPDATE",
    )
    .bind(id)
    .bind(server_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if let Some(report) = &update.report {
        service::validate_plugin_report(&row.get::<Value, _>("job"), report)?;
    }
    let status: String = row.get("status");
    if status == "cancel_requested" {
        // A late natural result cannot confirm that cancellation has cleaned up.
        let report = update
            .report
            .map(serde_json::to_value)
            .transpose()
            .map_err(anyhow::Error::from)?;
        sqlx::query("UPDATE diagnostic_jobs SET report=COALESCE($2,report),report_completeness=CASE WHEN cardinality(expected_sections)=0 AND COALESCE($2,report) IS NOT NULL THEN 'legacy' ELSE report_completeness END,agent_completed=agent_completed OR $3,updated_at=$4 WHERE id=$1")
            .bind(id).bind(report).bind(update.status.is_terminal()).bind(now_timestamp())
            .execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    if status == "cleaning" && update.status == DiagnosticStatus::Running {
        // An in-flight running request can arrive after a cleanup checkpoint.
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    if matches!(status.as_str(), "succeeded" | "failed" | "cancelled")
        && (row.get::<bool, _>("agent_completed") || update.status == DiagnosticStatus::Running)
    {
        // Final updates are retried durably by devices; terminal results never regress.
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    let now = now_timestamp();
    let completed = update.status.is_terminal();
    if update.status == DiagnosticStatus::Cleaning {
        let conflict: bool = sqlx::query_scalar(UNRESOLVED_QUERY)
            .bind(server_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if conflict {
            // Preserve submitted evidence even when an older panel timeout has
            // already admitted another task. Keep the device's cleanup pending;
            // only a later retry may restore the active status.
            let report = update
                .report
                .map(serde_json::to_value)
                .transpose()
                .map_err(anyhow::Error::from)?;
            let error: String = update
                .error
                .unwrap_or_else(|| "设备正在清理诊断进程和挂载，等待确认".into())
                .chars()
                .take(4096)
                .collect();
            sqlx::query("UPDATE diagnostic_jobs SET report=COALESCE($2,report),error=$3,report_completeness=CASE WHEN cardinality(expected_sections)=0 AND COALESCE($2,report) IS NOT NULL THEN 'legacy' ELSE report_completeness END,updated_at=$4 WHERE id=$1")
                .bind(id).bind(report).bind(error).bind(now).execute(&mut *tx).await?;
            tx.commit().await?;
            return Err(ApiError::Conflict(
                "同机已有另一项待处理诊断，已保留清理报告；设备仍须确认原任务清理".into(),
            ));
        }
    }
    let (status, error) = if row.get::<i64, _>("expires_at") <= now
        && update.status == DiagnosticStatus::Running
    {
        ("failed", Some("任务超时，迟到回报已忽略".to_owned()))
    } else {
        let status = match update.status {
            DiagnosticStatus::Running => "running",
            DiagnosticStatus::Cleaning => "cleaning",
            DiagnosticStatus::Succeeded => "succeeded",
            DiagnosticStatus::Failed => "failed",
        };
        let error = update.error.map(|value| value.chars().take(4096).collect());
        (
            status,
            error.or_else(|| match update.status {
                DiagnosticStatus::Failed => Some("插件执行失败，未提供错误详情".into()),
                DiagnosticStatus::Cleaning => Some("设备正在清理诊断进程和挂载，等待确认".into()),
                _ => None,
            }),
        )
    };
    let report = update
        .report
        .map(serde_json::to_value)
        .transpose()
        .map_err(anyhow::Error::from)?;
    sqlx::query(
        "UPDATE diagnostic_jobs SET status=$2,report=COALESCE($3,report),error=$4,updated_at=$5,agent_completed=$6 WHERE id=$1",
    )
    .bind(id)
    .bind(status)
    .bind(&report)
    .bind(error)
    .bind(now)
    .bind(completed)
    .execute(&mut *tx)
    .await?;
    if report.is_some() {
        sqlx::query("UPDATE diagnostic_jobs SET report_completeness='legacy' WHERE id=$1 AND cardinality(expected_sections)=0")
            .bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub use sections::upload_section;
