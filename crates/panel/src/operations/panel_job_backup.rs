use super::{
    api::history,
    model::{Plan, digest, label},
    typed_steps,
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
use sqlx::{Postgres, Row, Transaction};
use std::time::Duration;
use uuid::Uuid;

pub(super) async fn run(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let outcome = tick(&state).await;
        let (status, details) = match outcome {
            Ok(()) => (
                "healthy",
                json!({"scope":"once_per_job_backup_cycle","actual_results":"任务内单一完整恢复点的实际执行记录"}),
            ),
            Err(error) => {
                tracing::error!(%error,"job backup worker failed");
                (
                    "failed",
                    json!({"scope":"once_per_job_backup_cycle","completed":false}),
                )
            }
        };
        if let Err(error) = control_center::system::heartbeat(
            &state.pool,
            "operations-job-backups",
            status,
            details,
        )
        .await
        {
            tracing::error!(%error,"job backup heartbeat storage failed");
        }
    }
}

struct Execution {
    job: Uuid,
    id: Uuid,
    schedule: Uuid,
    recipient: String,
    actor: i64,
    name: String,
    budget: u64,
}

async fn interrupted(state: &AppState) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    let rows=sqlx::query("UPDATE operations_panel_steps p SET state='uncertain',backup_id=(SELECT id FROM operations_backup_records WHERE id=p.execution_id),result=jsonb_build_object('original_result','unknown','process_stop_confirmed',false,'cleanup_confirmed',false,'reason','面板在执行结果确认前重启；保留单次执行身份，不自动重放') WHERE state='running' AND claimed_at<$1 RETURNING job_id,execution_id")
        .bind(state.started_at).fetch_all(&mut *tx).await?;
    for row in rows {
        history(
            &mut tx,
            row.get("job_id"),
            None,
            "panel_backup_uncertain",
            json!({"execution_id":row.get::<Uuid,_>("execution_id"),"retry":false}),
            now_timestamp(),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn fail_before_execution(
    tx: &mut Transaction<'_, Postgres>,
    job: Uuid,
    reason: &str,
    now: i64,
) -> ApiResult<()> {
    sqlx::query("UPDATE operations_panel_steps SET state='failed',finished_at=$2,result=jsonb_build_object('executed',false,'error',$3::text,'cleanup_confirmed',true) WHERE job_id=$1 AND state='queued'")
        .bind(job).bind(now).bind(reason).execute(&mut **tx).await?;
    history(
        tx,
        job,
        None,
        "panel_backup_failed",
        json!({"executed":false,"error":reason}),
        now,
    )
    .await
}

async fn claim(state: &AppState) -> ApiResult<Option<Execution>> {
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let unknown: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM operations_panel_steps WHERE state='uncertain')",
    )
    .fetch_one(&mut *tx)
    .await?;
    if unknown {
        return Ok(None);
    }
    let row=sqlx::query("SELECT p.execution_id,p.spec AS step_spec,j.id,j.requested_by,j.name,j.targets,j.spec AS job_spec,j.expires_at,j.status,j.cancel_requested_at FROM operations_panel_steps p JOIN operations_jobs j ON j.id=p.job_id WHERE p.state='queued' ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF p SKIP LOCKED")
        .fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let job: Uuid = row.get("id");
    if row.get::<i64, _>("expires_at") <= now
        || row.get::<Option<i64>, _>("cancel_requested_at").is_some()
        || !matches!(
            row.get::<String, _>("status").as_str(),
            "queued" | "running"
        )
    {
        sqlx::query("UPDATE operations_panel_steps SET state='cancelled',finished_at=$2,result=jsonb_build_object('executed',false,'reason','取消或总预算已到，未执行备份') WHERE job_id=$1").bind(job).bind(now).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let actor: i64 = row.get("requested_by");
    let job_spec: Value = row.get("job_spec");
    let plan: Plan =
        serde_json::from_value(job_spec["plan"].clone()).map_err(anyhow::Error::from)?;
    let mut permitted = typed_steps::actor_authorized(state, actor, &plan).await?;
    for server in row.get::<Vec<i64>, _>("targets") {
        permitted &=
            control_center::actor_server_allowed(&state.pool, actor, server, "operations:write")
                .await?;
    }
    if !permitted {
        fail_before_execution(
            &mut tx,
            job,
            "提交者的全局完整备份或固定目标权限已撤销",
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let frozen: Value = row.get("step_spec");
    let schedule: Uuid =
        serde_json::from_value(frozen["backup"]["id"].clone()).map_err(anyhow::Error::from)?;
    let current = typed_steps::backup_snapshot(&mut tx, schedule).await?;
    if digest(&current)? != frozen["backup_digest"].as_str().unwrap_or("") {
        fail_before_execution(
            &mut tx,
            job,
            "备份计划设置已改变，须重新预览，不采用其他接收密钥或保留策略",
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let id: Uuid = row.get("execution_id");
    let prior: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_backup_records WHERE id=$1)")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if prior {
        sqlx::query("UPDATE operations_panel_steps SET state='uncertain',backup_id=$2,result=jsonb_build_object('original_result','unknown','reason','单次身份已有恢复点记录；仍需核对进程与清理，不重新执行') WHERE job_id=$1").bind(job).bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(None);
    }
    let step = plan
        .steps
        .first()
        .filter(|step| step.is_panel())
        .ok_or_else(|| ApiError::Conflict("完整备份首步快照缺失".into()))?;
    let budget = u64::from(step.timeout_secs).min((row.get::<i64, _>("expires_at") - now) as u64);
    sqlx::query("UPDATE operations_panel_steps SET state='running',claimed_at=$2 WHERE job_id=$1 AND state='queued'").bind(job).bind(now).execute(&mut *tx).await?;
    history(&mut tx,job,None,"panel_backup_started",json!({"execution_id":id,"backup_schedule_id":schedule,"once_per_job":true,"budget_secs":budget}),now).await?;
    let execution = Execution {
        job,
        id,
        schedule,
        recipient: current["recipient"]
            .as_str()
            .ok_or_else(|| ApiError::Conflict("备份接收公钥缺失".into()))?
            .into(),
        actor,
        name: format!("{} · 单次完整恢复点", row.get::<String, _>("name")),
        budget,
    };
    tx.commit().await?;
    Ok(Some(execution))
}

pub(super) async fn tick(state: &AppState) -> ApiResult<()> {
    interrupted(state).await?;
    let Some(execution) = claim(state).await? else {
        return Ok(());
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(execution.budget),
        super::backup_executor::execute(
            state,
            execution.id,
            execution.schedule,
            &execution.recipient,
            execution.actor,
            &execution.name,
        ),
    )
    .await;
    let (phase, result) = match outcome {
        Ok(Ok(backup)) => {
            let receipt:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('backup_id',id,'verification',verification,'encrypted',encrypted,'manifest_sha256',manifest_sha256,'storage_sha256',storage_sha256) FROM operations_backup_records WHERE id=$1 AND encrypted AND verification='integrity_verified' AND manifest->>'complete'='true' AND storage_sha256 IS NOT NULL")
                .bind(backup).fetch_optional(&state.pool).await?;
            match receipt {
                Some(receipt) if backup == execution.id => (
                    "succeeded",
                    json!({"receipt":receipt,"backup_id":backup,"process_stop_confirmed":true,"cleanup_confirmed":true,"restore_drill_passed":false}),
                ),
                _ => (
                    "uncertain",
                    json!({"original_result":"unknown","reason":"完整备份完成记录尚未核对","process_stop_confirmed":true,"cleanup_confirmed":true}),
                ),
            }
        }
        Ok(Err(ApiError::Conflict(message) | ApiError::BadRequest(message))) => {
            let unknown = message.contains("未确认清理");
            (
                if unknown { "uncertain" } else { "failed" },
                json!({"error":message,"original_result":if unknown {"unknown"}else{"failed"},"cleanup_confirmed":!unknown}),
            )
        }
        Ok(Err(_)) => (
            "uncertain",
            json!({"original_result":"unknown","reason":"工具、数据库或执行结果未取得可核对完成状态；须检查原单次执行","process_stop_confirmed":false,"cleanup_confirmed":false}),
        ),
        Err(_) => (
            "uncertain",
            json!({"original_result":"unknown","reason":"达到单次步骤时长预算；进程停止与私有临时材料清理须分别核对，不自动重试","process_stop_confirmed":false,"cleanup_confirmed":false}),
        ),
    };
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE operations_backup_records b SET retain_until=GREATEST(COALESCE(b.retain_until,0),j.expires_at+86400) FROM operations_jobs j WHERE b.id=$1 AND j.id=$2")
        .bind(execution.id).bind(execution.job).execute(&mut *tx).await?;
    sqlx::query("UPDATE operations_panel_steps p SET state=$3,finished_at=CASE WHEN $3='uncertain' THEN NULL ELSE $4 END,result=$5,backup_id=(SELECT id FROM operations_backup_records WHERE id=p.execution_id) WHERE job_id=$1 AND execution_id=$2 AND state='running'")
        .bind(execution.job).bind(execution.id).bind(phase).bind(now_timestamp()).bind(&result).execute(&mut *tx).await?;
    history(
        &mut tx,
        execution.job,
        None,
        if phase == "succeeded" {
            "panel_backup_completed"
        } else if phase == "uncertain" {
            "panel_backup_uncertain"
        } else {
            "panel_backup_failed"
        },
        result,
        now_timestamp(),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reconciliation {
    process_stopped: bool,
    temporary_material_cleaned: bool,
    observed_at: i64,
    evidence: String,
}

pub(super) async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job): Path<Uuid>,
    Json(input): Json<Reconciliation>,
) -> ApiResult<Json<Value>> {
    let actor = super::require_global(&state, &headers, "recovery:write").await?;
    let targets = super::api::targets(&state.pool, job).await?;
    super::api::authorize(&state, &headers, &targets, true).await?;
    control_center::require_recent_proof(&state, &headers).await?;
    label(&input.evidence, 4096)?;
    let now = now_timestamp();
    if !input.process_stopped
        || !input.temporary_material_cleaned
        || input.observed_at > now
        || input.observed_at < now - 600
    {
        return Err(ApiError::BadRequest(
            "须提供最近十分钟面板本机进程已停止及该单次执行私有临时材料已清理的独立核对证据".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    // The worker locks this job before synchronizing its shared panel row.
    let status: String =
        sqlx::query_scalar("SELECT status FROM operations_jobs WHERE id=$1 FOR UPDATE")
            .bind(job)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    if !matches!(status.as_str(), "uncertain" | "cancel_requested") {
        return Err(ApiError::Conflict(
            "先刷新并等待任务进入未知结果核对阶段".into(),
        ));
    }
    let id:Uuid=sqlx::query_scalar("UPDATE operations_panel_steps SET state='failed',finished_at=$2,result=COALESCE(result,'{}'::jsonb)||$3 WHERE job_id=$1 AND state='uncertain' RETURNING execution_id")
        .bind(job).bind(now).bind(json!({"manual_reconciliation":true,"actor":actor,"observed_at":input.observed_at,"evidence":input.evidence,"process_stop_confirmed":true,"cleanup_confirmed":true,"original_result":"unknown","success":null}))
        .fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::Conflict("仅未知的单次完整面板备份可人工核对；不会重放原执行".into()))?;
    typed_steps::sync(&mut tx, job, now).await?;
    history(&mut tx,job,Some(actor),"panel_backup_manually_reconciled",json!({"execution_id":id,"evidence":input.evidence,"original_result":"unknown","success":null}),now).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"job_id":job,"execution_id":id,"state":"failed","original_result":"unknown","automatic_replay":false}),
    ))
}

#[cfg(test)]
mod tests;
