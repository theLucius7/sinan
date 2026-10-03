use super::{
    api::{history, materialize, supported},
    model::{Plan, digest},
};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction};
use std::time::Duration;
use uuid::Uuid;

pub async fn run(state: AppState) {
    tokio::join!(
        run_operations(state.clone()),
        run_backups(state.clone()),
        super::panel_job_backup::run(state)
    );
}

async fn run_operations(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let outcome = tick(&state).await;
        let (status, details) = match outcome {
            Ok(()) => (
                "healthy",
                json!({"scope":"orchestration_cycle","completed":true,"target_service_health_confirmed":false}),
            ),
            Err(error) => {
                tracing::error!(%error,"operations worker failed");
                (
                    "failed",
                    json!({"scope":"orchestration_cycle","completed":false,"error":error.to_string(),"target_service_health_confirmed":false}),
                )
            }
        };
        if let Err(error) =
            control_center::system::heartbeat(&state.pool, "operations", status, details).await
        {
            tracing::error!(%error,"operations heartbeat storage failed");
        }
    }
}

async fn run_backups(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let outcome = super::backups::tick(&state).await;
        let (status, details) = match outcome {
            Ok(()) => (
                "healthy",
                json!({"scope":"backup_scheduler_cycle","backup_success":"查看实际备份执行记录","completed":true}),
            ),
            Err(error) => {
                tracing::error!(%error,"backup executor failed");
                (
                    "failed",
                    json!({"scope":"backup_scheduler_cycle","completed":false,"error":error.to_string()}),
                )
            }
        };
        if let Err(error) =
            control_center::system::heartbeat(&state.pool, "operations-backups", status, details)
                .await
        {
            tracing::error!(%error,"backup heartbeat storage failed");
        }
    }
}

pub async fn tick(state: &AppState) -> ApiResult<()> {
    schedules(state).await?;
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM operations_jobs WHERE status IN ('queued','running','paused','cancel_requested','uncertain') ORDER BY CASE WHEN status='uncertain' THEN 1 ELSE 0 END,updated_at,id LIMIT 32").fetch_all(&state.pool).await?;
    for id in ids {
        advance(state, id).await?;
    }
    super::incidents::observe(state).await?;
    super::remediation::tick(state).await?;
    super::cloud::observe(&state.pool).await?;
    super::cancellation_reminders::tick(state).await?;
    Ok(())
}

async fn schedules(state: &AppState) -> ApiResult<()> {
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let rows=sqlx::query("SELECT * FROM operations_schedules WHERE NOT paused AND next_run_at<=$1 AND run_count<max_runs ORDER BY next_run_at LIMIT 8 FOR UPDATE SKIP LOCKED").bind(now).fetch_all(&mut *tx).await?;
    for row in rows {
        let id: Uuid = row.get("id");
        let due: i64 = row.get("next_run_at");
        let interval: i64 = row.get("interval_secs");
        let actor: i64 = row.get("requested_by");
        let targets: Vec<i64> = row.get("targets");
        let spec: Value = row.get("spec");
        let plan: Plan =
            serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
        plan.validate(&targets)?;
        let mut authorized = super::typed_steps::actor_authorized(state, actor, &plan).await?;
        for server in &targets {
            authorized &= control_center::actor_server_allowed(
                &state.pool,
                actor,
                *server,
                "operations:write",
            )
            .await?;
            for step in &plan.steps {
                authorized &= control_center::actor_server_allowed(
                    &state.pool,
                    actor,
                    *server,
                    step.permission(),
                )
                .await?;
            }
        }
        let previous_live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_jobs WHERE source_schedule=$1 AND status IN ('queued','running','paused','cancel_requested','uncertain'))").bind(id).fetch_one(&mut *tx).await?;
        let missed = row.get::<String, _>("missed_policy") == "skip" && now - due > 60;
        let next = due + ((now - due) / interval + 1) * interval;
        if !authorized {
            sqlx::query("UPDATE operations_schedules SET paused=true,updated_at=$2 WHERE id=$1")
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            continue;
        }
        if previous_live || missed {
            sqlx::query("UPDATE operations_schedules SET next_run_at=$2,updated_at=$3 WHERE id=$1")
                .bind(id)
                .bind(next)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            continue;
        }
        let job = Uuid::new_v4();
        let inserted=sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest,source_schedule,source_window) VALUES($1,$2,$3,$4,$5,'queued',$6,$6,$7,$8,$9,$10) ON CONFLICT(source_schedule,source_window) DO NOTHING")
            .bind(job).bind(&plan.name).bind(actor).bind(&spec).bind(&targets).bind(now).bind(now+plan.max_duration_secs).bind(digest(&spec)?).bind(id).bind(due).execute(&mut *tx).await?.rows_affected();
        if inserted == 0 {
            sqlx::query("UPDATE operations_schedules SET next_run_at=$2,updated_at=$3 WHERE id=$1")
                .bind(id)
                .bind(next)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            continue;
        }
        materialize(&mut tx, job, &targets, &plan, &spec).await?;
        history(&mut tx,job,None,"scheduled",json!({"schedule":id,"window":due,"missed_policy":row.get::<String,_>("missed_policy"),"targets":targets}),now).await?;
        sqlx::query("UPDATE operations_schedules SET next_run_at=$2,run_count=run_count+1,last_job=$3,updated_at=$4 WHERE id=$1").bind(id).bind(next).bind(job).bind(now).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn sync_commands(tx: &mut Transaction<'_, Postgres>, id: Uuid, now: i64) -> ApiResult<()> {
    super::typed_steps::sync(tx, id, now).await?;
    sqlx::query("UPDATE fleet_operations SET status='expired' WHERE id IN (SELECT fleet_operation_id FROM operations_target_steps WHERE job_id=$1) AND status='queued' AND expires_at<=$2").bind(id).bind(now).execute(&mut **tx).await?;
    let rows=sqlx::query("SELECT t.server_id,t.position,c.status,c.result,c.dispatched_at,c.expires_at FROM operations_target_steps t JOIN fleet_operations c ON c.id=t.fleet_operation_id WHERE t.job_id=$1 AND t.state IN ('queued','running','cancel_requested','uncertain')").bind(id).fetch_all(&mut **tx).await?;
    for row in rows {
        let current: String = row.get("status");
        let result: Option<Value> = row.get("result");
        let terminal = matches!(
            current.as_str(),
            "succeeded" | "failed" | "cancelled" | "expired"
        );
        let state = match current.as_str() {
            "succeeded" if result.is_some() => "succeeded",
            "failed" | "expired" => "failed",
            "cancelled" => "cancelled",
            "unknown" => "uncertain",
            "dispatched" if row.get::<i64, _>("expires_at") <= now => "uncertain",
            "dispatched" => "running",
            _ => "queued",
        };
        sqlx::query("UPDATE operations_target_steps SET state=$4,result=COALESCE($5,result),started_at=COALESCE(started_at,$6),finished_at=CASE WHEN $7 THEN COALESCE($8,$9) ELSE NULL END WHERE job_id=$1 AND server_id=$2 AND position=$3")
            .bind(id).bind(row.get::<i64,_>("server_id")).bind(row.get::<i32,_>("position")).bind(state).bind(&result).bind(row.get::<Option<i64>,_>("dispatched_at")).bind(terminal).bind(result.as_ref().and_then(|v|v["completed_at"].as_i64())).bind(now).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn request_cancellation(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    now: i64,
) -> ApiResult<()> {
    super::typed_steps::cancel(tx, id, now).await?;
    sqlx::query("UPDATE operations_target_steps SET state='skipped',finished_at=$2 WHERE job_id=$1 AND state='pending'").bind(id).bind(now).execute(&mut **tx).await?;
    sqlx::query("UPDATE fleet_operations SET status='cancelled' WHERE id IN (SELECT fleet_operation_id FROM operations_target_steps WHERE job_id=$1) AND status='queued'").bind(id).execute(&mut **tx).await?;
    sync_commands(tx, id, now).await?;
    sqlx::query("UPDATE operations_target_steps t SET state='uncertain' FROM fleet_operations c WHERE t.job_id=$1 AND t.fleet_operation_id=c.id AND c.status IN ('dispatched','unknown')").bind(id).execute(&mut **tx).await?;
    Ok(())
}

async fn advance(state: &AppState, id: Uuid) -> ApiResult<()> {
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM operations_jobs WHERE id=$1 FOR UPDATE SKIP LOCKED")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let status: String = row.get("status");
    if !matches!(
        status.as_str(),
        "queued" | "running" | "paused" | "cancel_requested" | "uncertain"
    ) {
        return Ok(());
    }
    let spec: Value = row.get("spec");
    let plan: Plan = serde_json::from_value(spec["plan"].clone()).map_err(anyhow::Error::from)?;
    let actor: i64 = row.get("requested_by");
    sync_commands(&mut tx, id, now).await?;
    let failed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_target_steps WHERE job_id=$1 AND state IN ('failed','cancelled'))").bind(id).fetch_one(&mut *tx).await?;
    let expired = row.get::<i64, _>("expires_at") <= now;
    let uncertain_steps:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_target_steps WHERE job_id=$1 AND state='uncertain')").bind(id).fetch_one(&mut *tx).await?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operations_target_steps WHERE job_id=$1 AND state<>'succeeded'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if remaining == 0 && row.get::<Option<i64>, _>("cancel_requested_at").is_none() && !expired {
        sqlx::query("UPDATE operations_jobs SET status='succeeded',updated_at=$2 WHERE id=$1")
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        history(
            &mut tx,
            id,
            None,
            "completed",
            json!({"all_steps":"actual_typed_executor_receipts_confirmed"}),
            now,
        )
        .await?;
        release_finished(&mut tx, id).await?;
        tx.commit().await?;
        return Ok(());
    }
    if failed
        || expired
        || uncertain_steps
        || matches!(status.as_str(), "cancel_requested" | "uncertain")
    {
        request_cancellation(&mut tx, id, now).await?;
        let uncertain:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_target_steps WHERE job_id=$1 AND state='uncertain')").bind(id).fetch_one(&mut *tx).await?;
        let live:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_target_steps WHERE job_id=$1 AND state IN ('queued','running','cancel_requested','uncertain'))").bind(id).fetch_one(&mut *tx).await?;
        let next = if uncertain {
            "uncertain"
        } else if live {
            "cancel_requested"
        } else if status == "cancel_requested" && !failed && !expired {
            "cancelled"
        } else {
            "failed"
        };
        sqlx::query("UPDATE operations_jobs SET status=$2,updated_at=$3,failure_reason=COALESCE(failure_reason,$4) WHERE id=$1")
            .bind(id).bind(next).bind(now).bind(if expired { "已达到总时长预算，取消后等待设备确认" } else if uncertain { "执行结果或进程停止尚未确认，禁止自动重试" } else { "步骤失败或取消，后续步骤已停止" }).execute(&mut *tx).await?;
        release_finished(&mut tx, id).await?;
        tx.commit().await?;
        return Ok(());
    }
    release_finished(&mut tx, id).await?;
    if status == "paused" {
        tx.commit().await?;
        return Ok(());
    }
    let current: i32 = sqlx::query_scalar(
        "SELECT MIN(batch) FROM operations_target_steps WHERE job_id=$1 AND state<>'succeeded'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if plan.pause_between_batches && current > row.get::<i32, _>("approved_batch") {
        sqlx::query("UPDATE operations_jobs SET status='paused',updated_at=$2 WHERE id=$1")
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        history(
            &mut tx,
            id,
            None,
            "batch_waiting_confirmation",
            json!({"next_batch":current}),
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(());
    }
    let active:i64=sqlx::query_scalar("SELECT COUNT(DISTINCT server_id) FROM operations_target_steps WHERE job_id=$1 AND state IN ('queued','running','cancel_requested','uncertain')").bind(id).fetch_one(&mut *tx).await?;
    let capacity = plan.concurrency.saturating_sub(active as usize);
    let ready=sqlx::query("SELECT t.server_id,t.position FROM operations_target_steps t WHERE t.job_id=$1 AND t.batch=$2 AND t.state='pending' AND NOT EXISTS(SELECT 1 FROM operations_target_steps previous WHERE previous.job_id=t.job_id AND previous.server_id=t.server_id AND previous.position<t.position AND previous.state<>'succeeded') ORDER BY array_position($3::bigint[],t.server_id),t.position LIMIT $4")
        .bind(id).bind(current).bind(row.get::<Vec<i64>,_>("targets")).bind(capacity as i64).fetch_all(&mut *tx).await?;
    for target in ready {
        let server: i64 = target.get("server_id");
        let position: i32 = target.get("position");
        if !super::typed_steps::actor_authorized(state, actor, &plan).await? {
            sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(now).bind(json!({"error":"全局完整备份授权已撤销"})).execute(&mut *tx).await?;
            break;
        }
        if !control_center::actor_server_allowed(&state.pool, actor, server, "operations:write")
            .await?
            || !control_center::actor_server_allowed(
                &state.pool,
                actor,
                server,
                plan.steps[position as usize].permission(),
            )
            .await?
        {
            sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(now).bind(json!({"error":"提交者的服务器权限已撤销"})).execute(&mut *tx).await?;
            break;
        }
        enqueue(
            state,
            &mut tx,
            id,
            server,
            position,
            &plan,
            now,
            row.get("expires_at"),
        )
        .await?;
    }
    sqlx::query("UPDATE operations_jobs SET status='running',updated_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn release_finished(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<()> {
    sqlx::query("DELETE FROM operations_server_locks l WHERE l.job_id=$1 AND NOT EXISTS(SELECT 1 FROM operations_target_steps t WHERE t.job_id=l.job_id AND t.server_id=l.server_id AND t.state IN ('pending','queued','running','cancel_requested','uncertain'))").bind(id).execute(&mut **tx).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn enqueue(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: i64,
    position: i32,
    plan: &Plan,
    now: i64,
    expires: i64,
) -> ApiResult<()> {
    let step = plan
        .steps
        .get(position as usize)
        .ok_or_else(|| ApiError::Conflict("步骤快照不完整".into()))?;
    if step.is_panel() {
        return super::typed_steps::queue_backup(tx, id, now).await;
    }
    let row = sqlx::query(
        "SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(server)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(now).bind(json!({"error":"服务器已删除"})).execute(&mut **tx).await?;
        return Ok(());
    };
    let capabilities: Value = row.get("capabilities");
    let unavailable:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) OR EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND block_new_tasks AND starts_at<=$2 AND ends_at>$2) OR EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND (lifecycle IN ('draining','retired') OR (lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$2 AND (maintenance_until IS NULL OR maintenance_until>$2))))").bind(server).bind(now).fetch_one(&mut **tx).await?;
    if unavailable {
        return Ok(());
    }
    if step.is_fleet() && !supported(&capabilities) {
        sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(now).bind(json!({"error":"设备命令执行能力已不可用"})).execute(&mut **tx).await?;
        return Ok(());
    }
    let conflicts:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_server_locks WHERE server_id=$1 AND job_id<>$2) OR EXISTS(SELECT 1 FROM remote_commands WHERE server_id=$1 AND state IN ('queued','claimed','running','cancel_requested')) OR EXISTS(SELECT 1 FROM fleet_operations WHERE server_id=$1 AND reconciled_at IS NULL AND status IN ('queued','dispatched','unknown')) OR EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL AND dispatched_at IS NOT NULL) OR EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND (status IN ('queued','running','cleaning','cancel_requested') OR (NOT agent_completed AND job ? 'id')))")
        .bind(server).bind(id).fetch_one(&mut **tx).await?;
    if conflicts {
        return Ok(());
    }
    sqlx::query("INSERT INTO operations_server_locks(server_id,job_id,acquired_at) VALUES($1,$2,$3) ON CONFLICT(server_id) DO NOTHING").bind(server).bind(id).bind(now).execute(&mut **tx).await?;
    if step.is_runtime() {
        let parent = sqlx::query("SELECT requested_by,spec FROM operations_jobs WHERE id=$1")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
        let result = super::typed_steps::enqueue_runtime(
            state,
            tx,
            super::typed_steps::RuntimeStep {
                job: id,
                server,
                position,
                actor: parent.get("requested_by"),
                spec: &parent.get::<Value, _>("spec"),
                expires: expires.min(now + i64::from(step.timeout_secs)),
            },
        )
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(
                ApiError::BadRequest(error)
                | ApiError::Conflict(error)
                | ApiError::Forbidden(error),
            ) => {
                sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(now).bind(json!({"error":error,"executed":false})).execute(&mut **tx).await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    let step = plan
        .steps
        .get(position as usize)
        .ok_or_else(|| ApiError::Conflict("步骤快照不完整".into()))?;
    let operation = step.operation()?;
    let execution = match crate::fleet::enqueue_automation_tx(state, tx, server, id, operation)
        .await
    {
        Ok(id) => id,
        Err(ApiError::BadRequest(error) | ApiError::Conflict(error)) => {
            sqlx::query("UPDATE operations_target_steps SET state='failed',finished_at=$4,result=$5 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(now).bind(json!({"error":error})).execute(&mut **tx).await?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    sqlx::query("UPDATE fleet_operations SET expires_at=$2 WHERE id=$1")
        .bind(execution)
        .bind(expires.min(now + i64::from(step.timeout_secs)))
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE operations_target_steps SET state='queued',fleet_operation_id=$4 WHERE job_id=$1 AND server_id=$2 AND position=$3").bind(id).bind(server).bind(position).bind(execution).execute(&mut **tx).await?;
    history(tx,id,None,"step_dispatched",json!({"server_id":server,"position":position,"fleet_operation_id":execution,"retry":false,"executor":"Agent ServiceManager / Privileged","expires_at":expires.min(now+i64::from(step.timeout_secs))}),now).await?;
    Ok(())
}
