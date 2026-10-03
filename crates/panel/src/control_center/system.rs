use super::{require_capability, require_owner};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Row};
use std::time::Duration;

pub async fn heartbeat(
    pool: &PgPool,
    name: &str,
    status: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO system_worker_heartbeats(name,status,observed_at,last_success_at,details) VALUES($1,$2,$3,CASE WHEN $2='healthy' THEN $3 END,$4) ON CONFLICT(name) DO UPDATE SET status=EXCLUDED.status,observed_at=EXCLUDED.observed_at,last_success_at=COALESCE(EXCLUDED.last_success_at,system_worker_heartbeats.last_success_at),details=EXCLUDED.details")
        .bind(name).bind(status).bind(now_timestamp()).bind(super::guard::redact(&details)).execute(pool).await?;
    Ok(())
}

pub async fn health(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    let now = now_timestamp();
    let start = std::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT 1").execute(&state.pool),
    )
    .await
    .map_err(|_| ApiError::Busy)??;
    let database_elapsed_ms = start.elapsed().as_millis();
    let database_bytes: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())")
        .fetch_one(&state.pool)
        .await?;
    let commands:i64=sqlx::query_scalar("SELECT count(*) FROM remote_commands WHERE state IN ('queued','claimed','running','cancel_requested')").fetch_one(&state.pool).await?;
    let diagnostics: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM diagnostic_jobs WHERE status IN ('queued','running')",
    )
    .fetch_one(&state.pool)
    .await?;
    let notifications: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_outbox WHERE status='pending'")
            .fetch_one(&state.pool)
            .await?;
    let fleet:i64=sqlx::query_scalar("SELECT count(*) FROM fleet_operations WHERE status IN ('queued','dispatched','unknown') AND reconciled_at IS NULL").fetch_one(&state.pool).await?;
    let operations:i64=sqlx::query_scalar("SELECT count(*) FROM operations_jobs WHERE status IN ('queued','running','paused','cancel_requested','uncertain')").fetch_one(&state.pool).await?;
    let rows = sqlx::query("SELECT * FROM system_worker_heartbeats ORDER BY name")
        .fetch_all(&state.pool)
        .await?;
    let mut workers:Vec<Value>=rows.iter().map(|r| { let observed:i64=r.try_get("observed_at")?;Ok(json!({"name":r.try_get::<String,_>("name")?,"status":if now-observed>120 {"stale".to_owned()} else {r.try_get::<String,_>("status")?},"observed_at":observed,"last_success_at":r.try_get::<Option<i64>,_>("last_success_at")?,"details":r.try_get::<Value,_>("details")?})) }).collect::<Result<_,sqlx::Error>>()?;
    for name in [
        "maintenance",
        "telemetry-history",
        "control-center",
        "network-workbench",
        "operations",
        "operations-backups",
        "operations-job-backups",
        "network-certificates",
        "ddns",
        "alicloud",
        "alicloud-cost-cache",
        "alicloud-power",
        "sing-box",
    ] {
        if !workers
            .iter()
            .any(|value| value["name"].as_str() == Some(name))
        {
            workers.push(json!({"name":name,"status":"unknown","observed_at":null,"reason":"尚无此执行器周期观察"}));
        }
    }
    let reports =
        sqlx::query("SELECT * FROM system_observer_reports ORDER BY received_at DESC LIMIT 20")
            .fetch_all(&state.pool)
            .await?;
    let reports:Vec<Value>=reports.iter().map(|r|Ok(json!({"observer_name":r.try_get::<String,_>("observer_name")?,"target_origin":r.try_get::<String,_>("target_origin")?,"observed_at":r.try_get::<i64,_>("observed_at")?,"received_at":r.try_get::<i64,_>("received_at")?,"available":r.try_get::<Option<bool>,_>("available")?,"elapsed_ms":r.try_get::<Option<i64>,_>("elapsed_ms")?,"evidence":r.try_get::<Value,_>("evidence")?}))).collect::<Result<_,sqlx::Error>>()?;
    let disk = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("df")
            .args(["-Pk", "--"])
            .arg(&state.config.data_dir)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let disk = match disk {
        Ok(Ok(output)) if output.status.success() => {
            disk_observation(&String::from_utf8_lossy(&output.stdout), now)
        }
        _ => json!({"status":"unknown","reason":"磁盘观察工具不可用或请求超时"}),
    };
    let backup:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',b.id,'name',b.name,'created_at',b.created_at,'encrypted',b.encrypted,'verification',b.verification,'last_drill',(SELECT jsonb_build_object('passed',d.passed,'recorded_at',d.recorded_at,'action',d.report->>'action') FROM operations_restore_drills d WHERE d.backup_id=b.id ORDER BY d.recorded_at DESC LIMIT 1)) FROM operations_backup_records b WHERE b.retired_at IS NULL ORDER BY b.created_at DESC LIMIT 1").fetch_optional(&state.pool).await?;
    let backup_schedules:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'paused',paused,'next_run_at',next_run_at,'last_started_at',last_started_at,'last_finished_at',last_finished_at,'last_error',last_error) FROM operations_backup_schedules ORDER BY updated_at DESC LIMIT 20").fetch_all(&state.pool).await?;
    let update = match tokio::time::timeout(
        Duration::from_secs(5),
        crate::releases::entries(&state),
    )
    .await
    {
        Ok(Ok(entries)) => {
            json!({"status":"observed","source":"local-signed-artifact-inventory","observed_at":now,"entries":entries,"remote_checked":false})
        }
        _ => {
            json!({"status":"unknown","reason":"本地签名制品清单不可用或读取超时","remote_checked":false})
        }
    };
    Ok(Json(
        json!({"version":env!("CARGO_PKG_VERSION"),"sampled_at":now,"uptime_seconds":now-state.started_at,"database":{"available":true,"elapsed_ms":database_elapsed_ms,"bytes":database_bytes,"pool_size":state.pool.size(),"idle":state.pool.num_idle()},"disk":disk,"backlog":{"commands":commands,"diagnostics":diagnostics,"notifications":notifications,"fleet":fleet,"operations":operations},"workers":workers,"independent_observers":reports,"backup":{"status":if backup.is_some(){"recorded"}else{"unknown"},"latest":backup,"schedules":backup_schedules,"source":"local-backup-ledger"},"update":update}),
    ))
}

fn disk_observation(raw: &str, now: i64) -> Value {
    let columns: Vec<_> = raw
        .lines()
        .last()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    if columns.len() < 6 {
        return json!({"status":"unknown","reason":"磁盘工具未返回可解释的容量记录"});
    }
    let parse = |index: usize| {
        columns[index]
            .parse::<u64>()
            .ok()
            .and_then(|value| value.checked_mul(1024))
    };
    match (parse(1), parse(2), parse(3)) {
        (Some(total), Some(used), Some(available)) => {
            json!({"status":"observed","source":"df -Pk","observed_at":now,"total_bytes":total,"used_bytes":used,"available_bytes":available,"raw":raw.chars().take(2048).collect::<String>()})
        }
        _ => json!({"status":"unknown","reason":"磁盘容量记录无效"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_evidence_keeps_invalid_and_overflowing_results_unknown() {
        let observed = disk_observation(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/data 1024 100 924 10% /panel data\n",
            7,
        );
        assert_eq!(observed["available_bytes"], 924 * 1024);
        assert_eq!(observed["observed_at"], 7);
        assert_eq!(disk_observation("unavailable", 7)["status"], "unknown");
        assert_eq!(
            disk_observation("fs 18446744073709551615 1 1 0% /", 7)["status"],
            "unknown"
        );
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverInput {
    observer_name: String,
    target_origin: String,
    observed_at: i64,
    available: Option<bool>,
    elapsed_ms: Option<i64>,
    evidence: Value,
}
pub async fn observe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ObserverInput>,
) -> ApiResult<Json<Value>> {
    require_capability(&state, &headers, "monitoring:write").await?;
    let now = now_timestamp();
    if input.observer_name.trim().is_empty()
        || input.observer_name.len() > 200
        || input.target_origin != state.config.public_url
        || input.observed_at > now + 60
        || input.observed_at < now - 86400
        || input.elapsed_ms.is_some_and(|v| !(0..=300000).contains(&v))
        || serde_json::to_vec(&input.evidence)
            .map_err(anyhow::Error::from)?
            .len()
            > 16384
    {
        return Err(ApiError::BadRequest(
            "观察点、面板地址或证据时间无效".into(),
        ));
    }
    let id:i64=sqlx::query_scalar("INSERT INTO system_observer_reports(observer_name,target_origin,observed_at,received_at,available,elapsed_ms,evidence) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id")
        .bind(input.observer_name).bind(input.target_origin).bind(input.observed_at).bind(now).bind(input.available).bind(input.elapsed_ms).bind(super::guard::redact(&input.evidence)).fetch_one(&state.pool).await?;
    Ok(Json(
        json!({"id":id,"received_at":now,"source":"independent-observer-submitted-evidence"}),
    ))
}

pub async fn maintain(pool: &PgPool) -> Result<(), sqlx::Error> {
    let now = now_timestamp();
    let audit: i32 =
        sqlx::query_scalar("SELECT days FROM record_retention_policy WHERE kind='audit'")
            .fetch_one(pool)
            .await?;
    let ip: i32 = sqlx::query_scalar("SELECT days FROM record_retention_policy WHERE kind='ip'")
        .fetch_one(pool)
        .await?;
    let terminal: i32 =
        sqlx::query_scalar("SELECT days FROM record_retention_policy WHERE kind='terminal'")
            .fetch_one(pool)
            .await?;
    let logs: i32 =
        sqlx::query_scalar("SELECT days FROM record_retention_policy WHERE kind='logs'")
            .fetch_one(pool)
            .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM management_audit WHERE occurred_at<$1")
        .bind(now - i64::from(audit) * 86400)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM server_ip_quality_datasets WHERE checked_at<$1")
        .bind(now - i64::from(ip) * 86400)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM server_ip_quality WHERE checked_at<$1 AND NOT EXISTS(SELECT 1 FROM server_ip_quality_datasets d WHERE d.server_id=server_ip_quality.server_id AND d.ip=server_ip_quality.ip AND d.provider=server_ip_quality.provider)").bind(now-i64::from(ip)*86400).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM system_observer_reports WHERE received_at<$1")
        .bind(now - i64::from(audit) * 86400)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM management_api_tokens WHERE expires_at<$1 AND (revoked_at IS NULL OR revoked_at<$1)").bind(now-i64::from(audit)*86400).execute(&mut *tx).await?;
    let terminal_cutoff = now - i64::from(terminal) * 86400;
    sqlx::query("DELETE FROM fleet_terminal_inputs i USING fleet_terminal_sessions s WHERE i.session_id=s.id AND s.status IN ('closed','failed') AND s.expires_at<$1").bind(terminal_cutoff).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM fleet_terminal_outputs o USING fleet_terminal_sessions s WHERE o.session_id=s.id AND s.status IN ('closed','failed') AND s.expires_at<$1").bind(terminal_cutoff).execute(&mut *tx).await?;
    sqlx::query(
        "DELETE FROM fleet_terminal_sessions WHERE status IN ('closed','failed') AND expires_at<$1",
    )
    .bind(terminal_cutoff)
    .execute(&mut *tx)
    .await?;
    let log_cutoff = now - i64::from(logs) * 86400;
    sqlx::query("UPDATE fleet_config_history SET content='' WHERE created_at<$1 AND content<>''")
        .bind(log_cutoff)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE fleet_operations SET operation=CASE WHEN operation ? 'content' THEN jsonb_set(operation,'{content}',to_jsonb(''::text)) ELSE operation END,result=NULL WHERE requested_at<$1 AND (status IN ('succeeded','failed','expired','cancelled') OR reconciled_at IS NOT NULL) AND (COALESCE(operation->>'content','')<>'' OR result IS NOT NULL)").bind(log_cutoff).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM fleet_events WHERE occurred_at<$1")
        .bind(log_cutoff)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE remote_commands SET result=jsonb_set(jsonb_set(result,'{stdout}',to_jsonb('[按保留策略清理]'::text)),'{stderr}',to_jsonb('[按保留策略清理]'::text)) WHERE finished_at<$1 AND state IN ('succeeded','failed','cancelled','expired','interrupted') AND result IS NOT NULL AND (COALESCE(result->>'stdout','') NOT IN ('','[按保留策略清理]') OR COALESCE(result->>'stderr','') NOT IN ('','[按保留策略清理]'))").bind(log_cutoff).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
