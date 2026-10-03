use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::{CommandResult, RemoteCommand, TaskAck, now_timestamp};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

mod lifecycle;
pub use lifecycle::{cancel, claim, control, pending_lifecycle, started};

fn capability(capabilities: &Value, name: &str) -> bool {
    capabilities
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(name)))
}

fn storage_output(output: &mut String) -> bool {
    // PostgreSQL JSONB cannot represent NUL. Keep a display projection while the
    // result digest below continues to bind the original received event.
    if !output.contains('\0') {
        return false;
    }
    *output = output.replace('\0', "\u{fffd}");
    let mut limit = output.len().min(256 * 1024);
    while !output.is_char_boundary(limit) {
        limit -= 1;
    }
    let truncated = output.len() > limit;
    output.truncate(limit);
    truncated
}

async fn command_server(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
) -> ApiResult<(Value, bool)> {
    // Retirement takes this row lock before publishing its request. Read its
    // marker in a separate statement so a waiter sees the newly committed row.
    let capabilities: Value = sqlx::query_scalar(
        "SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(server)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let retiring =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) OR EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND (lifecycle IN ('draining','retired') OR (lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$2 AND (maintenance_until IS NULL OR maintenance_until>$2)))) OR EXISTS(SELECT 1 FROM operations_server_locks WHERE server_id=$1) OR EXISTS(SELECT 1 FROM fleet_operations WHERE server_id=$1 AND ((status IN ('dispatched','unknown') AND reconciled_at IS NULL) OR (status='queued' AND expires_at>$2))) OR EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND block_new_tasks AND starts_at<=$2 AND ends_at>$2)")
            .bind(server).bind(now_timestamp())
            .fetch_one(&mut **tx)
            .await?;
    Ok((capabilities, retiring))
}

async fn expire_queued(pool: &sqlx::PgPool, server: i64) -> ApiResult<()> {
    sqlx::query("UPDATE remote_commands SET state='expired',finished_at=$2 WHERE server_id=$1 AND state='queued' AND (spec->>'expires_at')::BIGINT<=$2")
        .bind(server).bind(now_timestamp()).execute(pool).await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCommand {
    pub command: String,
    pub timeout_secs: u32,
    pub ttl_secs: u32,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(request): Json<CreateCommand>,
) -> ApiResult<Json<RemoteCommand>> {
    auth::require_admin(&state, &headers).await?;
    let now = now_timestamp();
    let command = RemoteCommand {
        id: Uuid::new_v4(),
        command: request.command,
        timeout_secs: request.timeout_secs,
        expires_at: now + i64::from(request.ttl_secs),
    };
    if !command.valid() || !(1..=86400).contains(&request.ttl_secs) {
        return Err(ApiError::BadRequest("命令、超时或领取期限无效".into()));
    }
    let mut tx = state.pool.begin().await?;
    crate::fleet::ensure_accepts_tasks_tx(&mut tx, server).await?;
    let (capabilities, retiring) = command_server(&mut tx, server).await?;
    if retiring {
        return Err(ApiError::Conflict(
            "服务器处于维护、退役或互斥运维操作中，暂不接收新命令".into(),
        ));
    }
    if !capability(&capabilities, "command:execute") {
        return Err(ApiError::Conflict(
            "节点尚未在本机启用远程命令，请修改 Agent 本地配置后重启".into(),
        ));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM remote_commands WHERE server_id=$1 AND state IN ('queued','claimed','running','cancel_requested') AND (state<>'queued' OR (spec->>'expires_at')::BIGINT>$2)").bind(server).bind(now).fetch_one(&mut *tx).await?;
    if count >= 64 {
        return Err(ApiError::Conflict("待执行命令已达到 64 条上限".into()));
    }
    sqlx::query("INSERT INTO remote_commands(id,server_id,requested_at,spec,lifecycle_version,cancel_supported) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(command.id)
        .bind(server)
        .bind(now)
        .bind(serde_json::to_value(&command).map_err(anyhow::Error::from)?)
        .bind(i32::from(capability(&capabilities, "command:lifecycle:v1")))
        .bind(capability(&capabilities, "command:cancel:v1"))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(command))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Vec<Value>>> {
    auth::require_admin(&state, &headers).await?;
    expire_queued(&state.pool, server).await?;
    let rows = sqlx::query("SELECT * FROM remote_commands WHERE server_id=$1 ORDER BY requested_at DESC,id DESC LIMIT 100").bind(server).fetch_all(&state.pool).await?;
    Ok(Json(rows.iter().map(|row| json!({"spec":row.get::<Value,_>("spec"),"result":row.get::<Option<Value>,_>("result"),"requested_at":row.get::<i64,_>("requested_at"),"state":row.get::<String,_>("state"),"lifecycle_version":row.get::<i32,_>("lifecycle_version"),"claimed_at":row.get::<Option<i64>,_>("claimed_at"),"started_at":row.get::<Option<i64>,_>("started_at"),"cancel_requested_at":row.get::<Option<i64>,_>("cancel_requested_at"),"finished_at":row.get::<Option<i64>,_>("finished_at"),"cancel_supported":row.get::<bool,_>("cancel_supported")})).collect()))
}

pub async fn pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<RemoteCommand>>> {
    let server = auth::require_agent(&state, &headers).await?;
    expire_queued(&state.pool, server).await?;
    let mut tx = state.pool.begin().await?;
    if command_server(&mut tx, server).await?.1 {
        return Ok(Json(Vec::new()));
    }
    // Fetching through the legacy endpoint is itself a claim. Cancellation must
    // never call an already delivered legacy command safely cancelled.
    let rows: Vec<Value> = sqlx::query_scalar("UPDATE remote_commands SET state='claimed',claimed_at=COALESCE(claimed_at,$2) WHERE id IN (SELECT id FROM remote_commands WHERE server_id=$1 AND lifecycle_version=0 AND state IN ('queued','claimed') AND result IS NULL AND (spec->>'expires_at')::BIGINT>$2 ORDER BY requested_at,id LIMIT 64 FOR UPDATE) RETURNING spec").bind(server).bind(now_timestamp()).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(anyhow::Error::from)?,
    ))
}

pub async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(result): Json<CommandResult>,
) -> ApiResult<Json<TaskAck>> {
    let server = auth::require_agent(&state, &headers).await?;
    if id != result.id
        || result.stdout.len() > 256 * 1024
        || result.stderr.len() > 256 * 1024
        || result.finished_at <= 0
        || result.finished_at > now_timestamp() + 60
    {
        return Err(ApiError::BadRequest("命令结果标识、时间或输出无效".into()));
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&result).map_err(anyhow::Error::from)?)
    );
    let mut display = result.clone();
    display.truncated |= storage_output(&mut display.stdout);
    display.truncated |= storage_output(&mut display.stderr);
    let value = serde_json::to_value(display).map_err(anyhow::Error::from)?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "SELECT result_digest,state,lifecycle_version,claim_id,started_at FROM remote_commands WHERE id=$1 AND server_id=$2 FOR UPDATE",
    )
    .bind(id)
    .bind(server)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if let Some(previous) = row.get::<Option<String>, _>("result_digest") {
        if previous != digest {
            return Err(ApiError::Conflict("已完成命令结果不可更改".into()));
        }
    } else {
        let current: String = row.get("state");
        let terminal = serde_json::to_value(&result.status)
            .map_err(anyhow::Error::from)?
            .as_str()
            .unwrap()
            .to_owned();
        if (row.get::<i32, _>("lifecycle_version") > 0
            && row.get::<Option<Uuid>, _>("claim_id").is_none()
            && current != terminal)
            || (matches!(
                current.as_str(),
                "cancelled" | "expired" | "succeeded" | "failed" | "interrupted"
            ) && current != terminal)
            || (terminal == "cancelled"
                && !matches!(current.as_str(), "cancelled" | "cancel_requested"))
            || row
                .get::<Option<i64>, _>("started_at")
                .is_some_and(|started| result.finished_at < started)
        {
            return Err(ApiError::Conflict("命令状态不允许此完成结果".into()));
        }
        sqlx::query("UPDATE remote_commands SET result=$2,result_digest=$3,state=$4,finished_at=$5 WHERE id=$1")
            .bind(id)
            .bind(value)
            .bind(digest)
            .bind(terminal)
            .bind(result.finished_at)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(TaskAck { ids: vec![id] }))
}
