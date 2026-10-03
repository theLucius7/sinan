use super::*;
use sinan_protocol::{CommandClaim, CommandControl, CommandStarted};
use sqlx::postgres::PgRow;

fn snapshot(row: &PgRow) -> ApiResult<CommandControl> {
    Ok(CommandControl {
        id: row.get("id"),
        state: serde_json::from_value(json!(row.get::<String, _>("state")))
            .map_err(anyhow::Error::from)?,
        claimed_at: row.get("claimed_at"),
        started_at: row.get("started_at"),
        cancel_requested_at: row.get("cancel_requested_at"),
        finished_at: row.get("finished_at"),
        cancel_supported: row.get("cancel_supported"),
    })
}

pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((server, id)): Path<(i64, Uuid)>,
) -> ApiResult<Json<CommandControl>> {
    auth::require_admin(&state, &headers).await?;
    expire_queued(&state.pool, server).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM remote_commands WHERE id=$1 AND server_id=$2 FOR UPDATE")
        .bind(id)
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = snapshot(&row)?;
    if !current.state.terminal() && current.state != sinan_protocol::CommandState::CancelRequested {
        let queued = current.state == sinan_protocol::CommandState::Queued;
        if !queued && (row.get::<i32, _>("lifecycle_version") == 0 || !current.cancel_supported) {
            return Err(ApiError::Conflict(
                "设备可能已领取命令，且不能确认运行中取消；请等待执行结果".into(),
            ));
        }
        sqlx::query("UPDATE remote_commands SET state=$2,cancel_requested_at=$3,finished_at=CASE WHEN $4 THEN $3 ELSE NULL END WHERE id=$1")
            .bind(id).bind(if queued { "cancelled" } else { "cancel_requested" })
            .bind(now_timestamp()).bind(queued).execute(&mut *tx).await?;
    }
    let row = sqlx::query("SELECT * FROM remote_commands WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(snapshot(&row)?))
}

pub async fn pending_lifecycle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<RemoteCommand>>> {
    let server = auth::require_agent(&state, &headers).await?;
    expire_queued(&state.pool, server).await?;
    let mut tx = state.pool.begin().await?;
    if command_server(&mut tx, server).await?.1 {
        return Ok(Json(Vec::new()));
    }
    let rows: Vec<Value> = sqlx::query_scalar("SELECT spec FROM remote_commands WHERE server_id=$1 AND state='queued' AND (spec->>'expires_at')::BIGINT>$2 ORDER BY requested_at,id LIMIT 64")
        .bind(server).bind(now_timestamp()).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(anyhow::Error::from)?,
    ))
}

pub async fn claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<CommandClaim>,
) -> ApiResult<Json<CommandControl>> {
    let server = auth::require_agent(&state, &headers).await?;
    if request.claim_id.is_nil() {
        return Err(ApiError::BadRequest("领取标识无效".into()));
    }
    let mut tx = state.pool.begin().await?;
    if command_server(&mut tx, server).await?.1 {
        return Err(ApiError::Conflict("服务器正在退役，不能领取命令".into()));
    }
    let row = sqlx::query("SELECT * FROM remote_commands WHERE id=$1 AND server_id=$2 FOR UPDATE")
        .bind(id)
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = snapshot(&row)?;
    let previous: Option<Uuid> = row.get("claim_id");
    if previous.is_some_and(|claim| claim != request.claim_id)
        || (current.state == sinan_protocol::CommandState::Claimed && previous.is_none())
    {
        return Err(ApiError::Conflict("命令已由其他执行记录领取".into()));
    }
    if current.state == sinan_protocol::CommandState::Queued {
        let spec: RemoteCommand =
            serde_json::from_value(row.get("spec")).map_err(anyhow::Error::from)?;
        if spec.expires_at <= now_timestamp() {
            sqlx::query("UPDATE remote_commands SET state='expired',finished_at=$2 WHERE id=$1")
                .bind(id)
                .bind(now_timestamp())
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("UPDATE remote_commands SET state='claimed',claim_id=$2,claimed_at=$3,lifecycle_version=1 WHERE id=$1")
                .bind(id).bind(request.claim_id).bind(now_timestamp()).execute(&mut *tx).await?;
        }
    }
    let row = sqlx::query("SELECT * FROM remote_commands WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(snapshot(&row)?))
}

pub async fn control(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CommandControl>> {
    let server = auth::require_agent(&state, &headers).await?;
    let row = sqlx::query("SELECT * FROM remote_commands WHERE id=$1 AND server_id=$2")
        .bind(id)
        .bind(server)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(snapshot(&row)?))
}

pub async fn started(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<CommandStarted>,
) -> ApiResult<Json<TaskAck>> {
    let server = auth::require_agent(&state, &headers).await?;
    if request.started_at <= 0 || request.started_at > now_timestamp() + 60 {
        return Err(ApiError::BadRequest("开始时间无效".into()));
    }
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM remote_commands WHERE id=$1 AND server_id=$2 FOR UPDATE")
        .bind(id)
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.get::<Option<Uuid>, _>("claim_id") != Some(request.claim_id)
        || row
            .get::<Option<i64>, _>("started_at")
            .is_some_and(|at| at != request.started_at)
        || row
            .get::<Option<i64>, _>("claimed_at")
            .is_some_and(|at| request.started_at < at)
        || row
            .get::<Option<i64>, _>("finished_at")
            .is_some_and(|at| request.started_at > at)
    {
        return Err(ApiError::Conflict("命令领取记录或开始时间不一致".into()));
    }
    // Late start delivery records history without regressing cancellation or a terminal state.
    sqlx::query("UPDATE remote_commands SET started_at=$2,state=CASE WHEN state='claimed' THEN 'running' ELSE state END WHERE id=$1")
        .bind(id).bind(request.started_at).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(TaskAck { ids: vec![id] }))
}
