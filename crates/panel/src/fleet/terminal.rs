use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::{
    fleet::{TERMINAL_CAPABILITY, TerminalControl, TerminalEvent, TerminalInput},
    now_timestamp,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    account: String,
    columns: u16,
    rows: u16,
    timeout_secs: u32,
}
fn size(columns: u16, rows: u16) -> bool {
    (20..=300).contains(&columns) && (5..=120).contains(&rows)
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(input): Json<Create>,
) -> ApiResult<Json<Value>> {
    let admin =
        crate::control_center::require_server(&state, &headers, server, "terminal:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    if !size(input.columns, input.rows) || !(30..=1800).contains(&input.timeout_secs) {
        return Err(ApiError::BadRequest("终端窗口或会话时长无效".into()));
    }
    let session_hash = auth::security::session_hash(&headers)?;
    let mut tx = state.pool.begin().await?;
    lock_interactive_actor(&mut tx, server, admin, &session_hash, "terminal:write").await?;
    lock_recent_proof(&mut tx, &session_hash).await?;
    super::ensure_accepts_tasks_tx(&mut tx, server).await?;
    let cap: Value = sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&mut *tx)
        .await?;
    if !cap
        .as_array()
        .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(TERMINAL_CAPABILITY)))
    {
        return Err(ApiError::Conflict(
            "Agent 尚未启用独立 PTY 终端，需要 Linux、python3 和本机账号授权".into(),
        ));
    }
    let policy = super::policy(&mut tx, server).await?;
    if !policy.terminal_accounts.contains(&input.account) {
        return Err(ApiError::Conflict("执行账号未获此服务器终端授权".into()));
    }
    let active:i64=sqlx::query_scalar("SELECT count(*) FROM fleet_terminal_sessions WHERE server_id=$1 AND status IN ('queued','running') AND expires_at>$2").bind(server).bind(now_timestamp()).fetch_one(&mut *tx).await?;
    if active >= 2 {
        return Err(ApiError::Conflict(
            "每台服务器最多同时存在两个终端会话".into(),
        ));
    }
    let id = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO fleet_terminal_sessions(id,server_id,admin_id,account,admin_session_hash,policy,columns,rows,created_at,expires_at,last_input_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$9)")
        .bind(id).bind(server).bind(admin).bind(input.account).bind(session_hash).bind(json!(policy)).bind(i32::from(input.columns)).bind(i32::from(input.rows)).bind(now).bind(now+i64::from(input.timeout_secs)).execute(&mut *tx).await?;
    super::record(
        &mut tx,
        server,
        "terminal_opened",
        json!({"id":id,"admin_id":admin,"timeout_secs":input.timeout_secs}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"status":"queued","expires_at":now+i64::from(input.timeout_secs)}),
    ))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Vec<Value>>> {
    crate::control_center::require_server(&state, &headers, server, "terminal:read").await?;
    let sessions=sqlx::query_scalar("SELECT to_jsonb(s)-'policy'-'admin_session_hash' FROM fleet_terminal_sessions s WHERE server_id=$1 ORDER BY created_at DESC LIMIT 50").bind(server).fetch_all(&state.pool).await?;
    Ok(Json(sessions))
}

async fn authorize(state: &AppState, headers: &HeaderMap, id: Uuid, cap: &str) -> ApiResult<i64> {
    let server: i64 =
        sqlx::query_scalar("SELECT server_id FROM fleet_terminal_sessions WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    crate::control_center::require_server(state, headers, server, cap).await?;
    Ok(server)
}

async fn authorize_interactive(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    capability: &str,
) -> ApiResult<(i64, i64, String)> {
    let actor = crate::control_center::authenticate(state, headers).await?;
    if actor.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "终端输入和输出需要创建会话的管理员登录会话".into(),
        ));
    }
    let hash = auth::security::session_hash(headers)?;
    let row = sqlx::query(
        "SELECT server_id,admin_id,admin_session_hash FROM fleet_terminal_sessions WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let server: i64 = row.get("server_id");
    if !actor.allows(capability)
        || !actor.allows_server(server)
        || actor.admin_id != row.get::<i64, _>("admin_id")
        || hash != row.get::<String, _>("admin_session_hash")
    {
        return Err(ApiError::Forbidden(
            "只有创建终端的管理员登录会话可以读取输出或发送输入".into(),
        ));
    }
    Ok((server, actor.admin_id, hash))
}

async fn lock_interactive_actor(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    admin: i64,
    hash: &str,
    capability: &str,
) -> ApiResult<()> {
    // Pin authorization before server/session locks. NOWAIT prevents waiting
    // for reauthentication, which may acquire these rows in the reverse order.
    let profile = authorization_lock(sqlx::query("SELECT role,all_servers,capabilities FROM administrator_profiles WHERE admin_id=$1 AND enabled FOR SHARE NOWAIT")
        .bind(admin).fetch_optional(&mut **tx).await)?.ok_or(ApiError::Unauthorized)?;
    authorization_lock(sqlx::query("SELECT token_hash FROM sessions WHERE token_hash=$1 AND admin_id=$2 AND expires_at>$3 FOR SHARE NOWAIT")
        .bind(hash).bind(admin).bind(now_timestamp()).fetch_optional(&mut **tx).await)?.ok_or(ApiError::Unauthorized)?;
    let role: String = profile.get("role");
    let capabilities: Value = profile.get("capabilities");
    let granted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM administrator_server_grants WHERE admin_id=$1 AND server_id=$2)")
        .bind(admin).bind(server).fetch_one(&mut **tx).await?;
    if (role != "owner"
        && !capabilities
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(capability))))
        || (role == "viewer" && capability.ends_with(":write"))
        || (!profile.get::<bool, _>("all_servers") && !granted)
    {
        return Err(ApiError::Forbidden("管理员已失去此服务器终端权限".into()));
    }
    Ok(())
}

fn authorization_lock<T>(result: Result<T, sqlx::Error>) -> ApiResult<T> {
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

async fn lock_recent_proof(tx: &mut Transaction<'_, Postgres>, hash: &str) -> ApiResult<()> {
    authorization_lock(sqlx::query("SELECT session_hash FROM administrator_reauth WHERE session_hash=$1 AND expires_at>$2 FOR SHARE NOWAIT")
        .bind(hash).bind(now_timestamp()).fetch_optional(&mut **tx).await)?.ok_or_else(||ApiError::Forbidden("终端输入需要当前登录会话的有效再次验证".into()))?;
    Ok(())
}
#[derive(Deserialize)]
pub struct Cursor {
    #[serde(default)]
    after: i64,
}
pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(cursor): Query<Cursor>,
) -> ApiResult<Json<Value>> {
    let (server, admin, hash) =
        authorize_interactive(&state, &headers, id, "terminal:read").await?;
    let mut tx = state.pool.begin().await?;
    lock_interactive_actor(&mut tx, server, admin, &hash, "terminal:read").await?;
    let session:Value=sqlx::query_scalar("SELECT to_jsonb(s)-'policy'-'admin_session_hash' FROM fleet_terminal_sessions s WHERE id=$1 AND admin_id=$2 AND admin_session_hash=$3").bind(id).bind(admin).bind(&hash).fetch_one(&mut *tx).await?;
    let output:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('sequence',sequence,'data',data) FROM fleet_terminal_outputs WHERE session_id=$1 AND sequence>$2 ORDER BY sequence LIMIT 64").bind(id).bind(cursor.after).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"session":session,"output":output})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    data: String,
    columns: Option<u16>,
    rows: Option<u16>,
}
pub async fn input(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Input>,
) -> ApiResult<Json<Value>> {
    let (server, admin, hash) =
        authorize_interactive(&state, &headers, id, "terminal:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    if input.data.len() > 8192
        || input.columns.is_some() != input.rows.is_some()
        || input
            .columns
            .zip(input.rows)
            .is_some_and(|(c, r)| !size(c, r))
    {
        return Err(ApiError::BadRequest("输入超过 8 KiB 或窗口尺寸无效".into()));
    }
    let mut tx = state.pool.begin().await?;
    lock_interactive_actor(&mut tx, server, admin, &hash, "terminal:write").await?;
    lock_recent_proof(&mut tx, &hash).await?;
    super::ensure_terminal_input_tx(&mut tx, server).await?;
    let capabilities: Value = sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&mut *tx)
        .await?;
    if !capabilities.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.as_str() == Some(TERMINAL_CAPABILITY))
    }) {
        return Err(ApiError::Conflict(
            "Agent 当前不具备终端能力；仍可请求强制关闭".into(),
        ));
    }
    let row=sqlx::query("SELECT account,policy FROM fleet_terminal_sessions WHERE id=$1 AND admin_id=$2 AND admin_session_hash=$3 AND NOT close_requested AND status IN ('queued','running') AND expires_at>$4 FOR UPDATE")
        .bind(id).bind(admin).bind(&hash).bind(now_timestamp()).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::Conflict("终端已关闭或超时".into()))?;
    let account: String = row.get("account");
    let original: sinan_protocol::fleet::AccessPolicy =
        serde_json::from_value(row.get("policy")).map_err(anyhow::Error::from)?;
    let current = super::policy(&mut tx, server).await?;
    if !original.terminal_accounts.contains(&account)
        || !current.terminal_accounts.contains(&account)
    {
        return Err(ApiError::Conflict(
            "终端执行账号已失去服务器授权；仍可请求强制关闭".into(),
        ));
    }
    // Eligibility rows remain pinned, but their deadlines can elapse while
    // waiting for the server or terminal row. Recheck immediately before input.
    lock_interactive_actor(&mut tx, server, admin, &hash, "terminal:write").await?;
    lock_recent_proof(&mut tx, &hash).await?;
    let row=sqlx::query("UPDATE fleet_terminal_sessions SET input_sequence=input_sequence+1,last_input_at=$2 WHERE id=$1 RETURNING input_sequence")
        .bind(id).bind(now_timestamp()).fetch_one(&mut *tx).await?;
    let sequence: i64 = row.get("input_sequence");
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fleet_terminal_inputs WHERE session_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if count >= 64 {
        return Err(ApiError::Conflict("输入积压，请等待 Agent 接收".into()));
    }
    sqlx::query("INSERT INTO fleet_terminal_inputs(session_id,sequence,data,columns,rows) VALUES($1,$2,$3,$4,$5)").bind(id).bind(sequence).bind(input.data).bind(input.columns.map(i32::from)).bind(input.rows.map(i32::from)).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"queued":sequence})))
}

pub async fn close(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let server = authorize(&state, &headers, id, "terminal:write").await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE fleet_terminal_sessions SET close_requested=TRUE WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    super::record(
        &mut tx,
        server,
        "terminal_close_requested",
        json!({"id":id}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"status":"close_requested","process_stopped":false}),
    ))
}

pub(super) async fn controls(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    allowed: bool,
) -> ApiResult<Vec<TerminalControl>> {
    let now = now_timestamp();
    sqlx::query("UPDATE fleet_terminal_sessions SET close_requested=TRUE WHERE server_id=$1 AND status IN ('queued','running') AND (expires_at<=$2 OR last_input_at<=$2-300 OR NOT $3 OR NOT EXISTS(SELECT 1 FROM sessions a WHERE a.token_hash=fleet_terminal_sessions.admin_session_hash AND a.admin_id=fleet_terminal_sessions.admin_id AND a.expires_at>$2) OR NOT EXISTS(SELECT 1 FROM fleet_profiles p WHERE p.server_id=$1 AND p.policy->'terminal_accounts' ? fleet_terminal_sessions.account))").bind(server).bind(now).bind(allowed).execute(&mut **tx).await?;
    let rows=sqlx::query("SELECT id,admin_id,account,policy,columns,rows,expires_at,close_requested,output_sequence FROM fleet_terminal_sessions WHERE server_id=$1 AND status IN ('queued','running') ORDER BY created_at LIMIT 2").bind(server).fetch_all(&mut **tx).await?;
    let mut controls = Vec::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let actor_allowed = crate::control_center::actor_server_allowed(
            &state.pool,
            row.get("admin_id"),
            server,
            "terminal:write",
        )
        .await?;
        if !actor_allowed {
            sqlx::query("UPDATE fleet_terminal_sessions SET close_requested=TRUE WHERE id=$1")
                .bind(id)
                .execute(&mut **tx)
                .await?;
        }
        let inputs=sqlx::query("SELECT sequence,data,columns,rows FROM fleet_terminal_inputs WHERE session_id=$1 ORDER BY sequence LIMIT 16").bind(id).fetch_all(&mut **tx).await?.into_iter().map(|r|TerminalInput{sequence:r.get("sequence"),data:r.get("data"),columns:r.get::<Option<i32>,_>("columns").map(|v|v as u16),rows:r.get::<Option<i32>,_>("rows").map(|v|v as u16)}).collect();
        controls.push(TerminalControl {
            id,
            account: row.get("account"),
            policy: serde_json::from_value(row.get("policy")).map_err(anyhow::Error::from)?,
            columns: row.get::<i32, _>("columns") as u16,
            rows: row.get::<i32, _>("rows") as u16,
            expires_at: row.get("expires_at"),
            close_requested: row.get::<bool, _>("close_requested") || !actor_allowed,
            output_sequence: row.get("output_sequence"),
            inputs,
        });
    }
    Ok(controls)
}

pub async fn event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<TerminalEvent>,
) -> ApiResult<Json<Value>> {
    let server = auth::require_agent(&state, &headers).await?;
    if event.sequence <= 0
        || event.input_sequence < 0
        || event.output.len() > 32768
        || event.output.contains('\0')
        || !["running", "closed", "failed"].contains(&event.state.as_str())
        || event.error.as_ref().is_some_and(|error| error.len() > 2048)
    {
        return Err(ApiError::BadRequest("终端事件格式无效".into()));
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&event).map_err(anyhow::Error::from)?)
    );
    let mut tx = state.pool.begin().await?;
    let row=sqlx::query("SELECT status,output_sequence,output_bytes,input_sequence FROM fleet_terminal_sessions WHERE id=$1 AND server_id=$2 FOR UPDATE").bind(event.id).bind(server).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let previous: i64 = row.get("output_sequence");
    if event.sequence <= previous {
        let old: Option<String> = sqlx::query_scalar(
            "SELECT digest FROM fleet_terminal_outputs WHERE session_id=$1 AND sequence=$2",
        )
        .bind(event.id)
        .bind(event.sequence)
        .fetch_optional(&mut *tx)
        .await?;
        if old.as_deref() != Some(digest.as_str()) {
            return Err(ApiError::Conflict(
                "终端事件已改变或超出重放保留范围".into(),
            ));
        }
        tx.commit().await?;
        return Ok(Json(json!({"acknowledged":event.sequence})));
    }
    if ["closed", "failed"].contains(&row.get::<String, _>("status").as_str())
        && event.state == "running"
    {
        return Err(ApiError::Conflict("已结束终端不能恢复运行".into()));
    }
    if event.sequence != previous + 1 || event.input_sequence > row.get::<i64, _>("input_sequence")
    {
        return Err(ApiError::Conflict("终端事件序号不连续".into()));
    }
    let output_bytes = row.get::<i64, _>("output_bytes") + event.output.len() as i64;
    sqlx::query("INSERT INTO fleet_terminal_outputs(session_id,sequence,data,digest,created_at) VALUES($1,$2,$3,$4,$5)").bind(event.id).bind(event.sequence).bind(&event.output).bind(digest).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE fleet_terminal_sessions SET status=$2,output_sequence=$3,output_bytes=$4,error=$5,close_requested=close_requested OR $4>4194304 WHERE id=$1")
        .bind(event.id).bind(&event.state).bind(event.sequence).bind(output_bytes).bind(event.error).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM fleet_terminal_inputs WHERE session_id=$1 AND sequence<=$2")
        .bind(event.id)
        .bind(event.input_sequence)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM fleet_terminal_outputs WHERE session_id=$1 AND sequence<$2-128")
        .bind(event.id)
        .bind(event.sequence)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({"acknowledged":event.sequence})))
}
