use super::{
    access::{session_hash, valid_capability},
    authenticate, require_owner, require_recent_proof,
};
use crate::{
    AppState,
    auth::{hash_token, random_token},
    error::{ApiError, ApiResult},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministratorInput {
    login_name: String,
    display_name: String,
    role: String,
    #[serde(default)]
    all_servers: bool,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    server_ids: Vec<i64>,
    password: Option<String>,
    expected_revision: Option<i64>,
    #[serde(default = "enabled_default")]
    enabled: bool,
}
fn enabled_default() -> bool {
    true
}
async fn validate(state: &AppState, input: &AdministratorInput) -> ApiResult<()> {
    if input.login_name.is_empty()
        || input.login_name.len() > 100
        || !input
            .login_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        || input.display_name.trim().is_empty()
        || input.display_name.len() > 200
        || !["owner", "operator", "viewer"].contains(&input.role.as_str())
        || input.capabilities.len() > 64
        || input.server_ids.len() > 1000
    {
        return Err(ApiError::BadRequest(
            "管理员名称、角色或授权范围无效".into(),
        ));
    }
    if input
        .capabilities
        .iter()
        .any(|cap| !valid_capability(cap) || (input.role == "viewer" && cap.ends_with(":write")))
    {
        return Err(ApiError::BadRequest(
            "能力标识无效，只读角色不可授予写入能力".into(),
        ));
    }
    for id in &input.server_ids {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL)",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
        if !exists {
            return Err(ApiError::BadRequest("授权服务器已不存在".into()));
        }
    }
    Ok(())
}
async fn password_hash(password: String) -> ApiResult<String> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(ApiError::BadRequest("管理员密码须为12至1024字节".into()));
    }
    tokio::task::spawn_blocking(move || {
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);
        let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(ApiError::Internal)
}
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    let rows=sqlx::query("SELECT p.*,COALESCE((SELECT jsonb_agg(server_id ORDER BY server_id) FROM administrator_server_grants g WHERE g.admin_id=p.admin_id),'[]') AS server_ids FROM administrator_profiles p ORDER BY admin_id").fetch_all(&state.pool).await?;
    let values:Vec<Value>=rows.iter().map(|r|Ok(json!({"id":r.try_get::<i64,_>("admin_id")?,"login_name":r.try_get::<String,_>("login_name")?,"display_name":r.try_get::<String,_>("display_name")?,"role":r.try_get::<String,_>("role")?,"enabled":r.try_get::<bool,_>("enabled")?,"all_servers":r.try_get::<bool,_>("all_servers")?,"capabilities":r.try_get::<Value,_>("capabilities")?,"server_ids":r.try_get::<Value,_>("server_ids")?,"revision":r.try_get::<i64,_>("revision")?}))).collect::<Result<_,sqlx::Error>>()?;
    Ok(Json(
        json!({"administrators":values,"features":super::access::FEATURES}),
    ))
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AdministratorInput>,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    validate(&state, &input).await?;
    let hash = password_hash(
        input
            .password
            .clone()
            .ok_or_else(|| ApiError::BadRequest("新管理员需要独立密码".into()))?,
    )
    .await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(73002001)")
        .execute(&mut *tx)
        .await?;
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM administrator_profiles WHERE login_name=$1)",
    )
    .bind(&input.login_name)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(ApiError::Conflict("登录名已被使用，请选择独立名称".into()));
    }
    let id: i64 = sqlx::query_scalar("INSERT INTO admins(password_hash) VALUES($1) RETURNING id")
        .bind(hash)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,enabled,all_servers,capabilities,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)")
        .bind(id).bind(input.login_name).bind(input.display_name).bind(&input.role).bind(input.enabled).bind(input.all_servers || input.role=="owner").bind(json!(input.capabilities)).bind(now_timestamp()).execute(&mut *tx).await?;
    for server in input.server_ids {
        sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(id).bind(server).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"id":id,"revision":1})))
}
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<AdministratorInput>,
) -> ApiResult<Json<Value>> {
    let actor = require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    validate(&state, &input).await?;
    let hash = match input.password.clone() {
        Some(password) => Some(password_hash(password).await?),
        None => None,
    };
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(73002001)")
        .execute(&mut *tx)
        .await?;
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM administrator_profiles WHERE login_name=$1 AND admin_id<>$2)",
    )
    .bind(&input.login_name)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(ApiError::Conflict("登录名已被使用，请选择独立名称".into()));
    }
    let row = sqlx::query("SELECT * FROM administrator_profiles WHERE admin_id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let revision: i64 = row.try_get("revision")?;
    if input.expected_revision != Some(revision) {
        return Err(ApiError::Conflict(
            "管理员授权已变更，请刷新后重新确认".into(),
        ));
    }
    if row.try_get::<String, _>("role")? == "owner"
        && row.try_get::<bool, _>("enabled")?
        && (!input.enabled || input.role != "owner")
    {
        let owners: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM administrator_profiles WHERE role='owner' AND enabled",
        )
        .fetch_one(&mut *tx)
        .await?;
        if owners <= 1 {
            return Err(ApiError::Conflict("必须保留至少一个可登录的所有者".into()));
        }
    }
    if actor == id && !input.enabled {
        return Err(ApiError::Conflict("不能停用当前会话所属管理员".into()));
    }
    sqlx::query("UPDATE administrator_profiles SET login_name=$2,display_name=$3,role=$4,enabled=$5,all_servers=$6,capabilities=$7,revision=revision+1,updated_at=$8 WHERE admin_id=$1")
        .bind(id).bind(input.login_name).bind(input.display_name).bind(&input.role).bind(input.enabled).bind(input.all_servers || input.role=="owner").bind(json!(input.capabilities)).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM administrator_server_grants WHERE admin_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for server in input.server_ids {
        sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2) ON CONFLICT DO NOTHING").bind(id).bind(server).execute(&mut *tx).await?;
    }
    if let Some(hash) = hash {
        sqlx::query("UPDATE admins SET password_hash=$2 WHERE id=$1")
            .bind(id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
    }
    // Existing sessions are revoked after any scope or security change.
    sqlx::query("DELETE FROM sessions WHERE admin_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE management_api_tokens SET revoked_at=$2 WHERE admin_id=$1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now_timestamp())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"revision":revision+1,"sessions_revoked":true}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInput {
    name: String,
    capabilities: Vec<String>,
    #[serde(default)]
    server_ids: Vec<i64>,
    #[serde(default)]
    all_servers: bool,
    expires_at: i64,
}
pub async fn tokens(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = require_owner(&state, &headers).await?;
    let rows=sqlx::query("SELECT id,name,capabilities,server_ids,all_servers,expires_at,revoked_at,last_used_at FROM management_api_tokens WHERE admin_id=$1 ORDER BY created_at DESC LIMIT 200").bind(actor).fetch_all(&state.pool).await?;
    let values:Vec<Value>=rows.iter().map(|r|Ok(json!({"id":r.try_get::<Uuid,_>("id")?,"name":r.try_get::<String,_>("name")?,"capabilities":r.try_get::<Value,_>("capabilities")?,"server_ids":r.try_get::<Value,_>("server_ids")?,"all_servers":r.try_get::<bool,_>("all_servers")?,"expires_at":r.try_get::<i64,_>("expires_at")?,"revoked_at":r.try_get::<Option<i64>,_>("revoked_at")?,"last_used_at":r.try_get::<Option<i64>,_>("last_used_at")?}))).collect::<Result<_,sqlx::Error>>()?;
    Ok(Json(json!(values)))
}
pub async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TokenInput>,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    let actor = authenticate(&state, &headers).await?;
    let now = now_timestamp();
    if input.name.trim().is_empty()
        || input.name.len() > 200
        || input.expires_at <= now
        || input.expires_at > now + 366 * 86400
        || input.capabilities.is_empty()
        || input.capabilities.len() > 64
        || input.capabilities.iter().any(|cap| !actor.allows(cap))
        || input.server_ids.len() > 1000
        || input.server_ids.iter().any(|id| !actor.allows_server(*id))
    {
        return Err(ApiError::BadRequest("令牌名称、期限或授权范围无效".into()));
    }
    if input.all_servers && !actor.global_servers() {
        return Err(ApiError::Forbidden("不能扩大令牌服务器范围".into()));
    }
    let mut selected = input.server_ids.clone();
    selected.sort_unstable();
    selected.dedup();
    let existing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM servers WHERE id=ANY($1) AND deleted_at IS NULL")
            .bind(&selected)
            .fetch_one(&state.pool)
            .await?;
    if existing as usize != selected.len() {
        return Err(ApiError::BadRequest(
            "令牌授权只能选择当前存在的服务器".into(),
        ));
    }
    let token = format!("sinan_api_{}", random_token());
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(id).bind(actor.admin_id).bind(hash_token(&token)).bind(input.name).bind(json!(input.capabilities)).bind(json!(input.server_ids)).bind(input.all_servers).bind(input.expires_at).bind(now).execute(&state.pool).await?;
    Ok(Json(
        json!({"id":id,"token":token,"shown_once":true,"expires_at":input.expires_at}),
    ))
}
pub async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let actor = require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    if sqlx::query("UPDATE management_api_tokens SET revoked_at=$3 WHERE id=$1 AND admin_id=$2 AND revoked_at IS NULL").bind(id).bind(actor).bind(now_timestamp()).execute(&state.pool).await?.rows_affected()!=1 { return Err(ApiError::NotFound); }
    Ok(Json(json!({"revoked":true})))
}
pub async fn sessions(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    if actor.token_id.is_some() {
        return Err(ApiError::Forbidden("API令牌不能读取管理员会话".into()));
    }
    let current = session_hash(&headers);
    let rows=sqlx::query("SELECT token_hash,expires_at FROM sessions WHERE admin_id=$1 AND expires_at>$2 ORDER BY expires_at DESC LIMIT 100").bind(actor.admin_id).bind(now_timestamp()).fetch_all(&state.pool).await?;
    let values:Vec<Value>=rows.iter().map(|r| { let id:String=r.try_get("token_hash")?;Ok(json!({"id":id,"current":current.as_ref()==Some(&id),"expires_at":r.try_get::<i64,_>("expires_at")?})) }).collect::<Result<_,sqlx::Error>>()?;
    Ok(Json(json!(values)))
}
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("会话标识无效".into()));
    }
    if sqlx::query("DELETE FROM sessions WHERE token_hash=$1 AND admin_id=$2")
        .bind(id)
        .bind(actor.admin_id)
        .execute(&state.pool)
        .await?
        .rows_affected()
        != 1
    {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({"revoked":true})))
}
