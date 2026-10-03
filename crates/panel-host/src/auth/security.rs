use super::{cookie_token, hash_token, rate_limit, require_admin, totp, verified_password};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use data_encoding::BASE32_NOPAD;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRequest {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRequest {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableRequest {
    password: String,
    code: String,
}

fn reply(value: Value) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) async fn locked_admin(
    tx: &mut Transaction<'_, Postgres>,
    session: &str,
) -> ApiResult<PgRow> {
    let row = sqlx::query("SELECT * FROM admins WHERE id = 1 FOR UPDATE")
        .fetch_one(&mut **tx)
        .await?;
    let valid = sqlx::query("SELECT admin_id FROM sessions WHERE token_hash = $1 AND admin_id = 1 AND expires_at > $2 FOR UPDATE")
        .bind(session).bind(now_timestamp()).fetch_optional(&mut **tx).await?;
    if valid.is_none() {
        return Err(ApiError::Unauthorized);
    }
    Ok(row)
}

pub(super) fn session_hash(headers: &HeaderMap) -> ApiResult<String> {
    cookie_token(headers)
        .map(hash_token)
        .ok_or(ApiError::Unauthorized)
}

pub(super) async fn revoke_other_sessions(
    tx: &mut Transaction<'_, Postgres>,
    current: &str,
) -> ApiResult<()> {
    crate::passkeys::revoke(tx, crate::passkeys::ADMIN).await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id = 1 AND token_hash <> $1")
        .bind(current)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn totp_status(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    require_admin(&state, &headers).await?;
    let row = sqlx::query(
        "SELECT totp_secret IS NOT NULL AS enabled, totp_pending_expires FROM admins WHERE id = 1",
    )
    .fetch_one(&state.pool)
    .await?;
    let pending = row
        .try_get::<Option<i64>, _>("totp_pending_expires")?
        .filter(|expiry| *expiry > now_timestamp());
    Ok(reply(
        json!({"enabled": row.try_get::<bool, _>("enabled")?, "pending_expires_at": pending}),
    ))
}

pub async fn totp_setup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SetupRequest>,
) -> ApiResult<Response> {
    require_admin(&state, &headers).await?;
    let session = session_hash(&headers)?;
    let permit = state
        .login_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    rate_limit::consume(&state.pool, peer).await?;
    let (hash, _permit) = verified_password(&state, request.password, permit).await?;
    let hash = hash.ok_or_else(|| ApiError::BadRequest("密码不正确".into()))?;
    let mut tx = state.pool.begin().await?;
    let row = locked_admin(&mut tx, &session).await?;
    if row.try_get::<String, _>("password_hash")? != hash {
        return Err(ApiError::Unauthorized);
    }
    if row.try_get::<Option<Vec<u8>>, _>("totp_secret")?.is_some() {
        return Err(ApiError::Conflict(
            "已启用二步验证，请先验证并关闭后再更换".into(),
        ));
    }
    let mut secret = [0_u8; 20];
    OsRng.fill_bytes(&mut secret);
    let expires = now_timestamp() + 300;
    sqlx::query("UPDATE admins SET totp_pending_secret = $1, totp_pending_expires = $2, totp_pending_session = $3 WHERE id = 1")
        .bind(secret.as_slice()).bind(expires).bind(&session).execute(&mut *tx).await?;
    tx.commit().await?;
    let secret = BASE32_NOPAD.encode(&secret);
    Ok(reply(
        json!({"secret": secret, "otpauth_uri": format!("otpauth://totp/Sinan:admin?secret={secret}&issuer=Sinan&algorithm=SHA1&digits=6&period=30"), "expires_at": expires}),
    ))
}

pub async fn totp_confirm(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CodeRequest>,
) -> ApiResult<Response> {
    require_admin(&state, &headers).await?;
    let session = session_hash(&headers)?;
    let _permit = state
        .login_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    rate_limit::consume(&state.pool, peer).await?;
    let mut tx = state.pool.begin().await?;
    let row = locked_admin(&mut tx, &session).await?;
    let now = now_timestamp();
    let secret = row
        .try_get::<Option<Vec<u8>>, _>("totp_pending_secret")?
        .ok_or_else(|| ApiError::Conflict("请先开始二步验证设置".into()))?;
    if row.try_get::<Option<Vec<u8>>, _>("totp_secret")?.is_some()
        || row
            .try_get::<Option<i64>, _>("totp_pending_expires")?
            .is_none_or(|expiry| expiry <= now)
        || row
            .try_get::<Option<String>, _>("totp_pending_session")?
            .as_deref()
            != Some(&session)
    {
        return Err(ApiError::Conflict(
            "设置已失效，请在当前会话重新开始".into(),
        ));
    }
    let step = totp::verify(&secret, &request.code, now, None)
        .ok_or_else(|| ApiError::BadRequest("验证码不正确或已过期".into()))?;
    sqlx::query("UPDATE admins SET totp_secret = $1, totp_last_step = $2, totp_pending_secret = NULL, totp_pending_expires = NULL, totp_pending_session = NULL WHERE id = 1")
        .bind(secret).bind(step).execute(&mut *tx).await?;
    revoke_other_sessions(&mut tx, &session).await?;
    tx.commit().await?;
    Ok(reply(json!({"enabled": true})))
}

pub async fn totp_disable(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<DisableRequest>,
) -> ApiResult<Response> {
    require_admin(&state, &headers).await?;
    let session = session_hash(&headers)?;
    let permit = state
        .login_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    rate_limit::consume(&state.pool, peer).await?;
    let (hash, _permit) = verified_password(&state, request.password, permit).await?;
    let hash = hash.ok_or_else(|| ApiError::BadRequest("密码或验证码不正确".into()))?;
    let mut tx = state.pool.begin().await?;
    let row = locked_admin(&mut tx, &session).await?;
    if row.try_get::<String, _>("password_hash")? != hash {
        return Err(ApiError::Unauthorized);
    }
    let secret = row
        .try_get::<Option<Vec<u8>>, _>("totp_secret")?
        .ok_or_else(|| ApiError::Conflict("尚未启用二步验证".into()))?;
    totp::verify(
        &secret,
        &request.code,
        now_timestamp(),
        row.try_get("totp_last_step")?,
    )
    .ok_or_else(|| ApiError::BadRequest("密码或验证码不正确、已过期或已使用".into()))?;
    sqlx::query("UPDATE admins SET totp_secret = NULL, totp_last_step = NULL, totp_pending_secret = NULL, totp_pending_expires = NULL, totp_pending_session = NULL WHERE id = 1")
        .execute(&mut *tx).await?;
    revoke_other_sessions(&mut tx, &session).await?;
    tx.commit().await?;
    Ok(reply(json!({"enabled": false})))
}
