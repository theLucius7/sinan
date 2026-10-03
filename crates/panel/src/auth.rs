use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Row};
use std::net::SocketAddr;

pub(crate) mod passkeys;
pub(crate) mod proof;
pub(crate) mod rate_limit;
pub(crate) mod security;
mod totp;

pub use security::{totp_confirm, totp_disable, totp_setup, totp_status};

const ADMIN_SESSION_SECONDS: i64 = 86_400;

pub fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub async fn ensure_admin(pool: &PgPool, password: Option<&str>) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM admins WHERE id = 1)")
        .fetch_one(pool)
        .await?;
    if exists {
        return Ok(());
    }
    let password = password
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("SINAN_ADMIN_PASSWORD is required for the initial administrator")
        })?
        .to_owned();
    if password.len() > 1024 {
        anyhow::bail!("initial administrator password exceeds 1024 bytes");
    }
    let hash = tokio::task::spawn_blocking(move || {
        let mut salt = [0_u8; 16];
        OsRng.fill_bytes(&mut salt);
        let salt =
            SaltString::encode_b64(&salt).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    })
    .await??;
    sqlx::query(
        "INSERT INTO admins (id, password_hash) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
    )
    .bind(hash)
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,created_at,updated_at) VALUES(1,'admin','所有者','owner',true,$1,$1) ON CONFLICT(admin_id) DO NOTHING")
        .bind(now_timestamp()).execute(pool).await?;
    Ok(())
}

/// Device sessions are reissued on every reconnect; expired rows must not wait
/// for the next administrator login before they are removed.
pub async fn purge_expired_sessions(pool: &PgPool, now: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn require_admin(state: &AppState, headers: &HeaderMap) -> ApiResult<i64> {
    Ok(crate::control_center::authenticate(state, headers)
        .await?
        .admin_id)
}

pub async fn require_agent(state: &AppState, headers: &HeaderMap) -> ApiResult<i64> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(ApiError::Unauthorized)?;
    sqlx::query_scalar::<_, i64>("SELECT sessions.server_id FROM sessions JOIN servers ON servers.id = sessions.server_id WHERE sessions.token_hash = $1 AND sessions.server_id IS NOT NULL AND sessions.expires_at > $2 AND servers.deleted_at IS NULL")
        .bind(hash_token(token)).bind(now_timestamp()).fetch_optional(&state.pool).await?.ok_or(ApiError::Unauthorized)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
}

pub(crate) async fn verified_admin_password(
    state: &AppState,
    admin_id: i64,
    password: String,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> ApiResult<(Option<String>, tokio::sync::OwnedSemaphorePermit)> {
    if password.is_empty() || password.len() > 1024 {
        return Ok((None, permit));
    }
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM admins WHERE id = $1")
        .bind(admin_id)
        .fetch_one(&state.pool)
        .await?;
    let expected = hash.clone();
    let (verified, permit) = tokio::task::spawn_blocking(move || {
        let verified = PasswordHash::new(&expected).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        });
        (verified, permit)
    })
    .await
    .map_err(anyhow::Error::from)?;
    Ok((verified.then_some(hash), permit))
}

#[derive(Deserialize)]
pub struct NamedLoginRequest {
    #[serde(default)]
    pub login_name: Option<String>,
    #[serde(flatten)]
    pub credentials: LoginRequest,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<NamedLoginRequest>,
) -> ApiResult<Response> {
    let login_name = request
        .login_name
        .as_deref()
        .unwrap_or("admin")
        .chars()
        .take(100)
        .collect::<String>();
    let result = login_inner(state.clone(), peer, request).await;
    if result.is_err()
        && let Err(error)=sqlx::query("INSERT INTO management_audit(action,object_path,request_diff,result,occurred_at) VALUES('login','/api/login',$1,$2,$3)")
            .bind(json!({"login_name":login_name,"factor":"password"})).bind(json!({"phase":"authentication-denied","success":false})).bind(now_timestamp()).execute(&state.pool).await {
            tracing::warn!(%error,"authentication denial audit failed");
    }
    result
}

async fn login_inner(
    state: AppState,
    peer: SocketAddr,
    request: NamedLoginRequest,
) -> ApiResult<Response> {
    let permit = state
        .login_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    rate_limit::consume(&state.pool, peer).await?;
    let login_name = request.login_name.as_deref().unwrap_or("admin");
    if login_name.is_empty() || login_name.len() > 100 {
        return Err(ApiError::Unauthorized);
    }
    let admin_id: i64 = sqlx::query_scalar(
        "SELECT admin_id FROM administrator_profiles WHERE login_name=$1 AND enabled",
    )
    .bind(login_name)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let request = request.credentials;
    let (verified_hash, _permit) =
        verified_admin_password(&state, admin_id, request.password, permit).await?;
    let verified_hash = verified_hash.ok_or(ApiError::Unauthorized)?;
    let token = random_token();
    let mut transaction = state.pool.begin().await?;
    let admin = sqlx::query(
        "SELECT a.password_hash,a.totp_secret,a.totp_last_step FROM admins a JOIN administrator_profiles p ON p.admin_id=a.id WHERE a.id=$1 AND p.enabled FOR UPDATE OF a,p",
    )
    .bind(admin_id)
    .fetch_optional(&mut *transaction)
    .await?.ok_or(ApiError::Unauthorized)?;
    let now = now_timestamp();
    if admin.try_get::<String, _>("password_hash")? != verified_hash {
        return Err(ApiError::Unauthorized);
    }
    if let Some(secret) = admin.try_get::<Option<Vec<u8>>, _>("totp_secret")? {
        let step = totp::verify(
            &secret,
            request.totp_code.as_deref().unwrap_or(""),
            now,
            admin.try_get("totp_last_step")?,
        )
        .ok_or(ApiError::Unauthorized)?;
        sqlx::query("UPDATE admins SET totp_last_step = $1 WHERE id = $2")
            .bind(step)
            .bind(admin_id)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO sessions (token_hash, admin_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_token(&token))
        .bind(admin_id)
        .bind(now + ADMIN_SESSION_SECONDS)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)",
    )
    .bind(hash_token(&token))
    .bind(now)
    .bind(now + 300)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO management_audit(admin_id,action,object_path,request_diff,result,occurred_at) VALUES($1,'login','/api/login',$2,$3,$4)")
        .bind(admin_id).bind(json!({"factor":"password"})).bind(json!({"phase":"authenticated","success":true})).bind(now).execute(&mut *transaction).await?;
    transaction.commit().await?;
    let mut response = Json(json!({"id": admin_id})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&state, &token, ADMIN_SESSION_SECONDS)?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = cookie_token(&headers) {
        let mut tx = state.pool.begin().await?;
        let admin:Option<i64>=sqlx::query_scalar("DELETE FROM sessions WHERE token_hash = $1 AND admin_id IS NOT NULL RETURNING admin_id")
            .bind(hash_token(token))
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(admin) = admin {
            sqlx::query("INSERT INTO management_audit(admin_id,action,object_path,request_diff,result,occurred_at) VALUES($1,'logout','/api/logout','{}',$2,$3)").bind(admin).bind(json!({"phase":"session-revoked","success":true})).bind(now_timestamp()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
    }
    let mut response = Json(json!({"ok": true})).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&state, "", 0)?);
    Ok(response)
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = crate::control_center::authenticate(&state, &headers).await?;
    Ok(Json(json!({"id": actor.admin_id,"administrator":actor})))
}

fn session_cookie(state: &AppState, token: &str, lifetime: i64) -> ApiResult<HeaderValue> {
    let secure = if state.config.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "sinan_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={lifetime}{secure}"
    ))
    .map_err(|error| ApiError::Internal(anyhow::Error::from(error)))
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    let mut token = None;
    for header in headers.get_all(header::COOKIE) {
        for cookie in header.to_str().ok()?.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name == "sinan_session" {
                if token.is_some() || value.is_empty() || value.len() > 512 {
                    return None;
                }
                token = Some(value);
            }
        }
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn expired_sessions_are_purged_and_live_sessions_kept(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO admins(id,password_hash) VALUES(1,'TEST_ONLY')")
            .execute(&pool)
            .await?;
        let server: i64 =
            sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY') RETURNING id")
                .fetch_one(&pool)
                .await?;
        for (token, admin, device, expires_at) in [
            ("expired-admin", Some(1_i64), None, 100_i64),
            ("expired-device", None, Some(server), 200),
            ("live-admin", Some(1), None, 301),
            ("live-device", None, Some(server), 400),
        ] {
            sqlx::query(
                "INSERT INTO sessions(token_hash,admin_id,server_id,expires_at) VALUES($1,$2,$3,$4)",
            )
            .bind(hash_token(token))
            .bind(admin)
            .bind(device)
            .bind(expires_at)
            .execute(&pool)
            .await?;
        }
        purge_expired_sessions(&pool, 300).await?;
        let mut remaining: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_all(&pool)
            .await?;
        remaining.sort();
        let mut expected = vec![hash_token("live-admin"), hash_token("live-device")];
        expected.sort();
        assert_eq!(remaining, expected);
        Ok(())
    }
}
