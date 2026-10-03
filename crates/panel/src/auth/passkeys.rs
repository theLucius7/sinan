use super::{
    ADMIN_SESSION_SECONDS, LoginRequest, hash_token, proof, random_token, require_admin, security,
    session_cookie,
};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
    passkeys::{
        self as keys, ADMIN, ADMIN_BINDING, Ceremony, FinishAuthentication, FinishRegistration,
        PendingAuthentication, PendingRegistration,
    },
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, header},
    response::Response,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use sinan_protocol::now_timestamp;
use std::net::SocketAddr;
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/security/passkeys", get(list))
        .route(
            "/api/security/passkeys/register/start",
            post(register_start),
        )
        .route(
            "/api/security/passkeys/register/finish",
            post(register_finish),
        )
        .route("/api/security/passkeys/{id}/remove", post(remove))
        .route("/api/login/passkey/start", post(login_start))
        .route("/api/login/passkey/finish", post(login_finish))
        .layer(DefaultBodyLimit::max(65536))
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    require_initial_admin(&state, &headers).await?;
    Ok(keys::reply(
        json!({"configuration":state.passkeys.info(), "keys":keys::list(&state.pool, ADMIN).await?}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    name: String,
    password: String,
    totp_code: Option<String>,
}

async fn register_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Register>,
) -> ApiResult<Response> {
    require_initial_admin(&state, &headers).await?;
    let proof = proof::prepare(
        &state,
        &headers,
        peer,
        LoginRequest {
            password: input.password,
            totp_code: input.totp_code,
        },
    )
    .await?;
    let mut tx = state.pool.begin().await?;
    proof.lock(&mut tx).await?;
    let response = keys::start_registration(
        &state,
        &mut tx,
        ADMIN,
        input.name,
        proof.session.clone(),
        ADMIN_BINDING,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

async fn register_finish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<FinishRegistration>,
) -> ApiResult<Response> {
    require_initial_admin(&state, &headers).await?;
    let _permit = keys::permit(&state, &headers, peer).await?;
    let session = security::session_hash(&headers)?;
    let pending: Ceremony<PendingRegistration> = keys::consume(
        &state,
        &headers,
        input.challenge_id,
        ADMIN,
        "register",
        ADMIN_BINDING,
    )
    .await?;
    if pending.authorization != session {
        return Err(keys::invalid());
    }
    let key = state
        .passkeys
        .registration(input.credential, &pending.state)
        .await?;
    let mut tx = state.pool.begin().await?;
    security::locked_admin(&mut tx, &session).await?;
    keys::insert(&mut tx, &pending, key).await?;
    tx.commit().await?;
    Ok(keys::reply(json!({"ok":true})))
}

async fn remove(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<LoginRequest>,
) -> ApiResult<Response> {
    require_initial_admin(&state, &headers).await?;
    let proof = proof::prepare(&state, &headers, peer, input).await?;
    let mut tx = state.pool.begin().await?;
    proof.lock(&mut tx).await?;
    keys::lock(&mut tx, ADMIN).await?;
    if sqlx::query("DELETE FROM passkey_credentials WHERE id=$1 AND account_id=$2")
        .bind(id)
        .bind(ADMIN)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(ApiError::NotFound);
    }
    security::revoke_other_sessions(&mut tx, &proof.session).await?;
    tx.commit().await?;
    Ok(keys::reply(json!({"ok":true})))
}

async fn login_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let mut tx = state.pool.begin().await?;
    let response = keys::start_authentication(&state, &mut tx, ADMIN, ADMIN_BINDING).await?;
    tx.commit().await?;
    Ok(response)
}

async fn login_finish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<FinishAuthentication>,
) -> ApiResult<Response> {
    let result = login_finish_inner(state.clone(), peer, headers, input).await;
    if result.is_err()
        && let Err(error)=sqlx::query("INSERT INTO management_audit(action,object_path,request_diff,result,occurred_at) VALUES('login','/api/login/passkey/finish',$1,$2,$3)")
            .bind(json!({"factor":"passkey"})).bind(json!({"phase":"authentication-denied","success":false})).bind(now_timestamp()).execute(&state.pool).await {
            tracing::warn!(%error,"passkey denial audit failed");
    }
    result
}

async fn login_finish_inner(
    state: AppState,
    peer: SocketAddr,
    headers: HeaderMap,
    input: FinishAuthentication,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let pending: Ceremony<PendingAuthentication> = keys::consume(
        &state,
        &headers,
        input.challenge_id,
        ADMIN,
        "authenticate",
        ADMIN_BINDING,
    )
    .await?;
    let result = state
        .passkeys
        .authentication(input.credential, &pending.state)
        .await?;
    let token = random_token();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT a.id FROM admins a JOIN administrator_profiles p ON p.admin_id=a.id WHERE a.id=1 AND p.enabled FOR UPDATE OF a,p")
        .fetch_optional(&mut *tx).await?.ok_or(ApiError::Unauthorized)?;
    keys::authenticate(&mut tx, &pending, result).await?;
    let now = now_timestamp();
    sqlx::query("DELETE FROM sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,1,$2)")
        .bind(hash_token(&token))
        .bind(now + ADMIN_SESSION_SECONDS)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)",
    )
    .bind(hash_token(&token))
    .bind(now)
    .bind(now + 300)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO management_audit(admin_id,action,object_path,request_diff,result,occurred_at) VALUES(1,'login','/api/login/passkey/finish',$1,$2,$3)")
        .bind(json!({"factor":"passkey"})).bind(json!({"phase":"authenticated","success":true})).bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    let mut response = keys::reply(json!({"id":1}));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&state, &token, ADMIN_SESSION_SECONDS)?,
    );
    keys::set_cookie(&state, &mut response, ADMIN_BINDING, "", 0)?;
    Ok(response)
}

async fn require_initial_admin(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if require_admin(state, headers).await? != 1 {
        return Err(ApiError::Forbidden(
            "此入口管理初始所有者的 Passkey；其他管理员使用各自密码和二步验证".into(),
        ));
    }
    Ok(())
}
