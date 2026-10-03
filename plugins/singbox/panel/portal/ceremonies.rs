use super::access;
use crate::{
    AppState,
    auth::hash_token,
    error::{ApiError, ApiResult},
    passkeys::{
        self as keys, Ceremony, FinishAuthentication, FinishRegistration, PORTAL_BINDING,
        PendingAuthentication, PendingRegistration,
    },
};
use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use std::net::SocketAddr;
use uuid::Uuid;

pub(super) async fn login_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account): Path<Uuid>,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let mut tx = state.pool.begin().await?;
    access::lock(&mut tx, account).await?;
    let response = keys::start_authentication(&state, &mut tx, account, PORTAL_BINDING).await?;
    tx.commit().await?;
    Ok(response)
}

pub(super) async fn login_finish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account): Path<Uuid>,
    Json(input): Json<FinishAuthentication>,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let pending: Ceremony<PendingAuthentication> = keys::consume(
        &state,
        &headers,
        input.challenge_id,
        account,
        "authenticate",
        PORTAL_BINDING,
    )
    .await?;
    let result = match state
        .passkeys
        .authentication(input.credential, &pending.state)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            if let Err(audit) = login_failure(&state, account).await {
                tracing::warn!(%audit,"proxy login audit unavailable");
            }
            return Err(error);
        }
    };
    let mut tx = state.pool.begin().await?;
    let owner = access::lock(&mut tx, account).await?;
    keys::authenticate(&mut tx, &pending, result).await?;
    let token = access::issue(&mut tx, account).await?;
    super::super::operations_workflows::event(
        &mut tx,
        None,
        Some(owner.try_get("user_id")?),
        "security_portal_login",
        json!({"authentication":"passkey","result":"verified"}),
    )
    .await?;
    tx.commit().await?;
    access::logged_in(&state, &token)
}

async fn login_failure(state: &AppState, account: Uuid) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    let user: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM singbox_portal_accounts WHERE account_id=$1")
            .bind(account)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(user) = user {
        super::super::operations_workflows::event(
            &mut tx,
            None,
            Some(user),
            "security_portal_login_failed",
            json!({"stage":"passkey_verification","result":"rejected"}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Register {
    name: String,
    activation_token: Option<String>,
}

async fn invitation(
    tx: &mut Transaction<'_, Postgres>,
    row: &PgRow,
    account: Uuid,
    hash: &str,
) -> ApiResult<()> {
    if row
        .try_get::<Option<String>, _>("activation_hash")?
        .as_deref()
        != Some(hash)
        || row
            .try_get::<Option<i64>, _>("activation_expires_at")?
            .is_none_or(|t| t <= now_timestamp())
    {
        return Err(keys::invalid());
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE account_id=$1)")
            .bind(account)
            .fetch_one(&mut **tx)
            .await?;
    if exists {
        return Err(keys::invalid());
    }
    Ok(())
}

pub(super) async fn register_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account): Path<Uuid>,
    Json(input): Json<Register>,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let mut tx = state.pool.begin().await?;
    let row = access::lock(&mut tx, account).await?;
    let authorization = if let Some(token) = input.activation_token {
        if token.len() != 43 {
            return Err(keys::invalid());
        }
        let hash = hash_token(&token);
        invitation(&mut tx, &row, account, &hash).await?;
        format!("invite:{hash}")
    } else {
        let hash = access::session_hash(&headers)?;
        access::session(&mut tx, account, &hash, true).await?;
        format!("session:{hash}")
    };
    let response = keys::start_registration(
        &state,
        &mut tx,
        account,
        input.name,
        authorization,
        PORTAL_BINDING,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub(super) async fn register_finish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(account): Path<Uuid>,
    Json(input): Json<FinishRegistration>,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let pending: Ceremony<PendingRegistration> = keys::consume(
        &state,
        &headers,
        input.challenge_id,
        account,
        "register",
        PORTAL_BINDING,
    )
    .await?;
    let key = state
        .passkeys
        .registration(input.credential, &pending.state)
        .await?;
    let mut tx = state.pool.begin().await?;
    let row = access::lock(&mut tx, account).await?;
    let activate = if let Some(hash) = pending.authorization.strip_prefix("invite:") {
        invitation(&mut tx, &row, account, hash).await?;
        true
    } else if let Some(hash) = pending.authorization.strip_prefix("session:") {
        if access::session_hash(&headers)? != hash {
            return Err(keys::invalid());
        }
        access::session(&mut tx, account, hash, true).await?;
        false
    } else {
        return Err(keys::invalid());
    };
    keys::insert(&mut tx, &pending, key).await?;
    let token = if activate {
        sqlx::query("UPDATE singbox_portal_accounts SET activation_hash=NULL,activation_expires_at=NULL WHERE account_id=$1").bind(account).execute(&mut *tx).await?;
        Some(access::issue(&mut tx, account).await?)
    } else {
        None
    };
    super::super::operations_workflows::event(
        &mut tx,
        None,
        Some(row.try_get("user_id")?),
        "security_portal_key_register",
        json!({"activated":activate,"result":"verified"}),
    )
    .await?;
    tx.commit().await?;
    match token {
        Some(token) => access::logged_in(&state, &token),
        None => Ok(keys::reply(json!({"ok":true}))),
    }
}

pub(super) async fn remove(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((account, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    let _permit = keys::permit(&state, &headers, peer).await?;
    let hash = access::session_hash(&headers)?;
    let mut tx = state.pool.begin().await?;
    let owner = access::lock(&mut tx, account).await?;
    access::session(&mut tx, account, &hash, true).await?;
    keys::lock(&mut tx, account).await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM passkey_credentials WHERE account_id=$1")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?;
    if count <= 1 {
        return Err(ApiError::Conflict(
            "请保留至少一把 Passkey，先添加新密钥后再删除。".into(),
        ));
    }
    if sqlx::query("DELETE FROM passkey_credentials WHERE id=$1 AND account_id=$2")
        .bind(id)
        .bind(account)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(ApiError::NotFound);
    }
    keys::revoke(&mut tx, account).await?;
    sqlx::query("DELETE FROM singbox_portal_sessions WHERE account_id=$1 AND token_hash<>$2")
        .bind(account)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    super::super::operations_workflows::event(
        &mut tx,
        None,
        Some(owner.try_get("user_id")?),
        "security_portal_key_remove",
        json!({"key_id":id,"other_sessions_revoked":true}),
    )
    .await?;
    tx.commit().await?;
    Ok(keys::reply(json!({"ok":true})))
}
