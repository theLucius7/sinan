use crate::{
    AppState,
    auth::{hash_token, random_token},
    error::{ApiError, ApiResult},
    passkeys as keys,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use serde_json::json;
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

pub(super) const COOKIE: &str = "sinan_proxy_session";
const SESSION_SECONDS: i64 = 86400;

pub(super) fn session_hash(headers: &HeaderMap) -> ApiResult<String> {
    keys::cookie(headers, COOKIE)
        .map(hash_token)
        .ok_or(ApiError::Unauthorized)
}

pub(super) async fn lock(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> ApiResult<PgRow> {
    let id: i64 =
        sqlx::query_scalar("SELECT user_id FROM singbox_portal_accounts WHERE account_id=$1")
            .bind(account)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    super::super::business::lock_user(tx, id).await?;
    sqlx::query("SELECT * FROM singbox_portal_accounts WHERE account_id=$1 FOR UPDATE")
        .bind(account)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}

pub(super) async fn session(
    tx: &mut Transaction<'_, Postgres>,
    account: Uuid,
    hash: &str,
    recent: bool,
) -> ApiResult<()> {
    let verified: Option<i64> = sqlx::query_scalar("SELECT verified_at FROM singbox_portal_sessions WHERE token_hash=$1 AND account_id=$2 AND expires_at>$3 FOR UPDATE")
        .bind(hash).bind(account).bind(now_timestamp()).fetch_optional(&mut **tx).await?;
    let verified = verified.ok_or(ApiError::Unauthorized)?;
    if recent && verified <= now_timestamp() - keys::TTL {
        return Err(ApiError::Conflict(
            "请先使用 Passkey 重新验证，再管理密钥。".into(),
        ));
    }
    Ok(())
}

pub(super) async fn issue(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> ApiResult<String> {
    let now = now_timestamp();
    let token = random_token();
    sqlx::query("DELETE FROM singbox_portal_sessions WHERE account_id=$1 AND expires_at <= $2")
        .bind(account)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM singbox_portal_sessions WHERE account_id=$1 AND token_hash NOT IN (SELECT token_hash FROM singbox_portal_sessions WHERE account_id=$1 ORDER BY verified_at DESC,token_hash LIMIT 9)")
        .bind(account).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO singbox_portal_sessions(token_hash,account_id,expires_at,verified_at) VALUES($1,$2,$3,$4)")
        .bind(hash_token(&token)).bind(account).bind(now+SESSION_SECONDS).bind(now).execute(&mut **tx).await?;
    Ok(token)
}

pub(super) fn logged_in(state: &AppState, token: &str) -> ApiResult<Response> {
    let mut response = keys::reply(json!({"ok":true}));
    keys::set_cookie(state, &mut response, COOKIE, token, SESSION_SECONDS)?;
    keys::set_cookie(state, &mut response, keys::PORTAL_BINDING, "", 0)?;
    Ok(response)
}

pub(super) async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account): Path<Uuid>,
) -> ApiResult<Response> {
    let mut tx = state.pool.begin().await?;
    // Owner locking makes deletion and recovery immediately revoke this view.
    let owner = lock(&mut tx, account).await?;
    let hash = session_hash(&headers).unwrap_or_default();
    if let Err(error) = session(&mut tx, account, &hash, false).await {
        return match error {
            ApiError::Unauthorized => Ok(keys::reply(
                json!({"authenticated":false,"configuration":state.passkeys.info()}),
            )),
            error => Err(error),
        };
    }
    let id: i64 = owner.try_get("user_id")?;
    let row = sqlx::query("SELECT name,subscription_token FROM users WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let usage = sqlx::query("SELECT COALESCE(SUM(uplink),0)::text AS uplink,COALESCE(SUM(downlink),0)::text AS downlink FROM usage_records WHERE user_id=$1")
        .bind(id).fetch_one(&mut *tx).await?;
    let credentials = sqlx::query("SELECT id,name,created_at,last_used_at FROM passkey_credentials WHERE account_id=$1 ORDER BY created_at,id")
        .bind(account).fetch_all(&mut *tx).await?;
    let credentials = credentials.iter().map(|r| Ok(json!({"id":r.try_get::<Uuid,_>("id")?,"name":r.try_get::<String,_>("name")?,"created_at":r.try_get::<i64,_>("created_at")?,"last_used_at":r.try_get::<Option<i64>,_>("last_used_at")?}))).collect::<ApiResult<Vec<_>>>()?;
    let subscription_status = super::super::subscriptions::diagnostic_on(&mut tx, id).await?;
    let result = json!({"authenticated":true,"configuration":state.passkeys.info(),"name":row.try_get::<String,_>("name")?,
        "subscription_url":format!("{}/sub/{}?format=singbox",state.config.public_url,row.try_get::<String,_>("subscription_token")?),
        "usage":{"uplink":usage.try_get::<String,_>("uplink")?,"downlink":usage.try_get::<String,_>("downlink")?},"keys":credentials,"subscription_status":subscription_status});
    tx.commit().await?;
    Ok(keys::reply(result))
}

pub(super) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account): Path<Uuid>,
) -> ApiResult<Response> {
    state.passkeys.check_origin(&headers)?;
    if let Ok(hash) = session_hash(&headers) {
        let mut tx = state.pool.begin().await?;
        let deleted = sqlx::query(
            "DELETE FROM singbox_portal_sessions WHERE token_hash=$1 AND account_id=$2",
        )
        .bind(hash)
        .bind(account)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;
        if deleted {
            let user: Option<i64> = sqlx::query_scalar(
                "SELECT user_id FROM singbox_portal_accounts WHERE account_id=$1",
            )
            .bind(account)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(user) = user {
                super::super::operations_workflows::event(
                    &mut tx,
                    None,
                    Some(user),
                    "security_portal_logout",
                    json!({"session_revoked":true}),
                )
                .await?;
            }
        }
        tx.commit().await?;
    }
    let mut response = keys::reply(json!({"ok":true}));
    keys::set_cookie(&state, &mut response, COOKIE, "", 0)?;
    Ok(response)
}
