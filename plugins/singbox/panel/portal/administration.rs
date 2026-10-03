use crate::{
    AppState,
    auth::{self, LoginRequest, hash_token, random_token},
    error::{ApiError, ApiResult},
    passkeys as keys,
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
use sqlx::Row;
use std::net::SocketAddr;
use uuid::Uuid;

pub(super) async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    auth::require_admin(&state, &headers).await?;
    let row = sqlx::query("SELECT p.account_id,p.activation_expires_at,(SELECT count(*) FROM passkey_credentials c WHERE c.account_id=p.account_id) AS keys FROM users u LEFT JOIN singbox_portal_accounts p ON p.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL")
        .bind(id).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let account: Option<Uuid> = row.try_get("account_id")?;
    Ok(keys::reply(
        json!({"configuration":state.passkeys.info(),"keys":row.try_get::<i64,_>("keys")?,"url":account.map(|id| format!("{}/#/plugins/sing-box/account/{id}",state.config.public_url)),"activation_expires_at":row.try_get::<Option<i64>,_>("activation_expires_at")?.filter(|time| *time>now_timestamp())}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Invitation {
    password: String,
    totp_code: Option<String>,
    #[serde(default)]
    reset: bool,
}

pub(super) async fn invitation(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<Invitation>,
) -> ApiResult<Response> {
    let administrator = auth::require_admin(&state, &headers).await?;
    let proof = auth::proof::prepare(
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
    super::super::business::lock_user(&mut tx, id).await?;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT account_id FROM singbox_portal_accounts WHERE user_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let account = match existing {
        Some(account) => account,
        None => {
            let account = Uuid::new_v4();
            sqlx::query("INSERT INTO passkey_accounts(id) VALUES($1)")
                .bind(account)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO singbox_portal_accounts(user_id,account_id) VALUES($1,$2)")
                .bind(id)
                .bind(account)
                .execute(&mut *tx)
                .await?;
            account
        }
    };
    keys::lock(&mut tx, account).await?;
    let has_keys: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE account_id=$1)")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?;
    if has_keys && !input.reset {
        return Err(ApiError::Conflict(
            "用户已开通，请明确确认重置原有 Passkey。".into(),
        ));
    }
    keys::revoke(&mut tx, account).await?;
    sqlx::query("DELETE FROM singbox_portal_sessions WHERE account_id=$1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM passkey_credentials WHERE account_id=$1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    let token = random_token();
    let expiry = now_timestamp() + 900;
    sqlx::query("UPDATE singbox_portal_accounts SET activation_hash=$2,activation_expires_at=$3 WHERE account_id=$1")
        .bind(account).bind(hash_token(&token)).bind(expiry).execute(&mut *tx).await?;
    super::super::operations_workflows::event(&mut tx,Some(administrator),Some(id),"security_portal_invitation",json!({"reset_existing_keys":input.reset,"expires_at":expiry,"subscription_token_used":false})).await?;
    tx.commit().await?;
    Ok(keys::reply(
        json!({"url":format!("{}/#/plugins/sing-box/account/{account}?activate={token}",state.config.public_url),"expires_at":expiry}),
    ))
}
