use super::{TTL, cookie, credentials, decode, invalid, json_value, lock, reply, set_cookie};
use crate::{
    AppState,
    auth::{hash_token, random_token},
    error::{ApiError, ApiResult},
};
use axum::{http::HeaderMap, response::Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct PendingRegistration {
    pub name: String,
    pub registration: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
pub struct PendingAuthentication {
    pub keys: Vec<Uuid>,
    pub authentication: PasskeyAuthentication,
}

pub struct Ceremony<T> {
    pub account: Uuid,
    pub generation: i64,
    pub authorization: String,
    pub expires_at: i64,
    pub state: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishRegistration {
    pub challenge_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishAuthentication {
    pub challenge_id: Uuid,
    pub credential: PublicKeyCredential,
}

struct Pending {
    account: Uuid,
    generation: i64,
    purpose: &'static str,
    authorization: String,
    state: Value,
}

async fn save(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    pending: Pending,
    binding: &str,
    options: Value,
) -> ApiResult<Response> {
    let now = now_timestamp();
    // Serialize capacity checks across accounts without retaining browser-side state.
    sqlx::query("SELECT pg_advisory_xact_lock(739104859)")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM passkey_ceremonies WHERE expires_at <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM passkey_ceremonies")
        .fetch_one(&mut **tx)
        .await?;
    let own: i64 =
        sqlx::query_scalar("SELECT count(*) FROM passkey_ceremonies WHERE account_id=$1")
            .bind(pending.account)
            .fetch_one(&mut **tx)
            .await?;
    if count >= 256 || own >= 8 {
        return Err(ApiError::Busy);
    }
    let id = Uuid::new_v4();
    let token = random_token();
    sqlx::query("INSERT INTO passkey_ceremonies(id,account_id,generation,purpose,binding_hash,authorization_binding,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(pending.account).bind(pending.generation).bind(pending.purpose)
        .bind(hash_token(&token)).bind(pending.authorization).bind(pending.state).bind(now+TTL).execute(&mut **tx).await?;
    let mut response = reply(json!({"challenge_id":id,"options":options}));
    set_cookie(state, &mut response, binding, &token, TTL)?;
    Ok(response)
}

pub async fn start_registration(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    account: Uuid,
    name: String,
    authorization: String,
    binding: &str,
) -> ApiResult<Response> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 64
        || name.len() > 256
        || name.chars().any(char::is_control)
    {
        return Err(ApiError::BadRequest(
            "请填写 1 至 64 个字符的 Passkey 名称。".into(),
        ));
    }
    let generation = lock(tx, account).await?;
    let keys = credentials::keys(tx, account).await?;
    if keys.len() >= 10 {
        return Err(ApiError::Conflict("最多可以绑定十把 Passkey。".into()));
    }
    let excluded = keys.iter().map(|(_, key)| key.cred_id().clone()).collect();
    let (options, registration) = state
        .passkeys
        .engine()?
        .start_passkey_registration(account, &account.to_string(), "司南账户", Some(excluded))
        .map_err(|_| invalid())?;
    save(
        state,
        tx,
        Pending {
            account,
            generation,
            purpose: "register",
            authorization,
            state: json_value(PendingRegistration {
                name: name.to_owned(),
                registration,
            })?,
        },
        binding,
        json_value(options)?,
    )
    .await
}

pub async fn start_authentication(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    account: Uuid,
    binding: &str,
) -> ApiResult<Response> {
    let generation = lock(tx, account).await?;
    let keys = credentials::keys(tx, account).await?;
    if keys.is_empty() {
        return Err(ApiError::BadRequest("此账户尚未绑定 Passkey。".into()));
    }
    let (options, authentication) = state
        .passkeys
        .engine()?
        .start_passkey_authentication(&keys.iter().map(|(_, key)| key.clone()).collect::<Vec<_>>())
        .map_err(|_| invalid())?;
    save(
        state,
        tx,
        Pending {
            account,
            generation,
            purpose: "authenticate",
            authorization: String::new(),
            state: json_value(PendingAuthentication {
                keys: keys.into_iter().map(|(id, _)| id).collect(),
                authentication,
            })?,
        },
        binding,
        json_value(options)?,
    )
    .await
}

pub async fn consume<T: serde::de::DeserializeOwned>(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    account: Uuid,
    purpose: &str,
    binding: &str,
) -> ApiResult<Ceremony<T>> {
    let token = cookie(headers, binding).ok_or_else(invalid)?;
    // Consume before cryptographic verification; even rejected attempts cannot be replayed.
    let row = sqlx::query("DELETE FROM passkey_ceremonies WHERE id=$1 AND account_id=$2 AND purpose=$3 AND binding_hash=$4 AND expires_at>$5 RETURNING generation,authorization_binding,state,expires_at")
        .bind(id).bind(account).bind(purpose).bind(hash_token(token)).bind(now_timestamp()).fetch_optional(&state.pool).await?.ok_or_else(invalid)?;
    Ok(Ceremony {
        account,
        generation: row.try_get("generation")?,
        authorization: row.try_get("authorization_binding")?,
        expires_at: row.try_get("expires_at")?,
        state: decode(row.try_get("state")?)?,
    })
}
