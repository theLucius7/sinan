use super::{Ceremony, PendingAuthentication, PendingRegistration, decode, invalid, json_value};
use crate::error::{ApiError, ApiResult};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

pub async fn lock(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> ApiResult<i64> {
    sqlx::query_scalar("SELECT generation FROM passkey_accounts WHERE id=$1 FOR UPDATE")
        .bind(account)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(invalid)
}

pub async fn list(pool: &PgPool, account: Uuid) -> ApiResult<Vec<Value>> {
    let rows = sqlx::query("SELECT id,name,created_at,last_used_at FROM passkey_credentials WHERE account_id=$1 ORDER BY created_at,id")
        .bind(account).fetch_all(pool).await?;
    rows.iter().map(|r| Ok(json!({"id":r.try_get::<Uuid,_>("id")?, "name":r.try_get::<String,_>("name")?, "created_at":r.try_get::<i64,_>("created_at")?, "last_used_at":r.try_get::<Option<i64>,_>("last_used_at")?}))).collect()
}

pub(super) async fn keys(
    tx: &mut Transaction<'_, Postgres>,
    account: Uuid,
) -> ApiResult<Vec<(Uuid, Passkey)>> {
    let rows =
        sqlx::query("SELECT id,payload FROM passkey_credentials WHERE account_id=$1 ORDER BY id")
            .bind(account)
            .fetch_all(&mut **tx)
            .await?;
    rows.iter()
        .map(|r| Ok((r.try_get("id")?, decode(r.try_get("payload")?)?)))
        .collect()
}

pub async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    pending: &Ceremony<PendingRegistration>,
    key: Passkey,
) -> ApiResult<()> {
    if lock(tx, pending.account).await? != pending.generation
        || pending.expires_at <= now_timestamp()
    {
        return Err(invalid());
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM passkey_credentials WHERE account_id=$1")
            .bind(pending.account)
            .fetch_one(&mut **tx)
            .await?;
    if count >= 10 {
        return Err(ApiError::Conflict("最多可以绑定十把 Passkey。".into()));
    }
    let result = sqlx::query("INSERT INTO passkey_credentials(id,account_id,credential_id,payload,name,created_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(Uuid::new_v4()).bind(pending.account).bind(key.cred_id().as_slice())
        .bind(json_value(&key)?).bind(&pending.state.name).bind(now_timestamp()).execute(&mut **tx).await;
    match result {
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(
            ApiError::Conflict("这把 Passkey 已经绑定，请使用另一把密钥。".into()),
        ),
        result => {
            result?;
            Ok(())
        }
    }
}

pub async fn authenticate(
    tx: &mut Transaction<'_, Postgres>,
    pending: &Ceremony<PendingAuthentication>,
    result: AuthenticationResult,
) -> ApiResult<()> {
    if lock(tx, pending.account).await? != pending.generation
        || pending.expires_at <= now_timestamp()
    {
        return Err(invalid());
    }
    let row = sqlx::query("SELECT id,payload,signature_counter FROM passkey_credentials WHERE account_id=$1 AND credential_id=$2 FOR UPDATE")
        .bind(pending.account).bind(result.cred_id().as_slice()).fetch_optional(&mut **tx).await?.ok_or_else(invalid)?;
    let id: Uuid = row.try_get("id")?;
    if !pending.state.keys.contains(&id) {
        return Err(invalid());
    }
    let counter = i64::from(result.counter());
    let previous: i64 = row.try_get("signature_counter")?;
    if (counter > 0 || previous > 0) && counter <= previous {
        return Err(invalid());
    }
    let mut key: Passkey = decode(row.try_get("payload")?)?;
    key.update_credential(&result).ok_or_else(invalid)?;
    sqlx::query("UPDATE passkey_credentials SET payload=$2,last_used_at=$3,signature_counter=$4 WHERE id=$1")
        .bind(id).bind(json_value(key)?).bind(now_timestamp()).bind(counter).execute(&mut **tx).await?;
    Ok(())
}

pub async fn revoke(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> ApiResult<()> {
    lock(tx, account).await?;
    sqlx::query("UPDATE passkey_accounts SET generation=generation+1 WHERE id=$1")
        .bind(account)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM passkey_ceremonies WHERE account_id=$1")
        .bind(account)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
