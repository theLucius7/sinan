use super::{require_owner, require_recent_proof};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::TryStreamExt;
use rand::{RngCore, rngs::OsRng};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::collections::BTreeMap;
use uuid::Uuid;

fn keyring() -> ApiResult<(String, BTreeMap<String, Vec<u8>>)> {
    let raw = std::env::var("SINAN_CREDENTIAL_KEYS")
        .map_err(|_| ApiError::Conflict("凭据加密密钥环尚未配置".into()))?;
    let current = std::env::var("SINAN_CREDENTIAL_CURRENT_KEY")
        .map_err(|_| ApiError::Conflict("当前凭据加密密钥标识尚未配置".into()))?;
    let supplied: BTreeMap<String, String> =
        serde_json::from_str(&raw).map_err(|_| ApiError::Conflict("凭据密钥环格式无效".into()))?;
    let mut keys = BTreeMap::new();
    if supplied.is_empty() || supplied.len() > 16 {
        return Err(ApiError::Conflict("凭据密钥环数量无效".into()));
    }
    for (id, value) in supplied {
        if id.is_empty() || id.len() > 100 {
            return Err(ApiError::Conflict("凭据密钥标识无效".into()));
        }
        let bytes = STANDARD
            .decode(value)
            .map_err(|_| ApiError::Conflict("凭据密钥编码无效".into()))?;
        if bytes.len() != 32 {
            return Err(ApiError::Conflict("凭据密钥必须为32字节".into()));
        }
        keys.insert(id, bytes);
    }
    if !keys.contains_key(&current) {
        return Err(ApiError::Conflict("当前密钥不在凭据密钥环内".into()));
    }
    Ok((current, keys))
}

fn aad(id: Uuid, kind: &str, version: i64) -> String {
    format!("sinan-credential-v1:{id}:{kind}:{version}")
}
fn key(bytes: &[u8]) -> ApiResult<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| ApiError::Conflict("凭据加密密钥无效".into()))
}
fn seal(
    bytes: &[u8],
    id: Uuid,
    kind: &str,
    version: i64,
    value: &Value,
) -> ApiResult<([u8; 12], Vec<u8>)> {
    if !value.as_object().is_some_and(|fields| !fields.is_empty()) {
        return Err(ApiError::BadRequest("凭据正文必须是非空 JSON 对象".into()));
    }
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut payload = serde_json::to_vec(value).map_err(anyhow::Error::from)?;
    if payload.is_empty() || payload.len() > 65536 {
        return Err(ApiError::BadRequest("凭据正文须在64KiB内".into()));
    }
    key(bytes)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(id, kind, version).as_bytes()),
            &mut payload,
        )
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("credential encryption failed")))?;
    Ok((nonce, payload))
}
fn open(
    bytes: &[u8],
    id: Uuid,
    kind: &str,
    version: i64,
    nonce: &[u8],
    mut payload: Vec<u8>,
) -> ApiResult<Value> {
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| ApiError::Conflict("凭据nonce损坏".into()))?;
    let plain = key(bytes)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(id, kind, version).as_bytes()),
            &mut payload,
        )
        .map_err(|_| ApiError::Conflict("凭据认证失败，请核对密钥与备份版本".into()))?;
    serde_json::from_slice(plain).map_err(|_| ApiError::Conflict("凭据正文损坏".into()))
}

async fn verify_rows(pool: &sqlx::PgPool, keys: &BTreeMap<String, Vec<u8>>) -> ApiResult<u64> {
    let mut rows = sqlx::query(
        "SELECT id,kind,key_id,version,nonce,ciphertext FROM credential_entries ORDER BY id",
    )
    .fetch(pool);
    let mut verified = 0;
    while let Some(row) = rows.try_next().await? {
        let key_id: String = row.get("key_id");
        let bytes = keys
            .get(&key_id)
            .ok_or_else(|| ApiError::Conflict("恢复材料缺少凭据所需密钥".into()))?;
        let value = open(
            bytes,
            row.get("id"),
            &row.get::<String, _>("kind"),
            row.get("version"),
            &row.get::<Vec<u8>, _>("nonce"),
            row.get("ciphertext"),
        )?;
        if !value.as_object().is_some_and(|fields| !fields.is_empty()) {
            return Err(ApiError::Conflict("恢复凭据正文无效".into()));
        }
        verified += 1;
    }
    Ok(verified)
}

/// Authenticate restored ciphertext with independent keys before workers can run.
/// Plaintext is discarded locally and never returned, audited or logged.
pub async fn verify_recovery_material(pool: &sqlx::PgPool) -> ApiResult<u64> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credential_entries)")
        .fetch_one(pool)
        .await?;
    if !exists {
        return Ok(0);
    }
    let (_, keys) = keyring()?;
    verify_rows(pool, &keys).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialInput {
    name: String,
    kind: String,
    secret: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateInput {
    expected_version: i64,
    secret: Option<Value>,
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    let rows=sqlx::query("SELECT id,name,kind,key_id,version,enabled,created_at,updated_at,rotated_at FROM credential_entries ORDER BY updated_at DESC LIMIT 500").fetch_all(&state.pool).await?;
    let entries:Vec<Value>=rows.iter().map(|r|Ok(json!({"id":r.try_get::<Uuid,_>("id")?,"name":r.try_get::<String,_>("name")?,"kind":r.try_get::<String,_>("kind")?,"key_id":r.try_get::<String,_>("key_id")?,"version":r.try_get::<i64,_>("version")?,"enabled":r.try_get::<bool,_>("enabled")?,"updated_at":r.try_get::<i64,_>("updated_at")?,"rotated_at":r.try_get::<Option<i64>,_>("rotated_at")?}))).collect::<Result<_,sqlx::Error>>()?;
    let ready = keyring().is_ok();
    Ok(Json(
        json!({"entries":entries,"encryption_ready":ready,"algorithm":"AES-256-GCM","secret_read_available":false}),
    ))
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CredentialInput>,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    if input.name.trim().is_empty()
        || input.name.len() > 200
        || !["dns", "cloud", "backup", "external-api", "certificate"].contains(&input.kind.as_str())
    {
        return Err(ApiError::BadRequest("凭据名称或用途无效".into()));
    }
    let (current, keys) = keyring()?;
    let id = Uuid::new_v4();
    let (nonce, payload) = seal(&keys[&current], id, &input.kind, 1, &input.secret)?;
    sqlx::query("INSERT INTO credential_entries(id,name,kind,key_id,nonce,ciphertext,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)")
        .bind(id).bind(input.name.trim()).bind(input.kind).bind(current).bind(nonce.as_slice()).bind(payload).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(json!({"id":id,"version":1})))
}
pub async fn rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RotateInput>,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    let (current, keys) = keyring()?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM credential_entries WHERE id=$1 AND enabled FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let version: i64 = row.try_get("version")?;
    if version != input.expected_version {
        return Err(ApiError::Conflict(
            "凭据已被其他管理员修改，请刷新后重新确认".into(),
        ));
    }
    let kind: String = row.try_get("kind")?;
    let value = match input.secret {
        Some(value) => value,
        None => {
            let old: String = row.try_get("key_id")?;
            let old_key = keys
                .get(&old)
                .ok_or_else(|| ApiError::Conflict("旧凭据密钥缺失，不能轮换".into()))?;
            open(
                old_key,
                id,
                &kind,
                version,
                &row.try_get::<Vec<u8>, _>("nonce")?,
                row.try_get("ciphertext")?,
            )?
        }
    };
    let next = version
        .checked_add(1)
        .ok_or_else(|| ApiError::Conflict("凭据版本达到上限".into()))?;
    let (nonce, payload) = seal(&keys[&current], id, &kind, next, &value)?;
    sqlx::query("UPDATE credential_entries SET key_id=$2,nonce=$3,ciphertext=$4,version=$5,updated_at=$6,rotated_at=$6 WHERE id=$1")
        .bind(id).bind(current).bind(nonce.as_slice()).bind(payload).bind(next).bind(now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"version":next})))
}
pub async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    if sqlx::query(
        "UPDATE credential_entries SET enabled=false,updated_at=$2 WHERE id=$1 AND enabled",
    )
    .bind(id)
    .bind(now_timestamp())
    .execute(&state.pool)
    .await?
    .rows_affected()
        != 1
    {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({"id":id,"enabled":false})))
}

pub async fn resolve_reference(
    state: &AppState,
    id: Uuid,
    expected_kind: &str,
    consumer: &str,
) -> ApiResult<Value> {
    resolve_reference_pool(&state.pool, id, expected_kind, consumer).await
}

pub async fn resolve_reference_pool(
    pool: &sqlx::PgPool,
    id: Uuid,
    expected_kind: &str,
    consumer: &str,
) -> ApiResult<Value> {
    if consumer.is_empty() || consumer.len() > 200 {
        return Err(ApiError::BadRequest("凭据使用方标识无效".into()));
    }
    let (_, keys) = keyring()?;
    let row = sqlx::query("SELECT * FROM credential_entries WHERE id=$1 AND enabled AND kind=$2")
        .bind(id)
        .bind(expected_kind)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let key_id: String = row.try_get("key_id")?;
    let bytes = keys
        .get(&key_id)
        .ok_or_else(|| ApiError::Conflict("解密凭据需要的历史密钥缺失".into()))?;
    let value = open(
        bytes,
        id,
        expected_kind,
        row.try_get("version")?,
        &row.try_get::<Vec<u8>, _>("nonce")?,
        row.try_get("ciphertext")?,
    )?;
    sqlx::query("INSERT INTO management_audit(action,object_path,request_diff,result,occurred_at) VALUES('credential.resolve',$1,$2,$3,$4)")
        .bind(format!("credential:{id}")).bind(json!({"consumer":consumer,"kind":expected_kind})).bind(json!({"success":true,"version":row.try_get::<i64,_>("version")?})).bind(now_timestamp()).execute(pool).await?;
    Ok(value)
}

pub async fn store_generated(
    pool: &sqlx::PgPool,
    name: &str,
    kind: &str,
    secret: Value,
) -> ApiResult<Uuid> {
    if name.trim().is_empty()
        || name.len() > 200
        || !["dns", "cloud", "backup", "external-api", "certificate"].contains(&kind)
    {
        return Err(ApiError::BadRequest("生成凭据名称或用途无效".into()));
    }
    let (current, keys) = keyring()?;
    let id = Uuid::new_v4();
    let (nonce, payload) = seal(&keys[&current], id, kind, 1, &secret)?;
    sqlx::query("INSERT INTO credential_entries(id,name,kind,key_id,nonce,ciphertext,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)")
        .bind(id).bind(name).bind(kind).bind(current).bind(nonce.as_slice()).bind(payload).bind(now_timestamp()).execute(pool).await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_authenticates_enabled_and_disabled_material(pool: sqlx::PgPool) {
        let bytes = vec![7u8; 32];
        for enabled in [true, false] {
            let id = Uuid::new_v4();
            let (nonce, ciphertext) =
                seal(&bytes, id, "cloud", 1, &json!({"token":"fixture-only"})).unwrap();
            sqlx::query("INSERT INTO credential_entries(id,name,kind,key_id,nonce,ciphertext,enabled,created_at,updated_at) VALUES($1,'recovery fixture','cloud','archive-key',$2,$3,$4,1,1)")
                .bind(id).bind(nonce.as_slice()).bind(ciphertext).bind(enabled).execute(&pool).await.unwrap();
        }
        let keys = BTreeMap::from([("archive-key".into(), bytes)]);
        assert_eq!(verify_rows(&pool, &keys).await.unwrap(), 2);
        let wrong = BTreeMap::from([("archive-key".into(), vec![8u8; 32])]);
        assert!(verify_rows(&pool, &wrong).await.is_err());
        assert!(verify_rows(&pool, &BTreeMap::new()).await.is_err());
        let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM management_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(audit_count, 0);
    }

    #[test]
    fn ciphertext_cannot_move_between_identity_kind_or_version() {
        let bytes = [7u8; 32];
        let id = Uuid::new_v4();
        let value = json!({"token":"secret"});
        let (nonce, payload) = seal(&bytes, id, "dns", 1, &value).unwrap();
        assert_eq!(
            open(&bytes, id, "dns", 1, &nonce, payload.clone()).unwrap(),
            value
        );
        assert!(open(&bytes, Uuid::new_v4(), "dns", 1, &nonce, payload.clone()).is_err());
        assert!(open(&bytes, id, "cloud", 1, &nonce, payload.clone()).is_err());
        assert!(open(&bytes, id, "dns", 2, &nonce, payload.clone()).is_err());
        let mut corrupt = payload;
        corrupt[0] ^= 1;
        assert!(open(&bytes, id, "dns", 1, &nonce, corrupt).is_err());
    }
}
