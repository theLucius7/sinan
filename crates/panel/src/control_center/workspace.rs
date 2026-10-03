use super::{authenticate, require_owner, require_recent_proof};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceInput {
    value: Value,
    expected_revision: i64,
}
fn preference_key(key: &str) -> bool {
    key.len() <= 160
        && !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:/_-".contains(&b))
        && ["favorite", "recent", "view:", "draft:", "appearance"]
            .iter()
            .any(|prefix| key.starts_with(prefix))
}
fn validate_preference(key: &str, value: &Value) -> ApiResult<()> {
    if !preference_key(key)
        || serde_json::to_vec(value)
            .map_err(anyhow::Error::from)?
            .len()
            > 65536
    {
        return Err(ApiError::BadRequest("偏好键或正文大小无效".into()));
    }
    if key.starts_with("draft:") {
        // Long forms may retain non-secret fields, never credentials or command/file contents.
        if super::guard::redact(value) != *value {
            return Err(ApiError::BadRequest(
                "草稿不能保存口令、凭据、私钥、命令或文件正文".into(),
            ));
        }
    }
    if key == "appearance"
        && (!value
            .get("theme")
            .and_then(Value::as_str)
            .is_some_and(|v| ["light", "dark", "system"].contains(&v))
            || !value
                .get("density")
                .and_then(Value::as_str)
                .is_some_and(|v| ["comfortable", "compact"].contains(&v)))
    {
        return Err(ApiError::BadRequest("主题或密度无效".into()));
    }
    Ok(())
}
pub async fn preference(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    if actor.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "工作区偏好仅供交互式管理员会话读取".into(),
        ));
    }
    if !preference_key(&key) {
        return Err(ApiError::BadRequest("偏好键无效".into()));
    }
    let row=sqlx::query("SELECT value,revision,updated_at FROM administrator_preferences WHERE admin_id=$1 AND preference_key=$2").bind(actor.admin_id).bind(&key).fetch_optional(&state.pool).await?;
    Ok(Json(match row {
        Some(row) => {
            json!({"key":key,"value":row.try_get::<Value,_>("value")?,"revision":row.try_get::<i64,_>("revision")?,"updated_at":row.try_get::<i64,_>("updated_at")?})
        }
        None => json!({"key":key,"value":null,"revision":0}),
    }))
}
pub async fn save_preference(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(input): Json<PreferenceInput>,
) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    validate_preference(&key, &input.value)?;
    if actor.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "API令牌不能修改交互式工作区草稿".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(actor.admin_id.saturating_add(73002000))
        .execute(&mut *tx)
        .await?;
    let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM administrator_preferences WHERE admin_id=$1 AND preference_key=$2 FOR UPDATE").bind(actor.admin_id).bind(&key).fetch_optional(&mut *tx).await?;
    let current = revision.unwrap_or(0);
    if current != input.expected_revision {
        return Err(ApiError::Conflict(
            "此视图或草稿已在其他窗口修改，请读取新版本后再保存".into(),
        ));
    }
    let next = current
        .checked_add(1)
        .ok_or_else(|| ApiError::Conflict("偏好版本达到上限".into()))?;
    sqlx::query("INSERT INTO administrator_preferences(admin_id,preference_key,value,revision,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(admin_id,preference_key) DO UPDATE SET value=EXCLUDED.value,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at")
        .bind(actor.admin_id).bind(&key).bind(input.value).bind(next).bind(now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"key":key,"revision":next})))
}

pub async fn audit(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    let rows = sqlx::query("SELECT * FROM management_audit ORDER BY id DESC LIMIT 200")
        .fetch_all(&state.pool)
        .await?;
    let values:Vec<Value>=rows.iter().map(|r|Ok(json!({"id":r.try_get::<i64,_>("id")?,"admin_id":r.try_get::<Option<i64>,_>("admin_id")?,"action":r.try_get::<String,_>("action")?,"object_path":r.try_get::<String,_>("object_path")?,"request_diff":r.try_get::<Value,_>("request_diff")?,"result":r.try_get::<Value,_>("result")?,"occurred_at":r.try_get::<i64,_>("occurred_at")?}))).collect::<Result<_,sqlx::Error>>()?;
    Ok(Json(json!(values)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionInput {
    days: i32,
}
pub async fn retention(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    let rows =
        sqlx::query("SELECT kind,days,updated_at FROM record_retention_policy ORDER BY kind")
            .fetch_all(&state.pool)
            .await?;
    let values:Vec<Value>=rows.iter().map(|r|Ok(json!({"kind":r.try_get::<String,_>("kind")?,"days":r.try_get::<i32,_>("days")?,"updated_at":r.try_get::<i64,_>("updated_at")?}))).collect::<Result<_,sqlx::Error>>()?;
    Ok(Json(json!(values)))
}
pub async fn update_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(kind): Path<String>,
    Json(input): Json<RetentionInput>,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    if !(1..=3650).contains(&input.days) {
        return Err(ApiError::BadRequest("保留期限须为1至3650天".into()));
    }
    let mut tx = state.pool.begin().await?;
    if sqlx::query("UPDATE record_retention_policy SET days=$2,updated_at=$3 WHERE kind=$1")
        .bind(&kind)
        .bind(input.days)
        .bind(now_timestamp())
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(ApiError::NotFound);
    }
    if kind == "monitoring" {
        sqlx::query("UPDATE telemetry_policy SET history_retention_days=$1 WHERE singleton")
            .bind(input.days)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"kind":kind,"days":input.days,"applies_to_future_cleanup":true}),
    ))
}
