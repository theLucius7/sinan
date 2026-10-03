use super::{fetch, jobs, models::*, service};
use crate::{
    AppState, auth, business,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::now_timestamp;
use sqlx::PgConnection;
use std::collections::BTreeMap;
use uuid::Uuid;

fn input_error(error: SourceFailure) -> ApiError {
    ApiError::BadRequest(error.message)
}

fn source_name(value: &str) -> ApiResult<String> {
    if value.contains("://") || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "来源名称不能包含链接或控制字符".into(),
        ));
    }
    business::name(value)
}

fn content(content: &str) -> ApiResult<()> {
    if content.trim().is_empty() || content.len() > MAX_CONTENT_BYTES {
        return Err(ApiError::BadRequest("订阅内容须非空且不超过 2 MiB".into()));
    }
    Ok(())
}

fn normalize_input(input: &mut SourceInput) -> ApiResult<Option<String>> {
    match input {
        SourceInput::Url { url, auth_headers } => {
            let parsed = fetch::validate_url(url).map_err(input_error)?;
            *url = parsed.to_string();
            *auth_headers = fetch::validate_auth_headers(auth_headers).map_err(input_error)?;
            Ok(parsed.host_str().map(str::to_owned))
        }
        SourceInput::Inline { content: value } => {
            content(value)?;
            Ok(None)
        }
    }
}

fn interval(input: &SourceInput, value: Option<i64>) -> ApiResult<i64> {
    let value = match input {
        SourceInput::Inline { .. } => value.unwrap_or(0),
        SourceInput::Url { .. } => value.unwrap_or(DEFAULT_REFRESH_SECS),
    };
    if match input {
        SourceInput::Inline { .. } => value != 0,
        SourceInput::Url { .. } => !(MIN_REFRESH_SECS..=MAX_REFRESH_SECS).contains(&value),
    } {
        return Err(ApiError::BadRequest(
            "URL 来源周期须为 3600–604800 秒；粘贴或上传来源周期须为 0".into(),
        ));
    }
    Ok(value)
}

fn digest(value: &Value) -> ApiResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(anyhow::Error::from)?)
    ))
}

async fn receipt(
    connection: &mut PgConnection,
    key: Uuid,
    hash: &str,
) -> ApiResult<Option<MutationReceipt>> {
    if key.is_nil() {
        return Err(ApiError::BadRequest("request_id 必须为非零 UUID".into()));
    }
    let bytes = key.as_bytes();
    let lock_key = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    sqlx::query("SELECT pg_advisory_xact_lock(73402901,$1)")
        .bind(lock_key)
        .execute(&mut *connection)
        .await?;
    let previous: Option<(String, Value)> = sqlx::query_as("SELECT request_sha256,receipt FROM singbox_subscription_source_requests WHERE request_id=$1").bind(key).fetch_optional(connection).await?;
    match previous {
        Some((saved, _)) if saved != hash => Err(ApiError::Conflict(
            "此 request_id 已用于不同请求，请保留原请求重试或使用新编号".into(),
        )),
        Some((_, saved)) => Ok(Some(
            serde_json::from_value(saved).map_err(anyhow::Error::from)?,
        )),
        None => Ok(None),
    }
}

async fn save_receipt(
    connection: &mut PgConnection,
    key: Uuid,
    operation: &str,
    hash: &str,
    value: &MutationReceipt,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO singbox_subscription_source_requests(request_id,operation,source_id,request_sha256,receipt,created_at) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(key).bind(operation).bind(value.source_id).bind(hash).bind(json!(value)).bind(now_timestamp()).execute(connection).await?;
    Ok(())
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    ProtectedJson(mut input): ProtectedJson<CreateSource>,
) -> ApiResult<(StatusCode, Json<MutationReceipt>)> {
    auth::require_admin(&state, &headers).await?;
    input.name = source_name(&input.name)?;
    let host = normalize_input(&mut input.input)?;
    let refresh_interval_secs = interval(&input.input, input.refresh_interval_secs)?;
    input.refresh_interval_secs = Some(refresh_interval_secs);
    let hash = digest(&json!({"operation":"create","body":input}))?;
    let mut tx = state.pool.begin().await?;
    if let Some(previous) = receipt(&mut tx, input.request_id, &hash).await? {
        tx.commit().await?;
        return Ok((StatusCode::OK, Json(previous)));
    }
    sqlx::query("SELECT pg_advisory_xact_lock(73402902,1)")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM singbox_ordered_subscription_sources WHERE deleted_at IS NULL",
    )
    .fetch_one(&mut *tx)
    .await?;
    if count >= 128 {
        return Err(ApiError::Conflict(
            "最多保留 128 个未删除的订阅来源，请先整理来源".into(),
        ));
    }
    let kind = match &input.input {
        SourceInput::Url { .. } => "url",
        SourceInput::Inline { .. } => "inline",
    };
    let id: i64 = sqlx::query_scalar("INSERT INTO singbox_ordered_subscription_sources(name,kind,host,input_config,refresh_interval_secs,next_refresh_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$6,$6) RETURNING id")
        .bind(&input.name).bind(kind).bind(host).bind(json!(input.input)).bind(refresh_interval_secs).bind(now_timestamp()).fetch_one(&mut *tx).await?;
    let source = service::load_source(&mut tx, id, true).await?;
    let job_id = jobs::enqueue(&mut tx, &source).await?;
    let result = MutationReceipt {
        source_id: id,
        settings_revision: 1,
        identity_epoch: 1,
        job_id,
    };
    save_receipt(&mut tx, input.request_id, "create", &hash, &result).await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

fn normalize_patch(input: &mut UpdateSource) -> ApiResult<()> {
    if input.settings_revision <= 0 {
        return Err(ApiError::BadRequest(
            "settings_revision 必须为正整数".into(),
        ));
    }
    if let Some(name) = &mut input.name {
        *name = source_name(name)?;
    }
    if let Some(update) = &mut input.input {
        match update {
            InputUpdate::Url { url, auth_headers } => {
                if let Some(url) = url {
                    *url = fetch::validate_url(url).map_err(input_error)?.to_string();
                }
                if let Some(HeaderUpdate::Replace { value }) = auth_headers {
                    if value.is_empty() {
                        return Err(ApiError::BadRequest("移除认证头请使用 clear 操作".into()));
                    }
                    *value = fetch::validate_auth_headers(value).map_err(input_error)?;
                }
            }
            InputUpdate::Inline { content: value, .. } => content(value)?,
        }
    }
    Ok(())
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    ProtectedJson(mut input): ProtectedJson<UpdateSource>,
) -> ApiResult<Json<MutationReceipt>> {
    auth::require_admin(&state, &headers).await?;
    normalize_patch(&mut input)?;
    let hash = digest(&json!({"operation":"update","source_id":id,"body":input}))?;
    let mut tx = state.pool.begin().await?;
    if let Some(previous) = receipt(&mut tx, input.request_id, &hash).await? {
        tx.commit().await?;
        return Ok(Json(previous));
    }
    let old = service::load_source(&mut tx, id, true).await?;
    if old.settings_revision != input.settings_revision {
        return Err(ApiError::Conflict("来源设置已被修改，请刷新后重试".into()));
    }
    let previous: SourceInput =
        serde_json::from_value(old.input_config.clone()).map_err(anyhow::Error::from)?;
    let mut replacement = previous.clone();
    let mut replace_epoch = false;
    let mut import_content = false;
    if let Some(update) = &input.input {
        match update {
            InputUpdate::Url { url, auth_headers } => {
                let (previous_url, previous_headers) = match &previous {
                    SourceInput::Url { url, auth_headers } => {
                        (Some(url.clone()), auth_headers.clone())
                    }
                    SourceInput::Inline { .. } => (None, BTreeMap::new()),
                };
                let new_url = url.clone().or(previous_url).ok_or_else(|| {
                    ApiError::BadRequest("更换为 URL 来源时必须填写订阅地址".into())
                })?;
                let new_headers = match auth_headers {
                    None => previous_headers,
                    Some(HeaderUpdate::Clear) => BTreeMap::new(),
                    Some(HeaderUpdate::Replace { value }) => value.clone(),
                };
                replacement = SourceInput::Url {
                    url: new_url,
                    auth_headers: new_headers,
                };
                replace_epoch = json!(replacement) != old.input_config;
                import_content = replace_epoch;
            }
            InputUpdate::Inline {
                content,
                identity_action,
            } => {
                if matches!(identity_action, IdentityAction::Update) && old.kind != "inline" {
                    return Err(ApiError::BadRequest(
                        "同一来源更新内容仅适用于已有粘贴或上传来源；更换类型请使用 replace".into(),
                    ));
                }
                replacement = SourceInput::Inline {
                    content: content.clone(),
                };
                replace_epoch = matches!(identity_action, IdentityAction::Replace);
                import_content = true;
            }
        }
    }
    let host = normalize_input(&mut replacement)?;
    let kind = match &replacement {
        SourceInput::Url { .. } => "url",
        SourceInput::Inline { .. } => "inline",
    };
    let period = interval(
        &replacement,
        input
            .refresh_interval_secs
            .or((kind == old.kind).then_some(old.refresh_interval_secs)),
    )?;
    let name = input.name.as_deref().unwrap_or(&old.name);
    let archived = input.archived.unwrap_or(old.archived);
    let changed = import_content
        || name != old.name
        || period != old.refresh_interval_secs
        || archived != old.archived;
    let mut result = MutationReceipt {
        source_id: id,
        settings_revision: old.settings_revision,
        identity_epoch: old.identity_epoch,
        job_id: None,
    };
    if changed {
        result.settings_revision = old
            .settings_revision
            .checked_add(1)
            .ok_or_else(|| ApiError::Conflict("来源修订号已到上限，请保留历史并新建来源".into()))?;
        result.identity_epoch = old
            .identity_epoch
            .checked_add(i64::from(replace_epoch))
            .ok_or_else(|| ApiError::Conflict("来源身份代数已到上限，请新建来源".into()))?;
        let had_active = service::active_job(&mut tx, id).await?.is_some();
        jobs::supersede(&mut tx, id).await?;
        let due = if archived {
            None
        } else if import_content || old.archived || had_active {
            Some(now_timestamp())
        } else if period != old.refresh_interval_secs && kind == "url" {
            Some(now_timestamp() + period)
        } else {
            old.next_refresh_at
        };
        sqlx::query("UPDATE singbox_ordered_subscription_sources SET name=$2,kind=$3,host=$4,input_config=$5,settings_revision=$6,last_error=CASE WHEN identity_epoch<>$7 THEN NULL ELSE last_error END,last_attempt_at=CASE WHEN identity_epoch<>$7 THEN NULL ELSE last_attempt_at END,identity_epoch=$7,archived=$8,refresh_interval_secs=$9,next_refresh_at=$10,conditional_etag=NULL,conditional_last_modified=NULL,conditional_settings_revision=NULL,conditional_identity_epoch=NULL,updated_at=$11 WHERE id=$1")
            .bind(id).bind(name).bind(kind).bind(host).bind(json!(replacement)).bind(result.settings_revision).bind(result.identity_epoch).bind(archived).bind(period).bind(due).bind(now_timestamp()).execute(&mut *tx).await?;
        if !archived && (import_content || old.archived || had_active) {
            let source = service::load_source(&mut tx, id, false).await?;
            result.job_id = jobs::enqueue(&mut tx, &source).await?;
        }
    }
    save_receipt(&mut tx, input.request_id, "update", &hash, &result).await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    ProtectedJson(input): ProtectedJson<SourceRevisionInput>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    let source = service::load_source(&mut tx, id, true).await?;
    if source.settings_revision != input.settings_revision {
        return Err(ApiError::Conflict("来源设置已被修改，请刷新后重试".into()));
    }
    let dependencies = super::super::ordered_paths::source_dependencies(&mut tx, id).await?;
    if !dependencies.is_empty() {
        let names = dependencies
            .iter()
            .map(|reference| {
                format!(
                    "链路 #{}「{}」第 {} 跳（{} 代）",
                    reference.chain_id,
                    reference.chain_name,
                    reference.hop_position,
                    reference.generation
                )
            })
            .collect::<Vec<_>>()
            .join("、");
        return Err(ApiError::ConflictReferences {
            message: format!("来源仍被应用、候选或恢复路径引用，请先完成链路撤销：{names}"),
            references: serde_json::json!({"chains":dependencies}),
        });
    }
    jobs::supersede(&mut tx, id).await?;
    sqlx::query("UPDATE singbox_ordered_subscription_sources SET deleted_at=$2,archived=TRUE,input_config='{}'::jsonb,host=NULL,next_refresh_at=NULL,conditional_etag=NULL,conditional_last_modified=NULL,conditional_settings_revision=NULL,conditional_identity_epoch=NULL,updated_at=$2 WHERE id=$1")
        .bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
