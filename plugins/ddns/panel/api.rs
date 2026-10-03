use super::{
    MAX_RULES, editable, load,
    model::{self, Config, Provider, Rule},
    worker,
};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/rules", get(list).post(create))
        .route(
            "/api/plugins/ddns/rules/dual-stack",
            post(create_dual_stack),
        )
        .route("/api/plugins/ddns/rules/{id}", patch(update).delete(remove))
        .route("/api/plugins/ddns/rules/{id}/sync", post(sync))
        .merge(super::settings::routes())
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Value>>> {
    auth::require_admin(&state, &headers).await?;
    let rules = sqlx::query_as::<_, Rule>("SELECT * FROM ddns_rules ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    let mut result = Vec::new();
    for rule in rules {
        result.push(model::view(&state.pool, rule).await?);
    }
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    config: Config,
    api_token: Option<String>,
    access_key_id: Option<String>,
    access_key_secret: Option<String>,
    revision: Option<i64>,
}

async fn valid_server(state: &AppState, config: &Config) -> ApiResult<()> {
    let server = model::observation(&state.pool, config.server_id).await?;
    if !server.plugin_enabled {
        return Err(ApiError::Conflict("请先为该服务器启用 DDNS 插件".into()));
    }
    if server.deleted_at.is_some() || server.retiring {
        return Err(ApiError::Conflict(
            "无法绑定已删除或正在退役的服务器".into(),
        ));
    }
    Ok(())
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Write>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    auth::require_admin(&state, &headers).await?;
    let record_types = [input.config.record_type.clone()];
    let mut rules = create_rules(&state, input, &record_types).await?;
    Ok((StatusCode::CREATED, Json(rules.remove(0))))
}

async fn create_dual_stack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Write>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    auth::require_admin(&state, &headers).await?;
    let rules = create_rules(&state, input, &["A".into(), "AAAA".into()]).await?;
    Ok((StatusCode::CREATED, Json(json!({"rules": rules}))))
}

async fn create_rules(
    state: &AppState,
    mut input: Write,
    record_types: &[String],
) -> ApiResult<Vec<Value>> {
    input.config.normalize()?;
    valid_server(state, &input.config).await?;
    let (token, key, secret) = credentials(&input, None)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104823)")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM ddns_rules")
        .fetch_one(&mut *tx)
        .await?;
    if count + record_types.len() as i64 > MAX_RULES {
        return Err(ApiError::Conflict("最多配置 32 条 DDNS 规则".into()));
    }
    let mut ids = Vec::new();
    for record_type in record_types {
        let id = Uuid::new_v4();
        let mut config = input.config.clone();
        config.record_type.clone_from(record_type);
        let result =
        sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token,access_key_id,access_key_secret) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(id)
            .bind(config.server_id)
            .bind(json!(config))
            .bind(&token)
            .bind(&key)
            .bind(&secret)
            .execute(&mut *tx)
            .await;
        if result.as_ref().is_err_and(|error| {
            error
                .as_database_error()
                .is_some_and(|error| error.is_unique_violation())
        }) {
            return Err(ApiError::Conflict(
                "此提供方、Zone、域名、类型及线路已存在规则，未创建任何新规则".into(),
            ));
        }
        result?;
        ids.push(id);
    }
    tx.commit().await?;
    let mut rules = Vec::new();
    for id in ids {
        rules.push(model::view(&state.pool, load(&state.pool, id).await?).await?);
    }
    Ok(rules)
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(mut input): Json<Write>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    input.config.normalize()?;
    let mut tx = state.pool.begin().await?;
    let previous = editable(&mut tx, id).await?;
    if input.revision != Some(previous.revision) {
        return Err(ApiError::Conflict("规则已被修改，请刷新后重试".into()));
    }
    if input.config.provider != previous.config.provider
        || input.config.line != previous.config.line
        || input.config.zone_id != previous.config.zone_id
        || input.config.record_name != previous.config.record_name
        || input.config.record_type != previous.config.record_type
    {
        return Err(ApiError::BadRequest(
            "提供方、Zone、域名、类型和线路创建后固定，请另建规则".into(),
        ));
    }
    // A retired binding may still be paused or have its secret replaced.
    if input.config.enabled || input.config.server_id != previous.config.server_id {
        valid_server(&state, &input.config).await?;
    }
    let (token, key, secret) = credentials(&input, Some(&previous))?;
    sqlx::query("UPDATE ddns_rules SET server_id=$2,config=$3,api_token=$4,access_key_id=$5,access_key_secret=$6,revision=revision+1,next_run_at=GREATEST(0,COALESCE(attempted_at,0)+60),failures=0,status='pending',error_code=NULL,lease_id=NULL,lease_until=0 WHERE id=$1")
        .bind(id).bind(input.config.server_id).bind(json!(input.config)).bind(token).bind(key).bind(secret).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        model::view(&state.pool, load(&state.pool, id).await?).await?,
    ))
}

fn credentials(input: &Write, previous: Option<&Rule>) -> ApiResult<(String, String, String)> {
    let supplied = |value: &Option<String>| {
        value
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    if input.config.provider == Provider::Cloudflare {
        if supplied(&input.access_key_id).is_some() || supplied(&input.access_key_secret).is_some()
        {
            return Err(ApiError::BadRequest("Cloudflare 使用 API Token".into()));
        }
        let token = supplied(&input.api_token)
            .or_else(|| previous.map(|r| r.api_token.clone()))
            .unwrap_or_default();
        return Ok((model::token(&token)?, String::new(), String::new()));
    }
    if supplied(&input.api_token).is_some() {
        return Err(ApiError::BadRequest("此提供方使用访问密钥对".into()));
    }
    let key = supplied(&input.access_key_id);
    let secret = supplied(&input.access_key_secret);
    match (key, secret) {
        (None, None) if previous.is_some() => {
            let row = previous.expect("checked");
            Ok((
                String::new(),
                row.access_key_id.clone(),
                row.access_key_secret.clone(),
            ))
        }
        (Some(key), Some(secret))
            if crate::cloud_api::credential(&key) && crate::cloud_api::credential(&secret) =>
        {
            Ok((String::new(), key, secret))
        }
        _ => Err(ApiError::BadRequest(
            "请同时填写有效的访问密钥 ID 和 Secret；编辑时同时留空保留".into(),
        )),
    }
}

async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    editable(&mut tx, id).await?;
    sqlx::query("DELETE FROM ddns_rules WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    worker::sync(&state.pool, id, true).await?;
    Ok(Json(
        model::view(&state.pool, load(&state.pool, id).await?).await?,
    ))
}
