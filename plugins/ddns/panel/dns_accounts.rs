use super::{
    model::{Provider, domain, identifier},
    providers::RecordClient,
};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub name: String,
    pub provider: Provider,
    pub credential_id: Uuid,
    pub zone_ids: Vec<String>,
    #[serde(default)]
    pub server_ids: Vec<i64>,
    pub enabled: bool,
}
#[derive(FromRow, Serialize)]
pub(super) struct Account {
    pub id: Uuid,
    #[sqlx(json)]
    pub config: Config,
    pub revision: i64,
    pub checked_at: Option<i64>,
    pub error_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    config: Config,
    revision: Option<i64>,
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/accounts", get(list).post(create))
        .route("/api/plugins/ddns/accounts/{id}", put(update))
        .route("/api/plugins/ddns/accounts/{id}/check", post(check))
}

pub(super) async fn load(pool: &PgPool, id: Uuid) -> ApiResult<Account> {
    sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

pub(super) fn permits(
    actor: &control_center::Principal,
    config: &Config,
    capability: &str,
) -> bool {
    actor.allows(capability)
        && if config.server_ids.is_empty() {
            actor.global_servers()
        } else {
            config.server_ids.iter().all(|id| actor.allows_server(*id))
        }
}

pub(super) async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    config: &Config,
    capability: &str,
) -> ApiResult<()> {
    let actor = control_center::authenticate(state, headers).await?;
    if !permits(&actor, config, capability) {
        return Err(ApiError::Forbidden(
            "当前管理员没有此 DNS 账号完整授权范围的操作权限".into(),
        ));
    }
    Ok(())
}

async fn normalize(state: &AppState, headers: &HeaderMap, config: &mut Config) -> ApiResult<()> {
    config.name = config.name.trim().into();
    if config.name.is_empty()
        || config.name.len() > 128
        || config.name.chars().any(char::is_control)
        || config.zone_ids.is_empty()
        || config.zone_ids.len() > 32
        || config.server_ids.len() > 32
    {
        return Err(ApiError::BadRequest(
            "账号名称、区域或服务器授权范围无效".into(),
        ));
    }
    for zone in &mut config.zone_ids {
        *zone = zone.trim().to_ascii_lowercase();
        let valid = match config.provider {
            Provider::Cloudflare | Provider::Huawei => identifier(zone),
            Provider::Aliyun | Provider::Tencent => {
                domain(zone).is_some_and(|name| name == *zone && !name.starts_with("*."))
            }
        };
        if !valid {
            return Err(ApiError::BadRequest("DNS 区域标识无效".into()));
        }
    }
    config.zone_ids.sort();
    config.zone_ids.dedup();
    config.server_ids.sort();
    config.server_ids.dedup();
    authorize(state, headers, config, "dns:write").await?;
    for id in &config.server_ids {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1)")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
        if !exists {
            return Err(ApiError::BadRequest("授权范围包含不存在的服务器".into()));
        }
    }
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credential_entries WHERE id=$1 AND kind='dns' AND enabled)",
    )
    .bind(config.credential_id)
    .fetch_one(&state.pool)
    .await?;
    if !valid {
        return Err(ApiError::Conflict(
            "DNS 凭据不存在、已停用或用途不匹配".into(),
        ));
    }
    Ok(())
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Value>>> {
    let actor = control_center::authenticate(&state, &headers).await?;
    if !actor.allows("dns:read") {
        return Err(ApiError::Forbidden("没有 DNS 读取权限".into()));
    }
    let accounts: Vec<Account> =
        sqlx::query_as("SELECT * FROM dns_accounts ORDER BY created_at,id")
            .fetch_all(&state.pool)
            .await?;
    let mut values = Vec::new();
    for account in accounts {
        if permits(&actor, &account.config, "dns:read") {
            let capabilities = super::dns_record_spec::capabilities(account.config.provider);
            let mut value = serde_json::to_value(account).map_err(anyhow::Error::from)?;
            value["record_management_available"] = true.into();
            value["record_capabilities"] = capabilities;
            value["unavailable_reason"] = Value::Null;
            values.push(value);
        }
    }
    Ok(Json(values))
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<Write>,
) -> ApiResult<Json<Value>> {
    control_center::require_recent_proof(&state, &headers).await?;
    normalize(&state, &headers, &mut input.config).await?;
    let id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO dns_accounts(id,config,created_at,updated_at) VALUES($1,$2,$3,$3)")
        .bind(id)
        .bind(json!(input.config))
        .bind(now)
        .execute(&state.pool)
        .await?;
    Ok(Json(json!(load(&state.pool, id).await?)))
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(mut input): Json<Write>,
) -> ApiResult<Json<Value>> {
    control_center::require_recent_proof(&state, &headers).await?;
    let before = load(&state.pool, id).await?;
    authorize(&state, &headers, &before.config, "dns:write").await?;
    normalize(&state, &headers, &mut input.config).await?;
    if sqlx::query("UPDATE dns_accounts SET config=$2,revision=revision+1,updated_at=$3,checked_at=NULL,error_code=NULL WHERE id=$1 AND revision=$4")
        .bind(id).bind(json!(input.config)).bind(sinan_protocol::now_timestamp()).bind(input.revision)
        .execute(&state.pool).await?.rows_affected()!=1 { return Err(ApiError::Conflict("账号已修改，请刷新后重试".into())); }
    Ok(Json(json!(load(&state.pool, id).await?)))
}

pub(super) async fn client(pool: &PgPool, account: &Account) -> ApiResult<RecordClient> {
    if !account.config.enabled {
        return Err(ApiError::Conflict("DNS 账号已停用".into()));
    }
    let secret = control_center::credentials::resolve_reference_pool(
        pool,
        account.config.credential_id,
        "dns",
        &format!("dns-account:{}", account.id),
    )
    .await?;
    RecordClient::new(account.config.provider, &secret).map_err(failure)
}

pub(super) fn failure(error: super::cloudflare::Failure) -> ApiError {
    ApiError::Conflict(format!("DNS 提供方返回未确认结果：{}", error.code))
}

pub(super) async fn zone(client: &RecordClient, account: &Account, id: &str) -> ApiResult<String> {
    if !account.config.zone_ids.iter().any(|zone| zone == id) {
        return Err(ApiError::Forbidden("区域不在此账号的明确授权范围内".into()));
    }
    client.zone(id).await.map_err(failure)
}

pub(super) async fn lock_credential(
    connection: &mut sqlx::PgConnection,
    account: &Account,
) -> ApiResult<()> {
    let valid: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM credential_entries WHERE id=$1 AND kind='dns' AND enabled FOR SHARE",
    )
    .bind(account.config.credential_id)
    .fetch_optional(connection)
    .await?;
    if valid.is_none() {
        return Err(ApiError::Conflict("DNS 凭据不存在或已停用".into()));
    }
    Ok(())
}

async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let account = load(&state.pool, id).await?;
    authorize(&state, &headers, &account.config, "dns:read").await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let result = async {
        let client = client(&state.pool, &account).await?;
        let mut zones = Vec::new();
        for id in &account.config.zone_ids {
            match client.zone(id).await {
                Ok(name) => {
                    zones.push(json!({"id":id,"name":name,"available":true,"error_code":null}))
                }
                Err(error) => zones
                    .push(json!({"id":id,"name":null,"available":false,"error_code":error.code})),
            }
        }
        Ok::<_, ApiError>(zones)
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(super::REQUEST_BUDGET),
        result,
    )
    .await;
    let now = sinan_protocol::now_timestamp();
    let (zones, error) = match result {
        Ok(Ok(zones)) => {
            let failed = zones.iter().any(|zone| zone["available"] != true);
            (
                zones,
                if failed {
                    Some("zone_check_failed")
                } else {
                    None
                },
            )
        }
        Ok(Err(_)) => (Vec::new(), Some("connection_unconfirmed")),
        Err(_) => (Vec::new(), Some("request_timeout")),
    };
    sqlx::query("UPDATE dns_accounts SET checked_at=$2,error_code=$3 WHERE id=$1 AND revision=$4")
        .bind(id)
        .bind(now)
        .bind(error)
        .bind(account.revision)
        .execute(&state.pool)
        .await?;
    Ok(Json(
        json!({"zones":zones,"checked_at":now,"error_code":error,"provider":account.config.provider,"accepted":error.is_none(),"source":"provider_official_api"}),
    ))
}
