use super::{
    dns_accounts::{self},
    dns_record_actions::apply,
    dns_record_spec::normalize_for,
};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub operation: String,
    pub zone_id: String,
    pub record_id: Option<String>,
    pub record: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    zone_id: String,
    #[serde(default = "first_page")]
    page: u32,
}
fn first_page() -> u32 {
    1
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/accounts/{id}/records", get(list))
        .route(
            "/api/plugins/ddns/accounts/{id}/records/preview",
            post(preview),
        )
        .route("/api/plugins/ddns/accounts/{id}/records/apply", post(apply))
        .route(
            "/api/plugins/ddns/accounts/{id}/records/history",
            get(history),
        )
        .route(
            "/api/plugins/ddns/accounts/{id}/records/{history}/reconcile",
            post(super::dns_record_reconcile::reconcile),
        )
        .route(
            "/api/plugins/ddns/accounts/{id}/records/{history}/rollback",
            post(super::dns_record_rollback::rollback),
        )
}

pub(super) async fn current(
    client: &super::providers::RecordClient,
    request: &Request,
    zone_name: &str,
) -> ApiResult<Value> {
    if let Some(id) = &request.record_id {
        return client
            .get(&request.zone_id, id, zone_name)
            .await
            .map_err(dns_accounts::failure);
    }
    let owner = request.record["name"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("缺少记录名称".into()))?;
    let entries = client
        .find(&request.zone_id, owner, zone_name)
        .await
        .map_err(dns_accounts::failure)?;
    if entries.iter().any(|record| {
        (record["type"] == request.record["type"] && record["line"] == request.record["line"])
            || record["type"] == "CNAME"
            || request.record["type"] == "CNAME"
    }) {
        return Err(ApiError::Conflict(
            "同名同线路记录已有相同类型或别名冲突，请明确编辑已有记录".into(),
        ));
    }
    Ok(Value::Null)
}

pub(super) async fn protect_ddns(
    pool: &sqlx::PgPool,
    provider: super::model::Provider,
    request: &Request,
    before: &Value,
) -> ApiResult<()> {
    if before["comment"]
        .as_str()
        .is_some_and(|comment| comment.starts_with("sinan-acme:"))
    {
        return Err(ApiError::Conflict(
            "此记录由正在执行的证书挑战维护，不能通过普通 DNS 编辑覆盖".into(),
        ));
    }
    if before["locked"] == true
        || before["weight"].as_u64().is_some_and(|weight| weight != 0)
        || before["provider_state"]
            .as_str()
            .is_some_and(|state| state != "active")
    {
        return Err(ApiError::Conflict(
            "记录已锁定、加权或提供方尚未完成，需先在提供方确认状态".into(),
        ));
    }
    let owner = before["name"]
        .as_str()
        .or_else(|| request.record["name"].as_str())
        .unwrap_or_default();
    let kind = before["type"]
        .as_str()
        .or_else(|| request.record["type"].as_str())
        .unwrap_or_default();
    let managed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ddns_rules WHERE config->>'provider'=$4 AND config->>'zone_id'=$1 AND config->>'record_name'=ANY($2) AND config->>'record_type'=ANY($3) AND config->>'enabled'='true')")
        .bind(&request.zone_id).bind(vec![owner,request.record["name"].as_str().unwrap_or(owner)]).bind(vec![kind,request.record["type"].as_str().unwrap_or(kind)]).bind(serde_json::to_value(provider).map_err(anyhow::Error::from)?.as_str().unwrap_or_default()).fetch_one(pool).await?;
    if managed {
        return Err(ApiError::Conflict(
            "此记录由启用的 DDNS 规则维护，请先暂停该规则再编辑".into(),
        ));
    }
    Ok(())
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(input): Query<Listing>,
) -> ApiResult<Json<Value>> {
    let account = dns_accounts::load(&state.pool, id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:read").await?;
    if !(1..=1000).contains(&input.page) {
        return Err(ApiError::BadRequest("页码无效".into()));
    }
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let client = dns_accounts::client(&state.pool, &account).await?;
    let zone_name = dns_accounts::zone(&client, &account, &input.zone_id).await?;
    let mut result = client
        .list(&input.zone_id, &zone_name, input.page)
        .await
        .map_err(dns_accounts::failure)?;
    result["checked_at"] = sinan_protocol::now_timestamp().into();
    result["provider"] = json!(account.config.provider);
    result["source"] = "provider_official_api".into();
    Ok(Json(result))
}

async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(mut input): Json<Request>,
) -> ApiResult<Json<Value>> {
    let account = dns_accounts::load(&state.pool, id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:write").await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let client = dns_accounts::client(&state.pool, &account).await?;
    let owner = dns_accounts::zone(&client, &account, &input.zone_id).await?;
    normalize_for(&mut input, &owner, account.config.provider)?;
    let before = current(&client, &input, &owner).await?;
    protect_ddns(&state.pool, account.config.provider, &input, &before).await?;
    let preview = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("DELETE FROM dns_record_previews WHERE expires_at<=$1")
        .bind(now)
        .execute(&state.pool)
        .await?;
    sqlx::query("INSERT INTO dns_record_previews(id,account_id,account_revision,request,snapshot,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(preview).bind(id).bind(account.revision).bind(json!(input)).bind(&before).bind(now).bind(now+300).execute(&state.pool).await?;
    Ok(Json(
        json!({"preview_id":preview,"previous":before,"desired":input.record,"operation":input.operation,"expires_at":now+300,"dns_written":false}),
    ))
}

pub(super) async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    let account = dns_accounts::load(&state.pool, id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:read").await?;
    let actor = crate::control_center::authenticate(&state, &headers).await?;
    let entries: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(h) FROM dns_record_history h WHERE account_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 256")
        .bind(id).fetch_all(&state.pool).await?;
    Ok(Json(
        entries
            .into_iter()
            .filter(|entry| can_read_history(&actor, &account.config, entry))
            .collect(),
    ))
}

pub(super) fn can_read_history(
    actor: &crate::control_center::Principal,
    current: &dns_accounts::Config,
    entry: &Value,
) -> bool {
    can_access_history(actor, current, entry, "dns:read")
}

pub(super) fn can_access_history(
    actor: &crate::control_center::Principal,
    current: &dns_accounts::Config,
    entry: &Value,
    capability: &str,
) -> bool {
    if !dns_accounts::permits(actor, current, capability) {
        return false;
    }
    match entry
        .get("account_snapshot")
        .filter(|value| !value.is_null())
    {
        Some(snapshot) => serde_json::from_value::<dns_accounts::Config>(snapshot.clone())
            .is_ok_and(|original| dns_accounts::permits(actor, &original, capability)),
        // Older rows have no original scope evidence. A current revision match cannot
        // substitute for that missing evidence for a restricted administrator.
        None => actor.global_servers(),
    }
}
