use super::{
    documents,
    models::{Configuration, RenewalPolicy},
};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
    plugins::ddns::dns01,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/certificates/{id}/dns-challenges",
            get(list).post(create),
        )
        .route(
            "/api/network-configuration/dns-challenges/{id}/present",
            post(present),
        )
        .route(
            "/api/network-configuration/dns-challenges/{id}/cleanup",
            post(cleanup),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    domain_id: Uuid,
    value: String,
    expires_at: i64,
    credential_id: Option<Uuid>,
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Write>,
) -> ApiResult<Json<Value>> {
    let config = documents::configuration(&documents::load(&state, id).await?)?;
    documents::access(&state, &headers, &config, true).await?;
    crate::control_center::require_capability(&state, &headers, "dns:write").await?;
    let Configuration::Certificate {
        domain_ids,
        renewal: RenewalPolicy::Dns01 { ddns_rule_id, .. },
        ..
    } = config
    else {
        return Err(ApiError::Conflict(
            "请先为证书配置DNS-01与明确维护方".into(),
        ));
    };
    rule_permission(&state, &headers, ddns_rule_id).await?;
    if !domain_ids.contains(&input.domain_id) {
        return Err(ApiError::BadRequest("域名不属于该证书".into()));
    }
    let now = sinan_protocol::now_timestamp();
    if input.value.len() != 43
        || !input
            .value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        || input.expires_at <= now
        || input.expires_at > now + 86400
    {
        return Err(ApiError::BadRequest(
            "请输入签发方提供的43字符DNS-01摘要与24小时内的到期时间".into(),
        ));
    }
    let domain = documents::load(&state, input.domain_id).await?;
    let Configuration::Domain { name, .. } = documents::configuration(&domain)? else {
        return Err(ApiError::BadRequest("关联域名类型错误".into()));
    };
    let name = format!("_acme-challenge.{}", name.trim_start_matches("*."));
    let challenge = Uuid::new_v4();
    sqlx::query("INSERT INTO network_dns_challenges(id,certificate_id,ddns_rule_id,credential_id,name,value,status,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$8)").bind(challenge).bind(id).bind(ddns_rule_id).bind(input.credential_id).bind(&name).bind(input.value).bind(input.expires_at).bind(now).execute(&state.pool).await?;
    Ok(Json(
        json!({"id":challenge,"name":name,"status":"pending","issuer":"external_maintenance_owner","certificate_issued":false}),
    ))
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    let config = documents::configuration(&documents::load(&state, id).await?)?;
    documents::access(&state, &headers, &config, false).await?;
    Ok(Json(sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'status',status,'error_code',error_code,'expires_at',expires_at,'created_at',created_at,'updated_at',updated_at) FROM network_dns_challenges WHERE certificate_id=$1 ORDER BY created_at DESC LIMIT 100").bind(id).fetch_all(&state.pool).await?))
}

async fn present(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    run(state, headers, id, false).await
}
async fn cleanup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    run(state, headers, id, true).await
}

async fn run(
    state: AppState,
    headers: HeaderMap,
    id: Uuid,
    cleanup: bool,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "dns:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM network_dns_challenges WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let certificate_id: Uuid = row.get("certificate_id");
    let config = documents::configuration(&documents::load(&state, certificate_id).await?)?;
    documents::access(&state, &headers, &config, true).await?;
    let expires_at: i64 = row.get("expires_at");
    let now = sinan_protocol::now_timestamp();
    if !cleanup && expires_at <= now {
        return Err(ApiError::Conflict("验证挑战已过期，仅允许清理".into()));
    }
    let rule_id: Uuid = row.get("ddns_rule_id");
    let name: String = row.get("name");
    let value: String = row.get("value");
    let record_id: Option<String> = row.get("record_id");
    let credential_id: Option<Uuid> = row.get("credential_id");
    rule_permission(&state, &headers, rule_id).await?;
    let result = if cleanup {
        dns01::cleanup(
            &state,
            rule_id,
            id,
            &name,
            &value,
            record_id.as_deref(),
            credential_id,
        )
        .await
        .map(|_| None)
    } else {
        dns01::present(&state, rule_id, id, &name, &value, credential_id)
            .await
            .map(Some)
    };
    let (status, record, error) = match result {
        Ok(record) => (if cleanup { "cleaned" } else { "presented" }, record, None),
        Err(_) => ("unknown", record_id, Some("provider_operation_unconfirmed")),
    };
    sqlx::query("UPDATE network_dns_challenges SET status=$2,record_id=COALESCE($3,record_id),error_code=$4,updated_at=$5 WHERE id=$1").bind(id).bind(status).bind(record).bind(error).bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"status":status,"error_code":error,"provider_acceptance":status=="presented","resolver_observation":"not_checked","certificate_issued":false}),
    ))
}

async fn rule_permission(state: &AppState, headers: &HeaderMap, id: Uuid) -> ApiResult<()> {
    let server: i64 = sqlx::query_scalar("SELECT server_id FROM ddns_rules WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::control_center::require_server(state, headers, server, "dns:write").await?;
    Ok(())
}
