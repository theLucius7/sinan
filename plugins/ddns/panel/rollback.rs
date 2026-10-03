use super::{
    LEASE_SECS, REQUEST_BUDGET, editable,
    history::{self, Entry},
    lifecycle::Snapshot,
    model::{self, AddressSource, Rule},
    providers::Providers,
};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::{net::IpAddr, time::Duration};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub revision: i64,
    pub history_id: Uuid,
    pub confirmed: bool,
}

pub(super) async fn rollback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Request>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    crate::control_center::require_capability(&state, &headers, "dns:write").await?;
    let rule = super::load(&state.pool, id).await?;
    crate::control_center::require_server(&state, &headers, rule.config.server_id, "dns:write")
        .await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let client = Providers::new().map_err(|_| ApiError::Busy)?;
    Ok(Json(rollback_with(&state.pool, id, input, &client).await?))
}

pub(super) async fn rollback_with(
    pool: &PgPool,
    id: Uuid,
    input: Request,
    client: &Providers,
) -> ApiResult<Value> {
    if !input.confirmed {
        return Err(ApiError::BadRequest("请确认回退并暂停自动同步".into()));
    }
    let entry: Entry = sqlx::query_as("SELECT * FROM ddns_history WHERE id=$1 AND rule_id=$2 AND operation='sync' AND status='updated'")
        .bind(input.history_id).bind(id).fetch_optional(pool).await?.ok_or(ApiError::NotFound)?;
    let previous = entry
        .previous
        .ok_or_else(|| ApiError::Conflict("首次创建记录没有旧值，不能执行值回退".into()))?;
    let observed = entry
        .observed
        .ok_or_else(|| ApiError::Conflict("历史缺少已核对结果，不能回退".into()))?;
    let (lease, mut rule, ip) = claim(pool, id, input.revision, &previous, &observed).await?;
    let result = tokio::time::timeout(Duration::from_secs(REQUEST_BUDGET), async {
        super::credentials::hydrate(pool, &mut rule)
            .await
            .map_err(|_| super::cloudflare::Failure::from("credential_unavailable"))?;
        client
            .reconcile_expected_guarded(&rule, ip, Some(&observed), || guard(pool, &rule, lease))
            .await
    })
    .await
    .unwrap_or_else(|_| Err("request_timeout".into()));
    let now = sinan_protocol::now_timestamp();
    let (status, error, after) = match &result {
        Ok(outcome) => (
            if outcome.status == "submitted" {
                "submitted"
            } else {
                "rolled_back"
            },
            None,
            Some(history::observed(&rule, ip, outcome, Some(&previous))),
        ),
        Err(error) => ("error", Some(error.code.to_owned()), None),
    };
    let mut tx = pool.begin().await?;
    let updated = sqlx::query("UPDATE ddns_rules SET lease_id=NULL,lease_until=0,status=$3,error_code=$4,last_ip=CASE WHEN $5 THEN $6 ELSE last_ip END,last_success_at=CASE WHEN $5 THEN $7 ELSE last_success_at END WHERE id=$1 AND lease_id=$2 AND revision=$8")
        .bind(id).bind(lease).bind(status).bind(&error).bind(status == "rolled_back")
        .bind(ip.to_string()).bind(now).bind(rule.revision).execute(&mut *tx).await?;
    if updated.rows_affected() == 1 {
        history::append(
            &mut tx,
            Entry {
                id: Uuid::new_v4(),
                rule_id: id,
                server_id: rule.config.server_id,
                revision: rule.revision,
                operation: "rollback".into(),
                desired_ip: Some(ip.to_string()),
                previous: Some(observed),
                observed: after,
                status: status.into(),
                error_code: error.clone(),
                occurred_at: now,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(
        json!({"status":status,"error_code":error,"automatic_sync_paused":true,
        "rule":model::view(pool, super::load(pool, id).await?).await?}),
    )
}

async fn claim(
    pool: &PgPool,
    id: Uuid,
    revision: i64,
    before: &Snapshot,
    after: &Snapshot,
) -> ApiResult<(Uuid, Rule, IpAddr)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await?;
    let mut rule = editable(&mut tx, id).await?;
    if rule.revision != revision {
        return Err(ApiError::Conflict("规则已被修改，请刷新后重试".into()));
    }
    if before.id != after.id
        || before.name != rule.config.record_name
        || before.kind != rule.config.record_type
        || before.line != rule.config.line
        || before.values.len() != 1
        || !before.active
    {
        return Err(ApiError::Conflict(
            "历史记录与当前规则不匹配，不能回退".into(),
        ));
    }
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM ddns_rules WHERE lease_until>$1")
        .bind(sinan_protocol::now_timestamp())
        .fetch_one(&mut *tx)
        .await?;
    if active >= 2 {
        return Err(ApiError::Busy);
    }
    let ip = before.values[0]
        .parse::<IpAddr>()
        .map_err(|_| ApiError::Conflict("旧值不是有效地址".into()))?;
    let mut target = rule.config.clone();
    target.address_source = AddressSource::Manual;
    target.manual_ip = Some(ip.to_string());
    target.ttl =
        u32::try_from(before.ttl).map_err(|_| ApiError::Conflict("历史 TTL 无效".into()))?;
    target.proxied = before.proxied;
    target.normalize()?;
    let info = model::locked_observation(&mut tx, rule.config.server_id).await?;
    info.select(&target, None, sinan_protocol::now_timestamp())
        .map_err(|_| ApiError::Conflict("服务器已退役或 DDNS 插件停用，不能回退".into()))?;
    let lease = Uuid::new_v4();
    rule.config.enabled = false;
    rule.revision += 1;
    sqlx::query("UPDATE ddns_rules SET config=$2,revision=$3,lease_id=$4,lease_until=$5,status='rollback_running',attempted_at=$6 WHERE id=$1")
        .bind(id).bind(json!(rule.config)).bind(rule.revision).bind(lease)
        .bind(sinan_protocol::now_timestamp()+LEASE_SECS).bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx).await?;
    target.enabled = false;
    rule.config = target;
    tx.commit().await?;
    Ok((lease, rule, ip))
}

async fn guard(
    pool: &PgPool,
    rule: &Rule,
    lease: Uuid,
) -> Result<Transaction<'static, Postgres>, super::cloudflare::Failure> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| super::cloudflare::Failure::from("storage_error"))?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await
        .map_err(|_| super::cloudflare::Failure::from("storage_error"))?;
    let owned: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ddns_rules WHERE id=$1 AND lease_id=$2 AND revision=$3 AND lease_until>$4 FOR SHARE")
        .bind(rule.id).bind(lease).bind(rule.revision).bind(sinan_protocol::now_timestamp())
        .fetch_optional(&mut *tx).await.map_err(|_| super::cloudflare::Failure::from("storage_error"))?;
    if owned.is_none() {
        return Err("lease_lost".into());
    }
    super::credentials::guard_reference(&mut tx, rule).await?;
    let info = model::locked_observation(&mut tx, rule.config.server_id)
        .await
        .map_err(|_| super::cloudflare::Failure::from("storage_error"))?;
    info.select(&rule.config, None, sinan_protocol::now_timestamp())
        .map_err(super::cloudflare::Failure::from)?;
    Ok(tx)
}
