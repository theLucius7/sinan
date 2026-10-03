use super::{
    dns_accounts::{self, Account},
    dns_record_spec::normalize_for,
    dns_records::{Request, current, protect_ddns},
    providers::RecordClient,
};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Apply {
    preview_id: Uuid,
    confirmed: bool,
}

pub(super) async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Apply>,
) -> ApiResult<Json<Value>> {
    let account = dns_accounts::load(&state.pool, id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    if !input.confirmed {
        return Err(ApiError::BadRequest("请确认 DNS 变更预览".into()));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await?;
    let locked: Account = sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let row:Option<(i64,Value,Value,i64,Option<i64>)>=sqlx::query_as("SELECT account_revision,request,snapshot,expires_at,applied_at FROM dns_record_previews WHERE id=$1 AND account_id=$2 FOR UPDATE")
        .bind(input.preview_id).bind(id).fetch_optional(&mut *tx).await?;
    let (revision, request, before, expires, applied) = row.ok_or(ApiError::NotFound)?;
    if revision != locked.revision
        || expires <= sinan_protocol::now_timestamp()
        || applied.is_some()
    {
        return Err(ApiError::Conflict(
            "账号或预览已变化、过期或已经执行，请重新预览".into(),
        ));
    }
    dns_accounts::authorize(&state, &headers, &locked.config, "dns:write").await?;
    dns_accounts::lock_credential(&mut tx, &locked).await?;
    let request: Request = serde_json::from_value(request).map_err(anyhow::Error::from)?;
    let mut write_started = false;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(super::REQUEST_BUDGET),
        execute(&state.pool, &locked, &request, &before, &mut write_started),
    )
    .await;
    let now = sinan_protocol::now_timestamp();
    let (observed, status, error) = match result {
        Ok(Ok(value)) => {
            let status = confirmed_status(&value);
            (Some(value), status, None)
        }
        _ if !write_started => (None, "blocked", Some("precondition_failed")),
        Ok(Err(_)) => (None, "unknown", Some("provider_unconfirmed")),
        Err(_) => (None, "unknown", Some("request_timeout")),
    };
    sqlx::query("UPDATE dns_record_previews SET applied_at=$2 WHERE id=$1")
        .bind(input.preview_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    append(
        &mut tx,
        &locked,
        &request,
        Some(before),
        observed.clone(),
        (status, error),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"status":status,"observed":observed,"error_code":error,"reconcile_required":status=="unknown"||status=="submitted"}),
    ))
}

pub(super) fn confirmed_status(observed: &Value) -> &'static str {
    if observed["provider_state"]
        .as_str()
        .is_some_and(|state| state.starts_with("pending"))
    {
        "submitted"
    } else {
        "applied"
    }
}

pub(super) async fn execute(
    pool: &sqlx::PgPool,
    account: &Account,
    request: &Request,
    before: &Value,
    write_started: &mut bool,
) -> ApiResult<Value> {
    let client = dns_accounts::client(pool, account).await?;
    execute_with_client(pool, account, request, before, write_started, &client).await
}

pub(super) async fn execute_with_client(
    pool: &sqlx::PgPool,
    account: &Account,
    request: &Request,
    before: &Value,
    write_started: &mut bool,
    client: &RecordClient,
) -> ApiResult<Value> {
    let owner = dns_accounts::zone(client, account, &request.zone_id).await?;
    let mut request = request.clone();
    normalize_for(&mut request, &owner, account.config.provider)?;
    let remote = current(client, &request, &owner).await?;
    if &remote != before {
        return Err(ApiError::Conflict(
            "远端 DNS 记录已变化，拒绝覆盖；请重新预览".into(),
        ));
    }
    protect_ddns(pool, account.config.provider, &request, &remote).await?;
    *write_started = true;
    let written = client
        .write(&request, &owner)
        .await
        .map_err(dns_accounts::failure)?;
    if request.operation == "delete" {
        return Ok(written);
    }
    if written["id"].as_str().is_none()
        || request
            .record_id
            .as_ref()
            .is_some_and(|id| written["id"] != *id)
        || !super::dns_record_reconcile::desired_matches(&request, &written)
    {
        return Err(ApiError::Conflict(
            "提供方写入结果无法核对，请读取远端状态".into(),
        ));
    }
    Ok(written)
}

pub(super) async fn append(
    connection: &mut sqlx::PgConnection,
    account: &Account,
    request: &Request,
    previous: Option<Value>,
    observed: Option<Value>,
    result: (&str, Option<&str>),
) -> ApiResult<()> {
    let (status, error) = result;
    sqlx::query("INSERT INTO dns_record_history(id,account_id,account_revision,request,previous,observed,status,error_code,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(Uuid::new_v4()).bind(account.id).bind(account.revision).bind(json!(request)).bind(previous).bind(observed).bind(status).bind(error).bind(sinan_protocol::now_timestamp()).execute(&mut *connection).await?;
    sqlx::query("DELETE FROM dns_record_history WHERE account_id=$1 AND id IN (SELECT id FROM dns_record_history WHERE account_id=$1 ORDER BY occurred_at DESC,id DESC OFFSET 256)")
        .bind(account.id).execute(connection).await?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/dns_records.rs"]
mod tests;
