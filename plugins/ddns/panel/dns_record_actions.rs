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

const RECORD_LOCK: i64 = 739104824;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Apply {
    preview_id: Uuid,
    confirmed: bool,
}

pub(super) async fn lock(connection: &mut sqlx::PgConnection) -> ApiResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(RECORD_LOCK)
        .execute(connection)
        .await?;
    Ok(())
}

pub(super) async fn try_lock(connection: &mut sqlx::PgConnection) -> ApiResult<()> {
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(RECORD_LOCK)
        .fetch_one(connection)
        .await?;
    if !acquired {
        return Err(ApiError::Busy);
    }
    Ok(())
}

pub(super) async fn idle(connection: &mut sqlx::PgConnection, account: Uuid) -> ApiResult<()> {
    let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM dns_record_history WHERE account_id=$1 AND status IN ('unknown','submitted','observed'))")
        .bind(account).fetch_one(connection).await?;
    if unresolved {
        return Err(ApiError::Conflict(
            "此账号有尚未确认的 DNS 变更，仅允许只读核对，不能重放或提交另一项变更".into(),
        ));
    }
    Ok(())
}

pub(super) async fn credential_version(
    connection: &mut sqlx::PgConnection,
    account: &Account,
) -> ApiResult<i64> {
    sqlx::query_scalar(
        "SELECT version FROM credential_entries WHERE id=$1 AND kind='dns' AND enabled FOR SHARE",
    )
    .bind(account.config.credential_id)
    .fetch_optional(connection)
    .await?
    .ok_or_else(|| ApiError::Conflict("DNS 凭据不存在或已停用".into()))
}

pub(super) struct Origin {
    pub administrator: i64,
    pub credential_version: i64,
    pub preview: Option<Uuid>,
    pub rollback: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
pub(super) struct Intent {
    pub status: String,
    pub account_revision: i64,
    pub request: Value,
    pub previous: Option<Value>,
    pub observed: Option<Value>,
    pub requested_by: Option<i64>,
    pub account_snapshot: Option<Value>,
    pub credential_version: Option<i64>,
    pub write_started_at: Option<i64>,
}

pub(super) async fn reserve(
    connection: &mut sqlx::PgConnection,
    account: &Account,
    request: &Request,
    previous: Value,
    origin: Origin,
) -> ApiResult<Uuid> {
    idle_for(connection, account, request, &previous).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO dns_record_history(id,account_id,account_revision,request,previous,status,error_code,occurred_at,requested_by,account_snapshot,credential_version,preview_id,rollback_of) VALUES($1,$2,$3,$4,$5,'unknown','intent_committed',$6,$7,$8,$9,$10,$11)")
        .bind(id).bind(account.id).bind(account.revision).bind(json!(request)).bind(previous)
        .bind(sinan_protocol::now_timestamp()).bind(origin.administrator).bind(json!(account.config))
        .bind(origin.credential_version).bind(origin.preview).bind(origin.rollback)
        .execute(connection).await?;
    Ok(id)
}

async fn idle_for(
    connection: &mut sqlx::PgConnection,
    account: &Account,
    request: &Request,
    previous: &Value,
) -> ApiResult<()> {
    idle(connection, account.id).await?;
    let owner = previous["name"]
        .as_str()
        .or_else(|| request.record["name"].as_str());
    let provider = serde_json::to_value(account.config.provider).map_err(anyhow::Error::from)?;
    let overlapping: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM dns_record_history h WHERE h.status IN ('unknown','submitted','observed') AND h.request->>'zone_id'=$1 AND (h.account_snapshot IS NULL OR h.account_snapshot->>'provider'=$2) AND (($3::TEXT IS NOT NULL AND h.request->>'record_id'=$3) OR ($4::TEXT IS NOT NULL AND ($4=h.previous->>'name' OR $4=h.request->'record'->>'name' OR $4=h.observed->>'name'))))")
        .bind(&request.zone_id).bind(provider.as_str()).bind(request.record_id.as_deref()).bind(owner)
        .fetch_one(connection).await?;
    if overlapping {
        return Err(ApiError::Conflict(
            "此远端记录通过另一账号发起的变更尚未确认，仅允许只读核对".into(),
        ));
    }
    Ok(())
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
    lock(&mut tx).await?;
    let locked: Account = sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let row: Option<(i64, Value, Value, i64, Option<i64>)> = sqlx::query_as("SELECT account_revision,request,snapshot,expires_at,applied_at FROM dns_record_previews WHERE id=$1 AND account_id=$2 FOR UPDATE")
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
    control_center::require_recent_proof(&state, &headers).await?;
    let actor = control_center::authenticate(&state, &headers)
        .await?
        .admin_id;
    let credential_version = credential_version(&mut tx, &locked).await?;
    let request: Request = serde_json::from_value(request).map_err(anyhow::Error::from)?;
    let operation = reserve(
        &mut tx,
        &locked,
        &request,
        before,
        Origin {
            administrator: actor,
            credential_version,
            preview: Some(input.preview_id),
            rollback: None,
        },
    )
    .await?;
    sqlx::query("UPDATE dns_record_previews SET applied_at=$2 WHERE id=$1")
        .bind(input.preview_id)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    // The consumed preview and uncertain operation survive a dropped request or restart.
    tx.commit().await?;
    perform(&state, &headers, id, operation).await
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

pub(super) async fn perform(
    state: &AppState,
    headers: &HeaderMap,
    account_id: Uuid,
    operation: Uuid,
) -> ApiResult<Json<Value>> {
    perform_with(state, headers, account_id, operation, None).await
}

async fn perform_with(
    state: &AppState,
    headers: &HeaderMap,
    account_id: Uuid,
    operation: Uuid,
    supplied_client: Option<RecordClient>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.pool.begin().await?;
    // This transaction protects current account and credential identity, but is not the intent.
    // Dropping it releases the writer lock without erasing the already committed operation.
    lock(&mut tx).await?;
    let account: Account = sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1 FOR UPDATE")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;
    let row: Option<Intent> = sqlx::query_as("SELECT * FROM dns_record_history WHERE id=$1 AND account_id=$2 AND status='unknown' AND write_started_at IS NULL")
        .bind(operation).bind(account_id).fetch_optional(&mut *tx).await?;
    let entry =
        row.ok_or_else(|| ApiError::Conflict("DNS 变更已发送、核对或结束，不能重放".into()))?;
    let request: Request = serde_json::from_value(entry.request).map_err(anyhow::Error::from)?;
    let before = entry
        .previous
        .ok_or_else(|| ApiError::Conflict("DNS 意图缺少修改前记录".into()))?;
    let mut write_started = false;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(super::REQUEST_BUDGET),
        async {
            dns_accounts::authorize(state, headers, &account.config, "dns:write").await?;
            control_center::require_recent_proof(state, headers).await?;
            let actor = control_center::authenticate(state, headers).await?.admin_id;
            if entry.requested_by != Some(actor)
                || entry.account_revision != account.revision
                || entry.account_snapshot.as_ref() != Some(&json!(account.config))
                || entry.credential_version != Some(credential_version(&mut tx, &account).await?)
            {
                return Err(ApiError::Conflict(
                    "发起管理员、账号或凭据已变化，拒绝发送 DNS 变更".into(),
                ));
            }
            let client = match supplied_client {
                Some(client) => client,
                None => dns_accounts::client(&state.pool, &account).await?,
            };
            let (request, owner) =
                prepare(&state.pool, &account, &request, &before, &client).await?;
            mark_started(&state.pool, account_id, operation).await?;
            dns_accounts::authorize(state, headers, &account.config, "dns:write").await?;
            control_center::require_recent_proof(state, headers).await?;
            if control_center::authenticate(state, headers).await?.admin_id != actor {
                return Err(ApiError::Forbidden("DNS 变更发起管理员已变化".into()));
            }
            write(&request, &owner, &mut write_started, &client).await
        },
    )
    .await;
    let (observed, status, error) = match result {
        Ok(Ok(value)) => {
            let status = confirmed_status(&value);
            (Some(value), status, None)
        }
        _ if !write_started => (None, "blocked", Some("precondition_failed")),
        Ok(Err(_)) => (None, "unknown", Some("provider_unconfirmed")),
        Err(_) => (None, "unknown", Some("request_timeout")),
    };
    finish(
        &mut tx,
        account_id,
        operation,
        observed.clone(),
        status,
        error,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"history_id":operation,"status":status,"observed":observed,"error_code":error,"reconcile_required":status=="unknown"||status=="submitted"}),
    ))
}

pub(super) async fn mark_started(
    pool: &sqlx::PgPool,
    account: Uuid,
    operation: Uuid,
) -> ApiResult<()> {
    // Use a separate committed write before provider I/O. No history row lock is held by the writer.
    let changed = sqlx::query("UPDATE dns_record_history SET write_started_at=$3,error_code='provider_unconfirmed' WHERE id=$1 AND account_id=$2 AND status='unknown' AND write_started_at IS NULL")
        .bind(operation).bind(account).bind(sinan_protocol::now_timestamp()).execute(pool).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::Conflict(
            "DNS 变更已经发送或结束，不能重放".into(),
        ));
    }
    Ok(())
}

pub(super) async fn finish(
    connection: &mut sqlx::PgConnection,
    account: Uuid,
    operation: Uuid,
    observed: Option<Value>,
    status: &str,
    error: Option<&str>,
) -> ApiResult<()> {
    let changed = sqlx::query("UPDATE dns_record_history SET observed=$3,status=$4,error_code=$5 WHERE id=$1 AND account_id=$2 AND status='unknown'")
        .bind(operation).bind(account).bind(observed).bind(status).bind(error).execute(&mut *connection).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::Conflict("DNS 变更状态已变化，请只读核对".into()));
    }
    prune(connection, account).await
}

pub(super) async fn prune(connection: &mut sqlx::PgConnection, account: Uuid) -> ApiResult<()> {
    // An uncertain operation is an active identity, regardless of account revisions or age.
    sqlx::query("DELETE FROM dns_record_history WHERE account_id=$1 AND status NOT IN ('unknown','submitted','observed') AND id IN (SELECT id FROM dns_record_history WHERE account_id=$1 ORDER BY occurred_at DESC,id DESC OFFSET 256)")
        .bind(account).execute(connection).await?;
    Ok(())
}

async fn prepare(
    pool: &sqlx::PgPool,
    account: &Account,
    request: &Request,
    before: &Value,
    client: &RecordClient,
) -> ApiResult<(Request, String)> {
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
    Ok((request, owner))
}

async fn write(
    request: &Request,
    owner: &str,
    write_started: &mut bool,
    client: &RecordClient,
) -> ApiResult<Value> {
    *write_started = true;
    let written = client
        .write(request, owner)
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
        || !super::dns_record_reconcile::desired_matches(request, &written)
    {
        return Err(ApiError::Conflict(
            "提供方写入结果无法核对，请读取远端状态".into(),
        ));
    }
    Ok(written)
}

#[cfg(test)]
async fn execute_with_client(
    pool: &sqlx::PgPool,
    account: &Account,
    request: &Request,
    before: &Value,
    write_started: &mut bool,
    client: &RecordClient,
) -> ApiResult<Value> {
    let (request, owner) = prepare(pool, account, request, before, client).await?;
    write(&request, &owner, write_started, client).await
}

#[cfg(test)]
#[path = "tests/dns_record_intents.rs"]
mod intent_tests;
#[cfg(test)]
#[path = "tests/dns_records.rs"]
mod tests;
