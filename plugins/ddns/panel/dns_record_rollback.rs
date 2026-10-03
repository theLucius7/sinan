use super::{
    dns_accounts::{self, Account},
    dns_records::Request,
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
pub(super) struct Confirmation {
    confirmed: bool,
}

pub(super) async fn rollback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, history_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<Confirmation>,
) -> ApiResult<Json<Value>> {
    let account = dns_accounts::load(&state.pool, account_id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    if !input.confirmed {
        return Err(ApiError::BadRequest(
            "请确认恢复此前 DNS 记录；新建记录将删除，已删除记录将重新建立".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await?;
    let account: Account = sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1 FOR UPDATE")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:write").await?;
    dns_accounts::lock_credential(&mut tx, &account).await?;
    let entry:Option<(i64,Value,Option<Value>,Option<Value>)>=sqlx::query_as("SELECT account_revision,request,previous,observed FROM dns_record_history WHERE id=$1 AND account_id=$2 AND status='applied'")
        .bind(history_id).bind(account_id).fetch_optional(&mut *tx).await?;
    let (revision, request, previous, observed) = entry.ok_or(ApiError::NotFound)?;
    if revision != account.revision {
        return Err(ApiError::Conflict(
            "账号范围或凭据已变化，请核对后重新预览恢复内容".into(),
        ));
    }
    let original: Request = serde_json::from_value(request).map_err(anyhow::Error::from)?;
    let before = previous.ok_or_else(|| ApiError::Conflict("历史缺少修改前记录".into()))?;
    let after =
        observed.ok_or_else(|| ApiError::Conflict("历史缺少已核对结果，不能自动回退".into()))?;
    let mut request = Request {
        operation: "update".into(),
        zone_id: original.zone_id,
        record_id: None,
        record: Value::Null,
    };
    if before.is_null() {
        request.operation = "delete".into();
        request.record_id = after["id"].as_str().map(str::to_owned);
    } else {
        request.record = before.clone();
        let fields = request
            .record
            .as_object_mut()
            .ok_or_else(|| ApiError::Conflict("历史记录参数无效".into()))?;
        for key in ["id", "provider_state", "locked", "weight"] {
            fields.remove(key);
        }
        if after.get("comment").is_some() && !fields.contains_key("comment") {
            fields.insert("comment".into(), "".into());
        }
        if after.is_null() {
            request.operation = "create".into();
        } else {
            request.record_id = after["id"].as_str().map(str::to_owned);
        }
    }
    let mut write_started = false;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(super::REQUEST_BUDGET),
        super::dns_record_actions::execute(
            &state.pool,
            &account,
            &request,
            &after,
            &mut write_started,
        ),
    )
    .await;
    let (observed, status, error) = match result {
        Ok(Ok(value)) => {
            let status = super::dns_record_actions::confirmed_status(&value);
            (Some(value), status, None)
        }
        _ if !write_started => (None, "blocked", Some("precondition_failed")),
        _ => (None, "unknown", Some("provider_unconfirmed")),
    };
    super::dns_record_actions::append(
        &mut tx,
        &account,
        &request,
        Some(after),
        observed.clone(),
        (status, error),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"status":status,"observed":observed,"error_code":error,"reconcile_required":status=="unknown"||status=="submitted"}),
    ))
}
