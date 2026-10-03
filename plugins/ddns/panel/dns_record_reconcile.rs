use super::{
    dns_accounts::{self, Account},
    dns_record_spec::normalize_for,
    dns_records::Request,
    providers::RecordClient,
};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) fn desired_matches(request: &Request, observed: &Value) -> bool {
    request.record.as_object().is_some_and(|fields| {
        fields.iter().all(|(key, value)| {
            if key == "data" {
                let expected = value["records"].as_array();
                let actual = observed["data"]["records"].as_array();
                if let (Some(expected), Some(actual)) = (expected, actual) {
                    let expected: std::collections::BTreeSet<_> =
                        expected.iter().filter_map(Value::as_str).collect();
                    let actual: std::collections::BTreeSet<_> =
                        actual.iter().filter_map(Value::as_str).collect();
                    return expected == actual;
                }
            }
            observed[key] == *value
        })
    })
}

async fn observe(
    client: &RecordClient,
    request: &Request,
    previous: &Value,
    observed: &Value,
    owner: &str,
) -> ApiResult<(String, Value)> {
    if request.operation == "delete" {
        let name = previous["name"]
            .as_str()
            .ok_or_else(|| ApiError::Conflict("历史缺少已删除记录名称".into()))?;
        let entries = client
            .find(&request.zone_id, name, owner)
            .await
            .map_err(dns_accounts::failure)?;
        if entries.iter().any(|entry| {
            request
                .record_id
                .as_ref()
                .is_some_and(|id| entry["id"] == *id)
        }) {
            return Ok(("unconfirmed".into(), json!(entries)));
        }
        return Ok(("applied".into(), Value::Null));
    }
    let id = request
        .record_id
        .as_deref()
        .or_else(|| observed["id"].as_str());
    let candidate = if let Some(id) = id {
        client
            .get(&request.zone_id, id, owner)
            .await
            .map_err(dns_accounts::failure)?
    } else {
        let entries = client
            .find(
                &request.zone_id,
                request.record["name"].as_str().unwrap_or_default(),
                owner,
            )
            .await
            .map_err(dns_accounts::failure)?;
        let matching = entries
            .iter()
            .filter(|entry| desired_matches(request, entry))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Ok(("unconfirmed".into(), json!(entries)));
        }
        (*matching[0]).clone()
    };
    if candidate["provider_state"]
        .as_str()
        .is_some_and(|state| state != "active")
        || !desired_matches(request, &candidate)
    {
        return Ok(("unconfirmed".into(), candidate));
    }
    // A lost create response cannot prove that a matching record was created by this request.
    Ok((
        if id.is_none() { "observed" } else { "applied" }.into(),
        candidate,
    ))
}

pub(super) async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((account_id, history_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    let account = dns_accounts::load(&state.pool, account_id).await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:read").await?;
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let mut tx = state.pool.begin().await?;
    let account: Account = sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1 FOR SHARE")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:read").await?;
    let row:Option<(i64,Value,Option<Value>,Option<Value>)>=sqlx::query_as("SELECT account_revision,request,previous,observed FROM dns_record_history WHERE id=$1 AND account_id=$2 AND status IN('unknown','submitted','observed') FOR UPDATE").bind(history_id).bind(account_id).fetch_optional(&mut *tx).await?;
    let (revision, request, previous, observed) = row.ok_or(ApiError::NotFound)?;
    if revision != account.revision {
        return Err(ApiError::Conflict(
            "账号已变化，需按当前区域与凭据重新核对".into(),
        ));
    }
    let client = dns_accounts::client(&state.pool, &account).await?;
    let owner = dns_accounts::zone(
        &client,
        &account,
        request["zone_id"].as_str().unwrap_or_default(),
    )
    .await?;
    let mut request: Request = serde_json::from_value(request).map_err(anyhow::Error::from)?;
    normalize_for(&mut request, &owner, account.config.provider)?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(super::REQUEST_BUDGET),
        observe(
            &client,
            &request,
            &previous.unwrap_or(Value::Null),
            &observed.unwrap_or(Value::Null),
            &owner,
        ),
    )
    .await
    .map_err(|_| ApiError::Conflict("远端核对超时；原状态保留，未重放变更".into()))??;
    let (status, value) = result;
    if status != "unconfirmed" {
        sqlx::query("UPDATE dns_record_history SET status=$3,observed=$4,error_code=NULL WHERE id=$1 AND account_id=$2").bind(history_id).bind(account_id).bind(&status).bind(&value).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"status":status,"observed":value,"checked_at":sinan_protocol::now_timestamp(),"source":"provider_official_api","dns_written":false,"ownership_confirmed":status=="applied"}),
    ))
}
