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
use serde_json::Value;
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
    super::dns_record_actions::lock(&mut tx).await?;
    let account: Account = sqlx::query_as("SELECT * FROM dns_accounts WHERE id=$1 FOR UPDATE")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;
    dns_accounts::authorize(&state, &headers, &account.config, "dns:write").await?;
    let credential_version =
        super::dns_record_actions::credential_version(&mut tx, &account).await?;
    let entry:Option<super::dns_record_actions::Intent>=sqlx::query_as("SELECT * FROM dns_record_history WHERE id=$1 AND account_id=$2 AND status='applied' AND rollback_started_at IS NULL FOR UPDATE")
        .bind(history_id).bind(account_id).fetch_optional(&mut *tx).await?;
    let entry = entry.ok_or(ApiError::NotFound)?;
    let actor = control_center::authenticate(&state, &headers).await?;
    if !super::dns_records::can_access_history(
        &actor,
        &account.config,
        &serde_json::json!({"account_snapshot":entry.account_snapshot}),
        "dns:write",
    ) {
        return Err(ApiError::Forbidden(
            "当前管理员没有此 DNS 历史原授权范围的变更权限".into(),
        ));
    }
    if entry.account_revision != account.revision
        || entry
            .credential_version
            .is_some_and(|version| version != credential_version)
    {
        return Err(ApiError::Conflict(
            "账号范围或凭据已变化，请核对后重新预览恢复内容".into(),
        ));
    }
    let original: Request = serde_json::from_value(entry.request).map_err(anyhow::Error::from)?;
    let before = entry
        .previous
        .ok_or_else(|| ApiError::Conflict("历史缺少修改前记录".into()))?;
    let after = entry
        .observed
        .ok_or_else(|| ApiError::Conflict("历史缺少已核对结果，不能自动回退".into()))?;
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
    control_center::require_recent_proof(&state, &headers).await?;
    let administrator = control_center::authenticate(&state, &headers)
        .await?
        .admin_id;
    let operation = super::dns_record_actions::reserve(
        &mut tx,
        &account,
        &request,
        after,
        super::dns_record_actions::Origin {
            administrator,
            credential_version,
            preview: None,
            rollback: Some(history_id),
        },
    )
    .await?;
    sqlx::query("UPDATE dns_record_history SET rollback_started_at=$2 WHERE id=$1")
        .bind(history_id)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    super::dns_record_actions::perform(&state, &headers, account_id, operation).await
}
