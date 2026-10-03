mod client;
mod execution;
#[cfg(test)]
mod tests;

use super::{
    account_on,
    client::Cloud,
    lock,
    model::{Account, Resource},
    resource,
};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::now_timestamp;
use sqlx::{FromRow, PgPool, Postgres, Row, Transaction, types::Json as DbJson};
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/operations/cloud/{id}/security-groups", get(inventory))
        .route(
            "/api/operations/cloud/{id}/security-groups/preview",
            post(preview),
        )
        .route(
            "/api/operations/cloud/security-group-operations/{id}",
            get(detail),
        )
        .route(
            "/api/operations/cloud/security-group-operations/{id}/confirm",
            post(confirm),
        )
        .route(
            "/api/operations/cloud/security-group-operations/{id}/reconcile",
            post(reconcile),
        )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Group {
    id: String,
    vpc_id: String,
    kind: String,
    inner_access_policy: String,
    permissions: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Snapshot {
    resource_id: Uuid,
    account_id: Uuid,
    account_revision: i64,
    resource_revision: i64,
    instance_id: String,
    region: String,
    vpc_id: String,
    server_ids: Vec<i64>,
    link_updated_at: Option<i64>,
    current_groups: Vec<String>,
    managed_groups: Vec<String>,
    protected_groups: Vec<String>,
    groups: Vec<Group>,
}
#[derive(Serialize, FromRow)]
struct Operation {
    id: Uuid,
    resource_id: Uuid,
    requested_by: i64,
    #[sqlx(rename = "before_state")]
    before: DbJson<Snapshot>,
    target_groups: Vec<String>,
    impact: Value,
    snapshot_digest: String,
    status: String,
    steps: Value,
    created_at: i64,
    expires_at: i64,
    updated_at: i64,
    observed_at: Option<i64>,
    actual_groups: Option<Vec<String>>,
    error_code: Option<String>,
    original_result: Option<String>,
    reconciliation: Option<Value>,
}
fn digest<T: Serialize>(value: &T) -> ApiResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(anyhow::Error::from)?)
    ))
}
fn groups(mut value: Vec<String>) -> ApiResult<Vec<String>> {
    if !(1..=16).contains(&value.len())
        || value.iter().any(|id| !super::model::identifier(id, "sg-"))
    {
        return Err(ApiError::BadRequest(
            "目标必须为1–16个明确阿里云安全组ID，不能清空安全组".into(),
        ));
    }
    value.sort();
    if value.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ApiError::BadRequest("安全组ID不能重复".into()));
    }
    Ok(value)
}
fn fee() -> Value {
    json!({"status":"unknown","reason":"未取得阿里云费用报价；不将安全组成员调整或关联业务影响推断为免费。"})
}
fn impact(before: &Snapshot, target: &[String]) -> ApiResult<Value> {
    if before.protected_groups.is_empty()
        || before
            .protected_groups
            .iter()
            .any(|id| !target.contains(id))
    {
        return Err(ApiError::Conflict(
            "必须保留全部当前基线管理组；只允许移除本流程确认加入且规则未变的附加组".into(),
        ));
    }
    if before.groups.iter().any(|group| group.kind != "normal") {
        return Err(ApiError::Conflict(
            "当前流程仅支持普通安全组；企业安全组的组合规则不推断为安全".into(),
        ));
    }
    let added: Vec<_> = target
        .iter()
        .filter(|id| !before.current_groups.contains(id))
        .cloned()
        .collect();
    let removed: Vec<_> = before
        .current_groups
        .iter()
        .filter(|id| !target.contains(id))
        .cloned()
        .collect();
    if added.is_empty() && removed.is_empty() {
        return Err(ApiError::Conflict("当前安全组已等于目标，无需变更".into()));
    }
    for id in &added {
        let group = before
            .groups
            .iter()
            .find(|group| &group.id == id)
            .ok_or_else(|| ApiError::Conflict("目标组资料缺失".into()))?;
        if group.kind != "normal"
            || group.inner_access_policy != "Accept"
            || group
                .permissions
                .as_array()
                .is_none_or(|rules| rules.iter().any(|rule| rule["Policy"] != "Accept"))
        {
            return Err(ApiError::Conflict("只支持普通安全组且附加组规则全部明确Accept；Drop、企业组或不完整策略可能阻断管理连接".into()));
        }
    }
    Ok(
        json!({"added":added,"removed":removed,"baseline_retained":true,"management_connectivity":"existing_baseline_preserved_not_guaranteed","rules_changed":false,"fee":fee(),"order":"join_and_verify_before_leave","scope":"registered_ecs_group_membership_only"}),
    )
}
async fn linked(pool: &PgPool, id: Uuid) -> ApiResult<(Vec<i64>, Option<i64>)> {
    let row =
        sqlx::query("SELECT server_id,updated_at FROM operations_cloud_links WHERE resource_id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row
        .map(|row| {
            (
                row.get::<Option<i64>, _>("server_id").into_iter().collect(),
                Some(row.get("updated_at")),
            )
        })
        .unwrap_or_default())
}
async fn permission(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    historical: &[i64],
    write: bool,
) -> ApiResult<i64> {
    let actor = control_center::authenticate(state, headers).await?;
    if !actor.global_servers() || !actor.allows("cloud:read") {
        return Err(ApiError::Forbidden(
            "安全组官方账号与策略读取需要全局云读取授权".into(),
        ));
    }
    if write && actor.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "高风险云安全组操作需要管理员会话，API令牌不能确认延迟写入".into(),
        ));
    }
    let capability = if write { "cloud:write" } else { "cloud:read" };
    control_center::require_capability(state, headers, capability).await?;
    let (mut ids, _) = linked(&state.pool, id).await?;
    ids.extend(historical);
    ids.sort_unstable();
    ids.dedup();
    for server in ids {
        control_center::require_server(state, headers, server, capability).await?;
    }
    Ok(actor.admin_id)
}
async fn load(pool: &PgPool, id: Uuid) -> ApiResult<Operation> {
    sqlx::query_as("SELECT * FROM alicloud_security_group_operations WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}
async fn context(state: &AppState, id: Uuid) -> ApiResult<(Account, Resource)> {
    let resource = resource(&state.pool, id).await?;
    if resource.kind != "ecs" {
        return Err(ApiError::Conflict(
            "此能力只管理已登记阿里云ECS安全组成员，不支持EIP或其他提供方".into(),
        ));
    }
    let mut tx = lock(&state.pool, resource.account_id).await?;
    let account = account_on(&mut tx, resource.account_id).await?;
    if !account.enabled {
        return Err(ApiError::Conflict("云账号已停用".into()));
    }
    tx.commit().await?;
    Ok((account, resource))
}
async fn snapshot(
    state: &AppState,
    cloud: &Cloud,
    account: &Account,
    resource: &Resource,
    target: &[String],
) -> ApiResult<(Snapshot, i64)> {
    let (mut snapshot, observed_at) = client::snapshot(cloud, account, resource, target)
        .await
        .map_err(super::failure)?;
    let (ids, updated) = linked(&state.pool, resource.id).await?;
    snapshot.server_ids = ids;
    snapshot.link_updated_at = updated;
    let owned = sqlx::query(
        "SELECT group_id,group_digest FROM alicloud_managed_security_groups WHERE resource_id=$1",
    )
    .bind(resource.id)
    .fetch_all(&state.pool)
    .await?;
    for group in &snapshot.groups {
        if !snapshot.current_groups.contains(&group.id) {
            continue;
        }
        let hash = digest(group)?;
        let matches = owned.iter().any(|row| {
            row.get::<String, _>("group_id") == group.id
                && hash == row.get::<String, _>("group_digest")
        });
        if matches {
            snapshot.managed_groups.push(group.id.clone());
        } else {
            snapshot.protected_groups.push(group.id.clone());
        }
    }
    Ok((snapshot, observed_at))
}
async fn inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    permission(&state, &headers, id, &[], false).await?;
    let (account, resource) = context(&state, id).await?;
    let (before, observed_at) = snapshot(
        &state,
        &Cloud::new(&state.pool).map_err(super::failure)?,
        &account,
        &resource,
        &[],
    )
    .await?;
    let operations:Vec<Operation>=sqlx::query_as("SELECT * FROM alicloud_security_group_operations WHERE resource_id=$1 ORDER BY created_at DESC,id DESC LIMIT 50").bind(id).fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"resource_id":id,"instance_id":before.instance_id,"region":before.region,"server_ids":before.server_ids,
        "resource_revision":before.resource_revision,"account_revision":before.account_revision,"current_groups":before.current_groups,
        "managed_groups":before.managed_groups,"protected_groups":before.protected_groups,"observed_at":observed_at,"source":"AliCloud ECS official",
        "rules_edit_available":false,"fee":fee(),"operations":operations}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    target_groups: Vec<String>,
    resource_revision: i64,
}
async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Preview>,
) -> ApiResult<Json<Operation>> {
    preview_with(
        &state,
        &headers,
        id,
        input,
        &Cloud::new(&state.pool).map_err(super::failure)?,
    )
    .await
    .map(Json)
}
async fn preview_with(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    input: Preview,
    cloud: &Cloud,
) -> ApiResult<Operation> {
    let actor = permission(state, headers, id, &[], true).await?;
    control_center::require_recent_proof(state, headers).await?;
    let target = groups(input.target_groups)?;
    let (account, resource) = context(state, id).await?;
    if resource.revision != input.resource_revision {
        return Err(ApiError::Conflict("资源版本已变化，请重新读取".into()));
    }
    let (before, observed_at) = snapshot(state, cloud, &account, &resource, &target).await?;
    let impact = impact(&before, &target)?;
    let hash = digest(&json!({"before":before,"target":target,"impact":impact}))?;
    let mut tx = lock(&state.pool, account.id).await?;
    super::operations::idle(&mut tx, id).await?;
    let operation = Uuid::new_v4();
    let now = now_timestamp();
    sqlx::query("INSERT INTO alicloud_security_group_operations(id,resource_id,requested_by,before_state,target_groups,impact,snapshot_digest,status,created_at,expires_at,updated_at,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,'preview',$8,$9,$8,$10)")
        .bind(operation).bind(id).bind(actor).bind(DbJson(&before)).bind(target).bind(impact).bind(hash).bind(now).bind(now+300).bind(observed_at).execute(&mut *tx).await?;
    tx.commit().await?;
    load(&state.pool, operation).await
}
async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Operation>> {
    let value = load(&state.pool, id).await?;
    permission(
        &state,
        &headers,
        value.resource_id,
        &value.before.server_ids,
        false,
    )
    .await?;
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    confirm: bool,
    snapshot_digest: String,
}
async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Confirm>,
) -> ApiResult<Json<Operation>> {
    control_center::require_recent_proof(&state, &headers).await?;
    execution::confirm(
        &state,
        &headers,
        id,
        input,
        &Cloud::new(&state.pool).map_err(super::failure)?,
    )
    .await
    .map(Json)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconcile {
    process_stopped: bool,
    evidence: String,
}
async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Reconcile>,
) -> ApiResult<Json<Operation>> {
    control_center::require_recent_proof(&state, &headers).await?;
    execution::reconcile(
        &state,
        &headers,
        id,
        input,
        &Cloud::new(&state.pool).map_err(super::failure)?,
    )
    .await
    .map(Json)
}
async fn row_on(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<Operation> {
    sqlx::query_as("SELECT * FROM alicloud_security_group_operations WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
}
