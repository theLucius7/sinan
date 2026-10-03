use super::projection::catalog_on;
use crate::{
    AppState,
    auth::require_admin,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    items: Vec<Change>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    kind: String,
    id: i64,
    revision: String,
    name: Option<String>,
    tags: Option<Vec<String>>,
    note: Option<String>,
    sort_order: Option<i64>,
    enabled: Option<bool>,
}

fn validate(mut request: Batch, deleting: bool) -> ApiResult<Vec<Change>> {
    if request.items.is_empty() || request.items.len() > 200 {
        return Err(ApiError::BadRequest("每次请选择 1 至 200 个节点".into()));
    }
    let mut seen = BTreeSet::new();
    for item in &mut request.items {
        if !matches!(item.kind.as_str(), "direct" | "chain" | "external")
            || item.id <= 0
            || item.revision.len() != 64
            || !item.revision.bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err(ApiError::BadRequest("节点标识或管理版本无效".into()));
        }
        if item.id > super::super::business::MAX_SAFE_INTEGER
            || item.sort_order.is_some_and(|value| {
                !(-super::super::business::MAX_SAFE_INTEGER
                    ..=super::super::business::MAX_SAFE_INTEGER)
                    .contains(&value)
            })
        {
            return Err(ApiError::BadRequest(
                "节点标识与排序值必须是可精确表示的整数".into(),
            ));
        }
        if !seen.insert((item.kind.clone(), item.id)) {
            return Err(ApiError::BadRequest(format!(
                "重复选择节点 {}:{}",
                item.kind, item.id
            )));
        }
        let changed = item.name.is_some()
            || item.tags.is_some()
            || item.note.is_some()
            || item.sort_order.is_some()
            || item.enabled.is_some();
        if changed == deleting {
            return Err(ApiError::BadRequest(
                if deleting {
                    "删除请求仅允许节点标识与管理版本"
                } else {
                    "至少提供一个修改字段"
                }
                .into(),
            ));
        }
        if let Some(name) = item.name.as_mut() {
            *name = super::super::business::name(name)?;
        }
        if let Some(tags) = item.tags.as_mut() {
            if tags.len() > 16 {
                return Err(ApiError::BadRequest("每个节点最多添加 16 个标签".into()));
            }
            let mut normalized = Vec::new();
            for tag in tags.iter() {
                let tag = tag.trim();
                if tag.is_empty() || tag.len() > 64 || tag.chars().any(char::is_control) {
                    return Err(ApiError::BadRequest(
                        "标签需为 1 至 64 字节，且不能包含控制字符".into(),
                    ));
                }
                if !normalized.iter().any(|value| value == tag) {
                    normalized.push(tag.to_owned());
                }
            }
            *tags = normalized;
        }
        if item.note.as_ref().is_some_and(|v| {
            v.len() > 1024
                || v.chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        }) {
            return Err(ApiError::BadRequest(
                "备注最多 1024 字节，不能包含异常控制字符".into(),
            ));
        }
    }
    request
        .items
        .sort_by(|a, b| (&a.kind, a.id).cmp(&(&b.kind, b.id)));
    Ok(request.items)
}

async fn checked_resources(
    tx: &mut Transaction<'_, Postgres>,
    items: &[Change],
) -> ApiResult<BTreeMap<(String, i64), Value>> {
    let values: BTreeMap<_, _> = catalog_on(tx)
        .await?
        .into_iter()
        .map(|value| {
            (
                (
                    value["kind"].as_str().unwrap().to_owned(),
                    value["id"].as_i64().unwrap(),
                ),
                value,
            )
        })
        .collect();
    for item in items {
        let value = values
            .get(&(item.kind.clone(), item.id))
            .ok_or_else(|| item_error(item, "节点已删除、未采用或不存在"))?;
        if value["metadata_revision"].as_i64().is_none_or(|revision| {
            !(0..super::super::business::MAX_SAFE_INTEGER).contains(&revision)
        }) {
            return Err(item_error(item, "节点管理修订号已达上限或无法确认"));
        }
        if value["revision"] != item.revision {
            return Err(item_error(item, "节点已发生变化，请刷新后重试"));
        }
    }
    Ok(values)
}

fn item_error(item: &Change, message: &str) -> ApiError {
    ApiError::Conflict(format!("节点 {}:{}：{message}", item.kind, item.id))
}

pub async fn batch_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Batch>,
) -> ApiResult<Json<Vec<Value>>> {
    require_admin(&state, &headers).await?;
    let items = validate(request, false)?;
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    let current = checked_resources(&mut tx, &items).await?;
    let servers: BTreeSet<i64> = items
        .iter()
        .filter_map(|item| current[&(item.kind.clone(), item.id)]["server_id"].as_i64())
        .collect();
    for server in servers {
        super::super::business::lock_server(&mut tx, server).await?;
    }
    for item in &items {
        let resource = &current[&(item.kind.clone(), item.id)];
        if item.kind != "external" {
            let node = resource["entry_node_id"].as_i64().unwrap_or(item.id);
            let name_changed = item
                .name
                .as_ref()
                .is_some_and(|name| resource["name"] != *name);
            let enabled_changed = item
                .enabled
                .is_some_and(|enabled| resource["enabled"] != enabled);
            let node_changed = enabled_changed || (item.kind == "direct" && name_changed);
            // Catalog and the original resource editor share the same entity CAS.
            // Metadata-only edits use the independent catalog revision below.
            if node_changed {
                let changed = sqlx::query("UPDATE nodes SET resource_revision=resource_revision+1 WHERE id=$1 AND resource_revision>=1 AND resource_revision<$2")
                    .bind(node).bind(super::super::business::MAX_SAFE_INTEGER)
                    .execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(item_error(item, "节点设置修订号已达上限或无法确认"));
                }
            }
            if item.kind == "chain" && (name_changed || enabled_changed) {
                let changed = sqlx::query("UPDATE singbox_chains SET settings_revision=settings_revision+1 WHERE id=$1 AND settings_revision>=1 AND settings_revision<$2")
                    .bind(item.id).bind(super::super::business::MAX_SAFE_INTEGER)
                    .execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(item_error(item, "链路设置修订号已达上限或无法确认"));
                }
            }
            let mut dirty = false;
            if name_changed {
                let name = item.name.as_ref().expect("changed name");
                if item.kind == "chain" {
                    sqlx::query("UPDATE singbox_chains SET name=$2 WHERE id=$1")
                        .bind(item.id)
                        .bind(name)
                        .execute(&mut *tx)
                        .await?;
                } else {
                    sqlx::query("UPDATE nodes SET name=$2 WHERE id=$1")
                        .bind(node)
                        .bind(name)
                        .execute(&mut *tx)
                        .await?;
                    dirty = true;
                }
            }
            if enabled_changed {
                let enabled = item.enabled.expect("changed enabled state");
                sqlx::query("UPDATE nodes SET enabled=$2 WHERE id=$1")
                    .bind(node)
                    .bind(enabled)
                    .execute(&mut *tx)
                    .await?;
                let query = format!(
                    "SELECT {} FROM nodes n WHERE n.id=$1",
                    super::super::business::NODE_COLUMNS
                );
                let row = sqlx::query_as::<_, super::super::business::NodeRow>(&query)
                    .bind(node)
                    .fetch_one(&mut *tx)
                    .await?;
                super::super::nodes::validate_server_config(&mut tx, &row).await?;
                dirty = true;
            }
            if dirty {
                super::super::business::mark_dirty(
                    &mut tx,
                    &[resource["server_id"].as_i64().unwrap()],
                )
                .await?;
            }
        }
        sqlx::query("INSERT INTO singbox_node_metadata(kind,id,name_override,tags,note,sort_order,enabled) VALUES($1,$2,$3,COALESCE($4,'[]'::jsonb),COALESCE($5,''),COALESCE($6,0),COALESCE($7,TRUE)) ON CONFLICT(kind,id) DO UPDATE SET name_override=COALESCE($3,singbox_node_metadata.name_override),tags=COALESCE($4,singbox_node_metadata.tags),note=COALESCE($5,singbox_node_metadata.note),sort_order=COALESCE($6,singbox_node_metadata.sort_order),enabled=COALESCE($7,singbox_node_metadata.enabled),revision=singbox_node_metadata.revision+1")
            .bind(&item.kind).bind(item.id).bind(item.name.as_ref().filter(|_|item.kind=="external"))
            .bind(item.tags.as_ref().map(|v|json!(v))).bind(&item.note).bind(item.sort_order).bind(item.enabled.filter(|_|item.kind=="external"))
            .execute(&mut *tx).await?;
    }
    let result = catalog_on(&mut tx)
        .await?
        .into_iter()
        .filter(|value| {
            items
                .iter()
                .any(|item| value["kind"] == item.kind && value["id"] == item.id)
        })
        .collect();
    tx.commit().await?;
    Ok(Json(result))
}

pub(crate) async fn ensure_external_removable(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> ApiResult<()> {
    let used:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_chain_hops h JOIN singbox_chains c ON c.id=h.chain_id WHERE h.external_node_id=$1 AND c.deleted_at IS NULL) OR EXISTS(SELECT 1 FROM singbox_external_accesses a JOIN users u ON u.id=a.user_id WHERE a.external_node_id=$1 AND u.deleted_at IS NULL)")
        .bind(id).fetch_one(&mut **tx).await?;
    if used {
        return Err(ApiError::Conflict(format!(
            "外部节点 {id} 仍被链路或代理用户授权引用，请先解除引用"
        )));
    }
    Ok(())
}

pub async fn batch_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Batch>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers).await?;
    let items = validate(request, true)?;
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    checked_resources(&mut tx, &items).await?;
    // Check all dependencies before changing any row, including other selected resources.
    for item in &items {
        match item.kind.as_str() {
            "external" => ensure_external_removable(&mut tx, item.id).await?,
            "direct" => {
                super::super::proxy_resources::ensure_direct_node_unreferenced_on(&mut tx, item.id)
                    .await?
            }
            "chain" => {
                let entry =
                    sqlx::query_scalar("SELECT entry_node_id FROM singbox_live_chains WHERE id=$1")
                        .bind(item.id)
                        .fetch_optional(&mut *tx)
                        .await?
                        .ok_or(ApiError::NotFound)?;
                super::super::proxy_resources::ensure_chain_entry_unreferenced_on(
                    &mut tx, item.id, entry,
                )
                .await?;
            }
            _ => unreachable!(),
        }
    }
    for item in &items {
        match item.kind.as_str() {
            "direct" => super::super::nodes::remove_on(&mut tx, item.id).await?,
            "chain" => super::super::mixed_paths::resources::remove_on(&mut tx, item.id).await?,
            "external" => {
                sqlx::query("UPDATE singbox_external_nodes SET adopted=FALSE WHERE id=$1")
                    .bind(item.id)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("INSERT INTO singbox_node_metadata(kind,id,deleted_at) VALUES('external',$1,$2) ON CONFLICT(kind,id) DO UPDATE SET deleted_at=$2,revision=singbox_node_metadata.revision+1")
                    .bind(item.id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
            }
            _ => unreachable!(),
        }
    }
    tx.commit().await?;
    Ok(Json(
        json!({"deleted":items.iter().map(|item|json!({"kind":item.kind,"id":item.id})).collect::<Vec<_>>()}),
    ))
}
