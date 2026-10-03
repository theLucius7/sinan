mod compatibility;
mod plan;
mod transform;

use super::{
    documents,
    models::{Configuration, Document},
};
use crate::{
    AppState, control_center,
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
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/server-migrations/candidates",
            get(candidates),
        )
        .route(
            "/api/network-configuration/server-migrations/preview",
            post(preview),
        )
        .route(
            "/api/network-configuration/server-migrations/{id}",
            get(detail),
        )
        .route(
            "/api/network-configuration/server-migrations/{id}/apply",
            post(apply),
        )
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    document_id: Uuid,
    #[serde(default)]
    target_config: Option<Configuration>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    source_server_id: i64,
    target_server_id: i64,
    selections: Vec<Selection>,
}

#[derive(Deserialize)]
struct Candidates {
    source_server_id: i64,
    target_server_id: i64,
}

async fn actor(
    state: &AppState,
    headers: &HeaderMap,
    source: i64,
    target: i64,
    write: bool,
) -> ApiResult<i64> {
    if source <= 0 || target <= 0 || source == target {
        return Err(ApiError::BadRequest(
            "请选择不同的原服务器和替换服务器".into(),
        ));
    }
    let capability = if write {
        "network:write"
    } else {
        "network:read"
    };
    let principal = control_center::authenticate(state, headers).await?;
    if write && principal.token_id.is_some() {
        return Err(ApiError::Forbidden("服务器替换流程需要管理员会话".into()));
    }
    control_center::require_server(state, headers, source, capability).await?;
    control_center::require_server(state, headers, target, capability).await?;
    Ok(principal.admin_id)
}

async fn candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<Candidates>,
) -> ApiResult<Json<Value>> {
    actor(
        &state,
        &headers,
        input.source_server_id,
        input.target_server_id,
        false,
    )
    .await?;
    let rows: Vec<Document> = sqlx::query_as("SELECT * FROM network_documents WHERE config->>'server_id'=$1 OR config->'server_ids' @> $2::JSONB OR EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(config->'targets','[]'::JSONB)) AS target WHERE target->>'server_id'=$1) ORDER BY id LIMIT 1001")
        .bind(input.source_server_id.to_string()).bind(json!([input.source_server_id])).fetch_all(&state.pool).await?;
    let truncated = rows.len() > 1000;
    let mut visible = Vec::new();
    for document in rows.into_iter().take(1000) {
        let config = documents::configuration(&document)?;
        if !config.servers().contains(&input.source_server_id) {
            continue;
        }
        match documents::access(&state, &headers, &config, false).await {
            Ok(()) => {}
            Err(ApiError::Forbidden(_)) => continue,
            Err(error) => return Err(error),
        }
        match documents::reference_access(&state, &headers, &config).await {
            Ok(()) => {}
            Err(ApiError::Forbidden(_)) => continue,
            Err(error) => return Err(error),
        }
        let mut replacement =
            transform::replace(&config, input.source_server_id, input.target_server_id)?;
        let independent_identity = matches!(
            config,
            Configuration::Mesh { .. } | Configuration::Tunnel { .. }
        );
        if let Configuration::Tunnel { enabled, .. } = &mut replacement {
            *enabled = false;
        }
        visible.push(json!({"id":document.id,"kind":document.kind,"revision":document.revision,"before":config,"suggested_config":replacement,"active_version":document.active_version,"identity":if independent_identity{"new_document_and_new_local_key"}else{"retain_business_document"},"old_runtime_cleanup":"separate_action","deployment":"not_started","reachability":"not_verified"}));
    }
    Ok(Json(
        json!({"source_server_id":input.source_server_id,"target_server_id":input.target_server_id,"candidates":visible,"truncated":truncated,"identity_copied":false,"ddns_rules":"use_separate_ddns_migration_preview","scope":"selected_network_business_configuration"}),
    ))
}

async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Request>,
) -> ApiResult<Json<Value>> {
    let requested_by = actor(
        &state,
        &headers,
        input.source_server_id,
        input.target_server_id,
        true,
    )
    .await?;
    validate_selection(&input)?;
    let mut identity_map = BTreeMap::new();
    for selection in &input.selections {
        let document = documents::load(&state, selection.document_id).await?;
        if matches!(
            documents::configuration(&document)?,
            Configuration::Mesh { .. } | Configuration::Tunnel { .. }
        ) {
            identity_map.insert(selection.document_id, Uuid::new_v4());
        }
    }
    let mut tx = state.pool.begin().await?;
    let snapshot = plan::build(&state, &headers, &mut tx, &input, &identity_map).await?;
    let snapshot_digest = digest(&snapshot)?;
    let id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO network_server_migration_previews(id,requested_by,source_server_id,target_server_id,request,identity_map,snapshot,snapshot_digest,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(id).bind(requested_by).bind(input.source_server_id).bind(input.target_server_id).bind(json!(input))
        .bind(json!(identity_map)).bind(&snapshot).bind(&snapshot_digest).bind(now).bind(now+300).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"snapshot":snapshot,"snapshot_digest":snapshot_digest,"expires_at":now+300,"deployment":"not_started","reachability":"not_verified"}),
    ))
}

fn validate_selection(input: &Request) -> ApiResult<()> {
    let distinct: BTreeSet<Uuid> = input
        .selections
        .iter()
        .map(|selection| selection.document_id)
        .collect();
    if input.selections.is_empty()
        || input.selections.len() > 64
        || distinct.len() != input.selections.len()
    {
        return Err(ApiError::BadRequest(
            "请选择1–64个不重复的网络业务对象".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    confirmed: bool,
    snapshot_digest: String,
}

async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Apply>,
) -> ApiResult<Json<Value>> {
    control_center::require_recent_proof(&state, &headers).await?;
    if !input.confirmed {
        return Err(ApiError::BadRequest(
            "请确认所选网络业务、替换地址、授权影响和独立部署要求".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM network_server_migration_previews WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let requested_by = actor(
        &state,
        &headers,
        row.get("source_server_id"),
        row.get("target_server_id"),
        true,
    )
    .await?;
    if requested_by != row.get::<i64, _>("requested_by") {
        return Err(ApiError::Forbidden(
            "此迁移预览只允许原发起管理员确认".into(),
        ));
    }
    let stored: Value = row.get("snapshot");
    authorize_snapshot(&state, &headers, &stored, true).await?;
    if input.snapshot_digest != row.get::<String, _>("snapshot_digest") {
        return Err(ApiError::Conflict("迁移预览摘要不一致".into()));
    }
    if let Some(result) = row.get::<Option<Value>, _>("result") {
        return Ok(Json(result));
    }
    if row.get::<i64, _>("expires_at") <= sinan_protocol::now_timestamp() {
        return Err(ApiError::Conflict("迁移预览已过期，请重新核对".into()));
    }
    let request: Request =
        serde_json::from_value(row.get("request")).map_err(anyhow::Error::from)?;
    let identity_map: BTreeMap<Uuid, Uuid> =
        serde_json::from_value(row.get("identity_map")).map_err(anyhow::Error::from)?;
    let current = plan::build(&state, &headers, &mut tx, &request, &identity_map).await?;
    if current != stored || digest(&current)? != input.snapshot_digest {
        return Err(ApiError::Conflict(
            "业务版本、服务器能力、授权、证书或关联关系已变化，请重新预览".into(),
        ));
    }
    if current["blockers"]
        .as_array()
        .is_none_or(|values| !values.is_empty())
    {
        return Err(ApiError::Conflict(
            "迁移预检存在阻断项，请先解决再预览".into(),
        ));
    }
    let changes = current["changes"]
        .as_array()
        .ok_or_else(|| ApiError::Conflict("迁移对象缺失".into()))?;
    let now = sinan_protocol::now_timestamp();
    let mut applied = Vec::new();
    for change in changes {
        let source_id: Uuid = parse(change, "document_id")?;
        let destination_id: Uuid = parse(change, "destination_document_id")?;
        let revision = change["revision"]
            .as_i64()
            .ok_or_else(|| ApiError::Conflict("迁移版本缺失".into()))?;
        let config: Configuration =
            serde_json::from_value(change["after"].clone()).map_err(anyhow::Error::from)?;
        if source_id == destination_id {
            documents::archive(&mut tx, source_id, "server_migration_before").await?;
            let updated = sqlx::query("UPDATE network_documents SET config=$2,revision=revision+1,updated_at=$3 WHERE id=$1 AND revision=$4")
                .bind(source_id).bind(&change["after"]).bind(now).bind(revision).execute(&mut *tx).await.map_err(documents::unique)?.rows_affected();
            if updated != 1 {
                return Err(ApiError::Conflict("迁移对象被并发修改".into()));
            }
            documents::archive(&mut tx, source_id, "server_migration_target_pending").await?;
        } else {
            sqlx::query("INSERT INTO network_documents(id,kind,revision,config,created_at,updated_at) VALUES($1,$2,1,$3,$4,$4)")
                .bind(destination_id).bind(config.kind()).bind(&change["after"]).bind(now).execute(&mut *tx).await.map_err(documents::unique)?;
            documents::archive(
                &mut tx,
                source_id,
                "server_migration_identity_source_retained",
            )
            .await?;
            documents::archive(
                &mut tx,
                destination_id,
                "server_migration_fresh_identity_candidate",
            )
            .await?;
        }
        applied.push(json!({"source_document_id":source_id,"document_id":destination_id,"revision":if source_id==destination_id{revision+1}else{1},"configuration":"saved","deployment":"not_started","reachability":"not_verified","source_cleanup":"requires_separate_confirmation","independent_identity":change["independent_identity"]}));
    }
    for change in changes {
        let config: Configuration =
            serde_json::from_value(change["after"].clone()).map_err(anyhow::Error::from)?;
        documents::references(
            &mut tx,
            &config,
            Some(parse(change, "destination_document_id")?),
        )
        .await?;
    }
    let result = json!({"id":id,"applied_at":now,"source_server_id":request.source_server_id,"target_server_id":request.target_server_id,"objects":applied,"agent_identity_copied":false,"deployment":"not_started","reachability":"not_verified","source_services_stopped":false});
    sqlx::query("UPDATE network_server_migration_previews SET applied_at=$2,result=$3 WHERE id=$1")
        .bind(id)
        .bind(now)
        .bind(&result)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO fleet_events(id,server_id,kind,source,detail,occurred_at) VALUES($1,$2,'network_business_migrated','network_server_migration',$3,$4)")
        .bind(Uuid::new_v4()).bind(request.target_server_id).bind(json!({"migration_id":id,"source_server_id":request.source_server_id,"objects":applied,"deployment":"not_started"})).bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(result))
}

async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let row = sqlx::query("SELECT * FROM network_server_migration_previews WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    actor(
        &state,
        &headers,
        row.get("source_server_id"),
        row.get("target_server_id"),
        false,
    )
    .await?;
    let snapshot: Value = row.get("snapshot");
    authorize_snapshot(&state, &headers, &snapshot, false).await?;
    Ok(Json(
        json!({"id":id,"snapshot":snapshot,"snapshot_digest":row.get::<String,_>("snapshot_digest"),"expires_at":row.get::<i64,_>("expires_at"),"applied_at":row.get::<Option<i64>,_>("applied_at"),"result":row.get::<Option<Value>,_>("result")}),
    ))
}

async fn authorize_snapshot(
    state: &AppState,
    headers: &HeaderMap,
    snapshot: &Value,
    write: bool,
) -> ApiResult<()> {
    for change in snapshot["changes"].as_array().ok_or(ApiError::NotFound)? {
        for key in ["before", "after"] {
            let config: Configuration =
                serde_json::from_value(change[key].clone()).map_err(anyhow::Error::from)?;
            documents::access(state, headers, &config, write).await?;
            if key == "before" {
                documents::reference_access(state, headers, &config).await?;
            }
        }
    }
    for related in snapshot["related_documents"]
        .as_array()
        .ok_or(ApiError::NotFound)?
    {
        let config: Configuration =
            serde_json::from_value(related["config"].clone()).map_err(anyhow::Error::from)?;
        documents::access(state, headers, &config, false).await?;
    }
    let actor = control_center::authenticate(state, headers).await?;
    for related in snapshot["dns_references"]
        .as_array()
        .ok_or(ApiError::NotFound)?
    {
        let server = related["server_id"].as_i64().ok_or(ApiError::NotFound)?;
        control_center::require_server(state, headers, server, "dns:read").await?;
        if !related["account"].is_null() {
            let scope = related["account"]["config"]["server_ids"]
                .as_array()
                .ok_or(ApiError::NotFound)?;
            if (scope.is_empty() && !actor.global_servers())
                || scope.iter().any(|server| {
                    server
                        .as_i64()
                        .is_none_or(|server| !actor.allows_server(server))
                })
            {
                return Err(ApiError::Forbidden("历史DNS账号范围已不再可访问".into()));
            }
        }
    }
    Ok(())
}
fn parse(value: &Value, key: &str) -> ApiResult<Uuid> {
    value[key]
        .as_str()
        .ok_or(ApiError::NotFound)?
        .parse()
        .map_err(|_| ApiError::NotFound)
}
fn digest(value: &Value) -> ApiResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(anyhow::Error::from)?)
    ))
}
