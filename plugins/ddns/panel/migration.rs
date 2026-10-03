use super::{
    MAX_RULES, editable,
    history::{self, Entry},
    load,
    model::{self, Rule},
};
use crate::{
    AppState, control_center as access,
    error::{ApiError, ApiResult},
};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    target_server_id: i64,
    rules: Vec<Selection>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    id: Uuid,
    revision: i64,
    #[serde(default)]
    config: Option<model::Config>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Snapshot {
    id: Uuid,
    revision: i64,
    source_server_id: i64,
    #[serde(default)]
    target_config: Option<model::Config>,
}
type StoredPreviewRow = (i64, sqlx::types::Json<Vec<Snapshot>>, i64, Option<i64>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    preview_id: Uuid,
    confirmed: bool,
}

fn identity(config: &model::Config) -> String {
    serde_json::json!([
        config.provider,
        config.zone_id,
        config.record_name,
        config.record_type,
        config.line
    ])
    .to_string()
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/rules/migration-preview", post(preview))
        .route("/api/plugins/ddns/rules/migrate", post(apply))
}

async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<PreviewRequest>,
) -> ApiResult<Json<Value>> {
    access::require_capability(&state, &headers, "dns:write").await?;
    access::require_server(&state, &headers, input.target_server_id, "dns:write").await?;
    if input.rules.is_empty() || input.rules.len() > MAX_RULES as usize {
        return Err(ApiError::BadRequest("请选择 1–32 条 DDNS 规则".into()));
    }
    let unique: BTreeSet<_> = input.rules.iter().map(|rule| rule.id).collect();
    if unique.len() != input.rules.len() {
        return Err(ApiError::BadRequest("规则选择包含重复项".into()));
    }
    input.rules.sort_by_key(|rule| rule.id);
    let target = model::observation(&state.pool, input.target_server_id).await?;
    if target.deleted_at.is_some() || target.retiring || !target.plugin_enabled {
        return Err(ApiError::Conflict(
            "目标服务器不可用或尚未启用 DDNS 插件".into(),
        ));
    }
    let now = sinan_protocol::now_timestamp();
    let mut snapshot = Vec::new();
    let mut items = Vec::new();
    let mut destinations = BTreeSet::new();
    for selection in input.rules {
        let rule = load(&state.pool, selection.id).await?;
        access::require_server(&state, &headers, rule.config.server_id, "dns:write").await?;
        if rule.revision != selection.revision || rule.lease_until > now {
            return Err(ApiError::Conflict(
                "所选规则正在执行或已修改，请刷新后重新预览".into(),
            ));
        }
        let source = model::observation(&state.pool, rule.config.server_id).await?;
        let mut config = selection.config.unwrap_or_else(|| rule.config.clone());
        config.server_id = input.target_server_id;
        config.normalize()?;
        if config.provider != rule.config.provider
            && config.credential_id.is_none()
            && config.account_id.is_none()
        {
            return Err(ApiError::BadRequest(
                "更换提供方必须明确选择对应的凭据中心或 DNS 账号，不能复用原提供方秘密".into(),
            ));
        }
        let identity = identity(&config);
        if !destinations.insert(identity) {
            return Err(ApiError::Conflict(
                "批量目标中存在重复提供方、区域、名称、类型与线路".into(),
            ));
        }
        let existing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ddns_rules WHERE config->>'provider'=$1 AND config->>'zone_id'=$2 AND config->>'record_name'=$3 AND config->>'record_type'=$4 AND COALESCE(config->>'line','')=$5 AND NOT (id=ANY($6)))").bind(serde_json::to_value(config.provider).map_err(anyhow::Error::from)?.as_str().unwrap_or_default()).bind(&config.zone_id).bind(&config.record_name).bind(&config.record_type).bind(&config.line).bind(unique.iter().copied().collect::<Vec<_>>()).fetch_one(&state.pool).await?;
        if existing {
            return Err(ApiError::Conflict(
                "目标域名或提供方记录已由未选择的规则维护".into(),
            ));
        }
        super::credentials::authorize_reference(&state, &headers, &config).await?;
        super::credentials::validate_reference(&state.pool, &config).await?;
        let candidate = target.select(&config, rule.last_ip.as_deref(), now);
        items.push(json!({"id":rule.id,"name":rule.config.name,"revision":rule.revision,
            "record_name":rule.config.record_name,"record_type":rule.config.record_type,
            "source_server_id":rule.config.server_id,"source_server_name":source.name,
            "target_server_id":input.target_server_id,"target_server_name":target.name,
            "previous_ip":rule.last_ip,"candidate_ip":candidate.as_ref().ok().map(ToString::to_string),
            "source_status":candidate.err().unwrap_or("ready"),"enabled":config.enabled,
            "address_source":config.address_source,"previous_config":rule.config,"desired_config":config}));
        snapshot.push(Snapshot {
            id: rule.id,
            revision: rule.revision,
            source_server_id: rule.config.server_id,
            target_config: Some(config),
        });
    }
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM ddns_migration_previews WHERE expires_at<=$1")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO ddns_migration_previews(id,target_server_id,snapshot,created_at,expires_at) VALUES($1,$2,$3,$4,$5)")
        .bind(id).bind(input.target_server_id).bind(json!(snapshot)).bind(now).bind(now+300).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"preview_id":id,"target_server_id":input.target_server_id,"items":items,
        "created_at":now,"expires_at":now+300,"dns_written":false}),
    ))
}

async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApplyRequest>,
) -> ApiResult<Json<Value>> {
    access::require_capability(&state, &headers, "dns:write").await?;
    access::require_recent_proof(&state, &headers).await?;
    if !input.confirmed {
        return Err(ApiError::BadRequest("请确认批量变更的目标与影响".into()));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await?;
    let row: Option<StoredPreviewRow> = sqlx::query_as("SELECT target_server_id,snapshot,expires_at,applied_at FROM ddns_migration_previews WHERE id=$1 FOR UPDATE")
        .bind(input.preview_id).fetch_optional(&mut *tx).await?;
    let (target_id, sqlx::types::Json(snapshot), expires_at, applied_at) =
        row.ok_or(ApiError::NotFound)?;
    if expires_at <= sinan_protocol::now_timestamp() || applied_at.is_some() {
        return Err(ApiError::Conflict(
            "预览已过期或已经应用，请重新预览".into(),
        ));
    }
    access::require_server(&state, &headers, target_id, "dns:write").await?;
    let target = model::locked_observation(&mut tx, target_id).await?;
    if target.deleted_at.is_some() || target.retiring || !target.plugin_enabled {
        return Err(ApiError::Conflict(
            "目标服务器已退役或 DDNS 插件已停用".into(),
        ));
    }
    let mut rules: Vec<(Rule, model::Config)> = Vec::new();
    for selected in snapshot {
        access::require_server(&state, &headers, selected.source_server_id, "dns:write").await?;
        let rule = editable(&mut tx, selected.id).await?;
        if rule.revision != selected.revision || rule.config.server_id != selected.source_server_id
        {
            return Err(ApiError::Conflict(
                "至少一条规则与预览不一致，未迁移任何规则".into(),
            ));
        }
        let mut destination = selected
            .target_config
            .unwrap_or_else(|| rule.config.clone());
        destination.server_id = target_id;
        destination.normalize()?;
        super::credentials::authorize_reference(&state, &headers, &destination).await?;
        rules.push((rule, destination));
    }
    let now = sinan_protocol::now_timestamp();
    let mut ids = Vec::new();
    for (mut rule, destination) in rules {
        let reset_identity = identity(&rule.config) != identity(&destination);
        rule.config = destination;
        super::credentials::validate_reference(&state.pool, &rule.config).await?;
        sqlx::query("UPDATE ddns_rules SET server_id=$2,config=$3,revision=revision+1,status='pending',error_code=NULL,failures=0,next_run_at=GREATEST($4,COALESCE(attempted_at,0)+60),lease_id=NULL,lease_until=0,record_id=CASE WHEN $5 THEN NULL ELSE record_id END,last_ip=CASE WHEN $5 THEN NULL ELSE last_ip END,api_token=CASE WHEN $6 THEN '' ELSE api_token END,access_key_id=CASE WHEN $6 THEN '' ELSE access_key_id END,access_key_secret=CASE WHEN $6 THEN '' ELSE access_key_secret END WHERE id=$1")
            .bind(rule.id).bind(target_id).bind(json!(rule.config)).bind(now).bind(reset_identity).bind(rule.config.credential_id.is_some()||rule.config.account_id.is_some()).execute(&mut *tx).await.map_err(|error|if error.as_database_error().is_some_and(|error|error.is_unique_violation()){ApiError::Conflict("批量目标与现有规则冲突，未更改任何规则".into())}else{error.into()})?;
        let candidate = target.select(&rule.config, rule.last_ip.as_deref(), now);
        history::append(
            &mut tx,
            Entry {
                id: Uuid::new_v4(),
                rule_id: rule.id,
                server_id: rule.config.server_id,
                revision: rule.revision + 1,
                operation: "migration".into(),
                desired_ip: candidate.ok().map(|ip| ip.to_string()),
                previous: None,
                observed: None,
                status: "binding_changed".into(),
                error_code: None,
                occurred_at: now,
            },
        )
        .await?;
        ids.push(rule.id);
    }
    sqlx::query("UPDATE ddns_migration_previews SET applied_at=$2 WHERE id=$1")
        .bind(input.preview_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut values = Vec::new();
    for id in ids {
        values.push(model::view(&state.pool, load(&state.pool, id).await?).await?);
    }
    Ok(Json(
        json!({"rules":values,"target_server_id":target_id,"dns_written":false,"agent_identity_copied":false}),
    ))
}

#[cfg(test)]
#[path = "tests/migration.rs"]
mod tests;
