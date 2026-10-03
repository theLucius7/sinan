mod automation;
mod inventory;
mod preflight;
mod preflight_network;
pub(super) use preflight::{
    bootstrap_install, confirm as confirm_preflight, request as preflight_request,
};
pub(crate) use preflight::{ordinary_shape_changes_tx, publisher_ready_tx};
mod rollouts;
pub(crate) use automation::{
    automation_candidate, automation_deployment_receipt, automation_dispatch_matches_tx,
    cancel_automation_deployment_tx, enqueue_automation_deployment_tx,
    reconcile_automation_deployment_tx, request_automation_deployment_checkpoint_tx,
};
pub(super) use inventory::inventory;
pub(super) use rollouts::{advance, create_rollout, inspect_member, pause, rollouts};

use super::{digest, event};
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
use sinan_compiler::{Access, Node};
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

fn public_node(node: &Node) -> ApiResult<Value> {
    Ok(
        json!({"id":node.id,"name":node.name,"port":node.port,"public_host":node.public_host,"sni":node.sni,"enabled":node.enabled,"protocol":node.protocol_config.kind(),"protocol_config":super::super::node_protocol::view(&node.protocol_config),"settings":super::super::node_settings::view(serde_json::to_value(&node.settings).map_err(anyhow::Error::from)?)?,"user_ids":node.users.iter().map(|a|a.user_id).collect::<Vec<_>>()}),
    )
}

pub(super) fn differences(applied: &[Node], desired: &[Node]) -> ApiResult<Vec<Value>> {
    let old: BTreeMap<i64, &Node> = applied.iter().map(|n| (n.id, n)).collect();
    let new: BTreeMap<i64, &Node> = desired.iter().map(|n| (n.id, n)).collect();
    let all: BTreeSet<i64> = old.keys().chain(new.keys()).copied().collect();
    let mut result = Vec::new();
    for id in all {
        let previous = old.get(&id);
        let next = new.get(&id);
        let changed = match (previous, next) {
            (Some(before), Some(after)) => {
                digest(&serde_json::to_value(before).map_err(anyhow::Error::from)?)?
                    != digest(&serde_json::to_value(after).map_err(anyhow::Error::from)?)?
            }
            _ => true,
        };
        if changed {
            result.push(json!({"node_id":id,"change":if previous.is_none(){"added"}else if next.is_none(){"removed"}else{"changed"},"before":previous.map(|n|public_node(n)).transpose()?,"after":next.map(|n|public_node(n)).transpose()?,"affected_users":previous.into_iter().flat_map(|n|n.users.iter()).chain(next.into_iter().flat_map(|n|n.users.iter())).map(|a|a.user_id).collect::<BTreeSet<_>>(),"sensitive_values_hidden":true}));
        }
    }
    Ok(result)
}

pub(super) async fn view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, server, "proxy:read").await?;
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    super::super::business::lock_server(&mut tx, server).await?;
    super::super::settings::require_enabled(&mut tx, server).await?;
    let row=sqlx::query("SELECT s.static_info,s.capabilities,s.last_seen,s.dirty_at,m.target_rev,m.applied_rev,m.healthy,m.updated_at,m.last_error,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=s.id) AS retiring FROM servers s LEFT JOIN server_module_status m ON m.server_id=s.id AND m.module='singbox' WHERE s.id=$1").bind(server).fetch_one(&mut *tx).await?;
    let query = format!(
        "SELECT {} FROM nodes n JOIN servers s ON s.id=n.server_id WHERE n.server_id=$1 AND n.deleted_at IS NULL ORDER BY n.id",
        super::super::business::NODE_COLUMNS
    );
    let rows: Vec<super::super::business::NodeRow> = sqlx::query_as(&query)
        .bind(server)
        .fetch_all(&mut *tx)
        .await?;
    let mut desired = Vec::new();
    for node in rows {
        let accesses:Vec<(i64,Uuid,String)>=sqlx::query_as("SELECT user_id,uuid,credential FROM singbox_eligible_accesses($2) WHERE node_id=$1 ORDER BY user_id").bind(node.id).bind(now_timestamp()).fetch_all(&mut *tx).await?;
        desired.push(
            node.model(
                accesses
                    .into_iter()
                    .map(|(user_id, uuid, credential)| Access {
                        user_id,
                        uuid,
                        credential,
                    })
                    .collect(),
            )?,
        );
    }
    let applied_source:Option<Value>=sqlx::query_scalar("SELECT COALESCE(p.source_json,d.source_json) FROM deployments d LEFT JOIN singbox_deployment_projections p ON p.server_id=d.server_id AND p.rev=d.rev WHERE d.server_id=$1 AND d.module='singbox' AND d.rev=$2").bind(server).bind(row.get::<Option<i64>,_>("applied_rev")).fetch_optional(&mut *tx).await?;
    let applied = applied_source
        .map(super::super::ordered_paths::models::public_nodes)
        .transpose()
        .map_err(anyhow::Error::from)?
        .unwrap_or_default();
    let changes = differences(&applied, &desired)?;
    let history:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('revision',d.rev,'bundle_sha256',d.bundle_sha256,'created_at',d.created_at,'runtime_version',f.runtime_version,'artifact_sha256',f.artifact_sha256) FROM deployments d LEFT JOIN singbox_runtime_manifest_facts f ON f.server_id=d.server_id AND f.module=d.module AND f.revision=d.rev WHERE d.server_id=$1 AND d.module='singbox' ORDER BY d.rev DESC LIMIT 100").bind(server).fetch_all(&mut *tx).await?;
    let paths:Vec<Value>=sqlx::query_scalar("SELECT DISTINCT jsonb_build_object('id',c.id,'name',c.name,'kind',c.path_kind,'phase',c.phase,'desired_generation',c.desired_generation,'applied_generation',c.applied_generation,'candidate_generation',c.candidate_generation,'last_error',c.last_error,'route_enabled',c.route_enabled) FROM singbox_chains c LEFT JOIN nodes n ON n.id=c.entry_node_id LEFT JOIN nodes e ON e.id=c.exit_node_id LEFT JOIN singbox_ordered_chain_hops h ON h.chain_id=c.id WHERE (n.server_id=$1 OR e.server_id=$1 OR h.managed_server_id=$1) AND (c.deleted_at IS NULL OR c.phase<>'retired')").bind(server).fetch_all(&mut *tx).await?;
    let mut hop_observations:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('server_id',s.id,'name',s.name,'last_seen',s.last_seen,'metrics',s.latest_metrics,'target_revision',m.target_rev,'applied_revision',m.applied_rev,'healthy',m.healthy,'last_error',m.last_error) FROM servers s LEFT JOIN server_module_status m ON m.server_id=s.id AND m.module='singbox' WHERE s.id IN (SELECT $1 UNION SELECT h.managed_server_id FROM singbox_ordered_chain_hops h JOIN singbox_chains c ON c.id=h.chain_id JOIN nodes n ON n.id=c.entry_node_id WHERE n.server_id=$1 AND h.generation=c.desired_generation AND h.managed_server_id IS NOT NULL) ORDER BY s.id").bind(server).fetch_all(&mut *tx).await?;
    let target = row.get::<Option<i64>, _>("target_rev");
    let checkpoint = configuration_observation(&mut tx, server, target).await?;
    tx.commit().await?;
    for hop in &mut hop_observations {
        let id = hop["server_id"].as_i64().ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("missing observation server identity"))
        })?;
        match crate::control_center::require_server(&state, &headers, id, "proxy:read").await {
            Ok(_) => {}
            Err(ApiError::Forbidden(_)) => {
                *hop = json!({"server_id":id,"name":"未授权服务器","last_seen":null,"metrics":null,"target_revision":null,"applied_revision":null,"healthy":null,"last_error":null,"observation_access":"denied"});
            }
            Err(error) => return Err(error),
        }
    }
    let online = row
        .get::<Option<i64>, _>("last_seen")
        .is_some_and(|at| now_timestamp().saturating_sub(at) <= 60);
    let capabilities: Value = row.get("capabilities");
    let capability = |name: &str| {
        capabilities
            .as_array()
            .is_some_and(|v| v.iter().any(|c| c == name))
    };
    let preflight = preflight::view(&state, &headers, server).await?;
    let applied_revision = row.get::<Option<i64>, _>("applied_rev");
    let drift = if !online {
        "stale"
    } else if row.get::<Option<i64>, _>("dirty_at").is_some()
        && preflight["application"]["state"] == "needs_preflight"
    {
        "needs_preflight"
    } else if row.get::<Option<i64>, _>("dirty_at").is_some() {
        "pending_publish"
    } else if target.is_none() {
        "unknown"
    } else if target != applied_revision {
        "revision_mismatch"
    } else if checkpoint["state"] == "mismatch" {
        "configuration_mismatch"
    } else if checkpoint["state"] == "verified" {
        "configuration_verified"
    } else if checkpoint["state"] == "pending" {
        "inspection_pending"
    } else if row.get::<Option<bool>, _>("healthy") != Some(true) {
        "unhealthy"
    } else {
        "revision_aligned"
    };
    Ok(Json(
        json!({"server_id":server,"runtime":{"supported_versions":["1.14.2"],"selected_version":"1.14.2","other_versions_available":false,"compatibility_metadata":{"version":"1.14.2","upstream_repository":"https://github.com/SagerNet/sing-box","upstream_release":"https://github.com/SagerNet/sing-box/releases/tag/v1.14.2","upstream_commit":"af6e64c3b69e6132ebaee0e1a3d24e93903f6709","source_material":"tools/build-singbox.sh","protocols":["vless-reality","hysteria2","shadowsocks2022","tuic","anytls","naive","snell-v6"],"acceptance_scope":"仓库固定编译器与构建输入，平台制品另需签名匹配，不代表实时获取了所有官方版本"},"reason":"当前编译器、路径快照与签名制品固定版本，其他版本尚未完成兼容支持"},"preflight":preflight,"drift":{"state":drift,"target_revision":target,"applied_revision":applied_revision,"last_observed_at":row.get::<Option<i64>,_>("updated_at"),"checkpoint":checkpoint,"checkpoint_supported":capability(sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY),"live_config_hash_available":false,"reason":"主动核对实际文件、受管进程和签名执行文件；成功仅代表核对时匹配，五分钟后证据过期。目标包摘要不是原始运行文件摘要"},"changes":changes,"history":history,"paths":paths,"hop_observations":hop_observations,"path_diagnosis":"资源、部署、路径探测分别作为证据；外部跳资源不可观测时保持未知，不据单点指标自动断言瓶颈"}),
    ))
}

pub(super) fn inspection_reason(error: &str) -> (&'static str, &'static str) {
    if [
        "configuration file differs from the deployment",
        "configuration bundle digest differs from applied deployment",
        "revision file inventory differs from the deployment",
        "current configuration link does not select the applied revision",
        "configuration link escaped",
        "undeclared configuration file",
        "configuration is outside the applied revision",
        "configuration file changed",
        "configuration inode changed",
        "configuration path changed",
        "configuration path inode changed",
    ]
    .iter()
    .any(|message| error.contains(message))
    {
        (
            "configuration_mismatch",
            "实际配置文件、链接或清单与已发布部署不一致",
        )
    } else if [
        "another binary",
        "signed runtime",
        "executable",
        "runtime instance changed",
        "controlled instance",
    ]
    .iter()
    .any(|message| error.contains(message))
    {
        (
            "runtime_identity_mismatch",
            "受管进程或签名运行时身份不一致",
        )
    } else if error.contains("not healthy") {
        ("unhealthy", "实际运行时健康检查未通过")
    } else {
        (
            "inspection_failed",
            "目标设备未完成核对；配置是否偏离保持未知，请查看设备侧受控诊断",
        )
    }
}

async fn configuration_observation(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    target: Option<i64>,
) -> ApiResult<Value> {
    let request=sqlx::query("SELECT q.request_id,q.request_json,q.state,q.created_at,q.expires_at,r.outcome,r.received_at,r.result_json FROM runtime_control_requests q LEFT JOIN runtime_control_receipts r USING(request_id) WHERE q.server_id=$1 AND q.module='singbox' AND q.kind='checkpoint' AND (q.request_json->'expected'->>'revision')::bigint=$2 ORDER BY q.created_at DESC,q.request_id DESC LIMIT 1").bind(server).bind(target).fetch_optional(&mut **tx).await?;
    let Some(request) = request else {
        return Ok(json!({"state":"unknown","reason":"当前目标尚无实际文件与进程核对结果"}));
    };
    let outcome: Option<String> = request.get("outcome");
    let result: Option<sinan_protocol::RuntimeCheckpointResult> = request
        .get::<Option<Value>, _>("result_json")
        .map(serde_json::from_value)
        .transpose()
        .map_err(anyhow::Error::from)?;
    let age = request
        .get::<Option<i64>, _>("received_at")
        .map(|at| now_timestamp().saturating_sub(at));
    let current = if let Some(observed) = result.as_ref().and_then(|r| r.observed.as_ref()) {
        crate::runtime_control::confirmed_is_current(tx, server, &observed.binding).await?
    } else {
        false
    };
    let reason = result
        .as_ref()
        .and_then(|r| r.error.as_deref())
        .map(inspection_reason);
    let state = if age.is_some_and(|age| age > 300) {
        "stale"
    } else if outcome.as_deref() == Some("verified")
        && result.as_ref().is_some_and(|r| r.success)
        && current
    {
        "verified"
    } else if outcome.as_deref() == Some("mismatch")
        || reason.is_some_and(|(code, _)| {
            matches!(code, "configuration_mismatch" | "runtime_identity_mismatch")
        })
    {
        "mismatch"
    } else if matches!(outcome.as_deref(), Some("late" | "superseded")) {
        "stale"
    } else if outcome.as_deref() == Some("failed") {
        "unknown"
    } else if request.get::<i64, _>("expires_at") <= now_timestamp() {
        "expired"
    } else {
        "pending"
    };
    Ok(
        json!({"state":state,"request_id":request.get::<Uuid,_>("request_id"),"requested_at":request.get::<i64,_>("created_at"),"observed_at":request.get::<Option<i64>,_>("received_at"),"outcome":outcome,"failure_kind":reason.map(|(code,_)|code),"reason":reason.map(|(_,message)|message).unwrap_or(if state=="verified"{"目标 Agent 已逐文件核对配置并确认受管进程与签名运行时身份"}else if state=="stale"{"核对证据已过期或目标已变化，请主动重新核对"}else if state=="pending"{"等待设备实际核对结果"}else{"无法确认当前运行文件匹配，请重新核对"})}),
    )
}

pub(super) async fn checkpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Value>> {
    let administrator =
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    let mut tx = state.pool.begin().await?;
    super::super::business::lock_server(&mut tx, server).await?;
    super::super::settings::require_enabled(&mut tx, server).await?;
    let row=sqlx::query("SELECT capabilities,last_seen,dirty_at,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) AS retiring FROM servers WHERE id=$1").bind(server).fetch_one(&mut *tx).await?;
    let caps: Value = row.get("capabilities");
    if !caps.as_array().is_some_and(|v| {
        v.iter()
            .any(|c| c == sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY)
    }) {
        return Err(ApiError::Conflict(
            "Agent 不支持实际配置与进程核对，请先升级；不能仅用版本号确认一致".into(),
        ));
    }
    if row.get::<bool, _>("retiring")
        || row.get::<Option<i64>, _>("dirty_at").is_some()
        || !row
            .get::<Option<i64>, _>("last_seen")
            .is_some_and(|at| now_timestamp().saturating_sub(at) <= 60)
    {
        return Err(ApiError::Conflict(
            "设备离线、退役或仍待发布，暂不能核对当前目标".into(),
        ));
    }
    tx.commit().await?;
    let request = crate::runtime_control::request_checkpoint(&state, server, "singbox")
        .await
        .map_err(|_| {
            ApiError::Conflict(
                "当前目标尚无可核对的部署绑定，或已有请求未确认；请刷新配置状态".into(),
            )
        })?;
    let mut tx = state.pool.begin().await?;
    event(&mut tx,Some(administrator),None,"runtime_configuration_inspect",json!({"server_id":server,"request_id":request.request_id,"expected_revision":request.expected.revision,"configuration_changed":false})).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"state":"pending","request_id":request.request_id,"expires_at":request.expires_at}),
    ))
}
