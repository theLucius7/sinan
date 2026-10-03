use super::business;
use crate::{
    AppState,
    auth::require_admin,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Serialize;
use sinan_protocol::now_timestamp;
use sqlx::{FromRow, PgConnection, Postgres, Transaction};
use std::collections::BTreeMap;

mod references;
use references::node_chain_references;

#[derive(Clone, Serialize, FromRow)]
pub struct ResourceEndpoint {
    pub id: i64,
    pub name: String,
    pub server_id: i64,
    pub server_name: String,
    pub protocol: String,
    pub port: i32,
    #[sqlx(skip)]
    pub public_port: i32,
    pub public_host: String,
    pub sni: String,
    pub enabled: bool,
    pub node_deleted: bool,
    pub server_deleted: bool,
    pub plugin_enabled: bool,
    pub online: bool,
    pub desired_revision: Option<i64>,
    pub applied_revision: Option<i64>,
    pub applied_observed_at: Option<i64>,
    #[serde(skip)]
    settings: serde_json::Value,
    #[serde(skip)]
    protocol_config: serde_json::Value,
    #[serde(skip)]
    #[sqlx(skip)]
    public_port_valid: bool,
    #[serde(skip)]
    #[sqlx(skip)]
    protocol_config_valid: bool,
}

#[derive(Serialize)]
pub struct ChainReference {
    pub id: i64,
    pub name: String,
    pub role: &'static str,
    pub generation: i64,
    pub hop_position: Option<i32>,
    pub state: String,
}

#[derive(Serialize)]
pub struct ProxyResource {
    pub kind: &'static str,
    pub id: i64,
    pub name: String,
    pub entry: ResourceEndpoint,
    pub exit: Option<ResourceEndpoint>,
    /// Structural eligibility only; application and connectivity are separate.
    pub available: bool,
    pub unavailable_reasons: Vec<String>,
    pub policy_group_ids: Vec<i64>,
    pub user_count: i64,
    pub chain_refs: Vec<ChainReference>,
    pub settings_revision: i64,
    pub path_kind: Option<String>,
    pub hops: Vec<super::ordered_paths::models::PublicHop>,
    pub path_state: Option<super::ordered_paths::models::PathState>,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ProxyResource>>> {
    require_admin(&state, &headers).await?;
    Ok(Json(read_resources(&state).await?))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, i64)>,
) -> ApiResult<Json<ProxyResource>> {
    require_admin(&state, &headers).await?;
    validate_identity(&kind, id)?;
    let resource = read_resources(&state)
        .await?
        .into_iter()
        .find(|resource| resource.kind == kind && resource.id == id)
        .ok_or(ApiError::NotFound)?;
    Ok(Json(resource))
}

fn validate_identity(kind: &str, id: i64) -> ApiResult<()> {
    if !matches!(kind, "direct" | "chain") || id <= 0 {
        return Err(ApiError::BadRequest("请选择有效的直连或链路资源".into()));
    }
    Ok(())
}

async fn read_resources(state: &AppState) -> ApiResult<Vec<ProxyResource>> {
    use super::ordered_paths::{models::*, storage};
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let query = format!(
        "SELECT n.id,n.name,n.server_id,s.name AS server_name,n.protocol,n.port,n.settings,n.protocol_config,n.public_host,n.sni,n.enabled,n.deleted_at IS NOT NULL AS node_deleted,s.deleted_at IS NOT NULL AS server_deleted,({}) IS NOT NULL AS plugin_enabled,(s.last_seen IS NOT NULL AND $1-s.last_seen<=60) AS online,m.target_rev AS desired_revision,m.applied_rev AS applied_revision,m.updated_at AS applied_observed_at FROM nodes n JOIN servers s ON s.id=n.server_id LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' LEFT JOIN server_module_status m ON m.server_id=s.id AND m.module='singbox' ORDER BY n.id",
        super::settings::SOURCE_SQL
    );
    let endpoints: BTreeMap<i64, ResourceEndpoint> = sqlx::query_as::<_, ResourceEndpoint>(&query)
        .bind(now_timestamp())
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|mut endpoint| {
            let settings = serde_json::from_value::<sinan_compiler::NodeSettings>(std::mem::take(
                &mut endpoint.settings,
            ));
            let protocol = serde_json::from_value::<sinan_compiler::ProtocolConfig>(
                std::mem::take(&mut endpoint.protocol_config),
            );
            endpoint.protocol_config_valid =
                protocol.is_ok_and(|config| config.kind() == endpoint.protocol);
            endpoint.public_port = endpoint.port;
            if let Ok(settings) = settings
                && settings.public_port != Some(0)
            {
                endpoint.public_port = settings.public_port.map(i32::from).unwrap_or(endpoint.port);
                endpoint.public_port_valid = true;
            }
            (endpoint.id, endpoint)
        })
        .collect();
    let chains = sqlx::query_as::<_, super::ordered_paths::models::ChainRow>(&format!(
        "SELECT {CHAIN_COLUMNS} FROM singbox_chains WHERE deleted_at IS NULL AND path_kind IN ('legacy','ordered') ORDER BY id"
    ))
    .fetch_all(&mut *tx)
    .await?;
    // Both API projections share the dedicated entry namespace. In particular,
    // soft deletion is not device cleanup for an ordered lineage.
    let reserved_entries: Vec<i64> = sqlx::query_scalar("SELECT entry_node_id FROM singbox_chains WHERE deleted_at IS NULL OR (path_kind='ordered' AND phase<>'retired')")
        .fetch_all(&mut *tx)
        .await?;
    let mut resources = Vec::new();
    for endpoint in endpoints.values() {
        if endpoint.node_deleted
            || endpoint.server_deleted
            || reserved_entries.contains(&endpoint.id)
        {
            continue;
        }
        let policy_group_ids = sqlx::query_scalar(
            "SELECT group_id FROM singbox_policy_nodes WHERE node_id=$1 ORDER BY group_id",
        )
        .bind(endpoint.id)
        .fetch_all(&mut *tx)
        .await?;
        let user_count=sqlx::query_scalar("SELECT COUNT(DISTINCT g.user_id) FROM (SELECT user_id FROM accesses WHERE node_id=$1 AND direct_grant UNION SELECT up.user_id FROM singbox_user_policies up JOIN singbox_policy_nodes pn ON pn.group_id=up.group_id WHERE pn.node_id=$1) g JOIN users u ON u.id=g.user_id WHERE u.deleted_at IS NULL").bind(endpoint.id).fetch_one(&mut *tx).await?;
        let references = node_chain_references(&mut tx, endpoint.id, None).await?;
        let chain_refs = references
            .into_iter()
            .map(|reference| ChainReference {
                id: reference.id,
                name: reference.name,
                role: if reference.role == "entry" {
                    "entry"
                } else {
                    "exit"
                },
                generation: reference.generation,
                hop_position: reference.hop_position,
                state: reference.state,
            })
            .collect();
        let revision = sqlx::query_scalar("SELECT resource_revision FROM nodes WHERE id=$1")
            .bind(endpoint.id)
            .fetch_one(&mut *tx)
            .await?;
        let reasons = endpoint_reasons(endpoint, "节点");
        resources.push(ProxyResource {
            kind: "direct",
            id: endpoint.id,
            name: endpoint.name.clone(),
            entry: endpoint.clone(),
            exit: None,
            available: reasons.is_empty(),
            unavailable_reasons: reasons,
            policy_group_ids,
            user_count,
            chain_refs,
            settings_revision: revision,
            path_kind: None,
            hops: vec![],
            path_state: None,
        });
    }
    for chain in chains {
        let current_entry = endpoints
            .get(&chain.entry_node_id)
            .ok_or(ApiError::NotFound)?;
        let mut reasons = endpoint_reasons(current_entry, "入口");
        let mut generations = Vec::new();
        let desired = storage::version(&mut tx, chain.id, chain.desired_generation).await?;
        let entry = if chain.path_kind == "legacy" {
            current_entry.clone()
        } else {
            frozen_endpoint(&desired.snapshot.entry, &endpoints)?
        };
        let hops = project_hops(&mut tx, &desired.snapshot, &endpoints).await?;
        for hop in &hops {
            if let PublicHop::Managed {
                position, endpoint, ..
            } = hop
            {
                reasons.extend(endpoint_reasons(endpoint, &format!("第 {position} 跳")));
            }
        }
        for (state, generation) in [
            ("desired", Some(chain.desired_generation)),
            ("applied", chain.applied_generation),
            ("candidate", chain.candidate_generation),
            ("recovery", chain.recovery_generation),
        ] {
            if let Some(generation) = generation {
                let version = storage::version(&mut tx, chain.id, generation).await?;
                generations.push(GenerationView {
                    generation,
                    state: state.into(),
                    hops: project_hops(&mut tx, &version.snapshot, &endpoints).await?,
                });
            }
        }
        let exit = match hops.last() {
            Some(PublicHop::Managed { endpoint, .. }) => Some(endpoint.clone()),
            _ => None,
        };
        let dependencies=sqlx::query_as::<_,DependencyViewRow>("SELECT d.server_id,d.role,CASE WHEN d.role='entry' THEN NULL ELSE d.hop_position END AS hop_position,d.generation,d.stage,d.revision AS required_revision,m.applied_rev AS applied_revision,d.bundle_sha256,CASE WHEN d.observed_at IS NOT NULL AND m.applied_rev=d.revision AND m.target_rev=d.revision AND s.dirty_at IS NULL AND m.healthy THEN 'ready' WHEN m.last_result_rev>=d.revision AND NOT m.healthy AND m.last_error IS NOT NULL THEN 'failed' ELSE 'pending' END AS state,d.observed_at FROM singbox_path_stage_deployments d LEFT JOIN server_module_status m ON m.server_id=d.server_id AND m.module='singbox' JOIN servers s ON s.id=d.server_id WHERE d.chain_id=$1 AND d.generation=ANY(ARRAY[$2,$3,$4,$5]) ORDER BY d.generation,d.stage,d.server_id").bind(chain.id).bind(chain.desired_generation).bind(chain.applied_generation).bind(chain.candidate_generation).bind(chain.recovery_generation).fetch_all(&mut *tx).await?.into_iter().map(DependencyViewRow::view).collect();
        let probe=sqlx::query_as::<_,ProbeViewRow>("SELECT stage,request_id,state,observed_at,error FROM singbox_path_probes WHERE chain_id=$1 AND generation=$2 AND request_id IS NOT NULL ORDER BY CASE WHEN stage='switched' THEN 0 ELSE 1 END LIMIT 1").bind(chain.id).bind(chain.candidate_generation.or(chain.applied_generation).unwrap_or(chain.desired_generation)).fetch_optional(&mut *tx).await?.map(ProbeViewRow::view);
        let policy_group_ids = sqlx::query_scalar(
            "SELECT group_id FROM singbox_policy_chains WHERE chain_id=$1 ORDER BY group_id",
        )
        .bind(chain.id)
        .fetch_all(&mut *tx)
        .await?;
        let user_count=sqlx::query_scalar("SELECT COUNT(DISTINCT up.user_id) FROM singbox_user_policies up JOIN singbox_policy_chains pc ON pc.group_id=up.group_id JOIN users u ON u.id=up.user_id WHERE pc.chain_id=$1 AND u.deleted_at IS NULL").bind(chain.id).fetch_one(&mut *tx).await?;
        let path_state = PathState {
            desired_generation: desired.generation,
            candidate_generation: chain.candidate_generation,
            applied_generation: chain.applied_generation,
            recovery_generation: chain.recovery_generation,
            minimum_generation: chain.minimum_generation,
            phase: chain.phase,
            last_error: chain.last_error,
            capabilities: desired.capabilities,
            dependencies,
            probe,
            generations,
        };
        resources.push(ProxyResource {
            kind: "chain",
            id: chain.id,
            name: chain.name,
            entry,
            exit,
            available: reasons.is_empty(),
            unavailable_reasons: reasons,
            policy_group_ids,
            user_count,
            chain_refs: vec![],
            settings_revision: chain.settings_revision,
            path_kind: Some(chain.path_kind),
            hops,
            path_state: Some(path_state),
        });
    }
    tx.commit().await?;
    Ok(resources)
}

#[derive(FromRow)]
struct DependencyViewRow {
    server_id: i64,
    role: String,
    hop_position: Option<i32>,
    generation: i64,
    stage: String,
    required_revision: Option<i64>,
    applied_revision: Option<i64>,
    bundle_sha256: Option<String>,
    state: String,
    observed_at: Option<i64>,
}
impl DependencyViewRow {
    fn view(self) -> super::ordered_paths::models::DependencyView {
        super::ordered_paths::models::DependencyView {
            server_id: self.server_id,
            role: self.role,
            hop_position: self.hop_position,
            generation: self.generation,
            stage: self.stage,
            required_revision: self.required_revision,
            applied_revision: self.applied_revision,
            bundle_sha256: self.bundle_sha256,
            state: self.state,
            observed_at: self.observed_at,
        }
    }
}
#[derive(FromRow)]
struct ProbeViewRow {
    stage: String,
    request_id: uuid::Uuid,
    state: String,
    observed_at: Option<i64>,
    error: Option<String>,
}
impl ProbeViewRow {
    fn view(self) -> super::ordered_paths::models::ProbeView {
        super::ordered_paths::models::ProbeView {
            stage: self.stage,
            request_id: self.request_id,
            state: self.state,
            observed_at: self.observed_at,
            error: self.error,
        }
    }
}
fn frozen_endpoint(
    frozen: &sinan_compiler::ManagedEndpointSnapshot,
    endpoints: &BTreeMap<i64, ResourceEndpoint>,
) -> ApiResult<ResourceEndpoint> {
    let mut endpoint = endpoints
        .get(&frozen.node.id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    endpoint.port = i32::from(frozen.node.port);
    endpoint.public_port = i32::from(frozen.node.public_port());
    endpoint.public_host = frozen.node.public_host.clone();
    endpoint.sni = frozen.node.sni.clone();
    endpoint.protocol_config_valid &= endpoint.protocol == frozen.node.protocol_config.kind();
    endpoint.protocol = frozen.node.protocol_config.kind().into();
    Ok(endpoint)
}
async fn project_hops(
    connection: &mut PgConnection,
    frozen: &super::ordered_paths::models::FrozenVersion,
    endpoints: &BTreeMap<i64, ResourceEndpoint>,
) -> ApiResult<Vec<super::ordered_paths::models::PublicHop>> {
    use super::ordered_paths::models::*;
    let mut hops = Vec::new();
    for (index, hop) in frozen.hops.iter().enumerate() {
        let position = index + 1;
        hops.push(match hop{
            FrozenHop::Managed{endpoint,..}=>PublicHop::Managed{position,node_id:endpoint.node.id,endpoint_version_id:endpoint.version_id,endpoint:frozen_endpoint(endpoint,endpoints)?},
            FrozenHop::Subscription{source_id,identity_epoch,external_node_id,node_version_id,source_revision_id,update_mode,outbound,..}=>{
                let(source_name,archived,deleted,epoch,seen,current):(String,bool,Option<i64>,i64,Option<uuid::Uuid>,Option<uuid::Uuid>)=sqlx::query_as("SELECT s.name,s.archived,s.deleted_at,s.identity_epoch,n.last_seen_revision,s.current_success_revision FROM singbox_ordered_subscription_sources s JOIN singbox_ordered_external_nodes n ON n.source_id=s.id WHERE s.id=$1 AND n.id=$2").bind(source_id).bind(external_node_id).fetch_one(&mut *connection).await?;
                let preview:serde_json::Value=sqlx::query_scalar("SELECT public_preview FROM singbox_ordered_external_node_versions WHERE id=$1 AND node_id=$2").bind(node_version_id).bind(external_node_id).fetch_one(&mut *connection).await?;
                let node_present=current.is_some() && seen==current && epoch==*identity_epoch;
                let source_archived=archived || deleted.is_some();
                let common=outbound.common();
                let protocol=serde_json::to_value(outbound.protocol()).map_err(anyhow::Error::from)?.as_str().unwrap_or("unknown").to_owned();
                let transport=common.transport.as_ref().and_then(|transport|serde_json::to_value(transport).ok()).and_then(|value|value.get("type").and_then(serde_json::Value::as_str).map(str::to_owned));
                PublicHop::Subscription{position,source_id:*source_id,source_name,identity_epoch:*identity_epoch,external_node_id:*external_node_id,node_version_id:*node_version_id,source_revision_id:*source_revision_id,update_mode:update_mode.clone(),name:preview.get("name").and_then(serde_json::Value::as_str).unwrap_or("订阅节点").to_owned(),protocol,server:common.server.clone(),server_port:common.server_port,sni:common.tls.as_ref().and_then(|tls|tls.server_name.clone()),transport,capabilities:Capabilities{tcp:outbound.tcp(),udp:outbound.udp()},source_archived,node_present,update_error:if source_archived{Some("来源已归档或删除，保留冻结版本，不再自动跟随".into())}else if !node_present{Some("来源身份已更换或节点本次缺失，保留已冻结版本".into())}else{None}}
            },
        });
    }
    Ok(hops)
}

fn endpoint_reasons(endpoint: &ResourceEndpoint, role: &str) -> Vec<String> {
    let mut reasons = Vec::new();
    if endpoint.node_deleted {
        reasons.push(format!("{role}节点已删除"));
    }
    if endpoint.server_deleted {
        reasons.push(format!("{role}服务器已退役"));
    }
    if !endpoint.enabled {
        reasons.push(format!("{role}节点已停用"));
    }
    if !endpoint.plugin_enabled {
        reasons.push(format!("{role}服务器未启用 sing-box 插件"));
    }
    if !endpoint.public_port_valid {
        reasons.push(format!("{role}公开端口参数无法确认，暂显示监听端口"));
    }
    if !endpoint.protocol_config_valid {
        reasons.push(format!("{role}协议参数无法解析或与协议类型不一致"));
    }
    reasons
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, i64)>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &headers).await?;
    validate_identity(&kind, id)?;
    if kind == "direct" {
        remove_direct_node(&state, id).await?;
    } else {
        remove_chain_resource(&state, id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn remove_direct_node(state: &AppState, id: i64) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    super::entitlements::lock(&mut tx).await?;
    remove_direct_node_on(&mut tx, id).await?;
    tx.commit().await?;
    Ok(())
}

/// The caller owns the common topology lock; preserve retained server identities.
pub(super) async fn remove_direct_node_on(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> ApiResult<()> {
    let server: i64 =
        sqlx::query_scalar("SELECT server_id FROM nodes WHERE id=$1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    lock_cleanup_servers(tx, &[server]).await?;
    // Return actionable public references before the conservative corruption
    // guard. Missing frozen versions must still retain their cleanup owner.
    ensure_direct_node_unreferenced_on(tx, id).await?;
    soft_delete_node(tx, id).await?;
    business::mark_dirty(tx, &[server]).await?;
    Ok(())
}

/// Dependency preflight also serves an atomic catalog batch before any deletion.
pub(super) async fn ensure_direct_node_unreferenced_on(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> ApiResult<()> {
    ensure_node_unreferenced(tx, id).await?;
    super::nodes::ensure_unreferenced_on(tx, id).await
}

async fn remove_chain_resource(state: &AppState, id: i64) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    super::entitlements::lock(&mut tx).await?;
    let chain = super::ordered_paths::storage::chain(&mut tx, id, true).await?;
    if chain.deleted_at.is_some() {
        return Err(ApiError::NotFound);
    }
    let servers = super::ordered_paths::storage::referenced_servers(&mut tx, id).await?;
    lock_cleanup_servers(&mut tx, &servers).await?;
    ensure_chain_entry_unreferenced_on(&mut tx, id, chain.entry_node_id).await?;
    sqlx::query("UPDATE singbox_chains SET deleted_at=$2,route_enabled=FALSE,phase=CASE WHEN path_kind='ordered' THEN 'retiring' ELSE 'retired' END,applied_generation=CASE WHEN path_kind='legacy' THEN NULL ELSE applied_generation END WHERE id=$1").bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
    soft_delete_node(&mut tx, chain.entry_node_id).await?;
    business::mark_dirty(&mut tx, &servers).await?;
    tx.commit().await?;
    Ok(())
}

/// Common deletion preflight for rich and numeric catalog resources. Retained
/// raw identities still own cleanup even when immutable projections are damaged.
pub(super) async fn ensure_chain_entry_unreferenced_on(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    entry_node_id: i64,
) -> ApiResult<()> {
    let policies = sqlx::query_as::<_, PolicyReference>(
        "SELECT p.id,p.name FROM singbox_policy_groups p WHERE
            EXISTS(SELECT 1 FROM singbox_policy_chains c WHERE c.group_id=p.id AND c.chain_id=$1)
            OR EXISTS(SELECT 1 FROM singbox_policy_nodes n WHERE n.group_id=p.id AND n.node_id=$2)
            ORDER BY p.id LIMIT 32",
    )
    .bind(id)
    .bind(entry_node_id)
    .fetch_all(&mut **tx)
    .await?;
    let other_refs = node_chain_references(tx, entry_node_id, Some(id)).await?;
    if !policies.is_empty() || !other_refs.is_empty() {
        return Err(reference_error(policies, other_refs));
    }
    let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_chains c WHERE c.id<>$1 AND (c.deleted_at IS NULL OR (c.path_kind='ordered' AND c.phase<>'retired')) AND (c.entry_node_id=$2 OR c.exit_node_id=$2)) OR EXISTS(SELECT 1 FROM singbox_chain_hops h JOIN singbox_live_chains c ON c.id=h.chain_id WHERE h.chain_id<>$1 AND h.managed_node_id=$2) OR EXISTS(SELECT 1 FROM singbox_ordered_chain_hops h JOIN singbox_chains c ON c.id=h.chain_id WHERE h.chain_id<>$1 AND (c.deleted_at IS NULL OR c.phase<>'retired') AND h.managed_node_id=$2 AND (h.generation=ANY(ARRAY[c.desired_generation,c.applied_generation,c.candidate_generation,c.recovery_generation]) OR EXISTS(SELECT 1 FROM unnest(ARRAY[c.desired_generation,c.applied_generation,c.candidate_generation,c.recovery_generation]) AS selected(generation) WHERE selected.generation IS NOT NULL AND NOT EXISTS(SELECT 1 FROM singbox_ordered_chain_versions v WHERE v.chain_id=c.id AND v.generation=selected.generation))))")
        .bind(id).bind(entry_node_id).fetch_one(&mut **tx).await?;
    if retained {
        return Err(ApiError::Conflict(
            "链路入口仍被其它保留路径引用，请先完成引用清理".into(),
        ));
    }
    Ok(())
}

pub(super) async fn lock_cleanup_servers(
    tx: &mut Transaction<'_, Postgres>,
    servers: &[i64],
) -> ApiResult<()> {
    // Retired server identities still protect shared resources during cleanup.
    sqlx::query("SELECT id FROM servers WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(servers)
        .fetch_all(&mut **tx)
        .await?;
    Ok(())
}

async fn soft_delete_node(tx: &mut Transaction<'_, Postgres>, id: i64) -> ApiResult<()> {
    sqlx::query("UPDATE nodes SET deleted_at=COALESCE(deleted_at,$2) WHERE id=$1")
        .bind(id)
        .bind(now_timestamp())
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM accesses WHERE node_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[derive(Serialize, FromRow)]
struct PolicyReference {
    id: i64,
    name: String,
}

#[derive(Serialize, FromRow)]
struct NodeChainReference {
    id: i64,
    name: String,
    role: String,
    generation: i64,
    hop_position: Option<i32>,
    state: String,
}

async fn node_policies(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> ApiResult<Vec<PolicyReference>> {
    Ok(sqlx::query_as("SELECT p.id,p.name FROM singbox_policy_groups p JOIN singbox_policy_nodes n ON n.group_id=p.id WHERE n.node_id=$1 ORDER BY p.id LIMIT 32")
        .bind(id).fetch_all(&mut **tx).await?)
}

pub(super) async fn ensure_chain_unreferenced(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> ApiResult<()> {
    let policies = sqlx::query_as::<_, PolicyReference>("SELECT p.id,p.name FROM singbox_policy_groups p JOIN singbox_policy_chains c ON c.group_id=p.id WHERE c.chain_id=$1 ORDER BY p.id LIMIT 32")
        .bind(id).fetch_all(&mut **tx).await?;
    if !policies.is_empty() {
        return Err(reference_error(policies, vec![]));
    }
    Ok(())
}

async fn ensure_node_unreferenced(tx: &mut Transaction<'_, Postgres>, id: i64) -> ApiResult<()> {
    let policies = node_policies(tx, id).await?;
    let chains = node_chain_references(tx, id, None).await?;
    if !policies.is_empty() || !chains.is_empty() {
        return Err(reference_error(policies, chains));
    }
    Ok(())
}

fn reference_error(
    mut policies: Vec<PolicyReference>,
    mut chains: Vec<NodeChainReference>,
) -> ApiError {
    // This administrator projection contains only bounded public identities.
    // Queries decide whether ownership exists before bounding the projection.
    policies.truncate(32);
    chains.truncate(32);
    for name in policies
        .iter_mut()
        .map(|reference| &mut reference.name)
        .chain(chains.iter_mut().map(|reference| &mut reference.name))
    {
        *name = name
            .chars()
            .filter(|value| !value.is_control())
            .take(128)
            .collect();
    }
    let mut names: Vec<String> = policies
        .iter()
        .map(|reference| format!("策略组 #{}「{}」", reference.id, reference.name))
        .collect();
    names.extend(chains.iter().map(|reference| {
        let role = if reference.role == "entry" {
            "入口"
        } else {
            "出口"
        };
        format!("链路 #{}「{}」({role})", reference.id, reference.name)
    }));
    ApiError::ConflictReferences {
        message: format!("资源仍被引用，请先解除：{}", names.join("、")),
        references: serde_json::json!({"policies":policies,"chains":chains}),
    }
}
