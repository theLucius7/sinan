use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Serialize;
use serde_json::Value;
use sinan_protocol::now_timestamp;
use sqlx::{FromRow, Postgres, Transaction};

// Enablement requires an administrator choice or preserved legacy configuration.
// A device capability only establishes support, never installation or enablement.
pub(super) const SOURCE_SQL: &str = "CASE WHEN p.enabled AND p.source <> 'agent_capability' THEN p.source WHEN EXISTS(SELECT 1 FROM nodes n WHERE n.server_id=s.id) THEN 'legacy_nodes' WHEN EXISTS(SELECT 1 FROM deployments d WHERE d.server_id=s.id AND d.module='singbox') THEN 'legacy_deployments' END";

#[derive(Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    #[default]
    NotEnabled,
    Queued,
    WaitingAgent,
    Offline,
    Pending,
    Ready,
    Failed,
}

#[derive(Default, Serialize)]
pub struct Installation {
    pub state: InstallationState,
    pub reason: String,
    pub target_rev: i64,
    pub applied_rev: i64,
}

#[derive(Serialize, FromRow)]
pub struct PluginServer {
    pub id: i64,
    pub name: String,
    #[serde(skip)]
    pub last_seen: Option<i64>,
    #[serde(skip)]
    pub capabilities: Value,
    pub source: Option<String>,
    #[sqlx(default)]
    pub enabled: bool,
    #[sqlx(default)]
    pub online: bool,
    #[sqlx(default)]
    pub agent_supported: bool,
    #[sqlx(default)]
    pub read_only: bool,
    #[serde(skip)]
    pub dirty_at: Option<i64>,
    #[serde(skip)]
    pub target_rev: Option<i64>,
    #[serde(skip)]
    pub applied_rev: Option<i64>,
    #[serde(skip)]
    pub last_result_rev: Option<i64>,
    #[serde(skip)]
    pub healthy: Option<bool>,
    #[serde(skip)]
    pub last_error: Option<String>,
    #[serde(skip)]
    pub manifest_error: Option<String>,
    #[sqlx(skip)]
    pub installation: Installation,
}
impl PluginServer {
    fn view(mut self) -> Self {
        self.enabled = self.source.is_some();
        self.agent_supported = self
            .capabilities
            .as_array()
            .is_some_and(|caps| caps.iter().any(|cap| cap == "singbox"));
        self.online = self
            .last_seen
            .is_some_and(|seen| now_timestamp().saturating_sub(seen) <= 60);
        self.read_only = self.enabled && self.source.as_deref() != Some("administrator");
        self.installation = self.installation_view();
        self
    }

    fn installation_view(&self) -> Installation {
        let target = self.target_rev.filter(|revision| *revision > 0);
        let supported = self.agent_supported
            && self.capabilities.as_array().is_some_and(|capabilities| {
                capabilities.iter().any(|capability| {
                    capability.as_str()
                        == Some(sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY)
                })
            });
        let (state, reason) = if !self.enabled {
            (
                InstallationState::NotEnabled,
                "尚未启用插件；设备支持此插件不代表已安装".into(),
            )
        } else if target.is_none() {
            (
                InstallationState::Queued,
                "启用请求已保存，等待首次空运行时安装；已有有效业务节点时请采集完整预检，并明确首次安装空运行时".into(),
            )
        } else if let Some(error) = self.manifest_error.as_ref() {
            (InstallationState::Failed, error.clone())
        } else if !supported {
            (
                InstallationState::WaitingAgent,
                "等待支持 sing-box 及制品验签的 Agent；仅监控模式不能安装，请先调整设备安装模式"
                    .into(),
            )
        } else if !self.online {
            (
                InstallationState::Offline,
                "设备当前离线，启用请求会在重新连接后继续".into(),
            )
        } else if self.applied_rev == target
            && self.healthy == Some(true)
            && self.dirty_at.is_none()
        {
            (
                InstallationState::Ready,
                "设备已确认应用目标版本，运行时健康检查通过".into(),
            )
        } else if let Some(error) = self.last_error.as_ref().filter(|error| {
            !error.is_empty() && self.last_result_rev.unwrap_or(0) >= target.unwrap_or(0)
        }) {
            (InstallationState::Failed, format!("设备应用失败：{error}"))
        } else if self.last_result_rev.unwrap_or(0) >= target.unwrap_or(0)
            && self.healthy == Some(false)
        {
            (
                InstallationState::Failed,
                "设备未通过运行时健康检查，尚未确认安装完成".into(),
            )
        } else {
            (
                InstallationState::Pending,
                "等待设备下载已签制品、应用配置并确认健康；尚未确认安装完成".into(),
            )
        };
        Installation {
            state,
            reason,
            target_rev: target.unwrap_or(0),
            applied_rev: self.applied_rev.unwrap_or(0),
        }
    }
}
fn query() -> String {
    format!(
        "SELECT s.id,s.name,s.last_seen,s.capabilities,s.dirty_at,{SOURCE_SQL} AS source,m.target_rev,m.applied_rev,m.last_result_rev,m.healthy,m.last_error,e.error AS manifest_error FROM servers s LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' LEFT JOIN server_module_status m ON m.server_id=s.id AND m.module='singbox' LEFT JOIN singbox_installation e ON e.server_id=s.id AND e.target_rev=m.target_rev WHERE s.deleted_at IS NULL"
    )
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<PluginServer>>> {
    auth::require_admin(&state, &headers).await?;
    let rows = sqlx::query_as::<_, PluginServer>(&format!("{} ORDER BY s.id", query()))
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(rows.into_iter().map(PluginServer::view).collect()))
}
pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<PluginServer>> {
    auth::require_admin(&state, &headers).await?;
    let row = sqlx::query_as::<_, PluginServer>(&format!("{} AND s.id=$1", query()))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(row.view()))
}
pub async fn enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<(StatusCode, Json<PluginServer>)> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    super::business::lock_server(&mut tx, id).await?;
    sqlx::query("INSERT INTO server_plugins(server_id,plugin,source,enabled_at) VALUES($1,'sing-box','administrator',$2) ON CONFLICT(server_id,plugin) DO UPDATE SET enabled=TRUE,source='administrator'")
        .bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE servers SET dirty_at=COALESCE(dirty_at,FLOOR(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint) WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM deployments WHERE server_id=$1 AND module='singbox')")
        .bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    let row = get(State(state), headers, Path(id)).await?.0;
    Ok((StatusCode::OK, Json(row)))
}

pub(super) async fn is_enabled(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<bool, sqlx::Error> {
    let source: Option<String> = sqlx::query_scalar(&format!("SELECT {SOURCE_SQL} FROM servers s LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' WHERE s.id=$1 AND s.deleted_at IS NULL"))
        .bind(id).fetch_one(&mut **tx).await?;
    Ok(source.is_some())
}

pub(super) async fn require_enabled(tx: &mut Transaction<'_, Postgres>, id: i64) -> ApiResult<()> {
    if !is_enabled(tx, id).await? {
        return Err(ApiError::Conflict(
            "此服务器尚未启用 sing-box，请先在系统的插件设置中明确启用".into(),
        ));
    }
    Ok(())
}
