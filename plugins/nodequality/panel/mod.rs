use crate::{
    AppState, artifacts, auth,
    diagnostics::{
        ReportRecord, expire,
        service::{self, DiagnosticPlugin, JobPlan, PlanFuture},
    },
    error::{ApiError, ApiResult},
    ip_quality::{self, ServerIpInfoView},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sinan_protocol::{DiagnosticResourceBudget, now_timestamp};
use sqlx::Row;
use std::collections::BTreeMap;
mod modes;
pub mod node_queries;
pub const PLUGIN_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22";
pub const FULL_START_GATE_CAPABILITY: &str = "diagnostic:nodequality-full-start-gate";
pub const FULL_START_DENIAL: &str = "完整验机已暂停：离线受控工具链尚未就绪，旧工具链仍会下载在线代码、上传内层报告或修改宿主 swap。日常检查和已有报告回收、取消仍可使用。";
const TIMEOUT_SECS: u64 = 1800;
const EXPECTED_SECTIONS: [&str; 5] = [
    "header_info",
    "hardware_quality",
    "ip_quality",
    "net_quality",
    "backroute_trace",
];
#[derive(Serialize)]
pub struct NodeQualityView {
    pub plugin_ready: bool,
    pub plugin_reason: Option<String>,
    pub full_ready: bool,
    pub full_reason: Option<String>,
    pub reports: Vec<ReportRecord>,
    pub cancel_supported: bool,
    pub proxy_activity: modes::ProxyActivity,
}

#[derive(Serialize)]
pub struct LegacyNodeQualityView {
    #[serde(flatten)]
    pub node_quality: NodeQualityView,
    #[serde(flatten)]
    pub ip_info: ServerIpInfoView,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRequest {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub confirm_full: bool,
    #[serde(default)]
    pub acknowledge_traffic_warning: bool,
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    #[serde(default)]
    pub upload_report: bool,
}

fn default_mode() -> String {
    "full".into()
}

fn default_ip_version() -> String {
    "both".into()
}
fn default_network_mode() -> String {
    "low".into()
}

pub struct NodeQualityPlugin;
impl DiagnosticPlugin for NodeQualityPlugin {
    fn id(&self) -> &'static str {
        "nodequality"
    }
    fn version(&self) -> &'static str {
        PLUGIN_VERSION
    }
    fn title(&self) -> &'static str {
        "NodeQuality"
    }
    fn required_capabilities(&self) -> &'static [&'static str] {
        &["diagnostic:nodequality", "diagnostic:nodequality-modes"]
    }
    fn start_denial(&self, job: &Value) -> Option<&'static str> {
        // Exact r21 IP jobs select NodeIpQualityPlugin through for_job().
        // An unrecognized IP version must never exempt the original plugin's gate.
        (job["options"]["mode"].as_str() != Some("daily")).then_some(FULL_START_DENIAL)
    }
    fn can_dispatch(&self, job: &Value, capabilities: &Value) -> bool {
        if job["options"]["mode"].as_str() == Some("ip") {
            return node_queries::NodeIpQualityPlugin.can_dispatch(job, capabilities);
        }
        job["options"]["mode"].as_str() == Some("daily")
            || capabilities.as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.as_str() == Some(FULL_START_GATE_CAPABILITY))
            })
    }
    fn plan<'a>(
        &'a self,
        request: Value,
        server_id: i64,
        connection: &'a mut sqlx::PgConnection,
    ) -> PlanFuture<'a> {
        Box::pin(async move {
            let request: ReportRequest = serde_json::from_value(request)
                .map_err(|_| ApiError::BadRequest("诊断参数格式无效".into()))?;
            modes::validate_request(&request)?;
            if request.mode == "full" {
                return Err(ApiError::Conflict(FULL_START_DENIAL.into()));
            }
            if !matches!(request.ip_version.as_str(), "both" | "ipv4" | "ipv6")
                || !matches!(request.network_mode.as_str(), "low" | "normal")
            {
                return Err(ApiError::BadRequest("IP 版本或网络测试模式无效".into()));
            }
            let activity = modes::activity_on(connection, server_id).await?;
            if request.mode == "full"
                && activity.state != "not_enabled"
                && !request.acknowledge_traffic_warning
            {
                return Err(ApiError::Conflict(format!(
                    "{} 必须明确确认此警告后继续完整验机。",
                    activity.reason
                )));
            }
            let now = now_timestamp();
            let daily = request.mode == "daily";
            let confirmation = serde_json::json!({
                "confirmed_full": request.confirm_full,
                "acknowledged_traffic_warning": request.acknowledge_traffic_warning,
                "confirmed_at": now,
            });
            let timeout_secs = if daily { 90 } else { TIMEOUT_SECS };
            let mut options = BTreeMap::from([
                ("mode".into(), request.mode),
                ("environment_section".into(), "true".into()),
                ("ip_version".into(), request.ip_version),
                ("network_mode".into(), request.network_mode),
                ("upload_report".into(), request.upload_report.to_string()),
            ]);
            if daily {
                options.insert(
                    "daily_targets".into(),
                    modes::daily_targets(connection, server_id).await?,
                );
            }
            let expected_sections = if daily {
                vec!["net_quality", "environment"]
            } else {
                EXPECTED_SECTIONS
                    .into_iter()
                    .chain(["environment"])
                    .collect()
            };
            Ok(JobPlan {
                timeout_secs,
                budget: DiagnosticResourceBudget {
                    memory_max: if daily {
                        64 * 1024 * 1024
                    } else {
                        512 * 1024 * 1024
                    },
                    tasks_max: if daily { 32 } else { 128 },
                    cpu_max_percent: None,
                    cpu_weight: 10,
                    io_weight: 10,
                    oom_score_adjust: 500,
                },
                options,
                expected_sections: expected_sections.into_iter().map(str::to_owned).collect(),
                metadata: BTreeMap::from([
                    (
                        "proxy_activity".into(),
                        serde_json::to_value(activity).map_err(anyhow::Error::from)?,
                    ),
                    ("confirmation".into(), confirmation),
                ]),
            })
        })
    }
    fn report_url_allowed(&self, value: &str) -> bool {
        safe_report_url(value)
    }
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<ReportRequest>,
) -> ApiResult<(StatusCode, Json<ReportRecord>)> {
    auth::require_admin(&state, &headers).await?;
    let value = serde_json::to_value(request).map_err(anyhow::Error::from)?;
    let record = service::create_job(&state, id, &NodeQualityPlugin, value).await?;
    Ok((StatusCode::CREATED, Json(record)))
}
pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<NodeQualityView>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(view(&state, id).await?))
}

pub async fn legacy_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<LegacyNodeQualityView>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(LegacyNodeQualityView {
        node_quality: view(&state, id).await?,
        ip_info: ip_quality::view(&state, id).await?,
    }))
}

async fn view(state: &AppState, id: i64) -> ApiResult<NodeQualityView> {
    expire(state).await?;
    let row = sqlx::query(
        "SELECT static_info,last_seen,capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let mut reason = service::ready(&row, &NodeQualityPlugin)
        .err()
        .map(|error| error.to_string());
    if reason.is_none() {
        let arch = service::ready(&row, &NodeQualityPlugin)?;
        if let Err(error) = artifacts::descriptor(state, "nodequality", PLUGIN_VERSION, arch).await
        {
            reason = Some(match error {
                ApiError::NotFound => {
                    "NodeQuality 插件制品尚未上传，请先准备对应架构的制品及 SHA256SUMS".into()
                }
                other => format!("NodeQuality 插件制品不可用：{other}"),
            });
        }
    }
    Ok(NodeQualityView {
        plugin_ready: reason.is_none(),
        plugin_reason: reason,
        full_ready: false,
        full_reason: Some(FULL_START_DENIAL.into()),
        reports: service::history(state, id, Some("nodequality")).await?,
        cancel_supported: service::cancel_supported(&row.get::<Value, _>("capabilities")),
        proxy_activity: modes::activity(&state.pool, id).await?,
    })
}

pub fn safe_report_url(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    value.len() <= 2048
        && url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("nodequality.com" | "www.nodequality.com")
        )
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::{ReportRequest, safe_report_url};
    use serde_json::json;

    #[test]
    fn report_upload_requires_an_explicit_boolean_opt_in() {
        for request in [json!({}), json!({"upload_report":false})] {
            let request: ReportRequest = serde_json::from_value(request).unwrap();
            assert!(!request.upload_report);
        }
        let request: ReportRequest = serde_json::from_value(json!({"upload_report":true})).unwrap();
        assert!(request.upload_report);
        for value in [json!("true"), json!(1), json!(null)] {
            assert!(
                serde_json::from_value::<ReportRequest>(json!({"upload_report":value})).is_err()
            );
        }
    }
    #[test]
    fn report_links_are_restricted_to_the_official_https_origin() {
        assert!(safe_report_url("https://nodequality.com/r/example"));
        for url in [
            "http://nodequality.com/r/example",
            "https://nodequality.com.evil.invalid/r/x",
            "https://user:secret@nodequality.com/r/x",
            "https://nodequality.com:8443/r/x",
            "javascript:alert(1)",
            "https://nodequality.com/r/x#fragment",
        ] {
            assert!(!safe_report_url(url), "{url}");
        }
    }
}
