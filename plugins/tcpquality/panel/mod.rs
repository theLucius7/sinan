use crate::{
    AppState, auth,
    diagnostics::service::{DiagnosticPlugin, JobPlan, PlanFuture},
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::{DiagnosticResourceBudget, ProbeKind, ProbeSpec, now_timestamp};
use std::collections::BTreeMap;
use uuid::Uuid;

// Both signed architectures must identify this immutable source snapshot.
pub const PLUGIN_VERSION: &str = "0.3.0-b562effcd90f8ae319665fb4ead1807b770ed4d5-r1";
const REGIONS: [&str; 5] = ["east_asia", "southeast_asia", "europe", "americas", "other"];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_ip")]
    pub ip_version: String,
    #[serde(default = "default_count")]
    pub count: u8,
    #[serde(default = "default_concurrency")]
    pub concurrency: u8,
}
fn default_region() -> String {
    "configured".into()
}
fn default_ip() -> String {
    "4".into()
}
fn default_count() -> u8 {
    4
}
fn default_concurrency() -> u8 {
    1
}

impl Request {
    fn valid(&self) -> bool {
        (self.region == "configured" || REGIONS.contains(&self.region.as_str()))
            && matches!(self.ip_version.as_str(), "4" | "6")
            && matches!(self.count, 4 | 8)
            && matches!(self.concurrency, 1 | 2)
    }
}

fn valid_target(value: &str) -> bool {
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast());
    }
    value.len() <= 253
        && value.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && !value.is_empty()
        && !value.ends_with("..")
}

#[derive(Clone, Serialize)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub target: String,
    pub port: u16,
    pub carrier: String,
    pub region: Option<String>,
}

async fn targets(connection: &mut sqlx::PgConnection, server: i64) -> ApiResult<Vec<Target>> {
    let rows: Vec<(Uuid, Value, Option<String>)> = sqlx::query_as(
        "SELECT p.id,p.spec,r.region FROM network_probes p LEFT JOIN tcpquality_target_regions r ON r.probe_id=p.id WHERE p.server_id=$1 AND p.spec->>'kind'='tcp' AND p.spec->>'enabled'='true' ORDER BY p.id LIMIT 33",
    ).bind(server).fetch_all(connection).await?;
    if rows.len() > 32 {
        return Err(ApiError::Conflict("启用的 TCP 拨测目标超过配置上限".into()));
    }
    rows.into_iter()
        .map(|(id, value, region)| {
            let spec: ProbeSpec = serde_json::from_value(value).map_err(|_| {
                ApiError::Conflict("已配置的 TCP 拨测目标格式无效，请先修正配置".into())
            })?;
            if id != spec.id
                || !spec.valid()
                || spec.name.chars().any(char::is_control)
                || spec.carrier.chars().any(char::is_control)
                || !valid_target(&spec.target)
                || spec.kind != ProbeKind::Tcp
                || !spec.enabled
            {
                return Err(ApiError::Conflict(
                    "已配置的 TCP 拨测目标无效，请先修正配置".into(),
                ));
            }
            if !spec.runnable_at(now_timestamp())
                || spec.address_family() != sinan_protocol::ProbeAddressFamily::Any
                || spec
                    .monitor
                    .as_ref()
                    .and_then(|monitor| monitor.authorization.as_ref())
                    .is_none_or(|authorization| authorization.expires_at.is_some())
            {
                return Ok(None);
            }
            Ok(Some(Target {
                id,
                name: spec.name,
                target: spec.target,
                port: spec.port.unwrap(),
                carrier: spec.carrier,
                region,
            }))
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(|targets| targets.into_iter().flatten().collect())
}

pub struct TcpQualityPlugin;
impl DiagnosticPlugin for TcpQualityPlugin {
    fn id(&self) -> &'static str {
        "tcpquality"
    }
    fn version(&self) -> &'static str {
        PLUGIN_VERSION
    }
    fn title(&self) -> &'static str {
        "TCP 连接诊断"
    }
    fn required_capabilities(&self) -> &'static [&'static str] {
        &["diagnostic:tcpquality", "diagnostic:tcpquality-native-v1"]
    }
    fn plan<'a>(
        &'a self,
        request: Value,
        server: i64,
        connection: &'a mut sqlx::PgConnection,
    ) -> PlanFuture<'a> {
        Box::pin(async move {
            let request: Request = serde_json::from_value(request)
                .map_err(|_| ApiError::BadRequest("TCP 诊断参数格式无效".into()))?;
            if !request.valid() {
                return Err(ApiError::BadRequest(
                    "仅允许已列出的地区、IPv4/IPv6、4/8 次连接和 1/2 并发预设".into(),
                ));
            }
            let selected: Vec<_> = targets(connection, server)
                .await?
                .into_iter()
                .filter(|target| {
                    request.region == "configured"
                        || target.region.as_deref() == Some(request.region.as_str())
                })
                .collect();
            if selected.is_empty() {
                return Err(ApiError::Conflict(
                    "所选地区没有已启用的 TCP 拨测目标；请配置自有或获准使用的目标".into(),
                ));
            }
            if selected.len() > 8 {
                return Err(ApiError::Conflict(
                    "单次诊断最多 8 个目标，请按地区筛选或减少启用的 TCP 目标".into(),
                ));
            }
            let snapshot = serde_json::to_string(&json!({"schema":1,"targets":selected}))
                .map_err(anyhow::Error::from)?;
            if snapshot.len() > 16 * 1024 {
                return Err(ApiError::BadRequest("TCP 目标快照超过 16 KiB".into()));
            }
            let digest = format!("{:x}", Sha256::digest(snapshot.as_bytes()));
            let mut expected_sections = vec!["tcp_scope".into(), "tcp_summary".into()];
            for target in &selected {
                expected_sections.push(format!("tcp_target_{}", target.id.simple()));
            }
            expected_sections.push("environment".into());
            Ok(JobPlan {
                timeout_secs: 60,
                budget: DiagnosticResourceBudget {
                    memory_max: 64 * 1024 * 1024,
                    tasks_max: 32,
                    cpu_max_percent: None,
                    cpu_weight: 10,
                    io_weight: 10,
                    oom_score_adjust: 500,
                },
                options: BTreeMap::from([
                    ("ip_version".into(), request.ip_version.clone()),
                    ("count".into(), request.count.to_string()),
                    ("concurrency".into(), request.concurrency.to_string()),
                    ("targets".into(), snapshot),
                    ("target_digest".into(), digest.clone()),
                    ("environment_section".into(), "true".into()),
                ]),
                expected_sections,
                metadata: BTreeMap::from([(
                    "tcpquality".into(),
                    json!({
                        "method":"tcp_connect", "semantics":"TCP connection timing; no packet loss, retransmission, or throughput measurement",
                        "region":request.region, "ip_version":request.ip_version, "count":request.count,
                        "concurrency":request.concurrency, "target_digest":digest, "targets":selected,
                        "source_version":PLUGIN_VERSION, "configured_at":now_timestamp(),
                        "upload_enabled":false, "ranking_enabled":false, "speedtest_enabled":false,
                    }),
                )]),
            })
        })
    }
}

pub async fn list_targets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Vec<Target>>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL")
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(targets(&mut tx, server).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegionRequest {
    #[serde(deserialize_with = "explicit_region")]
    pub region: Option<String>,
}
// A null value clears the label; an absent key must not mutate settings.
fn explicit_region<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}
pub async fn set_region(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((server, probe)): Path<(i64, Uuid)>,
    Json(request): Json<RegionRequest>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    if request
        .region
        .as_ref()
        .is_some_and(|region| !REGIONS.contains(&region.as_str()))
    {
        return Err(ApiError::BadRequest("目标地区不在允许的预设中".into()));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let belongs: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_probes WHERE id=$1 AND server_id=$2 AND spec->>'kind'='tcp' AND spec->>'enabled'='true')")
        .bind(probe).bind(server).fetch_one(&mut *tx).await?;
    if !belongs {
        return Err(ApiError::NotFound);
    }
    if let Some(region) = request.region {
        sqlx::query("INSERT INTO tcpquality_target_regions(probe_id,region) VALUES($1,$2) ON CONFLICT(probe_id) DO UPDATE SET region=excluded.region")
            .bind(probe).bind(region).execute(&mut *tx).await?;
    } else {
        sqlx::query("DELETE FROM tcpquality_target_regions WHERE probe_id=$1")
            .bind(probe)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"saved":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_target_syntax_matches_the_native_snapshot_contract() {
        for value in ["example.test", "example.test.", "192.0.2.1", "2001:db8::1"] {
            assert!(valid_target(value));
        }
        for value in [
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "https://example.test",
            "[::1]",
            "foo..test",
            "-foo.test",
            "foo_.test",
            "foo.test..",
        ] {
            assert!(!valid_target(value), "{value}");
        }
    }
    #[test]
    fn whitelist_rejects_custom_commands_and_large_presets() {
        assert!(
            serde_json::from_value::<Request>(json!({}))
                .unwrap()
                .valid()
        );
        for value in [
            json!({"region":"global"}),
            json!({"ip_version":"both"}),
            json!({"count":100}),
            json!({"concurrency":32}),
            json!({"no_rank_upload":false}),
            json!({"allow_speedtest_staged":true}),
            json!({"no_rootfs":true}),
            json!({"command":"curl example.test"}),
        ] {
            assert!(
                serde_json::from_value::<Request>(value).map_or(true, |request| !request.valid())
            );
        }
    }
}
