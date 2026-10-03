//! Official node IP translation; diagnostic service owns execution and history.
use super::*;
use sha2::{Digest, Sha256};
use sinan_protocol::DiagnosticSectionUpdate;

mod parsing;
#[cfg(test)]
mod tests;

pub const NODE_QUERY_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21";
pub const NODE_QUERY_CAPABILITY: &str = "diagnostic:nodequality-node-query";
const SCHEMA: &str = "sinan.node-ip-quality.v1";

fn public_node_ip(ip: std::net::IpAddr) -> bool {
    if !ip_quality::public_ip(ip) {
        return false;
    }
    // Keep the legacy shared predicate unchanged, but exclude IANA special-use
    // documentation, benchmarking and deprecated relays from new node queries.
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 192 && b == 88 && c == 99)
        }
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            !(s[0] == 0x2001 && s[1] == 2 && s[2] == 0) && !(s[0] == 0x3fff && s[1] & 0xf000 == 0)
        }
    }
}

pub struct NodeSectionResults {
    pub identity: ip_quality::NodeResultIdentity,
    pub quality: Vec<ip_quality::IpQuality>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeQueryRequest {
    #[serde(default = "default_ip_version")]
    pub ip_version: String,
}

pub struct NodeIpQualityPlugin;
impl DiagnosticPlugin for NodeIpQualityPlugin {
    fn id(&self) -> &'static str {
        "nodequality"
    }
    fn version(&self) -> &'static str {
        NODE_QUERY_VERSION
    }
    fn title(&self) -> &'static str {
        "正式节点 IP 查询"
    }
    fn required_capabilities(&self) -> &'static [&'static str] {
        &[
            "diagnostic:nodequality",
            "diagnostic:nodequality-modes",
            NODE_QUERY_CAPABILITY,
        ]
    }
    fn can_dispatch(&self, job: &Value, capabilities: &Value) -> bool {
        job["version"].as_str() == Some(NODE_QUERY_VERSION)
            && job["options"]["mode"].as_str() == Some("ip")
            && capabilities.as_array().is_some_and(|items| {
                self.required_capabilities()
                    .iter()
                    .all(|required| items.iter().any(|item| item.as_str() == Some(required)))
            })
    }
    fn plan<'a>(
        &'a self,
        request: Value,
        server_id: i64,
        connection: &'a mut sqlx::PgConnection,
    ) -> PlanFuture<'a> {
        Box::pin(async move {
            let request: NodeQueryRequest = serde_json::from_value(request)
                .map_err(|_| ApiError::BadRequest("节点查询参数格式无效".into()))?;
            if !matches!(request.ip_version.as_str(), "both" | "ipv4" | "ipv6") {
                return Err(ApiError::BadRequest("IP 版本无效".into()));
            }
            let info: Value = sqlx::query_scalar(
                "SELECT static_info FROM servers WHERE id=$1 AND deleted_at IS NULL",
            )
            .bind(server_id)
            .fetch_optional(&mut *connection)
            .await?
            .ok_or(ApiError::NotFound)?;
            let ips: Vec<_> = ip_quality::reported_ips(&info)
                .into_iter()
                .filter(|ip| ip.parse().is_ok_and(public_node_ip))
                .collect();
            let family_present = ips.iter().any(|ip| {
                request.ip_version == "both" || (request.ip_version == "ipv6") == ip.contains(':')
            });
            if !family_present {
                return Err(ApiError::Conflict(
                    "Agent 尚未上报所选版本的公网 IP，不能将面板出口当作节点出口".into(),
                ));
            }
            // The shared service already holds the durable server lock here.
            // Creation order remains distinct when consecutive jobs share a second.
            let previous: i64 = sqlx::query_scalar("SELECT COALESCE(MAX((job->>'node_query_generation')::bigint),0) FROM diagnostic_jobs WHERE server_id=$1 AND job->>'plugin'='nodequality' AND job->'options'->>'mode'='ip' AND job ? 'node_query_generation'")
                .bind(server_id).fetch_one(&mut *connection).await?;
            let generation = previous
                .checked_add(1)
                .ok_or_else(|| ApiError::Conflict("节点查询历史序号已耗尽".into()))?;
            Ok(JobPlan {
                timeout_secs: 90,
                budget: DiagnosticResourceBudget {
                    memory_max: 64 * 1024 * 1024,
                    tasks_max: 32,
                    cpu_max_percent: None,
                    cpu_weight: 10,
                    io_weight: 10,
                    oom_score_adjust: 500,
                },
                options: BTreeMap::from([
                    ("mode".into(), "ip".into()),
                    ("ip_version".into(), request.ip_version),
                    (
                        "node_ips".into(),
                        serde_json::to_string(&ips).map_err(anyhow::Error::from)?,
                    ),
                    ("network_mode".into(), "low".into()),
                    ("upload_report".into(), "false".into()),
                    ("environment_section".into(), "true".into()),
                ]),
                expected_sections: vec!["ip_quality".into(), "environment".into()],
                metadata: BTreeMap::from([
                    ("node_query_schema".into(), Value::String(SCHEMA.into())),
                    ("node_query_generation".into(), Value::from(generation)),
                ]),
            })
        })
    }
}

pub async fn readiness(state: &AppState, server_id: i64) -> ApiResult<Option<String>> {
    let row = sqlx::query(
        "SELECT static_info,last_seen,capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(server_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let result = async {
        let arch = service::ready(&row, &NodeIpQualityPlugin)?;
        artifacts::descriptor(state, "nodequality", NODE_QUERY_VERSION, arch).await?;
        Ok::<(), ApiError>(())
    }
    .await;
    Ok(result.err().map(|error| match error {
        ApiError::NotFound => "正式节点查询 r21 制品尚未上传；需要对应架构的受控签名制品".into(),
        error => error.to_string(),
    }))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<NodeQueryRequest>,
) -> ApiResult<(StatusCode, Json<ReportRecord>)> {
    auth::require_admin(&state, &headers).await?;
    let value = serde_json::to_value(request).map_err(anyhow::Error::from)?;
    let record = service::create_job(&state, id, &NodeIpQualityPlugin, value).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

pub fn parse_section(
    job: &Value,
    update: &DiagnosticSectionUpdate,
    created_at: i64,
    expires_at: i64,
) -> ApiResult<Option<NodeSectionResults>> {
    if job["options"]["mode"].as_str() != Some("ip") || update.name != "ip_quality" {
        return Ok(None);
    }
    Ok(Some(NodeSectionResults {
        identity: ip_quality::NodeResultIdentity {
            job_id: update.id,
            revision: update.revision,
            text_sha256: format!("{:x}", Sha256::digest(update.text.as_bytes())),
        },
        quality: parsing::parse(job, update, created_at, expires_at)?,
    }))
}

pub async fn persist_section(
    state: &AppState,
    server_id: i64,
    results: Option<NodeSectionResults>,
) -> ApiResult<()> {
    if let Some(results) = results {
        ip_quality::persist_node_results(state, server_id, &results.identity, &results.quality)
            .await?;
    }
    Ok(())
}
