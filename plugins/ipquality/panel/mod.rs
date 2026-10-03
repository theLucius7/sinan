use crate::{
    diagnostics::service::{DiagnosticPlugin, JobPlan, PlanFuture, SectionContext, SectionFuture},
    error::ApiError,
    ip_quality,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::{DiagnosticResourceBudget, DiagnosticSectionUpdate};
use std::collections::BTreeMap;

mod result;
#[cfg(test)]
mod tests;

pub const PLUGIN_VERSION: &str = "87397e2c3196ec796f5477c83343c2354df601ea-node-r1";
pub const SOURCE_COMMIT: &str = "87397e2c3196ec796f5477c83343c2354df601ea";
pub const SOURCE_SHA256: &str = "b30df5a3c2204276c54e99dcc5080b46f8a627667730aee7de63b109b8ecaecf";
pub const CAPABILITY: &str = "diagnostic:ipquality-node-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub ip_version: String,
}

impl Request {
    fn valid(&self) -> bool {
        matches!(self.ip_version.as_str(), "4" | "6")
    }
}

pub struct IpQualityPlugin;

impl DiagnosticPlugin for IpQualityPlugin {
    fn id(&self) -> &'static str {
        "ipquality"
    }
    fn version(&self) -> &'static str {
        PLUGIN_VERSION
    }
    fn title(&self) -> &'static str {
        "IPQuality 节点出口自查"
    }
    fn required_capabilities(&self) -> &'static [&'static str] {
        &[CAPABILITY]
    }

    fn plan<'a>(
        &'a self,
        request: Value,
        _server_id: i64,
        _connection: &'a mut sqlx::PgConnection,
    ) -> PlanFuture<'a> {
        Box::pin(async move {
            let request: Request = serde_json::from_value(request).map_err(|_| {
                ApiError::BadRequest("节点自查只接受明确的 IPv4 或 IPv6 参数".into())
            })?;
            if !request.valid() {
                return Err(ApiError::BadRequest(
                    "单次节点自查必须选择 IPv4 或 IPv6".into(),
                ));
            }
            Ok(JobPlan {
                timeout_secs: 300,
                budget: DiagnosticResourceBudget {
                    memory_max: 128 * 1024 * 1024,
                    tasks_max: 64,
                    cpu_max_percent: None,
                    cpu_weight: 10,
                    io_weight: 10,
                    oom_score_adjust: 500,
                },
                options: BTreeMap::from([
                    ("ip_version".into(), request.ip_version.clone()),
                    ("environment_section".into(), "true".into()),
                ]),
                expected_sections: vec!["ipquality_result".into(), "environment".into()],
                metadata: BTreeMap::from([(
                    "ipquality".into(),
                    json!({
                        "source_commit": SOURCE_COMMIT,
                        "source_sha256": SOURCE_SHA256,
                        "source_version": "v2026-09-16",
                        "license": "AGPL-3.0",
                        "ip_version": request.ip_version,
                        "execution": "node_egress",
                        "host_changes": false,
                        "upload_enabled": false,
                        "panel_credentials_forwarded": false,
                    }),
                )]),
            })
        })
    }

    fn record_section<'a>(
        &'a self,
        context: SectionContext<'a>,
        update: &'a DiagnosticSectionUpdate,
        connection: &'a mut sqlx::PgConnection,
    ) -> SectionFuture<'a> {
        Box::pin(async move {
            if update.name != "ipquality_result" {
                return Ok(());
            }
            let projection = result::parse(&context, update)?;
            ip_quality::node::persist(connection, &context, update, projection).await
        })
    }
}

pub(crate) use result::SOURCES;
pub(crate) use result::{Projection, validate_cached_fields};

pub(crate) fn invalid(message: &str) -> ApiError {
    ApiError::BadRequest(format!("节点自查报告无效：{message}"))
}
