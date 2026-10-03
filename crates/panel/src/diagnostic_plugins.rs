use crate::diagnostics::service::DiagnosticPlugin;
#[path = "../../../plugins/ipquality/panel/mod.rs"]
pub mod ipquality;
#[path = "../../../plugins/nodequality/panel/mod.rs"]
pub mod nodequality;
#[path = "../../../plugins/tcpquality/panel/mod.rs"]
pub mod tcpquality;
static NODEQUALITY: nodequality::NodeQualityPlugin = nodequality::NodeQualityPlugin;
static NODE_IPQUALITY: nodequality::node_queries::NodeIpQualityPlugin =
    nodequality::node_queries::NodeIpQualityPlugin;
static TCPQUALITY: tcpquality::TcpQualityPlugin = tcpquality::TcpQualityPlugin;
static IPQUALITY: ipquality::IpQualityPlugin = ipquality::IpQualityPlugin;
static NETWORK_WORKBENCH: crate::network_workbench::NetworkWorkbenchPlugin =
    crate::network_workbench::NetworkWorkbenchPlugin;
static REGISTERED: [&dyn DiagnosticPlugin; 4] =
    [&NODEQUALITY, &TCPQUALITY, &IPQUALITY, &NETWORK_WORKBENCH];
pub fn all() -> &'static [&'static dyn DiagnosticPlugin] {
    &REGISTERED
}
pub fn find(id: &str) -> Option<&'static dyn DiagnosticPlugin> {
    all().iter().copied().find(|plugin| plugin.id() == id)
}

/// Jobs created before plugin registration belong to the original diagnostic plugin.
pub fn for_job(job: &serde_json::Value) -> Option<&'static dyn DiagnosticPlugin> {
    if job["plugin"].as_str() == Some("nodequality")
        && job["version"].as_str() == Some(nodequality::node_queries::NODE_QUERY_VERSION)
        && job["options"]["mode"].as_str() == Some("ip")
    {
        return Some(&NODE_IPQUALITY);
    }
    find(job["plugin"].as_str().unwrap_or("nodequality"))
}
