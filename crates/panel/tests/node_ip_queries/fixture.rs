use super::*;
use sinan_protocol::{Hello, Message, PROTOCOL_VERSION};
use std::collections::BTreeMap;
pub const VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21";

pub async fn prepare(panel: &TestPanel, server: i64) -> Result<()> {
    sqlx::query("UPDATE servers SET static_info=static_info || '{\"os\":\"linux\",\"ip_addresses\":[\"1.1.1.1\",\"127.0.0.1\"]}'::jsonb WHERE id=$1")
        .bind(server).execute(&panel.state.pool).await?;
    sinan_panel::agent_api::process_message(
        &panel.state,
        server,
        Message::Hello(Hello {
            agent_version: "TEST_ONLY node IP query".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![
                "diagnostic:nodequality",
                "diagnostic:nodequality-modes",
                "diagnostic:nodequality-node-query",
                sinan_protocol::DIAGNOSTIC_CANCEL_CAPABILITY,
                sinan_protocol::DIAGNOSTIC_SECTIONS_CAPABILITY,
                sinan_protocol::DIAGNOSTIC_SERVICE_CAPABILITY,
                sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY,
                sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY,
                sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            applied: BTreeMap::new(),
        }),
    )
    .await?;
    let binary = b"TEST_ONLY signed node query fixture";
    let archive = release_fixture::archive("nodequality", binary)?;
    release_fixture::write(
        &panel.state.config.data_dir,
        "nodequality",
        VERSION,
        "nodequality",
        &archive,
        binary,
        "tar.gz",
    )?;
    Ok(())
}
pub async fn create(panel: &TestPanel, server: i64, cookie: &str) -> Result<Value> {
    Ok(panel
        .admin(
            Method::POST,
            &format!("/api/servers/{server}/ip-quality/node-query"),
            cookie,
            Some(json!({"ip_version":"both"})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}
pub async fn upload(
    panel: &TestPanel,
    token: &str,
    id: &str,
    receipt: &Value,
) -> Result<StatusCode> {
    Ok(panel
        .client
        .post(format!(
            "{}/api/agent/v1/diagnostics/{id}/sections",
            panel.base
        ))
        .bearer_auth(token)
        .json(receipt)
        .send()
        .await?
        .status())
}
pub async fn view(panel: &TestPanel, server: i64, cookie: &str) -> Result<Value> {
    Ok(panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/ip-quality"),
            cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}
pub fn section(
    id: &str,
    at: i64,
    revision: u64,
    complete: bool,
    failure: Option<(&str, Option<u16>)>,
) -> Value {
    let rows: Vec<_> = [("ipregistry-node", "ipregistry-v1", "https://api.ipregistry.co"),
        ("dbip-node", "dbip-v2", "https://api.db-ip.com/v2")].into_iter().map(|(provider, database, source)| {
            let omitted = failure.is_some_and(|(kind, _)| kind == "not_attempted");
            json!({"provider":provider,"database":database,"source":source,"target_ip":"1.1.1.1","execution":"node",
                "available":!omitted,"observed_ip":if omitted {Value::Null} else {json!("1.1.1.1")},
                "attempted_at":if omitted {Value::Null} else {json!(at)},"elapsed_ms":if omitted {Value::Null} else {json!(0)},
                "data":if failure.is_some() {Value::Null} else if provider=="ipregistry-node" {
                    json!({"ip":"1.1.1.1","type":"IPv4","security":{"is_proxy":false}})
                } else {json!({"ipAddress":"1.1.1.1","latitude":0,"isProxy":false})},
                "error":failure.map(|(kind,status)| json!({"kind":kind,"message":"TEST_ONLY 未完成正式查询，信息未知","http_status":status}))})
        }).collect();
    let body = json!({"schema":"sinan.node-ip-quality.v1","job_id":id,"execution":"node","ip_version":"both",
        "started_at":at,"finished_at":at,"ips":["1.1.1.1"],"results":rows,
        "streaming":{"execution":"node","status":"unknown","reason":"TEST_ONLY 正式流媒体认证未配置，信息未知"}});
    json!({"id":id,"name":"ip_quality","text":body.to_string(),"complete":complete,"revision":revision,"collected_at":at})
}
fn datasets(quality: &Value) -> impl Iterator<Item = &Value> {
    quality["quality"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| &entry["databases"][0])
}
pub fn assert_current_false_zero(quality: &Value, at: i64) {
    assert_eq!(quality["quality"].as_array().unwrap().len(), 2);
    for dataset in datasets(quality) {
        assert_eq!(dataset["status"], "succeeded");
        assert_eq!(dataset["historical"], false);
        assert_eq!(dataset["last_success_at"], at);
        assert_eq!(dataset["execution"], "node");
        assert_false_zero(dataset);
    }
}
pub fn assert_history_false_zero(quality: &Value, at: i64, kind: &str) {
    assert_eq!(quality["quality"].as_array().unwrap().len(), 2);
    for dataset in datasets(quality) {
        assert_eq!(dataset["status"], "failed");
        assert_eq!(dataset["historical"], true);
        assert_eq!(dataset["last_success_at"], at);
        assert_eq!(dataset["last_error"]["kind"], kind);
        assert_false_zero(dataset);
    }
}
fn assert_false_zero(dataset: &Value) {
    let fields = dataset["fields"].as_array().unwrap();
    assert_eq!(
        fields
            .iter()
            .find(|field| field["label"] == "代理")
            .unwrap()["value"],
        false
    );
    if dataset["database"] == "dbip-v2" {
        assert_eq!(
            fields
                .iter()
                .find(|field| field["label"] == "纬度")
                .unwrap()["value"],
            0
        );
    }
}
