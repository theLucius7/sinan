use super::{TestPanel, release_fixture};
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Method, Response, header};
use serde_json::{Value, json};
use sinan_panel::AppState;
use sinan_protocol::{
    fleet::{JobResult, Operation, Work},
    now_timestamp,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Ordinary publisher tests exercise compilation and accounting, not public DNS
/// or native runtime execution. They still cross the production request, dispatch,
/// receipt, current-fingerprint and explicit confirmation boundaries.
pub(super) async fn prepare(panel: &TestPanel) -> Result<()> {
    let servers = selected(&panel.state.pool).await?;
    if servers.is_empty() {
        return Ok(());
    }
    let cookie = panel.admin_cookie().await?;
    let fixture = Fixture {
        state: &panel.state,
        client: &panel.client,
        base: &panel.base,
    };
    for server in servers {
        prepare_server(&fixture, &cookie, server, true).await?;
    }
    Ok(())
}

/// Reuse the same explicit API gate when a fixture owns its own HTTP harness.
/// Its Agent runner must be paused while controlled typed observations are sent.
/// The supplied administrator cookie must carry its real recent login proof.
pub async fn prepare_with(
    state: &AppState,
    client: &Client,
    base: &str,
    cookie: &str,
) -> Result<()> {
    let fixture = Fixture {
        state,
        client,
        base,
    };
    for server in selected(&state.pool).await? {
        prepare_server(&fixture, cookie, server, true).await?;
    }
    Ok(())
}

/// Observe the actual queued requests without recording administrator confirmation.
pub async fn observe(panel: &TestPanel, cookie: &str, server: i64) -> Result<Uuid> {
    prepare_server(
        &Fixture {
            state: &panel.state,
            client: &panel.client,
            base: &panel.base,
        },
        cookie,
        server,
        false,
    )
    .await
}

struct Fixture<'a> {
    state: &'a AppState,
    client: &'a Client,
    base: &'a str,
}
impl Fixture<'_> {
    async fn admin(
        &self,
        method: Method,
        path: &str,
        cookie: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        let request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .header(header::COOKIE, cookie);
        Ok(match body {
            Some(body) => request.json(&body),
            None => request,
        }
        .send()
        .await?)
    }
}

async fn selected(pool: &PgPool) -> Result<Vec<i64>> {
    let servers:Vec<i64>=sqlx::query_scalar("SELECT s.id FROM servers s JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' AND p.enabled AND p.source='administrator' WHERE s.deleted_at IS NULL AND s.dirty_at IS NOT NULL AND EXISTS(SELECT 1 FROM nodes n WHERE n.server_id=s.id AND n.deleted_at IS NULL AND n.enabled AND EXISTS(SELECT 1 FROM singbox_eligible_accesses($1) a WHERE a.node_id=n.id) AND NOT EXISTS(SELECT 1 FROM singbox_chains c WHERE (c.deleted_at IS NULL OR c.phase<>'retired') AND (c.entry_node_id=n.id OR c.exit_node_id=n.id OR EXISTS(SELECT 1 FROM singbox_ordered_chain_hops h WHERE h.chain_id=c.id AND h.managed_node_id=n.id)))) ORDER BY s.id")
        .bind(now_timestamp()).fetch_all(pool).await?;
    Ok(servers)
}

async fn prepare_server(
    panel: &Fixture<'_>,
    cookie: &str,
    server: i64,
    confirm: bool,
) -> Result<Uuid> {
    let row = sqlx::query("SELECT capabilities,static_info FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    let mut capabilities: Vec<String> = serde_json::from_value(row.get("capabilities"))?;
    for capability in [
        "singbox",
        sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY,
        sinan_protocol::fleet::OPERATIONS_CAPABILITY,
        sinan_protocol::fleet::RUNTIME_PREFLIGHT_CAPABILITY,
    ] {
        if !capabilities.iter().any(|item| item == capability) {
            capabilities.push(capability.into());
        }
    }
    let mut info: Value = row.get("static_info");
    if !info.is_object() {
        info = json!({});
    }
    for (key, value) in [
        ("os", "linux"),
        ("arch", sinan_protocol::release::native_arch()?),
        ("libc", "gnu"),
        ("runtime_libc", "gnu"),
    ] {
        if info.get(key).is_none_or(Value::is_null) {
            info[key] = json!(value);
        }
    }
    let target = sinan_protocol::platform::artifact_target(
        info["os"].as_str().context("TEST_ONLY platform")?,
        info["runtime_libc"]
            .as_str()
            .or_else(|| info["libc"].as_str()),
        info["arch"].as_str().context("TEST_ONLY architecture")?,
    )
    .context("TEST_ONLY supported runtime artifact target")?;
    let legacy = if info["os"] == "linux"
        && matches!(info["runtime_libc"].as_str(), Some("gnu" | "glibc"))
    {
        match info["arch"].as_str() {
            Some("x86_64" | "amd64") => Some("amd64"),
            Some("aarch64" | "arm64") => Some("arm64"),
            _ => None,
        }
    } else {
        None
    };
    sqlx::query("UPDATE servers SET capabilities=$2,static_info=$3,last_seen=$4 WHERE id=$1")
        .bind(server)
        .bind(json!(capabilities))
        .bind(info)
        .bind(now_timestamp())
        .execute(&panel.state.pool)
        .await?;
    let runtime = panel
        .state
        .config
        .data_dir
        .join("artifacts/releases/agent-v0.3.0/sing-box/1.14.2");
    if !runtime.join(&target).is_file() && !legacy.is_some_and(|arch| runtime.join(arch).is_file())
    {
        ensure!(
            !panel
                .state
                .config
                .data_dir
                .join("artifacts/releases/agent-v0.3.0/release.json")
                .exists(),
            "TEST_ONLY existing signed release lacks the requested runtime fixture; preserve it rather than rewrite its proof"
        );
        let binary = b"TEST_ONLY inert deployment preflight fixture; never executed";
        let archive = release_fixture::archive("sing-box", binary)?;
        release_fixture::write(
            &panel.state.config.data_dir,
            "sing-box",
            "1.14.2",
            "sing-box",
            &archive,
            binary,
            "tar.gz",
        )?;
    }
    let profile_path = format!("/api/servers/{server}/fleet");
    let profile: Value = panel
        .admin(Method::GET, &profile_path, cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    if profile["policy"]["runtime_inspection"] != true {
        let mut policy = profile["policy"].clone();
        policy["runtime_inspection"] = json!(true);
        panel.admin(Method::PUT,&profile_path,cookie,Some(json!({"asset":profile["asset"],"policy":policy,"expected_digest":profile["digest"]}))).await?.error_for_status()?;
    }
    let path = format!("/api/plugins/sing-box/servers/{server}/operations-view/preflight");
    let response = panel.admin(Method::POST, &path, cookie, None).await?;
    ensure!(
        response.status().is_success(),
        "TEST_ONLY deployment preflight request failed: {}",
        response.text().await?
    );
    let request: Value = response.json().await?;
    let preflight: Uuid = serde_json::from_value(request["id"].clone())?;
    let expected = [
        serde_json::from_value::<Uuid>(request["permissions_operation_id"].clone())?,
        serde_json::from_value::<Uuid>(request["ports_operation_id"].clone())?,
    ];
    controlled_network_evidence(panel, preflight).await?;

    // Seed a controlled authenticated-device session, as other HTTP fixtures do.
    // Work must actually dispatch each requested typed job before a receipt can
    // be accepted. No operation status or confirmation is updated directly.
    let token = format!("TEST_ONLY-preflight-{}", Uuid::new_v4());
    sqlx::query("INSERT INTO sessions(token_hash,server_id,expires_at) VALUES($1,$2,$3)")
        .bind(sinan_panel::auth::hash_token(&token))
        .bind(server)
        .bind(now_timestamp() + 300)
        .execute(&panel.state.pool)
        .await?;
    let outcome=async {
        let mut completed=std::collections::BTreeSet::new();
        for _ in 0..expected.len() {
            let work:Work=panel.client.get(format!("{}/api/agent/v1/fleet/work",panel.base)).bearer_auth(&token).send().await?.error_for_status()?.json().await?;
            ensure!(work.jobs.len()==1,"TEST_ONLY preflight expected one dispatched job, got {}",work.jobs.len());
            let job=&work.jobs[0];
            ensure!(expected.contains(&job.id)&&completed.insert(job.id),"TEST_ONLY preflight dispatched an unrelated or duplicate job");
            let result=match &job.operation {
                Operation::Ports {}=>json!({"stdout":"","stderr":"","truncated":false,"timed_out":false,"exit_code":0,"fixture":"TEST_ONLY controlled empty listening sockets"}),
                Operation::RuntimePermissions{module}=>{
                    ensure!(module=="sing-box"&&job.policy.runtime_inspection,"TEST_ONLY runtime inspection requires the current allowed policy");
                    let root="/var/lib/sinan/runtimes/sing-box@main";
                    json!({"module":module,"sampled_at":now_timestamp(),"privileged_effective_uid":0,"runtime_account":{"known":true,"uid":65534,"gid":65534,"supplementary_gids":[65534],"source":"TEST_ONLY controlled installed runtime account"},"runtime_directory":directory(root),"data_directory":directory(&format!("{root}/data")),"certificate_directory":directory(&format!("{root}/data/certificates")),"service_manager":{"kind":"systemd","available":true,"management_authorized":true,"privileged_effective_uid":0,"managed_unit":"sinan-singbox@main.service","managed_pid":null,"load_state":"loaded","authorization_basis":"TEST_ONLY controlled privileged service backend"},"secret_values_recorded":false})
                }
                other=>anyhow::bail!("unexpected TEST_ONLY preflight operation: {other:?}"),
            };
            let receipt=JobResult{id:job.id,succeeded:true,result,error:None,completed_at:now_timestamp()};
            let acknowledged:Value=panel.client.post(format!("{}/api/agent/v1/fleet/results",panel.base)).bearer_auth(&token).json(&receipt).send().await?.error_for_status()?.json().await?;
            ensure!(acknowledged["acknowledged"]==json!(job.id),"TEST_ONLY result did not acknowledge the delivered job");
        }
        if confirm {
            let response=panel.admin(Method::POST,&format!("{path}/confirm"),cookie,Some(json!({"id":preflight,"confirm":true}))).await?;
            ensure!(response.status().is_success(),"TEST_ONLY deployment preflight confirmation failed: {}",response.text().await?);
            let confirmed:Value=response.json().await?;
            ensure!(confirmed["confirmed"]==true&&confirmed["deployment_requested"]==false,"TEST_ONLY preflight confirmation must not claim deployment");
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    sqlx::query("DELETE FROM sessions WHERE token_hash=$1")
        .bind(sinan_panel::auth::hash_token(&token))
        .execute(&panel.state.pool)
        .await?;
    outcome?;
    Ok(preflight)
}

fn directory(path: &str) -> Value {
    json!({"path":path,"exists":true,"nearest_existing_parent":path,"symlink_free":true,"readable":true,"writable":true,"executable":true,"error":null,"runtime_readable":true,"runtime_writable":true,"runtime_executable":true,"runtime_error":null,"fixture":"TEST_ONLY controlled runtime directory permissions"})
}

async fn controlled_network_evidence(panel: &Fixture<'_>, id: Uuid) -> Result<()> {
    let mut checks: Value =
        sqlx::query_scalar("SELECT panel_checks FROM singbox_deployment_preflights WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.state.pool)
            .await?;
    for check in checks
        .as_array_mut()
        .context("TEST_ONLY captured network checks")?
    {
        let key = check["key"].as_str().unwrap_or("");
        if key.starts_with("dns:") || key.starts_with("acme_dns:") {
            check["state"] = json!("passed");
            check["blocking"] = json!(false);
            check["observed_at"] = json!(now_timestamp());
            check["source"] = json!("TEST_ONLY controlled DNS fixture");
            check["evidence"] = json!({"fixture":"TEST_ONLY reserved example-domain observation","real_public_dns_verified":false,"real_certificate_issued":false,"private_key_returned":false});
            check["detail"] = json!(
                "TEST_ONLY fixture replaces external DNS evidence; this test does not verify public DNS. Certificate and ACME preparation checks remain separate."
            );
        }
    }
    sqlx::query("UPDATE singbox_deployment_preflights SET panel_checks=$2 WHERE id=$1")
        .bind(id)
        .bind(checks)
        .execute(&panel.state.pool)
        .await?;
    Ok(())
}
