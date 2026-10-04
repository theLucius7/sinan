#![forbid(unsafe_code)]

mod business_support;
#[path = "e2e_support/preflight.rs"]
mod deployment_preflight;
mod e2e_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use e2e_support::{AgentTask, Harness, PanelAdapter, eventually};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_adapter_sdk::{Counter, Prepared};
use sinan_agent_core::{fake::FakeServiceManager, identity, state::State, transport};
use sinan_protocol::{UsageBatch, UsageRecord};
use sqlx::{PgPool, Row};
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

#[sqlx::test(migrations = "./migrations")]
async fn published_configuration_usage_and_lost_ack_survive_agent_restart(
    pool: PgPool,
) -> Result<()> {
    let panel = Harness::start(pool.clone()).await?;
    let expected_binary = panel.write_runtime_artifact()?;
    let config = panel.agent_config();
    let adapter = Arc::new(PanelAdapter::default());
    let services = Arc::new(FakeServiceManager::default());
    let server = panel
        .api(Method::POST, "/api/servers", json!({"name": "E2E server"}))
        .await?;
    let server_id = server["id"].as_i64().context("server id")?;
    let enrollment = panel
        .api(
            Method::POST,
            &format!("/api/servers/{server_id}/enrollment"),
            json!({}),
        )
        .await?;
    assert_eq!(
        identity::enroll(&config, enrollment["token"].as_str().context("token")?).await?,
        server_id
    );
    // This fixture explicitly enables only the independent read-only capability.
    // No runtime deployment bypass is present in the production configuration.
    let policy_path = config
        .identity_dir
        .parent()
        .context("fixture Agent root")?
        .join("fleet-policy.json");
    fs::write(
        &policy_path,
        serde_json::to_vec(&sinan_protocol::fleet::AccessPolicy {
            runtime_inspection: true,
            ..Default::default()
        })?,
    )?;
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600))?;
    let original_key = fs::read(config.identity_dir.join("device.key"))?;
    let agent = AgentTask::start(config.clone(), adapter.clone(), services.clone());
    eventually("authenticated agent telemetry", 10, || async {
        let server = panel
            .api(
                Method::GET,
                &format!("/api/servers/{server_id}"),
                Value::Null,
            )
            .await?;
        Ok(server["online"] == true && server["static_info"]["arch"].is_string())
    })
    .await?;

    panel
        .api(
            Method::POST,
            &format!("/api/plugins/sing-box/servers/{server_id}/enable"),
            json!({}),
        )
        .await?;
    let node = panel
        .api(
            Method::POST,
            "/api/plugins/sing-box/nodes",
            json!({
                "name": "E2E node", "server_id": server_id,
                "public_host": "node.example.invalid", "sni": "www.example.com"
            }),
        )
        .await?;
    let node_id = node["id"].as_i64().context("node id")?;
    let user = panel
        .api(
            Method::POST,
            "/api/plugins/sing-box/users",
            json!({"name": "E2E user"}),
        )
        .await?;
    let user_id = user["id"].as_i64().context("user id")?;
    let access = panel
        .api(
            Method::POST,
            &format!("/api/plugins/sing-box/users/{user_id}/accesses"),
            json!({"node_id": node_id}),
        )
        .await?;
    let stat_name = access["stat_name"]
        .as_str()
        .context("stat name")?
        .to_owned();
    let subscription = format!(
        "{}/sub/{}",
        panel.base,
        user["subscription_token"]
            .as_str()
            .context("subscription token")?
    );
    assert_eq!(
        panel
            .client
            .get(format!("{subscription}?format=singbox"))
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert!(
        panel
            .client
            .get(&subscription)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?
            .is_empty()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployments WHERE server_id=$1")
            .bind(server_id)
            .fetch_one(&pool)
            .await?,
        0
    );

    // Pause the native transport while the controlled Agent fixture claims the
    // two real typed requests. This prevents racing a mock service backend that
    // does not implement system permission inspection. The reserved DNS and
    // directory/service receipts are TEST_ONLY; no public DNS or host service
    // permission is being accepted by this accounting/restart scenario.
    agent.stop().await?;
    eventually(
        "Agent paused before controlled deployment preflight",
        5,
        || async { Ok(!config.status_socket.exists()) },
    )
    .await?;
    let preflight = deployment_preflight::prepare(&panel, server_id).await?;
    // Let the production publisher consume the current explicit confirmation
    // before the real Agent replaces TEST_ONLY read-only fixture declarations
    // with its actual platform capabilities. Its immutable deployment remains
    // pending and is applied through the real authenticated WebSocket on restart.
    eventually("debounced confirmed deployment committed while Agent is paused", 15, || async {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT manifest_rev,(SELECT count(*) FROM deployments d WHERE d.server_id=s.id AND d.module='singbox') FROM servers s WHERE s.id=$1"
        ).bind(server_id).fetch_optional(&pool).await?;
        Ok(row.is_some_and(|(revision, count)| revision > 0 && count == 1))
    }).await?;
    let confirmed: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT confirmed_at,confirmed_by FROM singbox_deployment_preflights WHERE id=$1 AND server_id=$2"
    ).bind(preflight).bind(server_id).fetch_one(&pool).await?;
    assert!(confirmed.0.is_some() && confirmed.1.is_some());
    assert!(
        State::open(&config.state_db)?
            .get_json::<Prepared>("applied:singbox")?
            .is_none()
    );
    let agent = AgentTask::start(config.clone(), adapter.clone(), services.clone());

    // The real publisher's immutable bundle still crosses its authenticated
    // WebSocket delivery and the existing adapter/configuration/accounting path.
    eventually("debounced deployment applied over WebSocket", 15, || async {
        let row: Option<(i64, i64, bool)> = sqlx::query_as(
            "SELECT target_rev,applied_rev,healthy FROM server_module_status WHERE server_id=$1 AND module='singbox'"
        ).bind(server_id).fetch_optional(&pool).await?;
        Ok(row.is_some_and(|(target, applied, healthy)| target > 0 && target == applied && healthy))
    }).await?;
    let actual = panel
        .api(
            Method::GET,
            &format!("/api/servers/{server_id}"),
            Value::Null,
        )
        .await?;
    assert_eq!(actual["static_info"]["os"], std::env::consts::OS);
    if std::env::consts::OS != "linux" {
        assert!(actual["static_info"].get("runtime_libc").is_none());
        assert!(actual["static_info"].get("libc").is_none());
        for capability in [
            sinan_protocol::fleet::OPERATIONS_CAPABILITY,
            sinan_protocol::fleet::RUNTIME_PREFLIGHT_CAPABILITY,
        ] {
            assert!(
                !actual["capabilities"]
                    .as_array()
                    .context("actual Agent capabilities")?
                    .iter()
                    .any(|value| value == capability)
            );
        }
    }
    let local = State::open(&config.state_db)?;
    let applied: Prepared = local
        .get_json("applied:singbox")?
        .context("applied local revision")?;
    assert!(local.pending_intents()?.is_empty());
    drop(local);
    assert_eq!(fs::read(&applied.spec.binary_path)?, expected_binary);
    assert_eq!(
        fs::read_link(config.runtime_root.join("sing-box@main/current"))?,
        applied.spec.revision_dir
    );
    let runtime_config: Value =
        serde_json::from_slice(&fs::read(applied.spec.revision_dir.join("config.json"))?)?;
    assert_eq!(runtime_config["inbounds"][0]["users"][0]["name"], stat_name);
    assert_eq!(
        runtime_config["inbounds"][0]["users"][0]["uuid"],
        access["uuid"]
    );
    assert_eq!(
        fs::metadata(&config.status_socket)?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(config.status_socket.parent().unwrap())?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let status = transport::status(&config.status_socket).await?;
    assert_eq!(status["connected"], true);
    assert_eq!(status["applied"]["singbox"], applied.spec.revision);
    assert_eq!(status["healthy"]["singbox"], true);
    let client_config: Value = panel
        .client
        .get(format!("{subscription}?format=singbox"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(client_config["outbounds"][1]["uuid"], access["uuid"]);
    let links = panel
        .client
        .get(&subscription)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let links = String::from_utf8(STANDARD.decode(links)?)?;
    assert!(links.contains(access["uuid"].as_str().context("access uuid")?));

    *adapter.0.counters.lock().unwrap() = vec![Counter {
        stat_name: stat_name.clone(),
        uplink: 100,
        downlink: 200,
    }];
    // The production 30 s sampler and 15 s outbox retry provide the first batch and ACK.
    eventually(
        "periodic usage batch committed and acknowledged",
        48,
        || async {
            let totals = panel
                .api(Method::GET, "/api/plugins/sing-box/usage", Value::Null)
                .await?;
            Ok(totals["uplink"] == "100"
                && totals["downlink"] == "200"
                && transport::status(&config.status_socket).await?["pending_batches"] == 0)
        },
    )
    .await?;
    assert_usage(&panel, user_id, node_id).await?;
    agent.stop().await?;
    eventually("agent children and status socket stopped", 5, || async {
        Ok(!config.status_socket.exists())
    })
    .await?;

    // Requeue the exact committed batch to model a process dying before its ACK was durable.
    let row = sqlx::query("SELECT b.epoch,b.seq::text AS seq,r.period_start,r.period_end,r.stat_name,r.uplink::text AS uplink,r.downlink::text AS downlink FROM usage_batches b JOIN usage_records r USING(server_id,epoch,seq) WHERE b.server_id=$1")
        .bind(server_id).fetch_one(&pool).await?;
    let batch = UsageBatch {
        epoch: row.get("epoch"),
        seq: row.get::<String, _>("seq").parse()?,
        period_start: row.get("period_start"),
        period_end: row.get("period_end"),
        records: vec![UsageRecord {
            stat_name: row.get("stat_name"),
            uplink: row.get::<String, _>("uplink").parse()?,
            downlink: row.get::<String, _>("downlink").parse()?,
        }],
    };
    {
        let connection = rusqlite::Connection::open(&config.state_db)?;
        connection.execute("INSERT INTO usage_outbox(epoch,seq,batch,acknowledged) VALUES(?1,?2,?3,0) ON CONFLICT(epoch,seq) DO UPDATE SET acknowledged=0",
            rusqlite::params![batch.epoch.to_string(), batch.seq.to_string(), serde_json::to_string(&batch)?])?;
    }
    assert_eq!(State::open(&config.state_db)?.pending_usage_count()?, 1);
    let actions_before_restart = services.actions.lock().unwrap().clone();
    let restarted = AgentTask::start(config.clone(), adapter, services.clone());
    eventually(
        "restarted agent retransmission acknowledged",
        10,
        || async {
            if !config.status_socket.exists() {
                return Ok(false);
            }
            let status = transport::status(&config.status_socket).await?;
            Ok(status["connected"] == true && status["pending_batches"] == 0)
        },
    )
    .await?;
    assert_usage(&panel, user_id, node_id).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM usage_batches WHERE server_id=$1")
            .bind(server_id)
            .fetch_one(&pool)
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM usage_records WHERE server_id=$1")
            .bind(server_id)
            .fetch_one(&pool)
            .await?,
        1
    );
    assert_eq!(
        fs::read(config.identity_dir.join("device.key"))?,
        original_key
    );
    assert_eq!(*services.actions.lock().unwrap(), actions_before_restart);
    assert_eq!(
        State::open(&config.state_db)?.get_json::<Prepared>("applied:singbox")?,
        Some(applied)
    );
    restarted.stop().await?;
    eventually("restarted agent children stopped", 5, || async {
        Ok(!config.status_socket.exists())
    })
    .await?;
    Ok(())
}

async fn assert_usage(panel: &Harness, user_id: i64, node_id: i64) -> Result<()> {
    let usage = panel
        .api(Method::GET, "/api/plugins/sing-box/usage", Value::Null)
        .await?;
    assert_eq!(usage["uplink"], "100");
    assert_eq!(usage["downlink"], "200");
    assert_eq!(usage["total"], "300");
    assert_eq!(usage["by_user"].as_array().context("user totals")?.len(), 1);
    assert_eq!(usage["by_user"][0]["user_id"], user_id);
    assert_eq!(usage["by_user"][0]["uplink"], "100");
    assert_eq!(usage["by_user"][0]["downlink"], "200");
    assert_eq!(usage["by_node"].as_array().context("node totals")?.len(), 1);
    assert_eq!(usage["by_node"][0]["node_id"], node_id);
    assert_eq!(usage["by_node"][0]["uplink"], "100");
    assert_eq!(usage["by_node"][0]["downlink"], "200");
    Ok(())
}
