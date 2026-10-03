use super::metadata;
use crate::business_support::{TestPanel, id, receive_envelope, release_fixture, send_envelope};
use anyhow::{Context, Result};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_protocol::{ApplyResult, ApplyStatus, Envelope, Heartbeat, now_timestamp};
use sqlx::PgPool;
use uuid::Uuid;

async fn supported_online(pool: &PgPool, server: i64) -> Result<()> {
    sqlx::query("UPDATE servers SET capabilities=$2,last_seen=$3 WHERE id=$1")
        .bind(server)
        .bind(json!([
            "singbox",
            sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY
        ]))
        .bind(now_timestamp())
        .execute(pool)
        .await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn explicit_enable_queues_once_and_first_publication_has_no_public_listener(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Installation fixture").await?;
    supported_online(&pool, server).await?;
    assert_eq!(metadata(&panel, &cookie, server).await?["enabled"], false);
    let enabled: Value = panel
        .admin(
            Method::POST,
            &format!("/api/plugins/sing-box/servers/{server}/enable"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(enabled["source"], "administrator");
    assert_eq!(enabled["read_only"], false);
    assert_eq!(enabled["installation"]["state"], "queued");
    assert_eq!(enabled["installation"]["target_rev"], 0);
    assert_eq!(enabled["installation"]["applied_rev"], 0);
    let scheduled: i64 = sqlx::query_scalar("SELECT dirty_at FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&pool)
        .await?;
    // Make a meaningful, already-due timestamp. Repeated enable must retain it.
    let due = scheduled - 6000;
    sqlx::query("UPDATE servers SET dirty_at=$2 WHERE id=$1")
        .bind(server)
        .bind(due)
        .execute(&pool)
        .await?;
    panel.enable_plugin(&cookie, server).await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT dirty_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        due
    );
    sinan_panel::plugins::singbox::publisher::publish_due(&panel.state).await?;
    let bundle: String = sqlx::query_scalar(
        "SELECT bundle FROM deployments WHERE server_id=$1 AND module='singbox'",
    )
    .bind(server)
    .fetch_one(&pool)
    .await?;
    let bundle: Value = serde_json::from_str(&bundle)?;
    let configuration: Value = serde_json::from_str(
        bundle["files"]["config.json"]
            .as_str()
            .context("native config")?,
    )?;
    assert_eq!(configuration["inbounds"], json!([]));
    assert_eq!(
        configuration["experimental"]["v2ray_api"]["listen"],
        "127.0.0.1:18085"
    );
    let pending = metadata(&panel, &cookie, server).await?;
    assert_eq!(pending["installation"]["state"], "pending");
    assert_eq!(pending["installation"]["target_rev"], 1);
    assert_eq!(pending["installation"]["applied_rev"], 0);
    panel.enable_plugin(&cookie, server).await?;
    assert_eq!(
        sqlx::query_scalar::<_, Option<i64>>("SELECT dirty_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        None
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_signed_runtime_is_visible_and_preparation_never_confirms_application(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "Signed installation")
        .await?;
    supported_online(&pool, server).await?;
    panel.enable_plugin(&cookie, server).await?;
    panel.publish_now().await?;
    let manifest_url = format!("{}/api/agent/v1/manifest", panel.base);
    let response = panel
        .client
        .get(&manifest_url)
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        response.json::<Value>().await?["error"]
            .as_str()
            .context("missing proof reason")?
            .contains("已验签")
    );
    let failure = metadata(&panel, &cookie, server).await?;
    assert_eq!(failure["installation"]["state"], "failed");
    assert!(
        failure["installation"]["reason"]
            .as_str()
            .context("installation reason")?
            .starts_with("清单准备失败：目标版本 1：")
    );
    let evidence: (i64, i64, bool) = sqlx::query_as("SELECT applied_rev,last_result_rev,healthy FROM server_module_status WHERE server_id=$1 AND module='singbox'")
        .bind(server).fetch_one(&pool).await?;
    assert_eq!(evidence, (0, 0, false));

    let binary = b"TEST_ONLY inert signed runtime fixture";
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
    let manifest: Value = panel
        .client
        .get(&manifest_url)
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(manifest["modules"]["singbox"]["artifact"]["proof"].is_object());
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?,
        None
    );
    let failure = ApplyResult {
        module: "singbox".into(),
        rev: 1,
        op_id: Uuid::new_v4(),
        status: ApplyStatus::Failed,
        healthy: false,
        error: Some("TEST_ONLY runtime did not start".into()),
    };
    sinan_panel::agent_api::record_apply_result(&panel.state, server, failure).await?;
    panel
        .client
        .get(&manifest_url)
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?,
        Some("TEST_ONLY runtime did not start".into())
    );
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "failed"
    );
    sinan_panel::agent_api::record_apply_result(
        &panel.state,
        server,
        ApplyResult {
            module: "singbox".into(),
            rev: 1,
            op_id: Uuid::new_v4(),
            status: ApplyStatus::Applied,
            healthy: true,
            error: None,
        },
    )
    .await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "ready"
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn installation_distinguishes_mode_offline_and_stale_preparation_error(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel
        .create_server(&cookie, "Monitor mode installation")
        .await?;
    panel.enable_plugin(&cookie, server).await?;
    panel.publish_now().await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "waiting_agent"
    );
    sqlx::query("UPDATE servers SET capabilities='[\"singbox\"]',last_seen=$2 WHERE id=$1")
        .bind(server)
        .bind(now_timestamp())
        .execute(&pool)
        .await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "waiting_agent"
    );
    sqlx::query("UPDATE servers SET capabilities=$2,last_seen=NULL WHERE id=$1")
        .bind(server)
        .bind(json!([
            "singbox",
            sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY
        ]))
        .execute(&pool)
        .await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "offline"
    );
    supported_online(&pool, server).await?;
    sinan_panel::agent_api::record_apply_result(
        &panel.state,
        server,
        ApplyResult {
            module: "singbox".into(),
            rev: 1,
            op_id: Uuid::new_v4(),
            status: ApplyStatus::Applied,
            healthy: true,
            error: None,
        },
    )
    .await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "ready"
    );
    sqlx::query("UPDATE servers SET last_seen=NULL WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "offline"
    );
    sqlx::query("UPDATE servers SET capabilities='[]',last_seen=$2 WHERE id=$1")
        .bind(server)
        .bind(now_timestamp())
        .execute(&pool)
        .await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "waiting_agent"
    );
    supported_online(&pool, server).await?;
    let info = json!({"arch":"unknown"});
    assert!(
        sinan_panel::plugins::singbox::agent::manifest_module(&panel.state, server, &info)
            .await
            .is_err()
    );
    assert_eq!(
        metadata(&panel, &cookie, server).await?["installation"]["state"],
        "failed"
    );
    sinan_panel::agent_api::record_apply_result(
        &panel.state,
        server,
        ApplyResult {
            module: "singbox".into(),
            rev: 1,
            op_id: Uuid::new_v4(),
            status: ApplyStatus::Failed,
            healthy: false,
            error: Some("TEST_ONLY original device error".into()),
        },
    )
    .await?;
    let node = id(&panel.create_node(&cookie, server, "New target").await?)?;
    let user = id(&panel.create_user(&cookie, "New target user").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.publish_now().await?;
    let pending = metadata(&panel, &cookie, server).await?;
    assert_eq!(pending["installation"]["target_rev"], 2);
    assert_eq!(pending["installation"]["state"], "pending");
    // The old preparation marker belongs to revision 1, not this new target.
    assert!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT error FROM singbox_installation WHERE server_id=$1"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?
        .context("preserved old marker")?
        .contains("目标版本 1：")
    );
    assert!(
        sinan_panel::plugins::singbox::agent::manifest_module(&panel.state, server, &info)
            .await
            .is_err()
    );
    let failed = metadata(&panel, &cookie, server).await?;
    assert_eq!(failed["installation"]["state"], "failed");
    assert!(
        failed["installation"]["reason"]
            .as_str()
            .context("new preparation failure")?
            .contains("目标版本 2：")
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?,
        Some("TEST_ONLY original device error".into())
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn authenticated_heartbeat_recovers_installation_after_lost_result_and_old_failure(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    for prior_failure in [false, true] {
        let (server, mut socket, _ack) = panel
            .authenticated_device(&cookie, "Checkpoint recovery")
            .await?;
        supported_online(&pool, server).await?;
        panel.enable_plugin(&cookie, server).await?;
        panel.publish_now().await?;
        assert_eq!(
            receive_envelope(&mut socket).await?.message_type,
            "manifest.changed"
        );
        if prior_failure {
            sinan_panel::agent_api::record_apply_result(
                &panel.state,
                server,
                ApplyResult {
                    module: "singbox".into(),
                    rev: 1,
                    op_id: Uuid::new_v4(),
                    status: ApplyStatus::Failed,
                    healthy: false,
                    error: Some("TEST_ONLY previous failed attempt".into()),
                },
            )
            .await?;
        }
        send_envelope(
            &mut socket,
            Envelope::new(
                "heartbeat",
                Heartbeat {
                    applied: [("singbox".into(), 1)].into(),
                    uptime_secs: 60,
                },
            )?,
        )
        .await?;
        // This hint is emitted only after the authenticated checkpoint commits.
        assert_eq!(
            receive_envelope(&mut socket).await?.message_type,
            "manifest.changed"
        );
        let evidence: (i64, i64, bool, Option<String>) = sqlx::query_as("SELECT applied_rev,last_result_rev,healthy,last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'")
            .bind(server).fetch_one(&pool).await?;
        assert_eq!(evidence.0, 1);
        assert_eq!(evidence.1, if prior_failure { 1 } else { 0 });
        assert!(evidence.2);
        assert_eq!(
            evidence.3,
            prior_failure.then(|| "TEST_ONLY previous failed attempt".into())
        );
        assert_eq!(
            metadata(&panel, &cookie, server).await?["installation"]["state"],
            "ready"
        );
    }
    Ok(())
}
