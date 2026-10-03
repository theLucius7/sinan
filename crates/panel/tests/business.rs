#![forbid(unsafe_code)]

mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use business_support::{TestPanel, id, receive_envelope, send_envelope};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{agent_api, publisher};
use sinan_protocol::{ApplyResult, ApplyStatus, Envelope, Heartbeat};
use sqlx::{PgPool, Row};
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

async fn applied(panel: &TestPanel, server_id: i64, rev: u64) -> Result<()> {
    agent_api::record_apply_result(
        &panel.state,
        server_id,
        ApplyResult {
            module: "singbox".into(),
            rev,
            op_id: Uuid::new_v4(),
            status: ApplyStatus::Applied,
            healthy: true,
            error: None,
        },
    )
    .await
}

async fn latest_revision(pool: &PgPool, server_id: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(MAX(rev),0) FROM deployments WHERE server_id=$1 AND module='singbox'",
    )
    .bind(server_id)
    .fetch_one(pool)
    .await?)
}

async fn links(panel: &TestPanel, token: &str) -> Result<String> {
    let response = panel
        .client
        .get(format!("{}/sub/{token}?format=links", panel.base))
        .send()
        .await?
        .error_for_status()?;
    anyhow::ensure!(
        response.headers()[reqwest::header::CACHE_CONTROL] == "no-store",
        "subscription must not be cached"
    );
    Ok(String::from_utf8(STANDARD.decode(response.text().await?)?)?)
}

#[sqlx::test(migrations = "./migrations")]
async fn business_routes_require_admin_and_node_ports_are_atomic(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    for (method, path, body) in [
        (Method::GET, "/api/plugins/sing-box/nodes", None),
        (Method::GET, "/api/plugins/sing-box/users", None),
        (Method::GET, "/api/plugins/sing-box/users/1/accesses", None),
        (
            Method::GET,
            "/api/plugins/sing-box/servers/1/deployments",
            None,
        ),
        (
            Method::POST,
            "/api/plugins/sing-box/nodes",
            Some(
                json!({"name":"Unauthorized", "server_id":1, "public_host":"proxy.example.com", "sni":"www.example.com"}),
            ),
        ),
        (
            Method::PATCH,
            "/api/plugins/sing-box/nodes/1",
            Some(json!({"name":"Unauthorized"})),
        ),
        (Method::DELETE, "/api/plugins/sing-box/nodes/1", None),
        (
            Method::POST,
            "/api/plugins/sing-box/users",
            Some(json!({"name":"Unauthorized"})),
        ),
        (
            Method::PATCH,
            "/api/plugins/sing-box/users/1",
            Some(json!({"name":"Unauthorized"})),
        ),
        (Method::DELETE, "/api/plugins/sing-box/users/1", None),
        (
            Method::POST,
            "/api/plugins/sing-box/users/1/accesses",
            Some(json!({"node_id":1})),
        ),
        (
            Method::DELETE,
            "/api/plugins/sing-box/users/1/accesses/1",
            None,
        ),
    ] {
        let request = panel
            .client
            .request(method, format!("{}{path}", panel.base));
        let response = match body {
            Some(body) => request.json(&body),
            None => request,
        }
        .send()
        .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Concurrent ports").await?;
    let names: Vec<_> = (0..8).map(|index| format!("Node {index}")).collect();
    let nodes = futures_util::future::join_all(
        names
            .iter()
            .map(|name| panel.create_node(&cookie, server, name)),
    )
    .await;
    let mut ports = BTreeSet::new();
    let mut node_ids = Vec::new();
    for node in nodes {
        let node = node?;
        assert!(node.get("private_key").is_none());
        assert_eq!(node["protocol"], "vless-reality");
        assert_eq!(node["public_key"].as_str().context("public key")?.len(), 43);
        assert_eq!(node["short_id"].as_str().context("short id")?.len(), 8);
        assert!(ports.insert(node["port"].as_i64().context("node port")?));
        node_ids.push(id(&node)?);
    }
    assert_eq!(ports, (20000..20008).collect());
    let other = panel.create_server(&cookie, "Independent ports").await?;
    assert_eq!(
        panel.create_node(&cookie, other, "Other node").await?["port"],
        20000
    );
    let node = node_ids[0];
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &format!("/api/plugins/sing-box/nodes/{node}"),
                &cookie,
                Some(json!({"sni":"127.0.0.1"}))
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &format!("/api/plugins/sing-box/nodes/{node}"),
                &cookie,
                Some(json!({"public_host":"https://proxy.example.com/path"}))
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    panel
        .admin(
            Method::PATCH,
            &format!("/api/plugins/sing-box/nodes/{node}"),
            &cookie,
            Some(json!({"name":"Renamed"})),
        )
        .await?
        .error_for_status()?;
    let listed: Value = panel
        .admin(Method::GET, "/api/plugins/sing-box/nodes", &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(!listed.to_string().contains("private_key"));
    assert!(listed.to_string().contains("Renamed"));
    let user = panel.create_user(&cookie, "User").await?;
    let user_id = id(&user)?;
    let access = panel.grant(&cookie, user_id, node).await?;
    assert_eq!(access, panel.grant(&cookie, user_id, node).await?);
    assert_eq!(access["stat_name"], format!("u{user_id}_n{node}"));
    panel
        .admin(
            Method::PATCH,
            &format!("/api/plugins/sing-box/users/{user_id}"),
            &cookie,
            Some(json!({"name":"Renamed user"})),
        )
        .await?
        .error_for_status()?;
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("/api/plugins/sing-box/nodes/{node}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(panel.grant(&cookie, user_id, node).await.is_err());
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("/api/plugins/sing-box/users/{user_id}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        panel
            .client
            .get(format!(
                "{}/sub/{}",
                panel.base,
                user["subscription_token"].as_str().unwrap()
            ))
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn publication_debounces_and_deduplicates_native_configurations(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, mut socket, _) = panel.authenticated_device(&cookie, "Publisher").await?;
    let node = panel.create_node(&cookie, server, "Node").await?;
    let user = panel.create_user(&cookie, "User").await?;
    panel.grant(&cookie, id(&user)?, id(&node)?).await?;
    panel.prepare_deployment_preflights().await?;
    publisher::publish_due(&panel.state).await?;
    assert_eq!(latest_revision(&pool, server).await?, 0);
    let dirty: i64 = sqlx::query_scalar("SELECT dirty_at FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&pool)
        .await?;
    assert!(dirty > 0);
    sqlx::query("UPDATE servers SET dirty_at=FLOOR(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint-4000 WHERE id=$1")
        .bind(server).execute(&pool).await?;
    publisher::publish_due(&panel.state).await?;
    assert_eq!(latest_revision(&pool, server).await?, 0);
    sqlx::query("UPDATE servers SET dirty_at=0 WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    let (first, second) = tokio::join!(
        publisher::publish_due(&panel.state),
        publisher::publish_due(&panel.state)
    );
    first?;
    second?;
    assert_eq!(latest_revision(&pool, server).await?, 1);
    assert_eq!(
        receive_envelope(&mut socket).await?.message_type,
        "manifest.changed"
    );
    let row = sqlx::query(
        "SELECT bundle,bundle_sha256,source_json FROM deployments WHERE server_id=$1 AND rev=1",
    )
    .bind(server)
    .fetch_one(&pool)
    .await?;
    let bundle: String = row.get("bundle");
    use sha2::{Digest, Sha256};
    assert_eq!(
        row.get::<String, _>("bundle_sha256"),
        format!("{:x}", Sha256::digest(bundle.as_bytes()))
    );
    assert!(bundle.contains(&format!("u{}_n{}", id(&user)?, id(&node)?)));
    applied(&panel, server, 1).await?;
    let node_id = id(&node)?;
    panel
        .admin(
            Method::PATCH,
            &format!("/api/plugins/sing-box/nodes/{node_id}"),
            &cookie,
            Some(json!({"name":"Updated display", "public_host":"updated.example.com"})),
        )
        .await?
        .error_for_status()?;
    panel.publish_now().await?;
    assert_eq!(latest_revision(&pool, server).await?, 1);
    assert!(
        links(&panel, user["subscription_token"].as_str().unwrap())
            .await?
            .contains("updated.example.com")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receive_envelope(&mut socket))
            .await
            .is_err()
    );
    panel
        .admin(
            Method::PATCH,
            &format!("/api/plugins/sing-box/nodes/{node_id}"),
            &cookie,
            Some(json!({"sni":"changed.example.com"})),
        )
        .await?
        .error_for_status()?;
    panel.publish_now().await?;
    assert_eq!(latest_revision(&pool, server).await?, 2);
    assert_eq!(
        receive_envelope(&mut socket).await?.message_type,
        "manifest.changed"
    );
    let status: Value = panel
        .admin(
            Method::GET,
            &format!("/api/plugins/sing-box/servers/{server}/deployments"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(status["status"]["target_rev"], 2);
    assert_eq!(status["status"]["applied_rev"], 1);
    assert_eq!(status["history"].as_array().unwrap().len(), 2);
    assert!(!status.to_string().contains("private_key"));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn subscriptions_use_applied_snapshots_and_current_authorization(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Subscription server").await?;
    let first_node = panel.create_node(&cookie, server, "First node").await?;
    let second_node = panel.create_node(&cookie, server, "Second node").await?;
    let first_user = panel.create_user(&cookie, "First user").await?;
    let second_user = panel.create_user(&cookie, "Second user").await?;
    let user_id = id(&first_user)?;
    let node_id = id(&first_node)?;
    let token = first_user["subscription_token"].as_str().unwrap();
    let other_token = second_user["subscription_token"].as_str().unwrap();
    assert_ne!(token, other_token);
    assert!(links(&panel, token).await?.is_empty());
    assert!(
        panel
            .client
            .get(format!("{}/sub/{token}?format=singbox", panel.base))
            .send()
            .await?
            .status()
            .is_client_error()
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/sub/unknown-token", panel.base))
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    let first_access = panel.grant(&cookie, user_id, node_id).await?;
    let second_access = panel
        .grant(&cookie, id(&second_user)?, id(&second_node)?)
        .await?;
    panel.publish_now().await?;
    assert!(links(&panel, token).await?.is_empty());
    applied(&panel, server, 1).await?;
    let own = links(&panel, token).await?;
    assert!(own.contains(first_access["uuid"].as_str().unwrap()));
    assert!(!own.contains(second_access["uuid"].as_str().unwrap()));
    let other = links(&panel, other_token).await?;
    assert!(other.contains(second_access["uuid"].as_str().unwrap()));
    assert!(!other.contains(first_access["uuid"].as_str().unwrap()));
    let client: Value = panel
        .client
        .get(format!("{}/sub/{token}?format=singbox", panel.base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let encoded = client.to_string();
    assert!(encoded.contains(first_access["uuid"].as_str().unwrap()));
    assert!(!encoded.contains(second_access["uuid"].as_str().unwrap()));
    assert!(!encoded.contains("private_key"));
    assert_eq!(client["inbounds"][0]["listen"], "127.0.0.1");
    panel
        .admin(
            Method::PATCH,
            &format!("/api/plugins/sing-box/nodes/{node_id}"),
            &cookie,
            Some(json!({"sni":"new.example.com"})),
        )
        .await?
        .error_for_status()?;
    panel.publish_now().await?;
    let pending = links(&panel, token).await?;
    assert!(pending.contains("sni=www.example.com"));
    assert!(!pending.contains("sni=new.example.com"));
    applied(&panel, server, 2).await?;
    assert!(links(&panel, token).await?.contains("sni=new.example.com"));
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("/api/plugins/sing-box/users/{user_id}/accesses/{node_id}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(links(&panel, token).await?.is_empty());
    let regrant = panel.grant(&cookie, user_id, node_id).await?;
    assert_ne!(regrant["uuid"], first_access["uuid"]);
    assert_eq!(regrant["stat_name"], first_access["stat_name"]);
    assert!(links(&panel, token).await?.is_empty());
    panel.publish_now().await?;
    let revision = latest_revision(&pool, server).await?;
    applied(&panel, server, revision as u64).await?;
    let current = links(&panel, token).await?;
    assert!(current.contains(regrant["uuid"].as_str().unwrap()));
    assert!(!current.contains(first_access["uuid"].as_str().unwrap()));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn apply_results_are_monotonic_and_heartbeat_repairs_lost_results(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, mut socket, _) = panel.authenticated_device(&cookie, "Status repair").await?;
    let node = panel.create_node(&cookie, server, "Node").await?;
    let user = panel.create_user(&cookie, "User").await?;
    panel.grant(&cookie, id(&user)?, id(&node)?).await?;
    panel.publish_now().await?;
    receive_envelope(&mut socket).await?;
    let first = ApplyResult {
        module: "singbox".into(),
        rev: 1,
        op_id: Uuid::new_v4(),
        status: ApplyStatus::Applied,
        healthy: true,
        error: None,
    };
    // A lost result leaves the panel behind although the Agent reports the target revision.
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
    assert_eq!(
        receive_envelope(&mut socket).await?.message_type,
        "manifest.changed"
    );
    let repaired: i64 = sqlx::query_scalar(
        "SELECT applied_rev FROM server_module_status WHERE server_id=$1 AND module='singbox'",
    )
    .bind(server)
    .fetch_one(&pool)
    .await?;
    assert_eq!(repaired, 1);
    agent_api::record_apply_result(&panel.state, server, first.clone()).await?;
    panel
        .admin(
            Method::PATCH,
            &format!("/api/plugins/sing-box/nodes/{}", id(&node)?),
            &cookie,
            Some(json!({"sni":"next.example.com"})),
        )
        .await?
        .error_for_status()?;
    panel.publish_now().await?;
    receive_envelope(&mut socket).await?;
    send_envelope(
        &mut socket,
        Envelope::new(
            "heartbeat",
            Heartbeat {
                applied: [("singbox".into(), 2)].into(),
                uptime_secs: 90,
            },
        )?,
    )
    .await?;
    assert_eq!(
        receive_envelope(&mut socket).await?.message_type,
        "manifest.changed"
    );
    agent_api::record_apply_result(
        &panel.state,
        server,
        ApplyResult {
            status: ApplyStatus::Failed,
            healthy: false,
            error: Some("stale failure".into()),
            ..first.clone()
        },
    )
    .await?;
    let repaired = sqlx::query("SELECT applied_rev,healthy,last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'")
        .bind(server).fetch_one(&pool).await?;
    assert_eq!(repaired.get::<i64, _>("applied_rev"), 2);
    assert!(repaired.get::<bool, _>("healthy"));
    assert!(repaired.get::<Option<String>, _>("last_error").is_none());
    agent_api::record_apply_result(&panel.state, server, first).await?;
    applied(&panel, server, 2).await?;
    let status = sqlx::query("SELECT applied_rev,last_result_rev,healthy,last_error FROM server_module_status WHERE server_id=$1 AND module='singbox'").bind(server).fetch_one(&pool).await?;
    assert_eq!(status.get::<i64, _>("applied_rev"), 2);
    assert_eq!(status.get::<i64, _>("last_result_rev"), 2);
    assert!(status.get::<bool, _>("healthy"));
    assert!(status.get::<Option<String>, _>("last_error").is_none());
    let unauthorized = ApplyResult {
        module: "singbox".into(),
        rev: 3,
        op_id: Uuid::new_v4(),
        status: ApplyStatus::Applied,
        healthy: true,
        error: None,
    };
    assert!(
        agent_api::record_apply_result(&panel.state, server, unauthorized)
            .await
            .is_err()
    );
    Ok(())
}
