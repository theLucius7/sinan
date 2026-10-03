#![forbid(unsafe_code)]
mod business_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::{TestPanel, id};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;

const ROOT: &str = "/api/plugins/sing-box";

async fn patch(panel: &TestPanel, cookie: &str, node: i64, body: Value) -> Result<Value> {
    Ok(panel
        .admin(
            Method::PATCH,
            &format!("{ROOT}/nodes/{node}"),
            cookie,
            Some(body),
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[sqlx::test]
async fn settings_preserve_secrets_validate_atomically_and_pause_without_revoking_grants(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Protocols").await?;
    panel.enable_plugin(&cookie, server).await?;
    let node: Value = panel.admin(Method::POST, &format!("{ROOT}/nodes"), &cookie, Some(json!({
        "name":"HY2", "server_id":server,"port":20443,"public_host":"proxy.example.com","sni":"proxy.example.com",
        "protocol_config":{"type":"hysteria2","tls":{"mode":"acme","email":"admin@example.com","challenge":"http-01"}},
        "settings":{"listen":"0.0.0.0","public_port":443,"hysteria2":{"obfs_enabled":true,"up_mbps":80,"down_mbps":40}}
    }))).await?.error_for_status()?.json().await?;
    let node = id(&node)?;
    let stored: Value = sqlx::query_scalar("SELECT settings FROM nodes WHERE id=$1")
        .bind(node)
        .fetch_one(&pool)
        .await?;
    let secret = stored["hysteria2"]["obfs_password"].as_str().unwrap();
    assert!(secret.len() >= 32);
    let current = patch(&panel, &cookie, node, json!({"name":"Renamed"})).await?;
    assert_eq!(current["settings"]["public_port"], 443);
    assert_eq!(current["settings"]["hysteria2"]["obfs_enabled"], true);
    assert!(!current.to_string().contains(secret));
    assert!(
        current["settings"]["hysteria2"]
            .get("obfs_password")
            .is_none()
    );
    patch(&panel, &cookie, node, json!({"settings":{"hysteria2":{"obfs_enabled":true,"obfs_password":"","up_mbps":80,"down_mbps":40}}})).await?;
    let preserved: Value = sqlx::query_scalar("SELECT settings FROM nodes WHERE id=$1")
        .bind(node)
        .fetch_one(&pool)
        .await?;
    assert_eq!(stored, preserved);
    for settings in [
        json!({"public_port":0}),
        json!({"hysteria2":{"obfs_enabled":true,"up_mbps":10}}),
        json!({"listen":"invalid"}),
    ] {
        let response = panel
            .admin(
                Method::PATCH,
                &format!("{ROOT}/nodes/{node}"),
                &cookie,
                Some(json!({"name":"Should rollback", "settings":settings})),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let current: Value = panel
        .admin(Method::GET, &format!("{ROOT}/nodes/{node}"), &cookie, None)
        .await?
        .json()
        .await?;
    assert_eq!(current["name"], "Renamed");
    let user = panel.create_user(&cookie, "Client").await?;
    let uid = id(&user)?;
    let granted = panel.grant(&cookie, uid, node).await?;
    panel.publish_now().await?;
    sqlx::query("UPDATE server_module_status SET applied_rev=target_rev,healthy=TRUE")
        .execute(&pool)
        .await?;
    let url = format!(
        "{}?format=singbox",
        user["subscription_url"].as_str().unwrap()
    );
    let client: Value = panel
        .client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(client["outbounds"][1]["server_port"], 443);
    assert_eq!(client["outbounds"][1]["obfs"]["password"], secret);
    patch(&panel, &cookie, node, json!({"enabled":false})).await?;
    assert_eq!(
        panel.client.get(&url).send().await?.status(),
        StatusCode::CONFLICT
    );
    let grants: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM accesses WHERE node_id=$1 AND user_id=$2")
            .bind(node)
            .bind(uid)
            .fetch_one(&pool)
            .await?;
    assert_eq!(grants, 1);
    panel.publish_now().await?;
    let bundle: String = sqlx::query_scalar(
        "SELECT bundle FROM deployments WHERE server_id=$1 ORDER BY rev DESC LIMIT 1",
    )
    .bind(server)
    .fetch_one(&pool)
    .await?;
    let bundle: sinan_protocol::Bundle = serde_json::from_str(&bundle)?;
    let native: Value = serde_json::from_str(&bundle.files["config.json"])?;
    assert!(native["inbounds"].as_array().unwrap().is_empty());
    patch(
        &panel,
        &cookie,
        node,
        json!({"enabled":true,"settings":{"public_port":null}}),
    )
    .await?;
    panel.publish_now().await?;
    sqlx::query("UPDATE server_module_status SET applied_rev=target_rev,healthy=TRUE")
        .execute(&pool)
        .await?;
    let client: Value = panel
        .client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(client["outbounds"][1]["server_port"], 20443);
    assert_eq!(client["outbounds"][1]["obfs"]["password"], secret);
    let accesses: Value = panel
        .admin(
            Method::GET,
            &format!("{ROOT}/users/{uid}/accesses"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(accesses[0]["uuid"], granted["uuid"]);
    let cleared = patch(
        &panel,
        &cookie,
        node,
        json!({"settings":{"hysteria2":{"obfs_enabled":false}}}),
    )
    .await?;
    assert_eq!(cleared["settings"]["hysteria2"]["obfs_enabled"], false);
    Ok(())
}

#[sqlx::test]
async fn deployment_checks_distinguish_pending_unenrolled_and_missing_artifacts(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Deployment").await?;
    panel.create_node(&cookie, server, "Reality").await?;
    let path = format!("{ROOT}/servers/{server}/deployments");
    for (method, path) in [
        (Method::GET, path.clone()),
        (Method::POST, format!("{path}/check")),
    ] {
        assert_eq!(
            panel
                .client
                .request(method, format!("{}{path}", panel.base))
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let progress: Value = panel
        .admin(Method::GET, &path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(progress["pending"], true);
    assert_eq!(progress["enabled_nodes"], 1);
    assert_eq!(progress["authorized_nodes"], 0);
    let check = format!("{path}/check");
    let result: Value = panel
        .admin(Method::POST, &check, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(result["ready"], false);
    assert!(
        result["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["passed"] == false)
    );
    sqlx::query("UPDATE servers SET device_public_key='fixture',last_seen=$2,capabilities='[\"singbox\"]',static_info='{\"arch\":\"amd64\",\"os\":\"linux\",\"libc\":\"musl\"}' WHERE id=$1").bind(server).bind(sinan_protocol::now_timestamp()).execute(&pool).await?;
    let result: Value = panel
        .admin(Method::POST, &check, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(result["ready"], false);
    assert!(
        result["checks"].as_array().unwrap()[..3]
            .iter()
            .all(|item| item["passed"] == true)
    );
    assert_eq!(result["checks"][3]["passed"], false);
    assert_eq!(result["checks"][3]["name"], "制品验签能力");
    assert_eq!(result["checks"][4]["passed"], false);
    assert!(
        result["checks"][4]["detail"]
            .as_str()
            .unwrap()
            .contains("缺少")
    );
    assert!(!result.to_string().contains("fixture"));
    panel.publish_now().await?;
    let progress: Value = panel
        .admin(Method::GET, &path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(progress["pending"], false);
    assert!(progress["status"]["target_rev"].as_i64().unwrap() > 0);
    assert_eq!(progress["status"]["applied_rev"], 0);
    Ok(())
}

#[sqlx::test]
async fn signed_runtime_cannot_make_an_agent_without_signature_support_ready(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "Signature readiness")
        .await?;
    panel.enable_plugin(&cookie, server).await?;
    let binary = b"TEST_ONLY inert signed readiness runtime";
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
    let check = format!("{ROOT}/servers/{server}/deployments/check");
    for (capabilities, expected) in [
        (json!(["singbox"]), false),
        (
            json!([
                "singbox",
                sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY
            ]),
            true,
        ),
    ] {
        sqlx::query("UPDATE servers SET capabilities=$2,last_seen=$3 WHERE id=$1")
            .bind(server)
            .bind(capabilities)
            .bind(sinan_protocol::now_timestamp())
            .execute(&pool)
            .await?;
        let result: Value = panel
            .admin(Method::POST, &check, &cookie, None)
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(result["ready"], expected);
        let checks = result["checks"].as_array().unwrap();
        let signature = checks
            .iter()
            .find(|check| check["name"] == "制品验签能力")
            .unwrap();
        assert_eq!(signature["passed"], expected);
        assert!(
            checks
                .iter()
                .all(|check| { check["name"] == "制品验签能力" || check["passed"] == true })
        );
        // Exercise the actual authenticated manifest capability gate too.
        let manifest = panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?;
        assert_eq!(
            manifest.status(),
            if expected {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            }
        );
        if !expected {
            assert!(manifest.text().await?.contains("尚不支持制品验签"));
        }
    }
    Ok(())
}
