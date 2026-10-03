#![forbid(unsafe_code)]

mod business_support;
#[path = "diagnostics/chain_gate.rs"]
mod chain_gate;
#[path = "diagnostics/completion.rs"]
mod completion;
#[path = "diagnostics/modes.rs"]
mod modes;
#[path = "probe_support.rs"]
mod probe_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{agent_api, diagnostics, ip_quality};
use sinan_protocol::{Hello, HelloAck, Message, PROTOCOL_VERSION};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

async fn capable(panel: &TestPanel, server_id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE servers SET static_info=static_info || '{\"os\":\"linux\"}'::jsonb WHERE id=$1",
    )
    .bind(server_id)
    .execute(&panel.state.pool)
    .await?;
    agent_api::process_message(
        &panel.state,
        server_id,
        Message::Hello(Hello {
            agent_version: "diagnostic-test".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec![
                "diagnostic:nodequality".into(),
                "diagnostic:nodequality-modes".into(),
                sinan_protocol::DIAGNOSTIC_SECTIONS_CAPABILITY.into(),
                sinan_protocol::DIAGNOSTIC_SERVICE_CAPABILITY.into(),
                sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY.into(),
                sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY.into(),
                sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY.into(),
            ],
            applied: BTreeMap::new(),
        }),
    )
    .await
}

async fn fixture(panel: &TestPanel) -> Result<()> {
    let binary = b"fixed diagnostic fixture";
    let archive = release_fixture::archive("nodequality", binary)?;
    release_fixture::write(
        &panel.state.config.data_dir,
        "nodequality",
        diagnostics::PLUGIN_VERSION,
        "nodequality",
        &archive,
        binary,
        "tar.gz",
    )?;
    Ok(())
}

async fn update(
    panel: &TestPanel,
    ack: &HelloAck,
    id: &str,
    payload: Value,
) -> Result<reqwest::Response> {
    Ok(panel
        .client
        .post(format!("{}/api/agent/v1/diagnostics/{id}", panel.base))
        .bearer_auth(&ack.session_token)
        .json(&payload)
        .send()
        .await?)
}

#[sqlx::test(migrations = "./migrations")]
async fn diagnostic_queue_is_durable_deduplicated_and_device_scoped(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server_id, _socket, ack) = panel.authenticated_device(&cookie, "报告设备").await?;
    let (other_id, _other_socket, other_ack) =
        panel.authenticated_device(&cookie, "其他设备").await?;
    capable(&panel, server_id).await?;
    fixture(&panel).await?;
    let path = format!("/api/servers/{server_id}/node-quality/reports");
    let (first, second) = tokio::join!(
        panel.admin(Method::POST, &path, &cookie, Some(json!({"mode":"daily"}))),
        panel.admin(Method::POST, &path, &cookie, Some(json!({"mode":"daily"})))
    );
    let first = first?;
    let second = second?;
    let response = if first.status() == StatusCode::CREATED {
        assert_eq!(second.status(), StatusCode::CONFLICT);
        first
    } else {
        assert_eq!(first.status(), StatusCode::CONFLICT);
        assert_eq!(second.status(), StatusCode::CREATED);
        second
    };
    let record: Value = response.json().await?;
    let id = record["id"].as_str().unwrap();
    assert_eq!(record["status"], "queued");
    assert_eq!(
        record["job"]["options"],
        json!({"mode":"daily","environment_section":"true","ip_version":"both","network_mode":"low","upload_report":"false","daily_targets":"[]"})
    );
    assert!(record["job"]["expires_at"].as_i64().is_some());
    let queue: Value = panel
        .client
        .get(format!("{}/api/agent/v1/diagnostics", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(queue.as_array().unwrap().len(), 1);
    let other_queue: Value = panel
        .client
        .get(format!("{}/api/agent/v1/diagnostics", panel.base))
        .bearer_auth(&other_ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(other_queue, json!([]));
    assert_eq!(
        update(&panel, &other_ack, id, json!({"id":id,"status":"running"}))
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        update(&panel, &ack, id, json!({"id":id,"status":"running"}))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let final_update = json!({"id":id,"status":"succeeded","report":{"text":"完整本地报告","report_url":"https://nodequality.com/r/example"}});
    assert_eq!(
        update(&panel, &ack, id, final_update.clone())
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        update(&panel, &ack, id, final_update).await?.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        update(&panel, &ack, id, json!({"id":id,"status":"running"}))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        update(
            &panel,
            &ack,
            id,
            json!({"id":id,"status":"failed","error":"late failure"})
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    let view: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server_id}/node-quality"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(view["reports"][0]["status"], "succeeded");
    assert_eq!(view["reports"][0]["report"]["text"], "完整本地报告");
    assert!(view["plugin_ready"].as_bool().unwrap());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_jobs WHERE server_id=$1")
        .bind(server_id)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(count, 1);
    let fresh_state =
        sinan_panel::AppState::new(panel.state.pool.clone(), (*panel.state.config).clone()).await?;
    let persisted: Value =
        sqlx::query_scalar("SELECT report FROM diagnostic_jobs WHERE server_id=$1")
            .bind(server_id)
            .fetch_one(&fresh_state.pool)
            .await?;
    assert_eq!(persisted["text"], "完整本地报告");
    assert_ne!(server_id, other_id);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn expiry_preserves_late_durable_reports_and_deleted_servers_cancel_work(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server_id, mut socket, ack) = panel.authenticated_device(&cookie, "重连设备").await?;
    capable(&panel, server_id).await?;
    fixture(&panel).await?;
    let path = format!("/api/servers/{server_id}/node-quality/reports");
    let record: Value = panel
        .admin(Method::POST, &path, &cookie, Some(json!({"mode":"daily"})))
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = record["id"].as_str().unwrap();
    sqlx::query("UPDATE diagnostic_jobs SET expires_at=0 WHERE server_id=$1")
        .bind(server_id)
        .execute(&panel.state.pool)
        .await?;
    diagnostics::expire(&panel.state).await?;
    assert_eq!(
        update(&panel, &ack, id, json!({"id":id,"status":"running"}))
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let before: String =
        sqlx::query_scalar("SELECT status FROM diagnostic_jobs WHERE server_id=$1")
            .bind(server_id)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(before, "failed");
    assert_eq!(
        update(
            &panel,
            &ack,
            id,
            json!({"id":id,"status":"succeeded","report":{"text":"断网期间完成，重连后回传"}})
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    let restored: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server_id}/node-quality"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(restored["reports"][0]["status"], "succeeded");
    assert_eq!(
        restored["reports"][0]["report"]["text"],
        "断网期间完成，重连后回传"
    );
    let new: Value = panel
        .admin(
            Method::POST,
            &path,
            &cookie,
            Some(json!({"mode":"daily","ip_version":"ipv6"})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(new["job"]["options"]["upload_report"], "false");
    // This assertion exercises offline deletion; online deletion now requires retirement.
    socket.close(None).await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while panel
            .state
            .connections
            .read()
            .await
            .contains_key(&server_id)
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("/api/servers/{server_id}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_jobs WHERE server_id=$1 AND status IN ('queued','running')").bind(server_id).fetch_one(&panel.state.pool).await?;
    assert_eq!(active, 0);
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/agent/v1/diagnostics", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn report_readiness_and_quality_refresh_require_auth_and_preserve_unknown(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server_id, _socket, ack) = panel.authenticated_device(&cookie, "旧设备").await?;
    let base = format!("/api/servers/{server_id}/node-quality");
    assert_eq!(
        panel
            .client
            .get(format!("{}{base}", panel.base))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .post(format!("{}{base}/refresh", panel.base))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("{base}/reports"),
                &cookie,
                Some(json!({"mode":"daily"}))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    capable(&panel, server_id).await?;
    let missing: Value = panel
        .admin(Method::GET, &base, &cookie, None)
        .await?
        .json()
        .await?;
    assert!(!missing["plugin_ready"].as_bool().unwrap());
    assert!(missing["plugin_reason"].as_str().unwrap().contains("制品"));
    fixture(&panel).await?;
    sqlx::query("UPDATE servers SET static_info=static_info || $2 WHERE id=$1")
        .bind(server_id)
        .bind(json!({"ip_addresses":["192.0.2.1","2001:db8::1"]}))
        .execute(&panel.state.pool)
        .await?;
    let refreshed: Value = panel
        .admin(Method::POST, &format!("{base}/refresh"), &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(refreshed.as_array().unwrap().len(), 2);
    assert!(refreshed.as_array().unwrap().iter().all(|entry| {
        entry["status"] == "failed"
            && entry["databases"]
                .as_array()
                .unwrap()
                .iter()
                .all(|database| {
                    database["fields"] == json!([])
                        && database["error"].as_str().unwrap().contains("公网")
                        && database["provider"] == "check-place"
                        && database["target_ip"] == entry["ip"]
                        && database["error_kind"] == "not_public"
                        && database["attempted_at"].is_i64()
                        && database["elapsed_ms"].is_u64()
                        && database["http_status"].is_null()
                })
    }));
    let persisted = ip_quality::cached(&panel.state, server_id, &["192.0.2.1".into()]).await?;
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].status, "failed");
    assert!(persisted[0].databases.iter().all(|entry| {
        entry.provider == "check-place"
            && entry.target_ip.as_deref() == Some("192.0.2.1")
            && entry.error_kind == Some(ip_quality::QueryErrorKind::NotPublic)
            && entry.attempted_at.is_some()
            && entry.elapsed_ms.is_some()
    }));
    assert_eq!(
        panel
            .admin(Method::POST, &format!("{base}/refresh"), &cookie, None)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let record: Value = panel
        .admin(
            Method::POST,
            &format!("{base}/reports"),
            &cookie,
            Some(json!({"mode":"daily"})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = record["id"].as_str().unwrap();
    assert_eq!(update(&panel, &ack, id, json!({"id":id,"status":"succeeded","report":{"text":"报告","report_url":"https://evil.example.com/x"}})).await?.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        update(&panel, &ack, id, json!({"id":id,"status":"succeeded"}))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        update(
            &panel,
            &ack,
            id,
            json!({"id":id,"status":"succeeded","report":{"text":" ","report_url":null}})
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        update(
            &panel,
            &ack,
            id,
            json!({"id":id,"status":"succeeded","report":{"text":"本地报告","report_url":null}})
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    Ok(())
}

#[path = "diagnostics/cancellation.rs"]
mod cancellation;
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_quality_refresh_admits_one_request_and_keeps_unknown(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel.create_server(&cookie, "刷新并发夹具").await?;
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server_id)
        .bind(json!({"ip_addresses":["192.0.2.1"]}))
        .execute(&panel.state.pool)
        .await?;
    let path = format!("/api/servers/{server_id}/node-quality/refresh");
    let (first, second) = tokio::join!(
        panel.admin(Method::POST, &path, &cookie, None),
        panel.admin(Method::POST, &path, &cookie, None)
    );
    let statuses = [first?.status(), second?.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&status| status == StatusCode::CONFLICT)
            .count(),
        1
    );
    let quality = ip_quality::cached(&panel.state, server_id, &["192.0.2.1".into()]).await?;
    assert_eq!(quality.len(), 1);
    assert_eq!(quality[0].provider, "check-place");
    assert_eq!(quality[0].last_success_at, None);
    assert!(
        quality[0]
            .databases
            .iter()
            .all(|entry| entry.fields.is_empty() && !entry.historical)
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn ip_and_nodequality_views_are_independent_and_legacy_routes_preserve_shape(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel.create_server(&cookie, "分离视图夹具").await?;
    let ip_path = format!("/api/servers/{server_id}/ip-quality");
    let legacy_path = format!("/api/servers/{server_id}/node-quality");
    let report_path = format!("{legacy_path}/reports");
    for (method, path) in [
        (Method::GET, ip_path.clone()),
        (Method::POST, format!("{ip_path}/refresh")),
        (Method::GET, report_path.clone()),
        (Method::GET, legacy_path.clone()),
        (Method::POST, format!("{legacy_path}/refresh")),
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
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server_id)
        .bind(json!({"ip_addresses":["192.0.2.1"]}))
        .execute(&panel.state.pool)
        .await?;
    let report_id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    let old_job = json!({"options":{"ip_version":"ipv4","network_mode":"low"}});
    let old_report = json!({"text":"拆分前的历史报告","report_url":null});
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,job,status,report,created_at,updated_at,expires_at) VALUES($1,$2,$3,'succeeded',$4,$5,$5,$5+60)")
        .bind(report_id).bind(server_id).bind(&old_job).bind(&old_report).bind(now).execute(&panel.state.pool).await?;
    let refreshed: Value = panel
        .admin(Method::POST, &format!("{ip_path}/refresh"), &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(refreshed[0]["status"], "failed");
    let ip: Value = panel
        .admin(Method::GET, &ip_path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(ip["ip_addresses"], json!(["192.0.2.1"]));
    assert_eq!(ip["public_ip_addresses"], json!([]));
    assert_eq!(ip["private_ip_addresses"], ip["ip_addresses"]);
    assert_eq!(ip["quality"], refreshed);
    assert!(ip.get("reports").is_none() && ip.get("plugin_ready").is_none());
    let node: Value = panel
        .admin(Method::GET, &report_path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(node["plugin_ready"], false);
    assert_eq!(node["cancel_supported"], false);
    assert!(node.get("quality").is_none() && node.get("ip_addresses").is_none());
    assert_eq!(node["reports"][0]["id"], report_id.to_string());
    assert_eq!(node["reports"][0]["job"], old_job);
    assert_eq!(node["reports"][0]["report"], old_report);
    let legacy: Value = panel
        .admin(Method::GET, &legacy_path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    for (key, value) in ip
        .as_object()
        .unwrap()
        .iter()
        .chain(node.as_object().unwrap())
    {
        if key == "proxy_activity" {
            for field in ["state", "reason", "last_positive_at"] {
                assert_eq!(legacy[key][field], value[field]);
            }
            assert!(
                legacy[key]["checked_at"].as_i64().unwrap()
                    >= value["checked_at"].as_i64().unwrap()
            );
        } else {
            assert_eq!(&legacy[key], value);
        }
    }
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("{legacy_path}/refresh"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    // A damaged IP cache must not prevent reading already completed reports.
    sqlx::query("UPDATE server_ip_quality SET payload=$2 WHERE server_id=$1")
        .bind(server_id)
        .bind(json!("malformed fixture cache"))
        .execute(&panel.state.pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::GET, &ip_path, &cookie, None)
            .await?
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let readable: Value = panel
        .admin(Method::GET, &report_path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(readable["reports"][0]["report"], old_report);
    sqlx::query("UPDATE servers SET deleted_at=$2 WHERE id=$1")
        .bind(server_id)
        .bind(now)
        .execute(&panel.state.pool)
        .await?;
    for path in [&ip_path, &report_path, &legacy_path] {
        assert_eq!(
            panel
                .admin(Method::GET, path, &cookie, None)
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}
