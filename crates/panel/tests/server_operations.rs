#![forbid(unsafe_code)]
mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{notifications, server_traffic, servers::Server};
use sinan_protocol::now_timestamp;
use sqlx::PgPool;

fn preferences(public: bool) -> Value {
    json!({"public_dashboard":public,"offline_alerts":true,"offline_minutes":2,"telegram_enabled":false,"telegram_chat_id":""})
}

#[sqlx::test]
async fn fleet_asset_and_access_changes_reject_concurrent_stale_forms(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let id = panel
        .create_server(&cookie, "TEST_ONLY fleet form concurrency")
        .await?;
    let path = format!("/api/servers/{id}/fleet");
    let original: Value = panel
        .admin(Method::GET, &path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let body = json!({"asset":{"provider":"TEST_ONLY provider first"},"policy":original["policy"],"expected_digest":original["digest"]});
    panel
        .admin(Method::PUT, &path, &cookie, Some(body))
        .await?
        .error_for_status()?;
    let stale = json!({"asset":{"provider":"TEST_ONLY stale overwrite"},"policy":original["policy"],"expected_digest":original["digest"]});
    assert_eq!(
        panel
            .admin(Method::PUT, &path, &cookie, Some(stale))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let current: Value = panel
        .admin(Method::GET, &path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(current["asset"]["provider"], "TEST_ONLY provider first");
    assert_ne!(current["digest"], original["digest"]);
    let policy: sinan_protocol::fleet::AccessPolicy =
        serde_json::from_value(current["policy"].clone())?;
    assert!(!policy.runtime_inspection);
    Ok(())
}

#[sqlx::test]
async fn public_dashboard_is_opt_in_and_never_exposes_hidden_servers_or_private_fields(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let visible = panel.create_server(&cookie, "公开设备").await?;
    let hidden = panel.create_server(&cookie, "隐藏设备").await?;
    for id in [visible, hidden] {
        sqlx::query("UPDATE servers SET device_public_key=$2,static_info=$3,asset_settings=$4,latest_metrics=$5 WHERE id=$1")
            .bind(id).bind(format!("TEST_ONLY_KEY_{id}"))
            .bind(json!({"hostname":"PRIVATE_HOST","ip_addresses":["192.0.2.1"],"cpu_cores":4}))
            .bind(json!({"hidden":id==hidden,"price":"12.00","agent_mirror":"https://mirror.example.com","region":"JP"}))
            .bind(json!({"cpu_percent":10,"network_interfaces":{"PRIVATE_INTERFACE":{"transmitted_bytes":123}},"disks":[{"mount_point":"PRIVATE_PATH"}]}))
            .execute(&panel.state.pool).await?;
    }
    let probe = uuid::Uuid::new_v4();
    let spec = json!({"id":probe,"name":"线路","kind":"tcp","target":"private.example.com","port":443,"interval_secs":30,"carrier":"","enabled":true});
    sqlx::query("INSERT INTO network_probes(id,server_id,spec) VALUES($1,$2,$3)")
        .bind(probe)
        .bind(visible)
        .bind(spec)
        .execute(&panel.state.pool)
        .await?;
    let base = format!("{}/api/dashboard", panel.base);
    assert_eq!(
        panel
            .client
            .get(format!("{base}/servers"))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    panel
        .admin(
            Method::PATCH,
            "/api/settings",
            &cookie,
            Some(preferences(true)),
        )
        .await?
        .error_for_status()?;
    let response = panel
        .client
        .get(format!("{base}/servers"))
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(response.headers()["cache-control"], "no-store");
    let text = response.text().await?;
    for private in [
        "PRIVATE",
        "device_public_key",
        "ip_addresses",
        "agent_mirror",
        "price",
    ] {
        assert!(!text.contains(private), "{private}");
    }
    let list: Vec<Value> = serde_json::from_str(&text)?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["registered"], true);
    assert_eq!(
        list[0]["agent_settings"],
        json!({"sample_interval_secs":1,"upload_interval_secs":3})
    );
    assert!(list[0]["agent_settings"].get("auto_update").is_none());
    assert!(
        list[0]["agent_settings"]
            .get("discover_public_ips")
            .is_none()
    );
    assert_eq!(list[0]["static_info"]["cpu_cores"], 4);
    for suffix in ["", "/metrics", "/history", "/probes", "/probe-results"] {
        assert_eq!(
            panel
                .client
                .get(format!("{base}/servers/{hidden}{suffix}"))
                .send()
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            panel
                .admin(
                    Method::GET,
                    &format!("/api/dashboard/servers/{hidden}{suffix}"),
                    &cookie,
                    None
                )
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    for path in [
        format!("{base}/servers/{visible}/probes"),
        format!("{base}/probes/overview"),
    ] {
        let text = panel
            .client
            .get(path)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        assert!(!text.contains("private.example.com"));
        assert!(!text.contains("443"));
    }
    for path in ["/api/servers", "/api/settings", "/api/notifications"] {
        assert_eq!(
            panel
                .client
                .get(format!("{}{path}", panel.base))
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    panel
        .admin(
            Method::PATCH,
            "/api/settings",
            &cookie,
            Some(preferences(false)),
        )
        .await?
        .error_for_status()?;
    for suffix in ["", "/metrics", "/probes", "/probe-results"] {
        assert_eq!(
            panel
                .client
                .get(format!("{base}/servers/{visible}{suffix}"))
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(
        panel
            .admin(
                Method::GET,
                &format!("/api/servers/{hidden}"),
                &cookie,
                None
            )
            .await?
            .status()
            .is_success()
    );
    Ok(())
}

#[sqlx::test]
async fn settings_mask_token_and_node_edits_preserve_sampling(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let id = panel.create_server(&cookie, "运营").await?;
    let mut value = preferences(false);
    value["telegram_enabled"] = json!(true);
    value["telegram_token"] = json!("12345:TEST_ONLY_SECRET_0000000000000");
    value["telegram_chat_id"] = json!("-1000000000");
    let saved = panel
        .admin(Method::PATCH, "/api/settings", &cookie, Some(value.clone()))
        .await?
        .error_for_status()?
        .text()
        .await?;
    assert!(!saved.contains("TEST_ONLY_SECRET"));
    assert!(saved.contains("telegram_token_configured\":true"));
    value.as_object_mut().unwrap().remove("telegram_token");
    panel
        .admin(Method::PATCH, "/api/settings", &cookie, Some(value))
        .await?
        .error_for_status()?;
    assert!(
        !panel
            .admin(Method::GET, "/api/settings", &cookie, None)
            .await?
            .text()
            .await?
            .contains("SECRET")
    );
    sqlx::query("UPDATE servers SET agent_settings=$2 WHERE id=$1").bind(id)
        .bind(json!({"sample_interval_secs":10,"upload_interval_secs":30,"auto_update":false,"discover_public_ips":false})).execute(&panel.state.pool).await?;
    let server: Value = panel.admin(Method::PATCH,&format!("/api/servers/{id}"),&cookie,
        Some(json!({"name":"运营","auto_update":true,"asset_settings":{"offline_notify":false,"agent_mirror":"https://mirror.example.com/"}})))
        .await?.error_for_status()?.json().await?;
    assert_eq!(server["agent_settings"]["auto_update"], true);
    assert_eq!(server["agent_settings"]["sample_interval_secs"], 10);
    assert_eq!(server["agent_settings"]["discover_public_ips"], false);
    assert_eq!(
        server["asset_settings"]["agent_mirror"],
        "https://mirror.example.com"
    );
    for mirror in [
        "http://mirror.example.com",
        "https://token@mirror.example.com",
        "https://mirror.example.com?token=secret",
        "https://localhost",
        "https://127.0.0.1",
    ] {
        assert_eq!(
            panel
                .admin(
                    Method::PATCH,
                    &format!("/api/servers/{id}"),
                    &cookie,
                    Some(json!({"name":"坏配置","asset_settings":{"agent_mirror":mirror}}))
                )
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

#[sqlx::test]
async fn offline_alerts_survive_restarts_deduplicate_and_record_recovery(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let id = panel.create_server(&cookie, "离线节点").await?;
    let never = panel.create_server(&cookie, "从未上报").await?;
    let disabled = panel.create_server(&cookie, "关闭告警").await?;
    let now = now_timestamp();
    sqlx::query("UPDATE servers SET last_seen=$1 WHERE id=ANY($2)")
        .bind(now - 600)
        .bind(vec![id, disabled])
        .execute(&panel.state.pool)
        .await?;
    sqlx::query("UPDATE servers SET asset_settings='{\"offline_notify\":false}' WHERE id=$1")
        .bind(disabled)
        .execute(&panel.state.pool)
        .await?;
    let mut config = preferences(false);
    config["telegram_enabled"] = json!(true);
    config["telegram_chat_id"] = json!("-100000");
    config["telegram_token"] = json!("123:TEST_ONLY_SECRET_00000000000");
    panel
        .admin(Method::PATCH, "/api/settings", &cookie, Some(config))
        .await?
        .error_for_status()?;
    notifications::evaluate(&panel.state.pool, now, now).await?;
    let count = || {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM server_alert_events")
            .fetch_one(&panel.state.pool)
    };
    assert_eq!(count().await?, 0);
    let (a, b) = tokio::join!(
        notifications::evaluate(&panel.state.pool, now - 600, now),
        notifications::evaluate(&panel.state.pool, now - 600, now)
    );
    a?;
    b?;
    assert_eq!(count().await?, 1);
    let events: Vec<Value> = panel
        .admin(Method::GET, "/api/notifications", &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(events[0]["server_id"], id);
    assert_ne!(events[0]["server_id"], never);
    assert_eq!(events[0]["deliveries"][0]["status"], "pending");
    sqlx::query("UPDATE servers SET last_seen=$2 WHERE id=$1")
        .bind(id)
        .bind(now)
        .execute(&panel.state.pool)
        .await?;
    notifications::evaluate(&panel.state.pool, now - 600, now).await?;
    notifications::evaluate(&panel.state.pool, now - 600, now).await?;
    let (resolution, total): (String, i64) = sqlx::query_as(
        "SELECT resolution,(SELECT COUNT(*) FROM notification_outbox) FROM server_alert_events",
    )
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(resolution, "recovered");
    assert_eq!(total, 2);
    sqlx::query("UPDATE servers SET last_seen=$2 WHERE id=$1")
        .bind(id)
        .bind(now - 600)
        .execute(&panel.state.pool)
        .await?;
    notifications::evaluate(&panel.state.pool, now - 600, now + 1).await?;
    assert_eq!(count().await?, 2);
    panel
        .admin(
            Method::PATCH,
            "/api/settings",
            &cookie,
            Some(preferences(false)),
        )
        .await?
        .error_for_status()?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM notification_outbox WHERE status='pending'"
        )
        .fetch_one(&panel.state.pool)
        .await?,
        0
    );
    Ok(())
}

#[sqlx::test]
async fn traffic_correction_preserves_new_samples_and_expires_with_cycle_or_selection(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let id = panel.create_server(&cookie, "矫正").await?;
    let now = now_timestamp();
    let start: i64 = sqlx::query_scalar("SELECT sinan_traffic_cycle_start($1,1)")
        .bind(now)
        .fetch_one(&panel.state.pool)
        .await?;
    sqlx::query("INSERT INTO server_network_daily(server_id,day,interface,uploaded,downloaded,first_sample_at,last_sample_at) VALUES($1,$2,'eth0',100,200,$3,$3)")
        .bind(id).bind(now/86400*86400).bind(now*1000).execute(&panel.state.pool).await?;
    let body = json!({"cycle_start":start,"reset_day":1,"network_interface":"","correction_id":null,"baseline_uploaded":"100","baseline_downloaded":"200","uploaded":"10","downloaded":"1000","reason":"测试账单校准"});
    // A fresh telemetry delta arrives while the administrator is editing the snapshot.
    sqlx::query("UPDATE server_network_daily SET uploaded=uploaded+5,downloaded=downloaded+7 WHERE server_id=$1").bind(id).execute(&panel.state.pool).await?;
    let path = format!("/api/servers/{id}/traffic-correction");
    assert_eq!(
        panel
            .client
            .post(format!("{}{path}", panel.base))
            .json(&body)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    panel
        .admin(Method::POST, &path, &cookie, Some(body.clone()))
        .await?
        .error_for_status()?;
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(body))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let server: Value = panel
        .admin(Method::GET, &format!("/api/servers/{id}"), &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(server["traffic"]["uploaded"], "15");
    assert_eq!(server["traffic"]["downloaded"], "1007");
    assert_eq!(server["traffic"]["corrected"], true);
    let raw: (String, String) = sqlx::query_as(
        "SELECT uploaded::text,downloaded::text FROM server_network_daily WHERE server_id=$1",
    )
    .bind(id)
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(raw, ("105".into(), "207".into()));
    let mut rows: Vec<Server> = sqlx::query_as("SELECT * FROM servers WHERE id=$1")
        .bind(id)
        .fetch_all(&panel.state.pool)
        .await?;
    server_traffic::attach(&panel.state.pool, &mut rows, start + 32 * 86400).await?;
    assert!(!rows[0].traffic.as_ref().unwrap().corrected);
    rows[0].asset_settings.network_interface = "eth0".into();
    server_traffic::attach(&panel.state.pool, &mut rows, now).await?;
    assert!(!rows[0].traffic.as_ref().unwrap().corrected);
    assert_eq!(rows[0].traffic.as_ref().unwrap().uploaded, "105");
    // Changing selection invalidates old adjustments, including after switching back.
    for selection in ["eth0", ""] {
        panel
            .admin(
                Method::PATCH,
                &format!("/api/servers/{id}"),
                &cookie,
                Some(json!({"name":"矫正","asset_settings":{"network_interface":selection}})),
            )
            .await?
            .error_for_status()?;
    }
    let after: Value = panel
        .admin(Method::GET, &format!("/api/servers/{id}"), &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(after["traffic"]["corrected"], false);
    assert_eq!(after["traffic"]["uploaded"], "105");
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM server_traffic_corrections WHERE server_id=$1 AND invalidated_at IS NOT NULL").bind(id).fetch_one(&panel.state.pool).await?,1);

    Ok(())
}

#[sqlx::test]
async fn monitoring_only_sessions_and_tokens_keep_private_server_fields_hidden(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let visible = panel.create_server(&cookie, "监控可见").await?;
    let hidden = panel.create_server(&cookie, "监控隐藏").await?;
    for id in [visible, hidden] {
        sqlx::query("UPDATE servers SET device_public_key=$2,static_info=$3,asset_settings=$4,latest_metrics=$5 WHERE id=$1")
            .bind(id).bind("TEST_ONLY_PRIVATE_IDENTITY")
            .bind(json!({"hostname":"TEST_ONLY_PRIVATE_HOST","ip_addresses":["192.0.2.1"],"cpu_cores":4}))
            .bind(json!({"hidden":id==hidden,"price":"123.45","agent_mirror":"https://mirror.example.com","region":"JP"}))
            .bind(json!({"cpu_percent":10,"process_resources":{"private":"TEST_ONLY_PROCESS_DETAIL"},"network_interfaces":{"TEST_ONLY_PRIVATE_INTERFACE":{"transmitted_bytes":123}}}))
            .execute(&panel.state.pool).await?;
    }
    let token = "sinan_api_TEST_ONLY_MONITORING";
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'test-monitoring',$3,'[]',true,$4,$5)")
        .bind(uuid::Uuid::new_v4()).bind(sinan_panel::auth::hash_token(token)).bind(json!(["monitoring:read"]))
        .bind(now_timestamp()+3600).bind(now_timestamp()).execute(&panel.state.pool).await?;
    for suffix in ["/servers", "/live"] {
        let response = panel
            .client
            .get(format!("{}/api/dashboard{suffix}", panel.base))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?;
        let text = response.text().await?;
        assert!(text.contains("cpu_percent"));
        for private in [
            "TEST_ONLY_PRIVATE",
            "TEST_ONLY_PROCESS_DETAIL",
            "device_public_key",
            "agent_mirror",
            "price",
        ] {
            assert!(!text.contains(private), "{private}");
        }
    }
    sqlx::query("UPDATE administrator_profiles SET role='viewer',capabilities=$1,all_servers=true WHERE admin_id=1").bind(json!(["monitoring:read"])).execute(&panel.state.pool).await?;
    let text = panel
        .admin(Method::GET, "/api/dashboard/servers", &cookie, None)
        .await?
        .error_for_status()?
        .text()
        .await?;
    let servers: Vec<Value> = serde_json::from_str(&text)?;
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["id"], visible);
    assert_eq!(servers[0]["public_view"], true);
    for private in [
        "TEST_ONLY_PRIVATE",
        "device_public_key",
        "agent_mirror",
        "price",
    ] {
        assert!(!text.contains(private), "{private}");
    }
    assert_eq!(
        panel
            .admin(
                Method::GET,
                &format!("/api/dashboard/servers/{hidden}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}
