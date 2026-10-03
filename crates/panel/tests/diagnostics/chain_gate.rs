use super::*;

async fn saved_full(panel: &TestPanel, server: i64, version: &str, status: &str) -> Result<Uuid> {
    let artifact = sinan_panel::artifacts::descriptor(
        &panel.state,
        "nodequality",
        diagnostics::PLUGIN_VERSION,
        "amd64",
    )
    .await?;
    let id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    let job = sinan_protocol::DiagnosticJob {
        id,
        plugin: "nodequality".into(),
        version: version.into(),
        artifact,
        timeout_secs: 1800,
        expires_at: Some(now + 2100),
        resource_budget: None,
        options: BTreeMap::new(),
    };
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,job,status,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$5,$6)")
        .bind(id).bind(server).bind(serde_json::to_value(job)?).bind(status)
        .bind(now).bind(now+2100).execute(&panel.state.pool).await?;
    Ok(id)
}

#[sqlx::test(migrations = "./migrations")]
async fn new_full_is_denied_on_both_routes_but_daily_remains_ready(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, _ack) = panel.authenticated_device(&cookie, "门禁入口夹具").await?;
    capable(&panel, server).await?;
    fixture(&panel).await?;
    for path in [
        format!("/api/servers/{server}/node-quality/reports"),
        format!("/api/servers/{server}/diagnostics/nodequality"),
    ] {
        let response = panel.admin(Method::POST, &path, &cookie,
            Some(json!({"mode":"full","confirm_full":true,"acknowledge_traffic_warning":true,"upload_report":false}))).await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.text().await?.contains("离线受控工具链"));
    }
    let view: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/node-quality/reports"),
            &cookie,
            None,
        )
        .await?
        .json()
        .await?;
    assert_eq!(view["plugin_ready"], true);
    assert_eq!(view["full_ready"], false);
    assert!(view["full_reason"].as_str().unwrap().contains("宿主 swap"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_jobs WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?,
        0
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/servers/{server}/node-quality/reports"),
                &cookie,
                Some(json!({"mode":"daily"}))
            )
            .await?
            .status(),
        StatusCode::CREATED
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn queued_full_is_failed_without_finalizing_a_device_and_blocks_until_confirmed(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "旧排队夹具").await?;
    capable(&panel, server).await?;
    fixture(&panel).await?;
    let mut ids = Vec::new();
    for version in [
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r2",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r3",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r4",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r5",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r6",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r7",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r8",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r9",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r10",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r11",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r12",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r13",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r14",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r15",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r16",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r17",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r18",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r19",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r20",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r1",
        "a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r2",
    ] {
        ids.push(saved_full(&panel, server, version, "queued").await?);
        if ids.len() == 1 {
            // Pre-registration payloads omitted plugin and mode; both default to full NodeQuality.
            sqlx::query("UPDATE diagnostic_jobs SET job=job-'plugin' WHERE id=$1")
                .bind(ids[0])
                .execute(&panel.state.pool)
                .await?;
        }
        let queue: Value = panel
            .client
            .get(format!("{}/api/agent/v1/diagnostics", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(queue, json!([]));
    }
    for id in &ids {
        let row: (String, String, bool) =
            sqlx::query_as("SELECT status,error,agent_completed FROM diagnostic_jobs WHERE id=$1")
                .bind(id)
                .fetch_one(&panel.state.pool)
                .await?;
        assert_eq!(row.0, "failed");
        assert!(row.1.contains("离线受控工具链"));
        assert!(!row.2);
    }
    // A device may have collected a registered chapter before its queued panel row was gated.
    sqlx::query(
        "UPDATE diagnostic_jobs SET expected_sections=ARRAY['hardware_quality'] WHERE id=$1",
    )
    .bind(ids[1])
    .execute(&panel.state.pool)
    .await?;
    let late_chapter = json!({
        "id": ids[1], "name": "hardware_quality", "text": "门禁前保存，断连后补报的硬件章节",
        "complete": true, "revision": 1, "collected_at": sinan_protocol::now_timestamp(),
    });
    assert_eq!(
        panel
            .client
            .post(format!(
                "{}/api/agent/v1/diagnostics/{}/sections",
                panel.base, ids[1]
            ))
            .bearer_auth(&ack.session_token)
            .json(&late_chapter)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let preserved: (String, String, bool, String) = sqlx::query_as(
        "SELECT status,error,agent_completed,report_completeness FROM diagnostic_jobs WHERE id=$1",
    )
    .bind(ids[1])
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(preserved.0, "failed");
    assert!(preserved.1.contains("离线受控工具链"));
    assert!(!preserved.2);
    assert_eq!(preserved.3, "complete");
    // A queued panel state can lag a device's durable Started checkpoint.
    let id = ids[0].to_string();
    assert_eq!(
        update(
            &panel,
            &ack,
            &id,
            json!({"id":id,"status":"succeeded","report":{"text":"门禁前已完成，重启后补报"}})
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM diagnostic_jobs WHERE id=$1")
            .bind(ids[0])
            .fetch_one(&panel.state.pool)
            .await?,
        "succeeded"
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/servers/{server}/node-quality/reports"),
                &cookie,
                Some(json!({"mode":"daily"}))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    // Every remaining pre-gate device task still needs an actual terminal
    // acknowledgement; rejecting its panel queue never proves cleanup.
    for id in ids.iter().skip(1) {
        let error: String = sqlx::query_scalar("SELECT error FROM diagnostic_jobs WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.state.pool)
            .await?;
        assert_eq!(
            update(
                &panel,
                &ack,
                &id.to_string(),
                json!({"id":id,"status":"failed","error":error})
            )
            .await?
            .status(),
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/servers/{server}/node-quality/reports"),
                &cookie,
                Some(json!({"mode":"daily"}))
            )
            .await?
            .status(),
        StatusCode::CREATED
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn running_full_is_not_redispatched_to_an_agent_without_the_start_gate(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "旧已运行夹具").await?;
    capable(&panel, server).await?;
    fixture(&panel).await?;
    let id = saved_full(&panel, server, diagnostics::PLUGIN_VERSION, "running").await?;
    sqlx::query("UPDATE diagnostic_jobs SET job=job-'plugin' WHERE id=$1")
        .bind(id)
        .execute(&panel.state.pool)
        .await?;
    let endpoint = format!("{}/api/agent/v1/diagnostics", panel.base);
    let queue: Value = panel
        .client
        .get(&endpoint)
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(queue, json!([]));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM diagnostic_jobs WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.state.pool)
            .await?,
        "running"
    );
    sqlx::query("UPDATE servers SET capabilities=capabilities || '[\"diagnostic:nodequality-full-start-gate\"]'::jsonb WHERE id=$1")
        .bind(server).execute(&panel.state.pool).await?;
    let queue: Value = panel
        .client
        .get(endpoint)
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(queue.as_array().unwrap().len(), 1);
    assert_eq!(queue[0]["id"], id.to_string());
    assert_eq!(queue[0]["plugin"], "nodequality");
    assert_eq!(queue[0]["version"], diagnostics::PLUGIN_VERSION);
    let saved: Value = sqlx::query_scalar("SELECT job FROM diagnostic_jobs WHERE id=$1")
        .bind(id)
        .fetch_one(&panel.state.pool)
        .await?;
    assert!(saved.get("plugin").is_none());
    assert!(saved["options"].get("mode").is_none());
    Ok(())
}
