use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_crosses_real_agent_websocket_http_and_recovers_after_restart(
    pool: PgPool,
) -> Result<()> {
    let harness = Harness::start(pool).await?;
    write_artifact(&harness)?;
    let server = harness
        .api(
            Method::POST,
            "/api/servers",
            json!({"name":"取消端到端夹具"}),
        )
        .await?;
    let id = server["id"].as_i64().context("server id")?;
    let enrollment = harness
        .api(
            Method::POST,
            &format!("/api/servers/{id}/enrollment"),
            json!({}),
        )
        .await?;
    let config = harness.agent_config();
    identity::enroll(
        &config,
        enrollment["token"].as_str().context("enrollment token")?,
    )
    .await?;
    let services = Arc::new(IndependentServices::default());
    let start = || {
        tokio::spawn(transport::run_with_diagnostics(
            config.clone(),
            vec![],
            vec![Arc::new(NodeQualityAdapter::new())],
            Arc::new(FakeResourceOps::new(Arc::new(SystemOps))),
            services.clone(),
            "cancellation-test-agent",
        ))
    };
    let agent = start();
    eventually("confirmed cancellation capability", 15, || async {
        let capabilities: serde_json::Value =
            sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1")
                .bind(id)
                .fetch_one(&harness.state.pool)
                .await?;
        Ok(capabilities.as_array().is_some_and(|caps| {
            caps.iter()
                .any(|cap| cap == sinan_protocol::DIAGNOSTIC_CANCEL_CAPABILITY)
                && caps
                    .iter()
                    .any(|cap| cap == sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY)
        }))
    })
    .await?;
    mark_simulated_linux(&harness, id).await?;
    let report = harness
        .api(
            Method::POST,
            &format!("/api/servers/{id}/node-quality/reports"),
            json!({"mode":"daily"}),
        )
        .await?;
    let job = uuid::Uuid::parse_str(report["id"].as_str().context("job id")?)?;
    eventually("diagnostic service started once", 15, || async {
        Ok(services.starts.load(Ordering::SeqCst) == 1)
    })
    .await?;
    {
        let jobs = services.jobs.lock().unwrap();
        let directory = &jobs.values().next().context("started service")?.0;
        fs::write(
            directory.join("result.txt"),
            "# 已完成的部分报告\n取消后保留。\n",
        )?;
    }
    services.block_stop.store(true, Ordering::SeqCst);
    let cancellation = harness
        .api(
            Method::POST,
            &format!("/api/servers/{id}/diagnostics/{job}/cancel"),
            json!({}),
        )
        .await?;
    assert_eq!(cancellation["status"], "cancel_requested");
    eventually("negative cleanup result remains pending", 15, || async {
        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status,cancel_error FROM diagnostic_jobs WHERE id=$1")
                .bind(job)
                .fetch_one(&harness.state.pool)
                .await?;
        Ok(row.0 == "cancel_requested" && row.1.is_some())
    })
    .await?;
    let last_seen: i64 = sqlx::query_scalar("SELECT last_seen FROM servers WHERE id=$1")
        .bind(id)
        .fetch_one(&harness.state.pool)
        .await?;
    eventually(
        "control connection remains responsive while stop fails",
        15,
        || async {
            anyhow::ensure!(
                !agent.is_finished(),
                "Agent stopped while cancellation was pending"
            );
            let seen: i64 = sqlx::query_scalar("SELECT last_seen FROM servers WHERE id=$1")
                .bind(id)
                .fetch_one(&harness.state.pool)
                .await?;
            Ok(seen > last_seen)
        },
    )
    .await?;
    let saved = State::open(&config.state_db)?
        .get_json::<Vec<sinan_protocol::DiagnosticCancelRequest>>("diagnostics:cancellations")?
        .context("durable cancellation intent")?;
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].job.id, job);
    agent.abort();
    let _ = agent.await;
    let mut state = State::open(&config.state_db)?;
    let mut saved: serde_json::Value = state
        .get_json("diagnostics:active")?
        .context("saved start")?;
    saved["Started"]["spec"]["version"] = json!("a92fca6c0067df29ddd03fdc2fee6f3000f64545-r3");
    saved["Started"]["spec"]["options"] = json!({});
    state.set_json("diagnostics:active", &saved)?;
    let mut requests: Vec<sinan_protocol::DiagnosticCancelRequest> = state
        .get_json("diagnostics:cancellations")?
        .context("saved cancellation")?;
    requests[0].job.version = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r3".into();
    requests[0].job.options.clear();
    state.set_json("diagnostics:cancellations", &requests)?;
    drop(state);
    sqlx::query("UPDATE diagnostic_jobs SET job=jsonb_set(jsonb_set(job,'{options}','{}'),'{version}','\"a92fca6c0067df29ddd03fdc2fee6f3000f64545-r3\"') WHERE id=$1")
        .bind(job).execute(&harness.state.pool).await?;
    services.block_stop.store(false, Ordering::SeqCst);
    let restarted = start();
    eventually(
        "confirmed cleanup after restart and HTTP replay",
        20,
        || async {
            anyhow::ensure!(
                !restarted.is_finished(),
                "Agent exited before cancellation recovery"
            );
            let row: (String, Option<serde_json::Value>, Option<i64>) = sqlx::query_as(
                "SELECT status,report,cancel_confirmed_at FROM diagnostic_jobs WHERE id=$1",
            )
            .bind(job)
            .fetch_one(&harness.state.pool)
            .await?;
            Ok(row.0 == "cancelled"
                && row.2.is_some()
                && row.1.is_some_and(|report| {
                    report["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("取消后保留"))
                }))
        },
    )
    .await?;
    assert_eq!(services.starts.load(Ordering::SeqCst), 1);
    assert!(services.jobs.lock().unwrap().is_empty());
    let duplicate = harness
        .api(
            Method::POST,
            &format!("/api/servers/{id}/diagnostics/{job}/cancel"),
            json!({}),
        )
        .await?;
    assert_eq!(duplicate["status"], "cancelled");
    restarted.abort();
    let _ = restarted.await;
    Ok(())
}
