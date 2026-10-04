#![forbid(unsafe_code)]
mod business_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

async fn ready(panel: &TestPanel, server: i64) -> Result<()> {
    sqlx::query("UPDATE servers SET static_info=static_info || '{\"os\":\"linux\"}'::jsonb,capabilities=$2,last_seen=$3 WHERE id=$1")
        .bind(server).bind(json!(["diagnostic:nodequality","diagnostic:nodequality-modes",sinan_protocol::DIAGNOSTIC_SECTIONS_CAPABILITY,sinan_protocol::DIAGNOSTIC_SERVICE_CAPABILITY,sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY,sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY,sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY]))
        .bind(sinan_protocol::now_timestamp()).execute(&panel.state.pool).await?;
    let binary = b"TEST_ONLY fixed diagnostic service fixture";
    let archive = release_fixture::archive("nodequality", binary)?;
    release_fixture::write(
        &panel.state.config.data_dir,
        "nodequality",
        sinan_panel::diagnostics::PLUGIN_VERSION,
        "nodequality",
        &archive,
        binary,
        "tar.gz",
    )?;
    Ok(())
}

fn workbench_budget() -> Value {
    json!({"duration_secs":60,"memory_bytes":67108864,"disk_bytes":134217728,
        "traffic_bytes":268435456,"rate_bps":20000000,"concurrency":1,
        "cpu_percent":20,"cpu_weight":20,"pause_on_service_error":true})
}

#[sqlx::test(migrations = "./migrations")]
async fn throughput_enqueue_freezes_the_same_exact_latency_identity_for_source_and_listener(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let source: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY source') RETURNING id")
            .fetch_one(&panel.state.pool)
            .await?;
    let receiver: i64 = sqlx::query_scalar(
        "INSERT INTO servers(name,static_info) VALUES('TEST_ONLY receiver',$1) RETURNING id",
    )
    .bind(json!({"ip_addresses":["127.0.0.1"]}))
    .fetch_one(&panel.state.pool)
    .await?;
    let target = Uuid::new_v4();
    let end = sinan_protocol::now_timestamp() + 3600;
    sqlx::query("INSERT INTO network_workbench_targets(id,name,host,purpose,authorization_snapshot,authorized_until,created_at,updated_at) VALUES($1,'TEST_ONLY latency','latency.example.test','isolated','original authorization',$2,0,0)")
        .bind(target).bind(end).execute(&panel.state.pool).await?;
    sqlx::query("INSERT INTO network_workbench_tools(id,version,license,source_url,licensed,updated_at) VALUES('iperf3','TEST_ONLY','TEST_ONLY','https://tools.example.test/iperf3',TRUE,0)")
        .execute(&panel.state.pool).await?;
    let plan = json!({"name":"TEST_ONLY exact latency","budget":workbench_budget(),"schedule":null,
        "steps":[{"name":"TEST_ONLY throughput","source":{"kind":"server","server_id":source},"stop_on_failure":true,
        "check":{"kind":"throughput","client_mode":"managed","receiver_server":receiver,"receiver_host":"127.0.0.1",
            "port":5201,"family":"ipv4","direction":"forward","protocol":"tcp","streams":1,
            "duration_secs":1,"rate_bps":1000,"tool_version":"TEST_ONLY","latency_target":"latency.example.test"}}]});
    let run: Value = panel
        .admin(
            Method::POST,
            "/api/network-workbench/runs",
            &cookie,
            Some(plan.clone()),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let snapshot: Value =
        sqlx::query_scalar("SELECT snapshot FROM network_workbench_runs WHERE id=$1")
            .bind(Uuid::parse_str(run["id"].as_str().unwrap())?)
            .fetch_one(&panel.state.pool)
            .await?;
    let entries = snapshot["executions"][0].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["role"], format!("listener:{receiver}"));
    assert_eq!(entries[1]["role"], format!("source:{source}"));
    for execution in entries {
        assert_eq!(execution["latency_target"]["id"], target.to_string());
        assert_eq!(
            execution["latency_target"]["authorization"],
            "original authorization"
        );
        assert_eq!(execution["latency_target"]["authorized_until"], end);
    }
    assert_eq!(entries[0]["latency_target"], entries[1]["latency_target"]);
    let alias = Uuid::new_v4();
    sqlx::query("INSERT INTO network_workbench_targets(id,name,host,purpose,authorization_snapshot,created_at,updated_at) VALUES($1,'TEST_ONLY alias','latency.example.test','isolated','different authorization',0,0)")
        .bind(alias).execute(&panel.state.pool).await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/network-workbench/runs",
                &cookie,
                Some(plan)
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let saved: Value =
        sqlx::query_scalar("SELECT snapshot FROM network_workbench_runs WHERE id=$1")
            .bind(Uuid::parse_str(run["id"].as_str().unwrap())?)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(saved, snapshot);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM network_workbench_runs")
            .fetch_one(&panel.state.pool)
            .await?,
        1
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn revoked_workbench_delivery_blocks_the_entire_same_server_mixed_response_until_cleanup_confirmation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "混合队列撤销夹具")
        .await?;
    ready(&panel, server).await?;
    sqlx::query("UPDATE servers SET capabilities=capabilities || $2::jsonb WHERE id=$1")
        .bind(server)
        .bind(json!([
            "diagnostic:network-workbench-v1",
            sinan_protocol::DIAGNOSTIC_CANCEL_CAPABILITY
        ]))
        .execute(&panel.state.pool)
        .await?;
    // Both tasks must remain in the same signed inventory. Two calls to write()
    // would replace the first proof while leaving an unlisted archive on disk.
    let mut artifacts = Vec::new();
    for (name, version, binary) in [
        (
            "nodequality",
            sinan_panel::diagnostics::PLUGIN_VERSION,
            &b"TEST_ONLY fixed diagnostic service fixture"[..],
        ),
        (
            "network-workbench",
            "1.0.0",
            &b"TEST_ONLY workbench mixed queue fixture"[..],
        ),
    ] {
        let archive = release_fixture::archive(name, binary)?;
        for arch in ["amd64", "arm64"] {
            let mut entry = release_support::entry(name, version, name, "tar.gz", &archive, binary);
            entry.arch = arch.into();
            entry.asset_name = sinan_protocol::release::canonical_asset_name(&entry)?;
            artifacts.push((entry, archive.clone()));
        }
    }
    release_fixture::write_entries(&panel.state.config.data_dir, artifacts)?;
    let entries = sinan_panel::releases::entries(&panel.state).await?;
    assert_eq!(entries.len(), 4);
    for name in ["nodequality", "network-workbench"] {
        let version = if name == "nodequality" {
            sinan_panel::diagnostics::PLUGIN_VERSION
        } else {
            "1.0.0"
        };
        for arch in ["amd64", "arm64"] {
            assert!(entries.iter().any(|entry| {
                entry.name == name && entry.version == version && entry.arch == arch
            }));
        }
    }
    let target = Uuid::new_v4();
    sqlx::query("INSERT INTO network_workbench_targets(id,name,host,purpose,authorization_snapshot,created_at,updated_at) VALUES($1,'TEST_ONLY TCP','127.0.0.1','isolated','original authorization',0,0)")
        .bind(target).execute(&panel.state.pool).await?;
    let plan = json!({"name":"TEST_ONLY mixed queue","budget":workbench_budget(),"schedule":null,
        "steps":[{"name":"TEST_ONLY TCP","source":{"kind":"server","server_id":server},"stop_on_failure":true,
        "check":{"kind":"tcp","target_id":target,"port":12345,"family":"ipv4","samples":1}}]});
    let run: Value = panel
        .admin(
            Method::POST,
            "/api/network-workbench/runs",
            &cookie,
            Some(plan),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let workbench: Value = panel
        .admin(
            Method::POST,
            &format!("/api/servers/{server}/diagnostics/network-workbench"),
            &cookie,
            Some(json!({"run_id":run["id"],"step_index":0,"role":format!("source:{server}")})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let revoked = Uuid::parse_str(workbench["id"].as_str().unwrap())?;
    sqlx::query("UPDATE diagnostic_jobs SET status='succeeded',agent_completed=TRUE WHERE id=$1")
        .bind(revoked)
        .execute(&panel.state.pool)
        .await?;
    let response = panel
        .admin(
            Method::POST,
            &format!("/api/servers/{server}/diagnostics/nodequality"),
            &cookie,
            Some(json!({"mode":"daily"})),
        )
        .await?;
    let status = response.status();
    let body = response.text().await?;
    anyhow::ensure!(
        status == StatusCode::CREATED,
        "mixed queue NodeQuality creation failed ({status}): {}",
        body.chars().take(2048).collect::<String>()
    );
    let nodequality: Value = serde_json::from_str(&body)?;
    let first = Uuid::parse_str(nodequality["id"].as_str().unwrap())?;
    // This isolated fixture represents a legacy/restored inconsistent queue.
    // Normal creation retains the production one-active-job index and mutex.
    sqlx::query("DROP INDEX diagnostic_active_server_idx")
        .execute(&panel.state.pool)
        .await?;
    let last = Uuid::new_v4();
    let mut last_job = nodequality["job"].clone();
    last_job["id"] = json!(last);
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,status,job,created_at,updated_at,expires_at) VALUES($1,$2,'queued',$3,$4,$4,$5)")
        .bind(last).bind(server).bind(&last_job).bind(now).bind(now+300).execute(&panel.state.pool).await?;
    let preserved = json!({"text":"TEST_ONLY original unknown partial report"});
    sqlx::query("DELETE FROM network_workbench_targets WHERE id=$1")
        .bind(target)
        .execute(&panel.state.pool)
        .await?;
    // Model a recovered mixed queue with the revoked task first, between two
    // valid tasks, and last. Every response must discard earlier starts too.
    for position in 0..3 {
        for id in [first, last, revoked] {
            sqlx::query("UPDATE diagnostic_jobs SET status='queued',agent_completed=FALSE,cancel_requested_at=NULL,cancel_error=NULL WHERE id=$1")
                .bind(id).execute(&panel.state.pool).await?;
        }
        sqlx::query("UPDATE diagnostic_jobs SET report=$2 WHERE id=$1")
            .bind(revoked)
            .bind(&preserved)
            .execute(&panel.state.pool)
            .await?;
        let order = match position {
            0 => [revoked, first, last],
            1 => [first, revoked, last],
            _ => [first, last, revoked],
        };
        for (index, id) in order.into_iter().enumerate() {
            sqlx::query("UPDATE diagnostic_jobs SET created_at=$2 WHERE id=$1")
                .bind(id)
                .bind(now - 10 + index as i64)
                .execute(&panel.state.pool)
                .await?;
        }
        for _ in 0..2 {
            let pending: Value = panel
                .client
                .get(format!("{}/api/agent/v1/diagnostics", panel.base))
                .bearer_auth(&ack.session_token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(pending, json!([]));
        }
        let saved: Value =
            sqlx::query_scalar("SELECT to_jsonb(j) FROM diagnostic_jobs j WHERE id=$1")
                .bind(revoked)
                .fetch_one(&panel.state.pool)
                .await?;
        assert_eq!(saved["status"], "cancel_requested");
        assert_eq!(saved["agent_completed"], false);
        assert!(saved["cancel_requested_at"].is_i64());
        assert_eq!(saved["report"], preserved);
        assert_eq!(saved["job"], workbench["job"]);
        for (id, job) in [(first, &nodequality["job"]), (last, &last_job)] {
            let saved: Value =
                sqlx::query_scalar("SELECT to_jsonb(j) FROM diagnostic_jobs j WHERE id=$1")
                    .bind(id)
                    .fetch_one(&panel.state.pool)
                    .await?;
            assert_eq!(saved["status"], "queued");
            assert_eq!(saved["job"], *job);
            assert_eq!(saved["agent_completed"], false);
        }
        let cancellations: Value = panel
            .client
            .get(format!(
                "{}/api/agent/v1/diagnostics/cancellations",
                panel.base
            ))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(cancellations.as_array().unwrap().len(), 1);
        assert_eq!(cancellations[0]["job"]["id"], revoked.to_string());
        assert_eq!(panel.client.post(format!("{}/api/agent/v1/diagnostics/{revoked}/cancel-confirmation",panel.base))
            .bearer_auth(&ack.session_token).json(&json!({"id":revoked,"server_id":server,"plugin":"network-workbench","confirmed":true}))
            .send().await?.status(), StatusCode::NO_CONTENT);
        let pending: Value = panel
            .client
            .get(format!("{}/api/agent/v1/diagnostics", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let ids: Vec<_> = pending
            .as_array()
            .unwrap()
            .iter()
            .map(|job| job["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec![first.to_string(), last.to_string()]);
        assert_eq!(
            sqlx::query_scalar::<_, Value>("SELECT report FROM diagnostic_jobs WHERE id=$1")
                .bind(revoked)
                .fetch_one(&panel.state.pool)
                .await?,
            preserved
        );
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn queued_jobs_wait_for_completion_capability_without_erasing_history(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "等待清理能力设备")
        .await?;
    ready(&panel, server).await?;
    let created: Value = panel
        .admin(
            Method::POST,
            &format!("/api/servers/{server}/diagnostics/nodequality"),
            &cookie,
            Some(json!({"mode":"daily"})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    sqlx::query("UPDATE servers SET capabilities=capabilities-$2 WHERE id=$1")
        .bind(server)
        .bind(sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY)
        .execute(&panel.state.pool)
        .await?;
    let pending: Value = panel
        .client
        .get(format!("{}/api/agent/v1/diagnostics", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(pending, json!([]));
    let saved: Value = sqlx::query_scalar("SELECT to_jsonb(j) FROM diagnostic_jobs j WHERE id=$1")
        .bind(Uuid::parse_str(created["id"].as_str().unwrap())?)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(saved["status"], "queued");
    assert_eq!(saved["job"], created["job"]);
    ready(&panel, server).await?;
    let pending: Value = panel
        .client
        .get(format!("{}/api/agent/v1/diagnostics", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(pending.as_array().unwrap().len(), 1);
    assert_eq!(pending[0]["id"], created["id"]);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn shared_service_keeps_legacy_history_and_serializes_both_creation_routes(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "共用诊断夹具").await?;
    ready(&panel, server).await?;
    let generic = format!("/api/servers/{server}/diagnostics/nodequality");
    let legacy = format!("/api/servers/{server}/node-quality/reports");
    let request = json!({"mode":"daily"});
    let (first, second) = tokio::join!(
        panel.admin(Method::POST, &generic, &cookie, Some(request.clone())),
        panel.admin(Method::POST, &legacy, &cookie, Some(request))
    );
    let (first, second) = (first?, second?);
    let created = if first.status() == StatusCode::CREATED {
        assert_eq!(second.status(), StatusCode::CONFLICT);
        first
    } else {
        assert_eq!(first.status(), StatusCode::CONFLICT);
        assert_eq!(second.status(), StatusCode::CREATED);
        second
    };
    let record: Value = created.json().await?;
    assert_eq!(
        record["job"]["resource_budget"],
        json!({"memory_max":64*1024*1024,"tasks_max":32,"cpu_weight":10,"io_weight":10,"oom_score_adjust":500})
    );
    assert_eq!(
        record["expected_sections"],
        json!(["net_quality", "environment"])
    );
    let id = record["id"].as_str().unwrap();
    let response=panel.client.post(format!("{}/api/agent/v1/diagnostics/{id}/sections",panel.base)).bearer_auth(&ack.session_token).json(&json!({"id":id,"name":"net_quality","text":"已保存的网络章节","complete":true,"revision":1,"collected_at":sinan_protocol::now_timestamp()})).send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = panel
        .client
        .post(format!("{}/api/agent/v1/diagnostics/{id}", panel.base))
        .bearer_auth(&ack.session_token)
        .json(&json!({"id":id,"status":"failed","error":"夹具取消连接，部分报告保留"}))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut old_job = record["job"].clone();
    let old_id = Uuid::new_v4();
    old_job["id"] = json!(old_id);
    old_job["version"] = json!("a92fca6c0067df29ddd03fdc2fee6f3000f64545-r2");
    old_job.as_object_mut().unwrap().remove("resource_budget");
    old_job.as_object_mut().unwrap().remove("plugin");
    let historical_job = old_job.clone();
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,status,job,report,created_at,updated_at,expires_at,agent_completed,report_completeness) VALUES($1,$2,'succeeded',$3,$4,$5,$5,$5+300,TRUE,'legacy')")
        .bind(old_id).bind(server).bind(old_job.clone()).bind(json!({"text":"迁移前的完整历史原文"})).bind(sinan_protocol::now_timestamp()-1).execute(&panel.state.pool).await?;
    let other_id = Uuid::new_v4();
    old_job["id"] = json!(other_id);
    old_job["plugin"] = json!("other-registered-history");
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,status,job,created_at,updated_at,expires_at) VALUES($1,$2,'failed',$3,$4,$4,$4)").bind(other_id).bind(server).bind(old_job).bind(sinan_protocol::now_timestamp()).execute(&panel.state.pool).await?;
    let view: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/diagnostics"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(view["plugins"][0]["plugin"], "nodequality");
    assert_eq!(view["plugins"][0]["ready"], true);
    assert_eq!(view["reports"].as_array().unwrap().len(), 3);
    let report = view["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["report_completeness"], "partial");
    assert_eq!(report["sections"][0]["text"], "已保存的网络章节");
    let legacy_view: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/node-quality"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(legacy_view["reports"].as_array().unwrap().len(), 2);
    let historical = legacy_view["reports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == old_id.to_string())
        .unwrap();
    assert_eq!(historical["job"], historical_job);
    assert!(historical["job"].get("plugin").is_none());
    assert!(historical["job"].get("resource_budget").is_none());
    assert_eq!(historical["report"]["text"], "迁移前的完整历史原文");
    assert_eq!(historical["report_completeness"], "legacy");
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn registered_plugins_use_one_server_mutex_and_require_budget_aware_agents(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "互斥与权限夹具")
        .await?;
    ready(&panel, server).await?;
    let path = format!("/api/servers/{server}/diagnostics/nodequality");
    assert_eq!(
        panel
            .client
            .post(format!("{}{}", panel.base, path))
            .bearer_auth(&ack.session_token)
            .json(&json!({"mode":"daily"}))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/servers/{server}/diagnostics/unregistered"),
                &cookie,
                Some(json!({}))
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &path,
                &cookie,
                Some(json!({"mode":"daily","resource_budget":{"memory_max":1}}))
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE servers SET capabilities=capabilities-$2 WHERE id=$1")
        .bind(server)
        .bind(sinan_protocol::DIAGNOSTIC_SERVICE_CAPABILITY)
        .execute(&panel.state.pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(json!({"mode":"daily"})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    ready(&panel, server).await?;
    sqlx::query("UPDATE servers SET capabilities=capabilities-$2 WHERE id=$1")
        .bind(server)
        .bind(sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY)
        .execute(&panel.state.pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(json!({"mode":"daily"})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    ready(&panel, server).await?;
    let existing = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,job,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$4,$4+300)").bind(existing).bind(server).bind(json!({"plugin":"different-diagnostic-plugin"})).bind(now).execute(&panel.state.pool).await?;
    for status in ["queued", "running", "cleaning", "cancel_requested"] {
        let expiry = if matches!(status, "cleaning" | "cancel_requested") {
            now - 1
        } else {
            now + 300
        };
        sqlx::query("UPDATE diagnostic_jobs SET status=$2,expires_at=$3 WHERE id=$1")
            .bind(existing)
            .bind(status)
            .bind(expiry)
            .execute(&panel.state.pool)
            .await?;
        for route in [
            &path,
            &format!("/api/servers/{server}/node-quality/reports"),
        ] {
            assert_eq!(
                panel
                    .admin(Method::POST, route, &cookie, Some(json!({"mode":"daily"})))
                    .await?
                    .status(),
                StatusCode::CONFLICT
            );
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_jobs WHERE server_id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}
