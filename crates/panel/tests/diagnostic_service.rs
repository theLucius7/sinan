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
