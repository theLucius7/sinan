#![forbid(unsafe_code)]

mod business_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{agent_api, diagnostics};
use sinan_protocol::{Hello, HelloAck, Message, PROTOCOL_VERSION};
use sqlx::PgPool;
use std::collections::BTreeMap;

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
async fn diagnostic_chapters_survive_failure_duplicates_late_delivery_and_recreation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server_id, _socket, ack) = panel.authenticated_device(&cookie, "章节设备").await?;
    let (_other, _other_socket, other_ack) =
        panel.authenticated_device(&cookie, "其他设备").await?;
    capable(&panel, server_id).await?;
    fixture(&panel).await?;
    let record: Value = panel
        .admin(
            Method::POST,
            &format!("/api/servers/{server_id}/node-quality/reports"),
            &cookie,
            Some(json!({"mode":"daily"})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = record["id"].as_str().unwrap();
    sqlx::query("UPDATE diagnostic_jobs SET status='running',job=jsonb_set(job,'{options,mode}','\"full\"'),expected_sections=ARRAY['header_info','hardware_quality','ip_quality','net_quality','backroute_trace','environment'] WHERE id=$1")
        .bind(uuid::Uuid::parse_str(id)?).execute(&panel.state.pool).await?;
    let endpoint = format!("{}/api/agent/v1/diagnostics/{id}/sections", panel.base);
    let chapter = json!({"id":id,"name":"header_info","text":"已经完成的报告信息","complete":true,"revision":2,"collected_at":sinan_protocol::now_timestamp()});
    assert_eq!(
        panel
            .client
            .post(&endpoint)
            .bearer_auth(&other_ack.session_token)
            .json(&chapter)
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    for _ in 0..2 {
        assert_eq!(
            panel
                .client
                .post(&endpoint)
                .bearer_auth(&ack.session_token)
                .json(&chapter)
                .send()
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let mut collision = chapter.clone();
    collision["text"] = json!("different content");
    assert_eq!(
        panel
            .client
            .post(&endpoint)
            .bearer_auth(&ack.session_token)
            .json(&collision)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    collision["revision"] = json!(1);
    collision["complete"] = json!(false);
    assert_eq!(
        panel
            .client
            .post(&endpoint)
            .bearer_auth(&ack.session_token)
            .json(&collision)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        update(
            &panel,
            &ack,
            id,
            json!({"id":id,"status":"failed","error":"OOM fixture"})
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    let partial = json!({"id":id,"name":"hardware_quality","text":"停止前的硬件输出","complete":false,"revision":1,"collected_at":sinan_protocol::now_timestamp()});
    assert_eq!(
        panel
            .client
            .post(&endpoint)
            .bearer_auth(&ack.session_token)
            .json(&partial)
            .send()
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
    let report = &view["reports"][0];
    assert_eq!(report["status"], "failed");
    assert_eq!(report["report_completeness"], "partial");
    assert_eq!(report["sections"].as_array().unwrap().len(), 2);
    assert_eq!(report["sections"][0]["text"], chapter["text"]);
    assert_eq!(report["report"], Value::Null);
    assert_eq!(report["error"], "OOM fixture");
    let recreated =
        sinan_panel::AppState::new(panel.state.pool.clone(), (*panel.state.config).clone()).await?;
    let saved: String = sqlx::query_scalar(
        "SELECT text FROM diagnostic_report_sections WHERE job_id=$1 AND name='header_info'",
    )
    .bind(uuid::Uuid::parse_str(id)?)
    .fetch_one(&recreated.pool)
    .await?;
    assert_eq!(saved, "已经完成的报告信息");
    for name in [
        "hardware_quality",
        "ip_quality",
        "net_quality",
        "backroute_trace",
        "environment",
    ] {
        let final_chapter = json!({"id":id,"name":name,"text":format!("saved {name}"),"complete":true,"revision":3,"collected_at":sinan_protocol::now_timestamp()});
        assert_eq!(
            panel
                .client
                .post(&endpoint)
                .bearer_auth(&ack.session_token)
                .json(&final_chapter)
                .send()
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    let state: (String, String) =
        sqlx::query_as("SELECT status,report_completeness FROM diagnostic_jobs WHERE id=$1")
            .bind(uuid::Uuid::parse_str(id)?)
            .fetch_one(&recreated.pool)
            .await?;
    assert_eq!(state, ("failed".into(), "complete".into()));
    let mut invalid = chapter;
    invalid["name"] = json!("undeclared");
    assert_eq!(
        panel
            .client
            .post(&endpoint)
            .bearer_auth(&ack.session_token)
            .json(&invalid)
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    invalid["name"] = json!("header_info");
    invalid["text"] = json!("a".repeat(65537));
    assert_eq!(
        panel
            .client
            .post(&endpoint)
            .bearer_auth(&ack.session_token)
            .json(&invalid)
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_report_text_is_retained_with_unknown_chapter_completeness(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server_id, _socket, ack) = panel.authenticated_device(&cookie, "历史设备").await?;
    let id = uuid::Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,job,created_at,updated_at,expires_at) VALUES($1,$2,'{}',$3,$3,$4)").bind(id).bind(server_id).bind(now).bind(now+300).execute(&panel.state.pool).await?;
    assert_eq!(
        update(
            &panel,
            &ack,
            &id.to_string(),
            json!({"id":id,"status":"succeeded","report":{"text":"旧版本完整文本"}})
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
    assert_eq!(view["reports"][0]["report"]["text"], "旧版本完整文本");
    assert_eq!(view["reports"][0]["report_completeness"], "legacy");
    assert_eq!(view["reports"][0]["sections"], json!([]));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_migration_applies_after_sections_without_losing_saved_reports(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel
        .create_server(&cookie, "已应用章节迁移的旧设备")
        .await?;
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,job,status,report,created_at,updated_at,expires_at,expected_sections,report_completeness) VALUES($1,$2,'{}','succeeded',$3,1,1,2,ARRAY['header_info'],'complete')")
        .bind(id).bind(server).bind(json!({"text":"保存的历史报告"})).execute(&pool).await?;
    sqlx::query("INSERT INTO diagnostic_report_sections(job_id,name,text,complete,revision,collected_at,received_at) VALUES($1,'header_info','保存的完整章节',TRUE,1,1,1)").bind(id).execute(&pool).await?;
    // Recreate the published main schema where 0011 already exists but 0010
    // was not yet introduced. Keep its migration checksum and all report data.
    sqlx::raw_sql("DROP INDEX diagnostic_cancel_pending_idx; ALTER TABLE diagnostic_jobs DROP COLUMN cancel_requested_at, DROP COLUMN cancel_confirmed_at, DROP COLUMN cancel_error; ALTER TABLE diagnostic_jobs DROP CONSTRAINT diagnostic_jobs_status_check; ALTER TABLE diagnostic_jobs ADD CONSTRAINT diagnostic_jobs_status_check CHECK(status IN ('queued','running','succeeded','failed')); DELETE FROM _sqlx_migrations WHERE version=10;").execute(&pool).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    let row: (String, Value, String, Option<i64>) = sqlx::query_as("SELECT status,report,report_completeness,cancel_requested_at FROM diagnostic_jobs WHERE id=$1").bind(id).fetch_one(&pool).await?;
    assert_eq!(
        row,
        (
            "succeeded".into(),
            json!({"text":"保存的历史报告"}),
            "complete".into(),
            None
        )
    );
    let chapter: String =
        sqlx::query_scalar("SELECT text FROM diagnostic_report_sections WHERE job_id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(chapter, "保存的完整章节");
    sqlx::query("UPDATE diagnostic_jobs SET status='cancel_requested' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await?;
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE version IN (10,11) AND success ORDER BY version").fetch_all(&pool).await?;
    assert_eq!(applied, vec![10, 11]);
    Ok(())
}
