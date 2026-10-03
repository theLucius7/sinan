#![forbid(unsafe_code)]
mod business_support;
#[path = "node_ip_queries/fixture.rs"]
mod fixture;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
use anyhow::Result;
use business_support::TestPanel;
use fixture::*;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn official_node_jobs_are_signed_capability_bound_deduplicated_and_cancelable(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "正式节点来源夹具")
        .await?;
    prepare(&panel, server).await?;
    let path = format!("/api/servers/{server}/ip-quality/node-query");
    sqlx::query("UPDATE servers SET capabilities=capabilities-'diagnostic:nodequality-node-query' WHERE id=$1")
        .bind(server).execute(&panel.state.pool).await?;
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(json!({})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    prepare(&panel, server).await?;
    for (request, rejection) in [
        (
            json!({"api_key":"TEST_ONLY_private"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (json!({"ip_version":"invalid"}), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            panel
                .admin(Method::POST, &path, &cookie, Some(request))
                .await?
                .status(),
            rejection
        );
    }
    let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_jobs WHERE server_id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(
        jobs, 0,
        "rejected credentials and invalid family never create a job"
    );
    let ordinary = format!("/api/servers/{server}/node-quality/reports");
    assert_eq!(
        panel
            .admin(Method::POST, &ordinary, &cookie, Some(json!({"mode":"ip"})))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let record = create(&panel, server, &cookie).await?;
    assert_eq!(record["job"]["version"], VERSION);
    assert_eq!(
        record["job"]["resource_budget"]["memory_max"],
        64 * 1024 * 1024
    );
    assert_eq!(record["job"]["resource_budget"]["tasks_max"], 32);
    assert_eq!(record["job"]["timeout_secs"], 90);
    assert_eq!(
        record["expected_sections"],
        json!(["ip_quality", "environment"])
    );
    assert_eq!(record["job"]["options"]["node_ips"], "[\"1.1.1.1\"]");
    assert!(!record.to_string().contains("api_key"));
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(json!({})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
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
    let id = record["id"].as_str().unwrap();
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/servers/{server}/diagnostics/{id}/cancel"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::ACCEPTED
    );
    let canceled: String =
        sqlx::query_scalar("SELECT status FROM diagnostic_jobs WHERE id=$1::uuid")
            .bind(id)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(canceled, "cancel_requested");
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn chapter_replay_repairs_postcommit_cache_failure_and_old_revisions_do_not_regress(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "章节重试夹具").await?;
    prepare(&panel, server).await?;
    let record = create(&panel, server, &cookie).await?;
    let id = record["id"].as_str().unwrap();
    let at = record["created_at"].as_i64().unwrap();
    let first = section(id, at, 1, true, None);
    sqlx::query("CREATE FUNCTION test_only_reject_node_cache() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'TEST_ONLY cache write failure'; END; $$")
        .execute(&panel.state.pool).await?;
    sqlx::query("CREATE TRIGGER test_only_cache_failure BEFORE INSERT ON server_ip_quality FOR EACH STATEMENT EXECUTE FUNCTION test_only_reject_node_cache()")
        .execute(&panel.state.pool).await?;
    assert_eq!(
        upload(&panel, &ack.session_token, id, &first).await?,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let chapters: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_report_sections WHERE job_id=$1::uuid")
            .bind(id)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(
        chapters, 1,
        "chapter commits before cache failure and remains retryable"
    );
    sqlx::query("DROP TRIGGER test_only_cache_failure ON server_ip_quality")
        .execute(&panel.state.pool)
        .await?;
    assert_eq!(
        upload(&panel, &ack.session_token, id, &first).await?,
        StatusCode::NO_CONTENT
    );
    let quality = view(&panel, server, &cookie).await?;
    assert_current_false_zero(&quality, at);
    let failure = section(id, at + 1, 2, true, Some(("http_429", Some(429))));
    assert_eq!(
        upload(&panel, &ack.session_token, id, &failure).await?,
        StatusCode::NO_CONTENT
    );
    let quality = view(&panel, server, &cookie).await?;
    assert_history_false_zero(&quality, at, "http_429");
    assert_eq!(
        upload(&panel, &ack.session_token, id, &first).await?,
        StatusCode::NO_CONTENT
    );
    let quality = view(&panel, server, &cookie).await?;
    assert_history_false_zero(&quality, at, "http_429");
    let changed_same_revision = section(id, at + 1, 2, true, Some(("http_403", Some(403))));
    assert_eq!(
        upload(&panel, &ack.session_token, id, &changed_same_revision).await?,
        StatusCode::CONFLICT
    );
    let downgrade = section(id, at + 2, 3, false, None);
    assert_eq!(
        upload(&panel, &ack.session_token, id, &downgrade).await?,
        StatusCode::NO_CONTENT
    );
    assert_history_false_zero(&view(&panel, server, &cookie).await?, at, "http_429");
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn deferred_cache_writes_cannot_regress_same_second_revisions_or_jobs(
    pool: PgPool,
) -> Result<()> {
    use sinan_panel::diagnostic_plugins::nodequality::node_queries::{
        parse_section, persist_section,
    };
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "延迟缓存并发夹具")
        .await?;
    prepare(&panel, server).await?;
    let record = create(&panel, server, &cookie).await?;
    let id = record["id"].as_str().unwrap();
    let at = record["created_at"].as_i64().unwrap();
    let first = section(id, at, 1, false, None);
    assert_eq!(
        upload(&panel, &ack.session_token, id, &first).await?,
        StatusCode::NO_CONTENT
    );
    let deferred = parse_section(
        &record["job"],
        &serde_json::from_value(first.clone())?,
        at,
        at + 390,
    )?;
    let failure = section(id, at, 2, true, Some(("http_429", Some(429))));
    assert_eq!(
        upload(&panel, &ack.session_token, id, &failure).await?,
        StatusCode::NO_CONTENT
    );
    // Reproduce an earlier accepted upload resuming its postcommit continuation
    // only after a newer revision has committed both chapter and cache.
    persist_section(&panel.state, server, deferred).await?;
    assert_history_false_zero(&view(&panel, server, &cookie).await?, at, "http_429");
    let conflicting_text = section(id, at, 2, true, Some(("http_403", Some(403))));
    let conflicting = parse_section(
        &record["job"],
        &serde_json::from_value(conflicting_text)?,
        at,
        at + 390,
    )?;
    persist_section(&panel.state, server, conflicting).await?;
    assert_history_false_zero(&view(&panel, server, &cookie).await?, at, "http_429");

    let latest_deferred = parse_section(
        &record["job"],
        &serde_json::from_value(failure)?,
        at,
        at + 390,
    )?;
    let final_response = panel.client.post(format!("{}/api/agent/v1/diagnostics/{id}", panel.base))
        .bearer_auth(&ack.session_token)
        .json(&json!({"id":id,"status":"succeeded","report":{"text":"TEST_ONLY completed node query"}}))
        .send().await?;
    assert_eq!(final_response.status(), StatusCode::NO_CONTENT);
    let next = create(&panel, server, &cookie).await?;
    assert!(
        next["job"]["node_query_generation"].as_i64().unwrap()
            > record["job"]["node_query_generation"].as_i64().unwrap()
    );
    let next_id = next["id"].as_str().unwrap();
    // Force identical creation and report seconds; lifecycle still creates these
    // jobs consecutively with only one active job at a time.
    sqlx::query("UPDATE diagnostic_jobs SET created_at=$2 WHERE id=$1::uuid")
        .bind(next_id)
        .bind(at)
        .execute(&panel.state.pool)
        .await?;
    let next_failure = section(next_id, at, 1, true, Some(("http_403", Some(403))));
    assert_eq!(
        upload(&panel, &ack.session_token, next_id, &next_failure).await?,
        StatusCode::NO_CONTENT
    );
    persist_section(&panel.state, server, latest_deferred).await?;
    let quality = view(&panel, server, &cookie).await?;
    assert_history_false_zero(&quality, at, "http_403");
    assert!(
        !quality.to_string().contains("_node_query_order"),
        "internal ordering never enters the public IP response"
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn credentials_removed_and_failed_refreshes_keep_success_across_panel_recreation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "凭证失效历史夹具")
        .await?;
    prepare(&panel, server).await?;
    let record = create(&panel, server, &cookie).await?;
    let id = record["id"].as_str().unwrap();
    let at = record["created_at"].as_i64().unwrap();
    assert_eq!(
        upload(
            &panel,
            &ack.session_token,
            id,
            &section(id, at, 1, false, None)
        )
        .await?,
        StatusCode::NO_CONTENT
    );
    for (index, (kind, status)) in [
        ("http_403", Some(403)),
        ("http_429", Some(429)),
        ("timeout", None),
        ("not_attempted", None),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            upload(
                &panel,
                &ack.session_token,
                id,
                &section(
                    id,
                    at + index as i64 + 1,
                    index as u64 + 2,
                    false,
                    Some((kind, status))
                )
            )
            .await?,
            StatusCode::NO_CONTENT
        );
        assert_history_false_zero(&view(&panel, server, &cookie).await?, at, kind);
    }
    let second = TestPanel::start(pool).await?;
    let cookie2 = second.admin_cookie().await?;
    let quality = view(&second, server, &cookie2).await?;
    assert_history_false_zero(&quality, at, "not_attempted");
    for entry in quality["quality"].as_array().unwrap() {
        assert_eq!(entry["databases"][0]["available"], false);
        assert_eq!(entry["databases"][0]["last_attempt_at"], at + 3);
    }
    Ok(())
}
