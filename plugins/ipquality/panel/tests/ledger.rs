use super::fixtures::{IP, body, chapter, saved_job, server, state, upload};
use crate::{error::ApiError, ip_quality};
use axum::http::StatusCode;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[sqlx::test(migrations = "../panel/migrations")]
async fn authenticated_partial_reports_are_atomic_idempotent_and_device_scoped(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await?;
    let first = server(&state, "TEST_ONLY first device").await?;
    let _other = server(&state, "TEST_ONLY second device").await?;
    let at = now_timestamp() - 100;
    let id = Uuid::new_v4();
    saved_job(&state, first, id, at).await?;
    let mut partial = body(id, at);
    partial["finished_at"] = Value::Null;
    let update = chapter(id, partial, at, 1, false);
    assert!(matches!(
        upload(&state, "TEST_ONLY second device", update.clone()).await,
        Err(ApiError::NotFound)
    ));
    assert_eq!(
        upload(&state, "TEST_ONLY first device", update.clone()).await?,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        upload(&state, "TEST_ONLY first device", update.clone()).await?,
        StatusCode::NO_CONTENT
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM server_ip_quality WHERE server_id=$1")
            .bind(first)
            .fetch_one(&state.pool)
            .await?;
    assert_eq!(count, 1);
    let view = ip_quality::view(&state, first).await?;
    assert_eq!(view.server_id, first);
    assert_eq!(view.ip_addresses, ["192.0.2.1"]);
    assert_eq!(view.node_quality.observed_egress_ips, [IP]);
    assert_eq!(view.node_quality.current_egress_ips, [IP]);
    assert!(!view.node_quality.ready);
    assert_eq!(view.quality[0].databases[0].status, "succeeded");
    assert!(!view.quality[0].databases[0].fields.is_empty());
    assert!(view.quality[0].databases[0].historical);
    assert_eq!(view.node_quality.reports[0].report_completeness, "partial");
    let mut forged = body(id, at);
    forged["artifact_sha256"] =
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(matches!(
        upload(
            &state,
            "TEST_ONLY first device",
            chapter(id, forged, at, 2, true)
        )
        .await,
        Err(ApiError::BadRequest(_))
    ));
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM diagnostic_report_sections WHERE job_id=$1")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    assert_eq!(revision, 1);
    let mut inconsistent = update;
    inconsistent.text.push(' ');
    assert!(matches!(
        upload(&state, "TEST_ONLY first device", inconsistent).await,
        Err(ApiError::Conflict(_))
    ));
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn failed_fresh_attempt_retains_success_and_older_generation_only_changes_history(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await?;
    let server = server(&state, "TEST_ONLY ledger device").await?;
    let at = now_timestamp() - 100;
    let old_id = Uuid::new_v4();
    let new_id = Uuid::new_v4();
    saved_job(&state, server, old_id, at).await?;
    // Same-second creation is ordered by the database sequence, not random UUIDs.
    saved_job(&state, server, new_id, at).await?;
    upload(
        &state,
        "TEST_ONLY ledger device",
        chapter(old_id, body(old_id, at), at, 1, true),
    )
    .await?;
    let mut failure = body(new_id, at + 1);
    failure["attempts"][1]["status"] = json!("failed");
    failure["attempts"][1]["error_kind"] = json!("http_429");
    failure["attempts"][1]["error_message"] = json!("TEST_ONLY rate limited");
    failure["attempts"][1]["http_status"] = json!(429);
    upload(
        &state,
        "TEST_ONLY ledger device",
        chapter(new_id, failure, at + 1, 1, true),
    )
    .await?;
    let view = ip_quality::view(&state, server).await?;
    let dataset = &view.quality[0].databases[0];
    assert_eq!(dataset.status, "failed");
    assert_eq!(dataset.last_success_at, Some(at));
    assert_eq!(
        dataset.last_error.as_ref().unwrap().kind,
        Some(crate::ip_quality::QueryErrorKind::Http429)
    );
    assert!(
        dataset
            .fields
            .iter()
            .any(|field| field.value.as_bool() == Some(false))
    );
    let before = serde_json::to_value(&view.quality)?;
    let late = chapter(old_id, body(old_id, at + 20), at + 20, 2, true);
    upload(&state, "TEST_ONLY ledger device", late).await?;
    let after = ip_quality::view(&state, server).await?;
    assert_eq!(serde_json::to_value(&after.quality)?, before);
    let row = sqlx::query("SELECT revision FROM diagnostic_report_sections WHERE job_id=$1")
        .bind(old_id)
        .fetch_one(&state.pool)
        .await?;
    assert_eq!(row.get::<i64, _>("revision"), 2);
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn a_discovery_failure_invalidates_current_observation_without_erasing_old_data(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await?;
    let server = server(&state, "TEST_ONLY discovery device").await?;
    let at = now_timestamp() - 100;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    saved_job(&state, server, first, at).await?;
    saved_job(&state, server, second, at + 1).await?;
    upload(
        &state,
        "TEST_ONLY discovery device",
        chapter(first, body(first, at), at, 1, true),
    )
    .await?;
    let mut failed = body(second, at + 1);
    failed["egress_ip"] = Value::Null;
    failed["upstream"] = Value::Null;
    failed["attempts"].as_array_mut().unwrap().truncate(1);
    failed["attempts"][0]["target_ip"] = Value::Null;
    failed["attempts"][0]["status"] = json!("failed");
    failed["attempts"][0]["error_kind"] = json!("timeout");
    failed["attempts"][0]["error_message"] = json!("TEST_ONLY discovery timeout");
    failed["attempts"][0]["curl_exit"] = json!(28);
    failed["attempts"][0]["http_status"] = Value::Null;
    upload(
        &state,
        "TEST_ONLY discovery device",
        chapter(second, failed, at + 1, 1, true),
    )
    .await?;
    let view = ip_quality::view(&state, server).await?;
    assert!(view.node_quality.current_egress_ips.is_empty());
    assert_eq!(view.node_quality.observed_egress_ips, [IP]);
    assert!(!view.quality[0].databases[0].fields.is_empty());
    assert!(view.quality[0].databases[0].historical);
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn chapter_storage_failure_rolls_back_cache_and_watermark_together(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await?;
    let server = server(&state, "TEST_ONLY transaction device").await?;
    let at = now_timestamp() - 100;
    let id = Uuid::new_v4();
    saved_job(&state, server, id, at).await?;
    sqlx::raw_sql("CREATE FUNCTION reject_test_node_chapter() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'TEST_ONLY chapter persistence rejected'; END; $$; CREATE TRIGGER reject_test_node_chapter BEFORE INSERT ON diagnostic_report_sections FOR EACH ROW EXECUTE FUNCTION reject_test_node_chapter();")
        .execute(&state.pool).await?;
    assert!(matches!(
        upload(
            &state,
            "TEST_ONLY transaction device",
            chapter(id, body(id, at), at, 1, true)
        )
        .await,
        Err(ApiError::Database(_))
    ));
    for table in [
        "server_ip_quality",
        "server_ip_quality_datasets",
        "server_ip_quality_node_generations",
    ] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE server_id=$1"))
                .bind(server)
                .fetch_one(&state.pool)
                .await?;
        assert_eq!(count, 0, "{table}");
    }
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn unrelated_cleanup_or_cancellation_blocks_new_ip_work_after_its_expiry(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await?;
    let server = server(&state, "TEST_ONLY mutual exclusion device").await?;
    let at = now_timestamp() - 100;
    let id = Uuid::new_v4();
    saved_job(&state, server, id, at).await?;
    sqlx::query("UPDATE diagnostic_jobs SET job=jsonb_set(job,'{plugin}','\"tcpquality\"'),status='cleaning',expires_at=$2 WHERE id=$1")
        .bind(id).bind(now_timestamp()-1).execute(&state.pool).await?;
    for status in ["cleaning", "cancel_requested"] {
        sqlx::query("UPDATE diagnostic_jobs SET status=$2 WHERE id=$1")
            .bind(id)
            .bind(status)
            .execute(&state.pool)
            .await?;
        let view = ip_quality::view(&state, server).await?;
        assert!(!view.node_quality.ready);
        assert!(
            view.node_quality
                .reason
                .as_deref()
                .unwrap()
                .contains("已有诊断")
        );
        assert!(view.node_quality.reports.is_empty());
    }
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn later_partial_dataset_preserves_completed_siblings_and_success_times(
    pool: PgPool,
) -> anyhow::Result<()> {
    let state = state(pool).await?;
    let server = server(&state, "TEST_ONLY partial dataset device").await?;
    let at = now_timestamp() - 100;
    let id = Uuid::new_v4();
    saved_job(&state, server, id, at).await?;
    let mut first = body(id, at);
    first["finished_at"] = Value::Null;
    upload(
        &state,
        "TEST_ONLY partial dataset device",
        chapter(id, first, at, 1, false),
    )
    .await?;
    let mut next = body(id, at + 10);
    next["finished_at"] = Value::Null;
    next["attempts"][1]["dataset"] = json!("IP2LOCATION");
    next["attempts"][1]["url"] = json!("https://ipinfo.check.place/fixture-next");
    next["upstream"]["Score"] = json!({"IP2LOCATION":"7"});
    next["upstream"]["Type"] = json!({});
    next["upstream"]["Factor"] = json!({});
    upload(
        &state,
        "TEST_ONLY partial dataset device",
        chapter(id, next, at + 10, 2, false),
    )
    .await?;
    let view = ip_quality::view(&state, server).await?;
    let entry = &view.quality[0];
    assert_eq!(entry.databases.len(), 2);
    let original = entry
        .databases
        .iter()
        .find(|dataset| dataset.database == "node-ipapi")
        .unwrap();
    let latest = entry
        .databases
        .iter()
        .find(|dataset| dataset.database == "node-IP2LOCATION")
        .unwrap();
    assert_eq!(original.last_success_at, Some(at));
    assert_eq!(latest.last_success_at, Some(at + 10));
    assert_eq!(view.node_quality.reports[0].report_completeness, "partial");
    Ok(())
}
