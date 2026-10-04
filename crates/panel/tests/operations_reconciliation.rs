#![forbid(unsafe_code)]
mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{
    auth::{hash_token, random_token},
    operations,
};
use sinan_protocol::{
    fleet::{AccessPolicy, JobResult, OPERATIONS_CAPABILITY, Operation, Work},
    now_timestamp,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

async fn fixture(panel: &TestPanel, cookie: &str) -> Result<(i64, Uuid, Uuid, String)> {
    let server = panel
        .create_server(cookie, "TEST_ONLY unknown automation")
        .await?;
    let now = now_timestamp();
    sqlx::query("UPDATE servers SET capabilities=$2 WHERE id=$1")
        .bind(server)
        .bind(json!([OPERATIONS_CAPABILITY]))
        .execute(&panel.state.pool)
        .await?;
    let policy = AccessPolicy {
        services: vec!["TEST_ONLY.service".into()],
        ..AccessPolicy::default()
    };
    sqlx::query("INSERT INTO fleet_profiles(server_id,policy) VALUES($1,$2)")
        .bind(server)
        .bind(json!(policy))
        .execute(&panel.state.pool)
        .await?;
    let job = Uuid::new_v4();
    let plan = json!({"name":"TEST_ONLY unknown operation","steps":[{"kind":"service_restart","service":"TEST_ONLY.service","timeout_secs":60}],"batch_size":1,"concurrency":1,"pause_between_batches":false,"max_duration_secs":3600});
    sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,'TEST_ONLY unknown automation',1,$2,$3,'uncertain',$4,$4,$5,$6)").bind(job).bind(json!({"plan":plan})).bind(vec![server]).bind(now-700).bind(now+3600).bind("0".repeat(64)).execute(&panel.state.pool).await?;
    let original = Uuid::new_v4();
    sqlx::query("INSERT INTO fleet_operations(id,server_id,operation,policy,requested_by,automation_job_id,requested_at,expires_at,status,dispatched_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,'unknown',$6)").bind(original).bind(server).bind(json!(Operation::Service { unit:"TEST_ONLY.service".into(), action:"restart".into() })).bind(json!(policy)).bind(job).bind(now-700).bind(now-600).execute(&panel.state.pool).await?;
    sqlx::query("INSERT INTO operations_target_steps(job_id,server_id,position,batch,state,fleet_operation_id) VALUES($1,$2,0,0,'uncertain',$3)").bind(job).bind(server).bind(original).execute(&panel.state.pool).await?;
    sqlx::query(
        "INSERT INTO operations_server_locks(server_id,job_id,acquired_at) VALUES($1,$2,$3)",
    )
    .bind(server)
    .bind(job)
    .bind(now - 700)
    .execute(&panel.state.pool)
    .await?;
    let token = random_token();
    sqlx::query("INSERT INTO sessions(token_hash,server_id,expires_at) VALUES($1,$2,$3)")
        .bind(hash_token(&token))
        .bind(server)
        .bind(now + 3600)
        .execute(&panel.state.pool)
        .await?;
    Ok((server, job, original, token))
}

async fn inspect(
    panel: &TestPanel,
    cookie: &str,
    server: i64,
    job: Uuid,
    original: Uuid,
) -> Result<Uuid> {
    let value: Value = panel
        .admin(
            Method::POST,
            &format!("/api/operations/jobs/{job}/inspection"),
            cookie,
            Some(json!({"server_id":server,"operation_id":original})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(value["reconciliation_of"], original.to_string());
    assert_eq!(value["read_only"], true);
    Ok(Uuid::parse_str(
        value["id"].as_str().context("inspection id")?,
    )?)
}

async fn receipt(panel: &TestPanel, token: &str, id: Uuid, completed: i64) -> Result<JobResult> {
    let result = JobResult {
        id,
        succeeded: true,
        result: json!({"active":false,"source":"TEST_ONLY controlled Agent receipt"}),
        error: None,
        completed_at: completed,
    };
    panel
        .client
        .post(format!("{}/api/agent/v1/fleet/results", panel.base))
        .bearer_auth(token)
        .json(&result)
        .send()
        .await?
        .error_for_status()?;
    Ok(result)
}

#[sqlx::test]
async fn manual_automation_reconciliation_requires_fresh_linked_inspection_and_preserves_late_receipts(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, job, original, token) = fixture(&panel, &cookie).await?;
    let inspection = inspect(&panel, &cookie, server, job, original).await?;
    let work: Work = panel
        .client
        .get(format!("{}/api/agent/v1/fleet/work", panel.base))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(work.jobs.len(), 1);
    assert_eq!(work.jobs[0].id, inspection);
    assert!(
        matches!(&work.jobs[0].operation, Operation::Service { action, .. } if action=="status")
    );
    let request = json!({"server_id":server,"operation_id":original,"inspection_id":inspection,"process_stopped":true,"cleanup_confirmed":true,"observed_at":now_timestamp(),"evidence":"TEST_ONLY exact process and cleanup inspection conclusion"});
    let path = format!("/api/operations/jobs/{job}/reconcile");
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(request.clone()))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    receipt(&panel, &token, inspection, now_timestamp() - 301).await?;
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(request.clone()))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let inspection = inspect(&panel, &cookie, server, job, original).await?;
    let work: Work = panel
        .client
        .get(format!("{}/api/agent/v1/fleet/work", panel.base))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(work.jobs[0].id, inspection);
    receipt(&panel, &token, inspection, now_timestamp()).await?;
    let metadata: Value = panel
        .admin(
            Method::GET,
            &format!("/api/fleet/operations/{inspection}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(metadata["server_id"], server);
    assert_eq!(metadata["reconciliation_of"], original.to_string());
    let mut request = request;
    request["inspection_id"] = json!(Uuid::new_v4());
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(request.clone()))
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    request["inspection_id"] = json!(inspection);
    request["cleanup_confirmed"] = json!(false);
    assert_eq!(
        panel
            .admin(Method::POST, &path, &cookie, Some(request.clone()))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    request["cleanup_confirmed"] = json!(true);
    let value: Value = panel
        .admin(Method::POST, &path, &cookie, Some(request))
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(value["original_receipt_preserved"], true);
    let row = sqlx::query(
        "SELECT status,result,result_digest,reconciled_at FROM fleet_operations WHERE id=$1",
    )
    .bind(original)
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(row.get::<String, _>("status"), "unknown");
    assert!(row.get::<Option<Value>, _>("result").is_none());
    assert!(row.get::<Option<String>, _>("result_digest").is_none());
    assert!(row.get::<Option<i64>, _>("reconciled_at").is_some());
    operations::tick(&panel.state).await?;
    let state: String = sqlx::query_scalar(
        "SELECT state FROM operations_target_steps WHERE job_id=$1 AND server_id=$2",
    )
    .bind(job)
    .bind(server)
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(state, "failed");
    let late = receipt(&panel, &token, original, now_timestamp()).await?;
    panel
        .client
        .post(format!("{}/api/agent/v1/fleet/results", panel.base))
        .bearer_auth(&token)
        .json(&late)
        .send()
        .await?
        .error_for_status()?;
    let row = sqlx::query("SELECT status,result,reconciliation FROM fleet_operations WHERE id=$1")
        .bind(original)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(row.get::<String, _>("status"), "succeeded");
    assert_eq!(row.get::<Value, _>("result"), json!(late));
    assert!(row.get::<Option<Value>, _>("reconciliation").is_some());
    operations::tick(&panel.state).await?;
    let state: String = sqlx::query_scalar(
        "SELECT state FROM operations_target_steps WHERE job_id=$1 AND server_id=$2",
    )
    .bind(job)
    .bind(server)
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(state, "failed");
    let locks: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_server_locks WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(locks, 0);
    Ok(())
}

#[sqlx::test]
async fn operations_only_grant_cannot_inspect_or_reconcile_service_work(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, job, original, _) = fixture(&panel, &cookie).await?;
    let actor: i64 = sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id").fetch_one(&panel.state.pool).await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,capabilities,created_at,updated_at) VALUES($1,'ops_only','TEST_ONLY operations only','operator','[\"operations:read\",\"operations:write\"]',0,0)").bind(actor).execute(&panel.state.pool).await?;
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(actor)
        .bind(server)
        .execute(&panel.state.pool)
        .await?;
    let token = random_token();
    let hash = hash_token(&token);
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
        .bind(&hash)
        .bind(actor)
        .bind(now_timestamp() + 3600)
        .execute(&panel.state.pool)
        .await?;
    sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$2+300)").bind(hash).bind(now_timestamp()).execute(&panel.state.pool).await?;
    let cookie = format!("sinan_session={token}");
    for (action, body) in [
        (
            "inspection",
            json!({"server_id":server,"operation_id":original}),
        ),
        (
            "reconcile",
            json!({"server_id":server,"operation_id":original,"inspection_id":Uuid::new_v4(),"process_stopped":true,"cleanup_confirmed":true,"observed_at":now_timestamp(),"evidence":"TEST_ONLY unauthorized process stop and cleanup conclusion"}),
        ),
    ] {
        assert_eq!(
            panel
                .admin(
                    Method::POST,
                    &format!("/api/operations/jobs/{job}/{action}"),
                    &cookie,
                    Some(body)
                )
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let row = sqlx::query("SELECT status,reconciled_at FROM fleet_operations WHERE id=$1")
        .bind(original)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(row.get::<String, _>("status"), "unknown");
    assert!(row.get::<Option<i64>, _>("reconciled_at").is_none());
    let locks: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_server_locks WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(locks, 1);
    Ok(())
}

#[sqlx::test]
async fn read_only_inspection_cannot_cross_an_unrelated_automation_lock(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, job, original, token) = fixture(&panel, &cookie).await?;
    let inspection = inspect(&panel, &cookie, server, job, original).await?;
    let unrelated = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) SELECT $2,'TEST_ONLY unrelated lock',requested_by,spec,targets,'uncertain',created_at,updated_at,expires_at,preview_digest FROM operations_jobs WHERE id=$1")
        .bind(job).bind(unrelated).execute(&panel.state.pool).await?;
    sqlx::query("UPDATE operations_server_locks SET job_id=$2 WHERE server_id=$1")
        .bind(server)
        .bind(unrelated)
        .execute(&panel.state.pool)
        .await?;
    let work: Work = panel
        .client
        .get(format!("{}/api/agent/v1/fleet/work", panel.base))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(work.jobs.is_empty());
    let status: String = sqlx::query_scalar("SELECT status FROM fleet_operations WHERE id=$1")
        .bind(inspection)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(status, "queued");
    sqlx::query("UPDATE operations_server_locks SET job_id=$2 WHERE server_id=$1")
        .bind(server)
        .bind(job)
        .execute(&panel.state.pool)
        .await?;
    let work: Work = panel
        .client
        .get(format!("{}/api/agent/v1/fleet/work", panel.base))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(work.jobs.len(), 1);
    assert_eq!(work.jobs[0].id, inspection);
    Ok(())
}

#[sqlx::test]
async fn real_original_receipt_during_inspection_rejects_the_outdated_manual_conclusion(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, job, original, token) = fixture(&panel, &cookie).await?;
    let inspection = inspect(&panel, &cookie, server, job, original).await?;
    let work: Work = panel
        .client
        .get(format!("{}/api/agent/v1/fleet/work", panel.base))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(work.jobs[0].id, inspection);
    let actual = receipt(&panel, &token, original, now_timestamp()).await?;
    let digest: String =
        sqlx::query_scalar("SELECT result_digest FROM fleet_operations WHERE id=$1")
            .bind(original)
            .fetch_one(&panel.state.pool)
            .await?;
    receipt(&panel, &token, inspection, now_timestamp()).await?;
    let request = json!({"server_id":server,"operation_id":original,"inspection_id":inspection,"process_stopped":true,"cleanup_confirmed":true,"observed_at":now_timestamp(),"evidence":"TEST_ONLY outdated manual process and cleanup conclusion"});
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/operations/jobs/{job}/reconcile"),
                &cookie,
                Some(request)
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let row = sqlx::query(
        "SELECT status,result,result_digest,reconciled_at FROM fleet_operations WHERE id=$1",
    )
    .bind(original)
    .fetch_one(&panel.state.pool)
    .await?;
    assert_eq!(row.get::<String, _>("status"), "succeeded");
    assert_eq!(row.get::<Value, _>("result"), json!(actual));
    assert_eq!(row.get::<String, _>("result_digest"), digest);
    assert!(row.get::<Option<i64>, _>("reconciled_at").is_none());
    Ok(())
}

#[sqlx::test]
async fn reconciliation_never_waits_through_an_auth_change_or_mutates_after_revocation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, job, original, _) = fixture(&panel, &cookie).await?;
    let hash = hash_token(
        cookie
            .strip_prefix("sinan_session=")
            .context("controlled admin cookie")?,
    );
    let original_body = json!({"server_id":server,"operation_id":original,"inspection_id":Uuid::new_v4(),"process_stopped":true,"cleanup_confirmed":true,"observed_at":now_timestamp(),"evidence":"TEST_ONLY current process and cleanup observation evidence"});
    for (query, binds_hash) in [
        (
            "SELECT admin_id FROM administrator_profiles WHERE admin_id=1 FOR UPDATE",
            false,
        ),
        (
            "SELECT admin_id FROM sessions WHERE token_hash=$1 FOR UPDATE",
            true,
        ),
        (
            "SELECT session_hash FROM administrator_reauth WHERE session_hash=$1 FOR UPDATE",
            true,
        ),
    ] {
        let mut change = panel.state.pool.begin().await?;
        if binds_hash {
            sqlx::query(query)
                .bind(&hash)
                .fetch_one(&mut *change)
                .await?;
        } else {
            sqlx::query(query).fetch_one(&mut *change).await?;
        }
        for (action, body) in [
            (
                "inspection",
                json!({"server_id":server,"operation_id":original}),
            ),
            ("reconcile", original_body.clone()),
        ] {
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                panel.admin(
                    Method::POST,
                    &format!("/api/operations/jobs/{job}/{action}"),
                    &cookie,
                    Some(body),
                ),
            )
            .await??;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let error: Value = response.json().await?;
            assert!(
                error.to_string().contains("正在变更"),
                "final auth lock must reject contention before receipt validation"
            );
        }
        change.rollback().await?;
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fleet_operations WHERE reconciliation_of=$1")
            .bind(original)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(count, 0);
    let row = sqlx::query("SELECT status,reconciled_at FROM fleet_operations WHERE id=$1")
        .bind(original)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(row.get::<String, _>("status"), "unknown");
    assert!(row.get::<Option<i64>, _>("reconciled_at").is_none());
    let locks: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_server_locks WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(locks, 1);
    sqlx::query(
        "UPDATE administrator_profiles SET enabled=false,revision=revision+1 WHERE admin_id=1",
    )
    .execute(&panel.state.pool)
    .await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("/api/operations/jobs/{job}/inspection"),
                &cookie,
                Some(json!({"server_id":server,"operation_id":original}))
            )
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE administrator_profiles SET enabled=true WHERE admin_id=1")
        .execute(&panel.state.pool)
        .await?;
    sqlx::query("UPDATE fleet_operations SET automation_job_id=NULL WHERE id=$1")
        .bind(original)
        .execute(&panel.state.pool)
        .await?;
    for query in [
        "SELECT admin_id FROM administrator_profiles WHERE admin_id=1 FOR UPDATE",
        "SELECT session_hash FROM administrator_reauth WHERE session_hash=$1 FOR UPDATE",
    ] {
        let mut change = panel.state.pool.begin().await?;
        if query.contains("$1") {
            sqlx::query(query)
                .bind(&hash)
                .fetch_one(&mut *change)
                .await?;
        } else {
            sqlx::query(query).fetch_one(&mut *change).await?;
        }
        for (action, body) in [
            ("inspection", json!({})),
            (
                "reconcile",
                json!({"inspection_id":Uuid::new_v4(),"outcome":"unknown","conclusion":"TEST_ONLY independent original and cleanup observation evidence","processes_stopped":true,"cleanup_confirmed":true}),
            ),
        ] {
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                panel.admin(
                    Method::POST,
                    &format!("/api/fleet/operations/{original}/{action}"),
                    &cookie,
                    Some(body),
                ),
            )
            .await??;
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let error: Value = response.json().await?;
            assert!(error.to_string().contains("正在变更"));
        }
        change.rollback().await?;
    }
    let row = sqlx::query("SELECT status,reconciled_at FROM fleet_operations WHERE id=$1")
        .bind(original)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(row.get::<String, _>("status"), "unknown");
    assert!(row.get::<Option<i64>, _>("reconciled_at").is_none());
    Ok(())
}
