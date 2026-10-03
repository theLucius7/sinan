#![forbid(unsafe_code)]
mod business_support;
#[path = "probe_support.rs"]
mod probe_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::probes::ConfiguredProbe;
use sinan_protocol::{
    PROBE_LEASE_CAPABILITY, ProbeBatch, ProbeExecution, ProbeLease, ProbeResult, TaskAck,
    now_timestamp, telemetry::now_millis,
};
use sqlx::PgPool;
use uuid::Uuid;

fn spec() -> Value {
    probe_support::authorized(
        json!({"id":Uuid::nil(),"name":"授权夹具","kind":"tcp","target":"127.0.0.1",
        "port":443,"interval_secs":10,"carrier":"fixture","enabled":true}),
    )
}

async fn capable(panel: &TestPanel, server: i64) -> Result<()> {
    sqlx::query("UPDATE servers SET capabilities=capabilities || $2 WHERE id=$1")
        .bind(server)
        .bind(json!([PROBE_LEASE_CAPABILITY]))
        .execute(&panel.state.pool)
        .await?;
    Ok(())
}

async fn lease(panel: &TestPanel, token: &str) -> Result<ProbeLease> {
    Ok(panel
        .client
        .get(format!("{}/api/agent/v1/probe-lease", panel.base))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn configured(panel: &TestPanel, cookie: &str, server: i64) -> Result<ConfiguredProbe> {
    Ok(panel
        .admin(
            Method::POST,
            &format!("/api/servers/{server}/probes"),
            cookie,
            Some(spec()),
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn sample(lease: &ProbeLease) -> ProbeResult {
    ProbeResult {
        id: Uuid::new_v4(),
        probe_id: lease.probes[0].spec.id,
        sampled_at: now_millis(),
        latency_ms: Some(1.0),
        loss_percent: 0.0,
        error: None,
        address_family: Some(sinan_protocol::ProbeAddressFamily::Ipv4),
        attempts: Some(4),
        execution: Some(ProbeExecution {
            lease_id: lease.id,
            revision: lease.revision,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            probe: lease.probes[0].clone(),
        }),
    }
}

async fn ingest(panel: &TestPanel, token: &str, results: Vec<ProbeResult>) -> Result<TaskAck> {
    Ok(panel
        .client
        .post(format!("{}/api/agent/v1/probe-results", panel.base))
        .bearer_auth(token)
        .json(&ProbeBatch { results })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[sqlx::test]
async fn issuance_requires_capability_and_reuses_only_the_same_device_session(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "lease issuance")
        .await?;
    let probe = configured(&panel, &cookie, server).await?;
    assert_eq!(probe.revision, Some(1));
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/agent/v1/probe-lease", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    capable(&panel, server).await?;
    let first = lease(&panel, &ack.session_token).await?;
    assert!(first.valid());
    assert_eq!(first.server_id, server);
    assert_eq!(first.expires_at - first.issued_at, 90);
    assert_eq!(first, lease(&panel, &ack.session_token).await?);
    let second_token = "TEST_ONLY independent session";
    sqlx::query("INSERT INTO sessions(token_hash,server_id,expires_at) VALUES($1,$2,$3)")
        .bind(sinan_panel::auth::hash_token(second_token))
        .bind(server)
        .bind(now_timestamp() + 60)
        .execute(&panel.state.pool)
        .await?;
    let second = lease(&panel, second_token).await?;
    assert_ne!(first.id, second.id);
    assert_eq!(first.revision, second.revision);
    assert_eq!(first.probes, second.probes);
    let old: Vec<Value> = panel
        .client
        .get(format!("{}/api/agent/v1/probes", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(old[0].as_object().unwrap().len(), 8);
    assert_eq!(old[0]["enabled"], false);
    let receipt: Value = sqlx::query_scalar("SELECT probe_digests FROM probe_leases WHERE id=$1")
        .bind(first.id)
        .fetch_one(&panel.state.pool)
        .await?;
    assert!(
        receipt[probe.id.to_string()]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    assert!(!serde_json::to_string(&receipt)?.contains("fixture inventory"));
    Ok(())
}

#[sqlx::test]
async fn exact_receipts_control_results_and_duplicates_survive_revocation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "proved result").await?;
    let probe = configured(&panel, &cookie, server).await?;
    capable(&panel, server).await?;
    let issued = lease(&panel, &ack.session_token).await?;
    let accepted = sample(&issued);
    let mut forged = accepted.clone();
    forged.id = Uuid::new_v4();
    forged.execution.as_mut().unwrap().lease_id = Uuid::new_v4();
    let mut unproved = accepted.clone();
    unproved.id = Uuid::new_v4();
    unproved.execution = None;
    // Capability loss or an Agent downgrade never turns an unproved sample into permission.
    sqlx::query("UPDATE servers SET capabilities='[]'::jsonb WHERE id=$1")
        .bind(server)
        .execute(&panel.state.pool)
        .await?;
    let acked = ingest(
        &panel,
        &ack.session_token,
        vec![forged.clone(), unproved.clone(), accepted.clone()],
    )
    .await?;
    capable(&panel, server).await?;
    assert_eq!(acked.ids, vec![forged.id, unproved.id, accepted.id]);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM probe_results WHERE server_id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(count, 1);
    let mut revoked = json!(probe);
    revoked["enabled"] = json!(false);
    revoked["monitor"]["authorization"]["enabled"] = json!(false);
    panel
        .admin(
            Method::PATCH,
            &format!("/api/servers/{server}/probes/{}", probe.id),
            &cookie,
            Some(revoked.clone()),
        )
        .await?
        .error_for_status()?;
    let current = lease(&panel, &ack.session_token).await?;
    assert!(current.probes.is_empty());
    assert!(current.revision > issued.revision);
    let mut late = accepted.clone();
    late.id = Uuid::new_v4();
    assert_eq!(
        ingest(&panel, &ack.session_token, vec![accepted.clone(), late])
            .await?
            .ids
            .len(),
        2
    );
    let saved: (Value, String) =
        sqlx::query_as("SELECT result,digest FROM probe_results WHERE id=$1")
            .bind(accepted.id)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(saved.0, json!(accepted));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM probe_results WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?,
        1
    );
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &format!("/api/servers/{server}/probes/{}", probe.id),
                &cookie,
                Some(revoked)
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("/api/servers/{server}/probes/{}", probe.id),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    Ok(())
}

#[sqlx::test]
async fn old_unproved_spool_drains_without_blocking_fresh_proved_results(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, device) = panel
        .authenticated_device(&cookie, "old unproved spool")
        .await?;
    configured(&panel, &cookie, server).await?;
    capable(&panel, server).await?;
    let issued = lease(&panel, &device.session_token).await?;
    assert!(issued.valid());
    let fresh = sample(&issued);
    let mut old = fresh.clone();
    old.id = Uuid::new_v4();
    old.sampled_at -= 8 * 86_400_000;
    old.execution = None;
    let mut future = fresh.clone();
    future.id = Uuid::new_v4();
    future.sampled_at += 3_600_000;
    future.execution = None;
    let results = vec![old.clone(), future.clone(), fresh.clone()];
    assert_eq!(
        ingest(&panel, &device.session_token, results.clone())
            .await?
            .ids,
        vec![old.id, future.id, fresh.id]
    );
    let saved: (Value, String) =
        sqlx::query_as("SELECT result,digest FROM probe_results WHERE id=$1")
            .bind(fresh.id)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(saved.0, json!(fresh));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM probe_results WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?,
        1
    );
    assert_eq!(
        ingest(&panel, &device.session_token, results).await?.ids,
        vec![old.id, future.id, fresh.id]
    );
    assert_eq!(
        sqlx::query_as::<_, (Value, String)>("SELECT result,digest FROM probe_results WHERE id=$1")
            .bind(fresh.id)
            .fetch_one(&panel.state.pool)
            .await?,
        saved
    );

    // New proved records retain their time window, even with a coherent context.
    for sampled_at in [old.sampled_at, future.sampled_at] {
        let mut outside = fresh.clone();
        outside.id = Uuid::new_v4();
        outside.sampled_at = sampled_at;
        let execution = outside.execution.as_mut().unwrap();
        execution.issued_at = sampled_at.div_euclid(1_000);
        execution.expires_at = execution.issued_at + 90;
        assert!(execution.valid());
        assert_eq!(
            panel
                .client
                .post(format!("{}/api/agent/v1/probe-results", panel.base))
                .bearer_auth(&device.session_token)
                .json(&ProbeBatch {
                    results: vec![outside],
                })
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut malformed = old.clone();
    malformed.loss_percent = 101.0;
    let mut collision = old;
    collision.id = fresh.id;
    for (result, expected) in [
        (malformed, StatusCode::BAD_REQUEST),
        (collision, StatusCode::CONFLICT),
    ] {
        assert_eq!(
            panel
                .client
                .post(format!("{}/api/agent/v1/probe-results", panel.base))
                .bearer_auth(&device.session_token)
                .json(&ProbeBatch {
                    results: vec![result],
                })
                .send()
                .await?
                .status(),
            expected
        );
    }
    Ok(())
}

#[sqlx::test]
async fn natural_expiry_changes_revision_and_receipt_retention_is_bounded(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "expiry").await?;
    let probe = configured(&panel, &cookie, server).await?;
    capable(&panel, server).await?;
    let first = lease(&panel, &ack.session_token).await?;
    sqlx::query("UPDATE network_probes SET spec=jsonb_set(spec,'{monitor,authorization,expires_at}',to_jsonb($2::bigint)) WHERE id=$1")
        .bind(probe.id).bind(now_timestamp()-1).execute(&panel.state.pool).await?;
    let expired = lease(&panel, &ack.session_token).await?;
    assert!(expired.probes.is_empty());
    assert!(expired.revision > first.revision);
    sqlx::query("INSERT INTO probe_leases(id,server_id,session_hash,revision,issued_at,expires_at,probe_digests) SELECT md5(i::text)::uuid,$1,'TEST_ONLY old receipt',0,$2::bigint-i,$2::bigint-i+90,'{}'::jsonb FROM generate_series(1,513) i")
        .bind(server).bind(now_timestamp()-12_000).execute(&panel.state.pool).await?;
    sqlx::query(
        "UPDATE probe_leases SET issued_at=issued_at-30,expires_at=expires_at-30 WHERE id=$1",
    )
    .bind(expired.id)
    .execute(&panel.state.pool)
    .await?;
    lease(&panel, &ack.session_token).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM probe_leases WHERE server_id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    assert!(count <= 512);
    let old: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM probe_leases WHERE server_id=$1 AND issued_at<$2")
            .bind(server)
            .bind(now_timestamp() - 10_800)
            .fetch_one(&panel.state.pool)
            .await?;
    assert_eq!(old, 0);
    Ok(())
}

#[sqlx::test]
async fn anonymous_history_redacts_execution_proof_but_preserves_monitor_fields(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "public projection")
        .await?;
    configured(&panel, &cookie, server).await?;
    capable(&panel, server).await?;
    let issued = lease(&panel, &ack.session_token).await?;
    ingest(&panel, &ack.session_token, vec![sample(&issued)]).await?;
    panel.admin(Method::PATCH,"/api/settings",&cookie,Some(json!({"public_dashboard":true,"offline_alerts":false,"offline_minutes":2,"telegram_enabled":false,"telegram_chat_id":""}))).await?.error_for_status()?;
    let public: Value = panel
        .client
        .get(format!("{}/api/dashboard/probes/overview", panel.base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(public[0]["probe"]["monitor"]["authorization"].is_null());
    assert_eq!(public[0]["probe"]["monitor"]["address_family"], "any");
    assert!(public[0]["results"][0].get("execution").is_none());
    let wire = serde_json::to_string(&public)?;
    assert!(!wire.contains("fixture inventory"));
    assert!(!wire.contains("lease_id"));
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn append_only_0035_preserves_all_existing_migrations_grants_and_history(
    pool: PgPool,
) -> Result<()> {
    use sqlx::migrate::Migrator;
    use std::borrow::Cow;
    let migrations = sqlx::migrate!();
    let previous = Migrator {
        migrations: Cow::Owned(
            migrations
                .iter()
                .filter(|migration| migration.version <= 34)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    previous.run(&pool).await?;
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY migration') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let id = Uuid::new_v4();
    let result_id = Uuid::new_v4();
    let mut granted = spec();
    granted["id"] = json!(id);
    let result = json!({"id":result_id,"probe_id":id,"sampled_at":1000,"latency_ms":0.0,"loss_percent":0.0,"error":null});
    sqlx::query("INSERT INTO network_probes(id,server_id,spec) VALUES($1,$2,$3)")
        .bind(id)
        .bind(server)
        .bind(&granted)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO probe_results(id,server_id,probe_id,sampled_at,result,digest) VALUES($1,$2,$3,1000,$4,'TEST_ONLY exact retained digest')").bind(result_id).bind(server).bind(id).bind(&result).execute(&pool).await?;
    let checksums: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await?;
    migrations.run(&pool).await?;
    let preserved: (Value, i64) =
        sqlx::query_as("SELECT spec,revision FROM network_probes WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(preserved, (granted, 1));
    assert_eq!(
        sqlx::query_scalar::<_, Value>("SELECT result FROM probe_results WHERE id=$1")
            .bind(result_id)
            .fetch_one(&pool)
            .await?,
        result
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT version,checksum FROM _sqlx_migrations WHERE version<=34 ORDER BY version"
        )
        .fetch_all(&pool)
        .await?,
        checksums
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT MAX(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await?,
        migrations
            .iter()
            .map(|migration| migration.version)
            .max()
            .expect("workspace migrations")
    );
    Ok(())
}
