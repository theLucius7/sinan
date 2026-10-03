#![forbid(unsafe_code)]

mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result, ensure};
use business_support::{TestPanel, deployment::observe, id};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{plugins::singbox::entitlements, publisher};
use sinan_protocol::{Bundle, UsageBatch, UsageRecord, now_timestamp};
use sqlx::PgPool;
use uuid::Uuid;

const ROOT: &str = "/api/plugins/sing-box";

async fn scenario(panel: &TestPanel, cookie: &str) -> Result<(i64, i64, i64)> {
    let server = panel.create_server(cookie, "Deployment gate").await?;
    let node = id(&panel
        .create_node(cookie, server, "Ordinary listener")
        .await?)?;
    let account = id(&panel.create_user(cookie, "Authorized account").await?)?;
    panel.grant(cookie, account, node).await?;
    Ok((server, node, account))
}

async fn due(panel: &TestPanel, server: i64) -> Result<()> {
    // Advance only the debounce fixture clock; never create a confirmation or deployment.
    sqlx::query("UPDATE servers SET dirty_at=0 WHERE id=$1 AND dirty_at IS NOT NULL")
        .bind(server)
        .execute(&panel.state.pool)
        .await?;
    publisher::publish_due(&panel.state).await
}

async fn revision(pool: &PgPool, server: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(MAX(rev),0) FROM deployments WHERE server_id=$1 AND module='singbox'",
    )
    .bind(server)
    .fetch_one(pool)
    .await?)
}

async fn pending(pool: &PgPool, server: i64) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT dirty_at IS NOT NULL FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(pool)
            .await?,
    )
}

async fn confirm(
    panel: &TestPanel,
    cookie: &str,
    server: i64,
    request: Uuid,
) -> Result<reqwest::Response> {
    panel
        .admin(
            Method::POST,
            &format!("{ROOT}/servers/{server}/operations-view/preflight/confirm"),
            cookie,
            Some(json!({"id":request,"confirm":true})),
        )
        .await
}

async fn configuration(pool: &PgPool, server: i64) -> Result<Value> {
    let bytes: String = sqlx::query_scalar("SELECT bundle FROM deployments WHERE server_id=$1 AND module='singbox' ORDER BY rev DESC LIMIT 1")
        .bind(server).fetch_one(pool).await?;
    let bundle: Bundle = serde_json::from_str(&bytes)?;
    Ok(serde_json::from_str(
        bundle
            .files
            .get("config.json")
            .context("native configuration")?,
    )?)
}

#[sqlx::test(migrations = "./migrations")]
async fn first_listener_waits_for_real_api_confirmation_and_rejects_expired_evidence(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _, _) = scenario(&panel, &cookie).await?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 0);
    assert!(pending(&pool, server).await?);

    let observed = observe(&panel, &cookie, server).await?;
    due(&panel, server).await?;
    assert_eq!(
        revision(&pool, server).await?,
        0,
        "delivered successful observations are not administrator confirmation"
    );
    assert!(pending(&pool, server).await?);
    // Control expiry, preserving the dispatched jobs, genuine receipts and unconfirmed state.
    sqlx::query("UPDATE singbox_deployment_preflights SET expires_at=$2 WHERE id=$1")
        .bind(observed)
        .bind(now_timestamp() - 1)
        .execute(&pool)
        .await?;
    assert_eq!(
        confirm(&panel, &cookie, server, observed).await?.status(),
        StatusCode::CONFLICT
    );
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 0);

    let fresh = observe(&panel, &cookie, server).await?;
    let result: Value = confirm(&panel, &cookie, server, fresh)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(result["confirmed"], true);
    assert_eq!(result["deployment_requested"], false);
    assert_eq!(
        revision(&pool, server).await?,
        0,
        "confirmation does not invent a deployment"
    );
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 1);
    assert!(!pending(&pool, server).await?);
    assert_eq!(
        configuration(&pool, server).await?["inbounds"]
            .as_array()
            .context("inbounds")?
            .len(),
        1
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn same_second_requests_use_submission_order_and_cannot_confirm_the_older_uuid(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _, _) = scenario(&panel, &cookie).await?;
    let first = observe(&panel, &cookie, server).await?;
    let common_second: i64 =
        sqlx::query_scalar("SELECT created_at FROM singbox_deployment_preflights WHERE id=$1")
            .bind(first)
            .fetch_one(&pool)
            .await?;
    let second = observe(&panel, &cookie, server).await?;
    let older_large_uuid = Uuid::from_u128(u128::MAX);
    ensure!(second < older_large_uuid, "controlled UUID ordering");
    // Force the clock tie and misleading UUID order. No confirmation, job status,
    // receipt or sequence is fabricated; both requests crossed the actual APIs.
    sqlx::query("UPDATE singbox_deployment_preflights SET id=$2,created_at=$3 WHERE id=$1")
        .bind(first)
        .bind(older_large_uuid)
        .bind(common_second)
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE singbox_deployment_preflights SET created_at=$2 WHERE id=$1")
        .bind(second)
        .bind(common_second)
        .execute(&pool)
        .await?;
    let view: Value = panel
        .admin(
            Method::GET,
            &format!("{ROOT}/servers/{server}/operations-view"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(view["preflight"]["id"], json!(second));
    assert_eq!(
        confirm(&panel, &cookie, server, older_large_uuid)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 0);
    confirm(&panel, &cookie, server, second)
        .await?
        .error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 1);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn material_changes_and_actor_permission_revocation_cannot_reuse_confirmed_preflight(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, node, _) = scenario(&panel, &cookie).await?;
    let original = observe(&panel, &cookie, server).await?;
    confirm(&panel, &cookie, server, original)
        .await?
        .error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 1);
    panel
        .admin(
            Method::PATCH,
            &format!("{ROOT}/nodes/{node}"),
            &cookie,
            Some(json!({"sni":"next.example.com"})),
        )
        .await?
        .error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 1);
    assert!(pending(&pool, server).await?);
    assert_eq!(
        confirm(&panel, &cookie, server, original).await?.status(),
        StatusCode::CONFLICT
    );
    let current = observe(&panel, &cookie, server).await?;
    confirm(&panel, &cookie, server, current)
        .await?
        .error_for_status()?;

    // Keep a valid owner, then revoke only the confirming actor's diagnostic permission
    // using the real administrator CAS API. The confirmed record itself is retained.
    panel
        .admin(
            Method::POST,
            "/api/control-center/administrators",
            &cookie,
            Some(json!({
                "login_name":"backup-owner","display_name":"Backup owner","role":"owner",
                "password":"TEST_ONLY-backup-owner-password","all_servers":true,
            })),
        )
        .await?
        .error_for_status()?;
    let actor: i64 =
        sqlx::query_scalar("SELECT confirmed_by FROM singbox_deployment_preflights WHERE id=$1")
            .bind(current)
            .fetch_one(&pool)
            .await?;
    let profiles: Value = panel
        .admin(
            Method::GET,
            "/api/control-center/administrators",
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let profile = profiles["administrators"]
        .as_array()
        .context("administrator list")?
        .iter()
        .find(|profile| profile["id"] == actor)
        .context("confirming administrator")?;
    panel.admin(Method::PUT, &format!("/api/control-center/administrators/{actor}"), &cookie, Some(json!({
        "login_name":profile["login_name"],"display_name":profile["display_name"],
        "role":"operator","enabled":true,"all_servers":true,"expected_revision":profile["revision"],
        "capabilities":["proxy:write","operations:read","monitoring:read"],"server_ids":[],
    }))).await?.error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(
        revision(&pool, server).await?,
        1,
        "publisher rechecks the confirming actor's current scope and permissions"
    );
    assert!(pending(&pool, server).await?);
    let remains_confirmed: bool = sqlx::query_scalar(
        "SELECT confirmed_at IS NOT NULL FROM singbox_deployment_preflights WHERE id=$1",
    )
    .bind(current)
    .fetch_one(&pool)
    .await?;
    assert!(
        remains_confirmed,
        "permission rejection does not rewrite past confirmation"
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn same_listener_credentials_quota_and_final_revocation_publish_without_new_shape_confirmation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, node, account) = scenario(&panel, &cookie).await?;
    let survivor = id(&panel.create_user(&cookie, "Surviving account").await?)?;
    panel.grant(&cookie, survivor, node).await?;
    let old: String =
        sqlx::query_scalar("SELECT uuid::text FROM accesses WHERE user_id=$1 AND node_id=$2")
            .bind(account)
            .bind(node)
            .fetch_one(&pool)
            .await?;
    let proof = observe(&panel, &cookie, server).await?;
    confirm(&panel, &cookie, server, proof)
        .await?
        .error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 1);
    panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/users/{account}/accesses/{node}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    let replacement = panel.grant(&cookie, account, node).await?;
    let replacement_uuid = replacement["uuid"]
        .as_str()
        .context("new connection UUID")?;
    assert_ne!(replacement_uuid, old);
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 2);
    let native = configuration(&pool, server).await?;
    assert!(native.to_string().contains(replacement_uuid));
    assert!(!native.to_string().contains(&old));

    let plan: Value = panel
        .admin(
            Method::POST,
            &format!("{ROOT}/package-groups"),
            &cookie,
            Some(json!({
                "name":"Bounded quota","monthly_bytes":"10","reset_day":1,"reset_hour":0,
                "reset_minute":0,"timezone":"UTC","duration_days":365,
            })),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let assignment: Value = panel
        .admin(
            Method::POST,
            &format!("{ROOT}/users/{account}/package"),
            &cookie,
            Some(json!({
                "package_group_id":id(&plan)?,"request_id":Uuid::new_v4(),
            })),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let starts = assignment["starts_at"].as_i64().context("package starts")?;
    sinan_panel::usage::ingest(
        &panel.state,
        server,
        UsageBatch {
            epoch: Uuid::new_v4(),
            seq: 1,
            period_start: starts,
            period_end: starts + 1,
            records: vec![UsageRecord {
                stat_name: format!("u{account}_n{node}"),
                uplink: 10,
                downlink: 0,
            }],
        },
    )
    .await?;
    entitlements::refresh(&pool, now_timestamp()).await?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 3);
    let native = configuration(&pool, server).await?;
    assert!(!native.to_string().contains(replacement_uuid));
    assert!(native.to_string().contains(&format!("u{survivor}_n{node}")));
    panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/users/{survivor}/accesses/{node}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 4);
    assert!(
        configuration(&pool, server).await?["inbounds"]
            .as_array()
            .context("inbounds")?
            .is_empty()
    );
    let preflights: i64 =
        sqlx::query_scalar("SELECT count(*) FROM singbox_deployment_preflights WHERE server_id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        preflights, 1,
        "credential and safety revocations did not manufacture a fresh preflight"
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn first_bootstrap_publishes_only_empty_business_and_requires_fresh_business_confirmation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _, _) = scenario(&panel, &cookie).await?;
    let evidence = observe(&panel, &cookie, server).await?;
    let path = format!("{ROOT}/servers/{server}/operations-view/preflight/bootstrap");
    let bootstrap: Value = panel
        .admin(
            Method::POST,
            &path,
            &cookie,
            Some(json!({"id":evidence,"confirm":true})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(bootstrap["business_applied"], false);
    assert_eq!(bootstrap["business_preflight_required"], true);
    assert_eq!(bootstrap["status"], "waiting_agent");
    assert_eq!(revision(&pool, server).await?, 1);
    assert!(
        configuration(&pool, server).await?["inbounds"]
            .as_array()
            .context("bootstrap inbounds")?
            .is_empty()
    );
    assert!(pending(&pool, server).await?);
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &path,
                &cookie,
                Some(json!({"id":evidence,"confirm":true}))
            )
            .await?
            .status(),
        StatusCode::CONFLICT,
        "empty installation is never replayed over an existing deployment"
    );
    assert_eq!(
        confirm(&panel, &cookie, server, evidence).await?.status(),
        StatusCode::CONFLICT
    );
    due(&panel, server).await?;
    assert_eq!(
        revision(&pool, server).await?,
        1,
        "bootstrap cannot authorize saved business targets"
    );
    let fresh = observe(&panel, &cookie, server).await?;
    confirm(&panel, &cookie, server, fresh)
        .await?
        .error_for_status()?;
    due(&panel, server).await?;
    assert_eq!(revision(&pool, server).await?, 2);
    assert_eq!(
        configuration(&pool, server).await?["inbounds"]
            .as_array()
            .context("business inbounds")?
            .len(),
        1
    );
    Ok(())
}
