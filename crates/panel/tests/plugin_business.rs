#![forbid(unsafe_code)]
mod business_support;
#[path = "plugin_business/installation.rs"]
mod installation;
#[path = "plugin_business/migration_recovery.rs"]
mod migration_recovery;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
#[path = "plugin_business/runtime.rs"]
mod runtime;

use anyhow::{Context, Result};
use business_support::{TestPanel, id};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_compiler::{Access, Node};
use sinan_protocol::{UsageBatch, UsageRecord};
use sqlx::{PgPool, migrate::Migrator};
use std::{borrow::Cow, collections::BTreeMap};
use uuid::Uuid;

async fn metadata(panel: &TestPanel, cookie: &str, server: i64) -> Result<Value> {
    Ok(panel
        .admin(
            Method::GET,
            &format!("/api/plugins/sing-box/servers/{server}"),
            cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[sqlx::test(migrations = "./migrations")]
async fn monitoring_server_requires_explicit_enablement_and_never_publishes_proxy_config(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Monitor only").await?;
    let before = metadata(&panel, &cookie, server).await?;
    assert_eq!(before["enabled"], false);
    assert_eq!(before["source"], Value::Null);
    sqlx::query("UPDATE servers SET dirty_at=0 WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    sinan_panel::plugins::singbox::publisher::publish_due(&panel.state).await?;
    let mut connection = pool.acquire().await?;
    let activity = sinan_panel::plugins::runtime_activity_on(
        &mut connection,
        server,
        sinan_protocol::now_timestamp(),
    )
    .await?;
    assert!(!activity.configured);
    assert_eq!(activity.last_positive_at, None);
    drop(connection);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM deployments WHERE server_id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        0
    );
    let body = json!({"name":"Node","server_id":server,"public_host":"proxy.example.com","sni":"www.example.com"});
    let response = panel
        .admin(
            Method::POST,
            "/api/plugins/sing-box/nodes",
            &cookie,
            Some(body.clone()),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        response.json::<Value>().await?["error"]
            .as_str()
            .context("reason")?
            .contains("插件设置")
    );
    assert_eq!(
        panel
            .admin(
                Method::GET,
                &format!("/api/plugins/sing-box/servers/{server}/deployments"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .client
            .post(format!(
                "{}/api/plugins/sing-box/servers/{server}/enable",
                panel.base
            ))
            .json(&json!({}))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    panel.enable_plugin(&cookie, server).await?;
    panel.enable_plugin(&cookie, server).await?;
    let enabled = metadata(&panel, &cookie, server).await?;
    assert_eq!(enabled["enabled"], true);
    assert_eq!(enabled["source"], "administrator");
    assert_eq!(enabled["read_only"], false);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM server_plugins WHERE server_id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        1
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/plugins/sing-box/nodes",
                &cookie,
                Some(body)
            )
            .await?
            .status(),
        StatusCode::CREATED
    );
    // The management namespace moved with the frontend; subscription URLs are separate.
    for old in ["/api/nodes", "/api/users", "/api/usage"] {
        assert_eq!(
            panel.admin(Method::GET, old, &cookie, None).await?.status(),
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn capability_only_establishes_support_and_an_administrator_must_enable_business(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Declared plugin").await?;
    sqlx::query("UPDATE servers SET capabilities='[\"singbox\"]' WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    let declared = metadata(&panel, &cookie, server).await?;
    assert_eq!(declared["enabled"], false);
    assert_eq!(declared["source"], Value::Null);
    assert_eq!(declared["read_only"], false);
    assert_eq!(declared["agent_supported"], true);
    assert_eq!(declared["installation"]["state"], "not_enabled");
    sqlx::query("INSERT INTO server_plugins(server_id,plugin,source,enabled_at) VALUES($1,'sing-box','agent_capability',0)").bind(server).execute(&pool).await?;
    sqlx::query("UPDATE servers SET capabilities='[]' WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    assert_eq!(metadata(&panel, &cookie, server).await?["enabled"], false);
    panel.enable_plugin(&cookie, server).await?;
    assert_eq!(
        metadata(&panel, &cookie, server).await?["source"],
        "administrator"
    );
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn migration_preserves_imported_subscription_credentials_access_and_accounting(
    pool: PgPool,
) -> Result<()> {
    migration_case(pool, None).await
}

#[sqlx::test(migrations = false)]
#[ignore = "Requires pinned real sing-box 1.14.2 and openssl on a dedicated test node; set SINAN_TEST_SINGBOX"]
async fn imported_subscription_keeps_real_connection_authorization_and_counters_after_migration(
    pool: PgPool,
) -> Result<()> {
    let binary = std::env::var_os("SINAN_TEST_SINGBOX").context("set SINAN_TEST_SINGBOX")?;
    migration_case(pool, Some(binary.into())).await
}

async fn migration_case(pool: PgPool, binary: Option<std::path::PathBuf>) -> Result<()> {
    let port = if binary.is_some() {
        runtime::port().await?
    } else {
        443
    };
    let host = if binary.is_some() {
        "127.0.0.1"
    } else {
        "imported.example.com"
    };
    let all = sqlx::migrate!();
    let old = Migrator {
        migrations: Cow::Owned(all.iter().filter(|m| m.version < 12).cloned().collect()),
        ..Migrator::DEFAULT
    };
    old.run(&pool).await?;
    let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,device_public_key,manifest_rev) VALUES('Imported server','imported-device-key',7) RETURNING id").fetch_one(&pool).await?;
    let monitor: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('Pure monitor') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let deploy_only: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('Legacy deployment') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let (private_key, public_key) =
        sinan_panel::plugins::singbox::business::generate_reality_keypair();
    let node_id: i64 = sqlx::query_scalar("INSERT INTO nodes(name,server_id,port,public_host,sni,private_key,public_key,short_id) VALUES('Imported node',$1,$2,$3,'www.example.com',$4,$5,'0123abcd') RETURNING id").bind(server).bind(i32::from(port)).bind(host).bind(&private_key).bind(&public_key).fetch_one(&pool).await?;
    let token = "imported-permanent-subscription-token";
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users(name,subscription_token) VALUES('Imported proxy user',$1) RETURNING id",
    )
    .bind(token)
    .fetch_one(&pool)
    .await?;
    let credential = Uuid::new_v4();
    let epoch = Uuid::new_v4();
    let stat_name = format!("u{user_id}_n{node_id}");
    sqlx::query("INSERT INTO accesses(user_id,node_id,uuid,stat_name) VALUES($1,$2,$3,$4)")
        .bind(user_id)
        .bind(node_id)
        .bind(credential)
        .bind(&stat_name)
        .execute(&pool)
        .await?;
    let node = Node {
        enabled: true,
        settings: Default::default(),
        id: node_id,
        name: "Imported node".into(),
        port,
        public_host: host.into(),
        sni: "www.example.com".into(),
        private_key: private_key.clone(),
        public_key: public_key.clone(),
        short_id: "0123abcd".into(),
        protocol_config: Default::default(),
        users: vec![Access {
            user_id,
            uuid: credential,
            credential: String::new(),
        }],
    };
    let expected_links = sinan_compiler::subscription_links(std::slice::from_ref(&node), user_id)?;
    let expected_client = runtime::legacy_client(&node, user_id);
    assert_eq!(
        expected_client,
        serde_json::from_str::<Value>(&sinan_compiler::compile_client(
            std::slice::from_ref(&node),
            user_id,
        )?)?
    );
    let mut live = if let Some(binary) = binary {
        Some(runtime::Runtime::start(binary, &node, &expected_client).await?)
    } else {
        None
    };
    let (uplink, downlink) = if let Some(runtime) = live.as_mut() {
        let before = runtime.traffic().await?;
        assert_eq!(before.stat_name, stat_name);
        (before.uplink, before.downlink)
    } else {
        (123, 456)
    };
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,source_json,created_at) VALUES($1,'singbox',7,'imported-bundle','imported-hash',$2,1234)").bind(server).bind(json!([node])).execute(&pool).await?;
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,created_at) VALUES($1,'singbox',1,'legacy','legacy',1234)").bind(deploy_only).execute(&pool).await?;
    sqlx::query("INSERT INTO server_module_status(server_id,module,target_rev,applied_rev,healthy) VALUES($1,'singbox',7,7,TRUE)").bind(server).execute(&pool).await?;
    let batch = UsageBatch {
        epoch,
        seq: 1,
        period_start: 10,
        period_end: 20,
        records: vec![UsageRecord {
            stat_name: stat_name.clone(),
            uplink,
            downlink,
        }],
    };
    let payload_hash = sinan_panel::auth::hash_token(&serde_json::to_string(&batch)?);
    sqlx::query("INSERT INTO usage_batches(server_id,epoch,seq,payload_hash) VALUES($1,$2,1,$3)")
        .bind(server)
        .bind(epoch)
        .bind(&payload_hash)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO usage_records(server_id,epoch,seq,stat_name,user_id,node_id,uplink,downlink,period_start,period_end) VALUES($1,$2,1,$3,$4,$5,$6,$7,10,20)").bind(server).bind(epoch).bind(&stat_name).bind(user_id).bind(node_id).bind(i64::try_from(uplink)?).bind(i64::try_from(downlink)?).execute(&pool).await?;
    sqlx::query("INSERT INTO sessions(token_hash,server_id,expires_at) VALUES('TEST_ONLY-imported-device-session',$1,4099680000)")
        .bind(server).execute(&pool).await?;
    sqlx::query("INSERT INTO enrollment_tokens(token_hash,server_id,expires_at,consumed_at) VALUES('TEST_ONLY-imported-enrollment',$1,4099680000,1234)")
        .bind(server).execute(&pool).await?;
    let mut legacy = migration_recovery::legacy_snapshot(&pool).await?;
    // New columns have explicit legacy defaults; every preexisting value stays identical.
    migration_recovery::append_expected_server_defaults(&mut legacy)?;
    for node in legacy.get_mut("nodes").unwrap().as_array_mut().unwrap() {
        node["protocol_config"] = json!({"type":"vless-reality"});
        node["enabled"] = json!(true);
        node["settings"] = json!({});
        node["resource_revision"] = json!(1);
    }
    for access in legacy
        .get_mut("accesses")
        .and_then(Value::as_array_mut)
        .context("legacy accesses")?
    {
        access["credential"] = json!("");
        access["direct_grant"] = json!(true);
    }
    // Starting the new panel applies the real migration to already imported records.
    let panel = TestPanel::start(pool.clone()).await?;
    let initial_observation = batch_observation(&pool, server, epoch).await?;
    assert_eq!(initial_observation, (None, None, 0));
    assert_eq!(
        without_batch_observation_columns(migration_recovery::legacy_snapshot(&pool).await?)?,
        legacy
    );
    let mut connection = pool.acquire().await?;
    let activity = sinan_panel::plugins::runtime_activity_on(&mut connection, server, 20).await?;
    assert!(activity.configured);
    assert_eq!(activity.last_positive_at, Some(20));
    drop(connection);
    // Reopening the migrated database must neither duplicate enablement nor
    // alter previously acknowledged batches. Offline outbox replay still dedupes.
    all.run(&pool).await?;
    assert_eq!(
        batch_observation(&pool, server, epoch).await?,
        initial_observation
    );
    let replay_started = sinan_protocol::now_timestamp();
    sinan_panel::plugins::singbox::usage::ingest(&panel.state, server, batch.clone()).await?;
    let replayed = batch_observation(&pool, server, epoch).await?;
    assert_eq!(
        replayed.0, None,
        "the imported first receive time is unknown"
    );
    assert_eq!(replayed.2, 1);
    assert!(
        replayed
            .1
            .is_some_and(|at| (replay_started..=sinan_protocol::now_timestamp()).contains(&at)),
        "replay observation must use the actual request interval"
    );
    assert_eq!(
        without_batch_observation_columns(migration_recovery::legacy_snapshot(&pool).await?)?,
        legacy
    );
    let mut altered = batch;
    altered.records[0].downlink += 1;
    assert!(
        sinan_panel::plugins::singbox::usage::ingest(&panel.state, server, altered)
            .await
            .is_err()
    );
    assert_eq!(batch_observation(&pool, server, epoch).await?, replayed);
    assert_eq!(
        without_batch_observation_columns(migration_recovery::legacy_snapshot(&pool).await?)?,
        legacy
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM server_plugins")
            .fetch_one(&pool)
            .await?,
        2
    );
    let cookie = panel.admin_cookie().await?;
    let user: Value = panel
        .admin(
            Method::GET,
            &format!("/api/plugins/sing-box/users/{user_id}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(id(&user)?, user_id);
    assert_eq!(user["subscription_token"], token);
    assert_eq!(
        user["subscription_url"],
        format!("{}/sub/{token}", panel.base)
    );
    let legacy_url = format!("{}/sub/{token}", panel.base);
    assert_eq!(
        panel
            .client
            .get(&legacy_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?,
        expected_links
    );
    assert_eq!(
        panel
            .client
            .get(format!("{legacy_url}?format=singbox"))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?,
        expected_client
    );
    assert_eq!(
        metadata(&panel, &cookie, server).await?["source"],
        "legacy_nodes"
    );
    assert_eq!(
        metadata(&panel, &cookie, deploy_only).await?["source"],
        "legacy_deployments"
    );
    assert_eq!(metadata(&panel, &cookie, monitor).await?["enabled"], false);
    let keys: (String, String, String) =
        sqlx::query_as("SELECT private_key,public_key,short_id FROM nodes WHERE id=$1")
            .bind(node_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(keys, (private_key, public_key, "0123abcd".into()));
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>("SELECT uuid FROM accesses WHERE user_id=$1 AND node_id=$2")
            .bind(user_id)
            .bind(node_id)
            .fetch_one(&pool)
            .await?,
        credential
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT device_public_key FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?,
        "imported-device-key"
    );
    let usage: Value = panel
        .admin(Method::GET, "/api/plugins/sing-box/usage", &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(usage["total"], (uplink + downlink).to_string());
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>("SELECT epoch FROM usage_records WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await?,
        epoch
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM usage_batches")
            .fetch_one(&pool)
            .await?,
        1
    );
    if let Some(mut runtime) = live.take() {
        assert_eq!(runtime.cached_client(), &expected_client);
        let after = runtime.traffic().await?;
        assert_eq!(after.stat_name, stat_name);
        let delta_up = after
            .uplink
            .checked_sub(uplink)
            .context("uplink counter went backwards")?;
        let delta_down = after
            .downlink
            .checked_sub(downlink)
            .context("downlink counter went backwards")?;
        assert!(delta_up >= 8192 && delta_down >= 8192);
        let actual = UsageBatch {
            epoch,
            seq: 2,
            period_start: 20,
            period_end: 30,
            records: vec![UsageRecord {
                stat_name,
                uplink: delta_up,
                downlink: delta_down,
            }],
        };
        sinan_panel::plugins::singbox::usage::ingest(&panel.state, server, actual.clone()).await?;
        sinan_panel::plugins::singbox::usage::ingest(&panel.state, server, actual).await?;
        let totals: (i64, i64, i64) = sqlx::query_as("SELECT SUM(uplink)::bigint,SUM(downlink)::bigint,COUNT(*) FROM usage_records WHERE user_id=$1 AND node_id=$2 AND epoch=$3")
            .bind(user_id).bind(node_id).bind(epoch).fetch_one(&pool).await?;
        assert_eq!(
            totals,
            (
                i64::try_from(after.uplink)?,
                i64::try_from(after.downlink)?,
                2
            )
        );
        runtime.stop().await?;
        eprintln!(
            "imported-client Reality traffic and exact counters survived migration; replay stayed deduplicated"
        );
    }
    Ok(())
}

async fn batch_observation(
    pool: &PgPool,
    server: i64,
    epoch: Uuid,
) -> Result<(Option<i64>, Option<i64>, i64)> {
    Ok(sqlx::query_as(
        "SELECT received_at,last_replayed_at,replay_count FROM usage_batches WHERE server_id=$1 AND epoch=$2 AND seq=1",
    )
    .bind(server)
    .bind(epoch)
    .fetch_one(pool)
    .await?)
}

fn without_batch_observation_columns(
    mut snapshot: BTreeMap<&'static str, Value>,
) -> Result<BTreeMap<&'static str, Value>> {
    // Only the new separately asserted observations are excluded. Every legacy
    // identity, payload hash, counter, credential and timestamp stays comparable.
    let batches = snapshot
        .get_mut("usage_batches")
        .and_then(Value::as_array_mut)
        .context("imported usage batches")?;
    for batch in batches {
        let fields = batch.as_object_mut().context("imported batch object")?;
        for field in ["received_at", "last_replayed_at", "replay_count"] {
            fields
                .remove(field)
                .context("new batch observation column")?;
        }
    }
    Ok(snapshot)
}
