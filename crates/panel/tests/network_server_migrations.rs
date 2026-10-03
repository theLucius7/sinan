#![forbid(unsafe_code)]
mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

async fn setup(pool: &PgPool) -> Result<(TestPanel, String, i64, i64)> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let source = panel.create_server(&cookie, "TEST_ONLY source").await?;
    let target = panel
        .create_server(&cookie, "TEST_ONLY replacement")
        .await?;
    sqlx::query("UPDATE servers SET device_public_key=$2 WHERE id=$1")
        .bind(source)
        .bind("TEST_ONLY_ORIGINAL_IDENTITY")
        .execute(pool)
        .await?;
    sqlx::query("UPDATE servers SET device_public_key=$2,capabilities=$3 WHERE id=$1")
        .bind(target)
        .bind("TEST_ONLY_REPLACEMENT_IDENTITY")
        .bind(json!([
            "fleet:operations:v1",
            "system:forwarding:v1",
            "system:private-mesh:v1",
            "system:reverse-tunnel:v1"
        ]))
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO fleet_profiles(server_id,policy,updated_at) VALUES($1,$2,0) ON CONFLICT(server_id) DO UPDATE SET policy=EXCLUDED.policy")
        .bind(target).bind(json!({"port_forward":true,"private_mesh":true,"reverse_tunnel":true})).execute(pool).await?;
    Ok((panel, cookie, source, target))
}

async fn create(panel: &TestPanel, cookie: &str, config: Value) -> Result<Value> {
    Ok(panel
        .admin(
            Method::POST,
            "/api/network-configuration/documents",
            cookie,
            Some(json!({"config":config})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}
fn forward(server: i64, name: &str) -> Value {
    json!({"kind":"forwarding","name":name,"server_id":server,"listen_address":"0.0.0.0","listen_port":18080,"target_address":"127.0.0.1","target_port":8080,"protocol":"tcp","owner":"sinan","enabled":true,"dependency_ids":[]})
}
async fn preview(
    panel: &TestPanel,
    cookie: &str,
    source: i64,
    target: i64,
    ids: &[Value],
) -> Result<Value> {
    Ok(panel.admin(Method::POST,"/api/network-configuration/server-migrations/preview",cookie,Some(json!({"source_server_id":source,"target_server_id":target,"selections":ids.iter().map(|id|json!({"document_id":id})).collect::<Vec<_>>()}))).await?.error_for_status()?.json().await?)
}
fn confirmation(preview: &Value) -> Value {
    json!({"confirmed":true,"snapshot_digest":preview["snapshot_digest"]})
}
fn apply_path(preview: &Value) -> Result<String> {
    Ok(format!(
        "/api/network-configuration/server-migrations/{}/apply",
        preview["id"].as_str().context("preview ID")?
    ))
}

#[sqlx::test]
async fn replacement_is_fixed_scope_idempotent_and_never_copies_agent_identity_or_dispatches_work(
    pool: PgPool,
) -> Result<()> {
    let (panel, cookie, source, target) = setup(&pool).await?;
    let forward = create(&panel, &cookie, forward(source, "TEST_ONLY forwarding")).await?;
    let domain=create(&panel,&cookie,json!({"kind":"domain","name":"migration.example.com","server_ids":[source],"ddns_rule_ids":[],"applications":["web"],"maintainer":"TEST_ONLY","notes":"preserve"})).await?;
    let unrelated=create(&panel,&cookie,json!({"kind":"endpoint","name":"TEST_ONLY unrelated","server_id":source,"listen_address":"127.0.0.1","public_address":null,"port":8443,"protocol":"tcp","owner":"external","notes":"preserve"})).await?;
    let preview = preview(
        &panel,
        &cookie,
        source,
        target,
        &[forward["id"].clone(), domain["id"].clone()],
    )
    .await?;
    assert_eq!(preview["snapshot"]["blockers"], json!([]));
    let result: Value = panel
        .admin(
            Method::POST,
            &apply_path(&preview)?,
            &cookie,
            Some(confirmation(&preview)),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(result["deployment"], "not_started");
    assert_eq!(result["reachability"], "not_verified");
    assert_eq!(result["agent_identity_copied"], false);
    let replay: Value = panel
        .admin(
            Method::POST,
            &apply_path(&preview)?,
            &cookie,
            Some(confirmation(&preview)),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(replay, result);
    for id in [&forward["id"], &domain["id"]] {
        let document: Value = panel
            .admin(
                Method::GET,
                &format!(
                    "/api/network-configuration/documents/{}",
                    id.as_str().context("document ID")?
                ),
                &cookie,
                None,
            )
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(document["revision"], 2);
        assert!(
            document["config"]["server_id"] == target
                || document["config"]["server_ids"] == json!([target])
        );
        let history:i64=sqlx::query_scalar("SELECT count(*) FROM network_document_history WHERE document_id=$1 AND action='server_migration_before'")
            .bind(id.as_str().context("document ID")?.parse::<Uuid>()?).fetch_one(&pool).await?;
        assert_eq!(history, 1);
    }
    let unchanged: Value = sqlx::query_scalar("SELECT config FROM network_documents WHERE id=$1")
        .bind(
            unrelated["id"]
                .as_str()
                .context("unrelated ID")?
                .parse::<Uuid>()?,
        )
        .fetch_one(&pool)
        .await?;
    assert_eq!(unchanged["server_id"], source);
    let identities: Vec<String> =
        sqlx::query_scalar("SELECT device_public_key FROM servers WHERE id=ANY($1) ORDER BY id")
            .bind(vec![source, target])
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        identities,
        vec![
            "TEST_ONLY_ORIGINAL_IDENTITY",
            "TEST_ONLY_REPLACEMENT_IDENTITY"
        ]
    );
    let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM fleet_operations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(operations, 0);
    Ok(())
}

#[sqlx::test]
async fn changed_target_authorization_or_source_revision_invalidates_migration(
    pool: PgPool,
) -> Result<()> {
    let (panel, cookie, source, target) = setup(&pool).await?;
    let document = create(&panel, &cookie, forward(source, "TEST_ONLY stale")).await?;
    let frozen = preview(&panel, &cookie, source, target, &[document["id"].clone()]).await?;
    sqlx::query("UPDATE fleet_profiles SET policy='{}'::JSONB WHERE server_id=$1")
        .bind(target)
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &apply_path(&frozen)?,
                &cookie,
                Some(confirmation(&frozen))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE fleet_profiles SET policy=$2 WHERE server_id=$1")
        .bind(target)
        .bind(json!({"port_forward":true,"private_mesh":true,"reverse_tunnel":true}))
        .execute(&pool)
        .await?;
    let frozen = preview(&panel, &cookie, source, target, &[document["id"].clone()]).await?;
    sqlx::query("UPDATE network_documents SET revision=revision+1,config=jsonb_set(config,'{target_port}','8081') WHERE id=$1")
        .bind(document["id"].as_str().context("document ID")?.parse::<Uuid>()?).execute(&pool).await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &apply_path(&frozen)?,
                &cookie,
                Some(confirmation(&frozen))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let saved: Value = sqlx::query_scalar("SELECT config FROM network_documents WHERE id=$1")
        .bind(
            document["id"]
                .as_str()
                .context("document ID")?
                .parse::<Uuid>()?,
        )
        .fetch_one(&pool)
        .await?;
    assert_eq!(saved["server_id"], source);
    assert_eq!(saved["target_port"], 8081);
    Ok(())
}

#[sqlx::test]
async fn configured_target_collision_and_expired_session_proof_block_apply(
    pool: PgPool,
) -> Result<()> {
    let (panel, cookie, source, target) = setup(&pool).await?;
    let document = create(&panel, &cookie, forward(source, "TEST_ONLY source")).await?;
    create(
        &panel,
        &cookie,
        forward(target, "TEST_ONLY occupied target"),
    )
    .await?;
    let frozen = preview(&panel, &cookie, source, target, &[document["id"].clone()]).await?;
    assert!(
        !frozen["snapshot"]["blockers"]
            .as_array()
            .context("blockers")?
            .is_empty()
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &apply_path(&frozen)?,
                &cookie,
                Some(confirmation(&frozen))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let token = cookie
        .strip_prefix("sinan_session=")
        .context("test cookie")?;
    sqlx::query("DELETE FROM administrator_reauth WHERE session_hash=$1")
        .bind(sinan_panel::auth::hash_token(token))
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &apply_path(&frozen)?,
                &cookie,
                Some(confirmation(&frozen))
            )
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[sqlx::test]
async fn mesh_replacement_creates_fresh_candidate_and_keeps_old_identity_configuration(
    pool: PgPool,
) -> Result<()> {
    let (panel, cookie, source, target) = setup(&pool).await?;
    let document=create(&panel,&cookie,json!({"kind":"mesh","name":"TEST_ONLY private mesh","server_id":source,"address":"10.17.0.1/24","listen_port":51820,"peers":[]})).await?;
    let frozen = preview(&panel, &cookie, source, target, &[document["id"].clone()]).await?;
    let change = &frozen["snapshot"]["changes"][0];
    assert_ne!(change["destination_document_id"], document["id"]);
    assert_eq!(change["independent_identity"], true);
    assert_eq!(change["source_retained"], true);
    panel
        .admin(
            Method::POST,
            &apply_path(&frozen)?,
            &cookie,
            Some(confirmation(&frozen)),
        )
        .await?
        .error_for_status()?;
    let old: Value = sqlx::query_scalar("SELECT config FROM network_documents WHERE id=$1")
        .bind(
            document["id"]
                .as_str()
                .context("source ID")?
                .parse::<Uuid>()?,
        )
        .fetch_one(&pool)
        .await?;
    let new: Value = sqlx::query_scalar("SELECT config FROM network_documents WHERE id=$1")
        .bind(
            change["destination_document_id"]
                .as_str()
                .context("candidate ID")?
                .parse::<Uuid>()?,
        )
        .fetch_one(&pool)
        .await?;
    assert_eq!(old["server_id"], source);
    assert_eq!(new["server_id"], target);
    assert!(new.get("private_key").is_none());
    assert_eq!(old, document["config"]);
    Ok(())
}

#[sqlx::test]
async fn target_only_scope_cannot_read_source_candidates_or_migration_history(
    pool: PgPool,
) -> Result<()> {
    let (panel, owner, source, target) = setup(&pool).await?;
    let document = create(&panel, &owner, forward(source, "TEST_ONLY scope")).await?;
    let frozen = preview(&panel, &owner, source, target, &[document["id"].clone()]).await?;
    let actor:i64=sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id")
        .fetch_one(&pool).await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,'migration-viewer','TEST_ONLY scoped','viewer',false,'[\"network:read\"]',0,0)")
        .bind(actor).execute(&pool).await?;
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(actor)
        .bind(target)
        .execute(&pool)
        .await?;
    let token = sinan_panel::auth::random_token();
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
        .bind(sinan_panel::auth::hash_token(&token))
        .bind(actor)
        .bind(sinan_protocol::now_timestamp() + 3600)
        .execute(&pool)
        .await?;
    let scoped = format!("sinan_session={token}");
    let candidates = format!(
        "/api/network-configuration/server-migrations/candidates?source_server_id={source}&target_server_id={target}"
    );
    assert_eq!(
        panel
            .admin(Method::GET, &candidates, &scoped, None)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let history = format!(
        "/api/network-configuration/server-migrations/{}",
        frozen["id"].as_str().context("migration ID")?
    );
    assert_eq!(
        panel
            .admin(Method::GET, &history, &scoped, None)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
