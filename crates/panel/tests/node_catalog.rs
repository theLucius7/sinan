#![forbid(unsafe_code)]

mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result, ensure};
use business_support::{TestPanel, id};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

const ROOT: &str = "/api/plugins/sing-box";

async fn call(
    panel: &TestPanel,
    cookie: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let response = panel
        .admin(method, &format!("{ROOT}{path}"), cookie, body)
        .await?;
    let status = response.status();
    let text = response.text().await?;
    ensure!(status.is_success(), "{path}: {status}: {text}");
    Ok(serde_json::from_str(&text)?)
}

async fn catalog(panel: &TestPanel, cookie: &str) -> Result<Vec<Value>> {
    Ok(call(panel, cookie, Method::GET, "/node-catalog", None)
        .await?
        .as_array()
        .context("catalog")?
        .clone())
}

fn change(row: &Value, fields: Value) -> Value {
    let mut value = json!({"kind":row["kind"],"id":row["id"],"revision":row["revision"]});
    value
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    value
}

async fn external(panel: &TestPanel, cookie: &str, pool: &PgPool) -> Result<(i64, i64, i64)> {
    let source=id(&call(panel,cookie,Method::POST,"/subscription-sources",Some(json!({"name":"Source","kind":"inline","content":"ss://YWVzLTEyOC1nY206dGVzdC1jYXRhbG9nLXNlY3JldA@proxy.example.com:443#Original"}))).await?)?;
    let (node,version)=tokio::time::timeout(Duration::from_secs(20),async {
        loop {
            let value:Option<(i64,i64)>=sqlx::query_as("SELECT id,current_version_id FROM singbox_external_nodes WHERE source_id=$1 AND current_version_id IS NOT NULL").bind(source).fetch_optional(pool).await?;
            if let Some(value)=value { return Ok::<_,anyhow::Error>(value); }
            sinan_panel::plugins::singbox::sources::refresh_due(&panel.state).await?;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await??;
    sqlx::query("UPDATE singbox_external_nodes SET adopted=TRUE WHERE id=$1")
        .bind(node)
        .execute(pool)
        .await?;
    Ok((source, node, version))
}

#[sqlx::test]
async fn metadata_is_safe_persistent_and_batches_reject_stale_edits_atomically(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Host").await?;
    let first = id(&panel.create_node(&cookie, server, "First").await?)?;
    let second = id(&panel.create_node(&cookie, server, "Second").await?)?;
    let user = id(&panel.create_user(&cookie, "User").await?)?;
    panel.grant(&cookie, user, first).await?;
    let identity: Value =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM accesses a WHERE user_id=$1 AND node_id=$2")
            .bind(user)
            .bind(first)
            .fetch_one(&pool)
            .await?;
    let private: String = sqlx::query_scalar("SELECT private_key FROM nodes WHERE id=$1")
        .bind(first)
        .fetch_one(&pool)
        .await?;
    let before = catalog(&panel, &cookie).await?;
    ensure!(!json!(before).to_string().contains(&private));
    let anonymous = panel
        .client
        .get(format!("{}{ROOT}/node-catalog", panel.base))
        .send()
        .await?;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let result=call(&panel,&cookie,Method::PATCH,"/node-catalog/batch",Some(json!({"items":[
        change(&before[0],json!({"tags":[" HK ","HK","Premium"],"note":"管理员备注","sort_order":20})),
        change(&before[1],json!({"sort_order":-10,"enabled":false,"name":"Renamed"}))
    ]}))).await?;
    assert_eq!(result[0]["id"], second);
    assert_eq!(result[0]["enabled"], false);
    let updated = catalog(&panel, &cookie).await?;
    assert_eq!(updated[1]["tags"], json!(["HK", "Premium"]));
    assert_eq!(updated[1]["note"], "管理员备注");
    let stale=panel.admin(Method::POST,&format!("{ROOT}/node-catalog/batch"),&cookie,Some(json!({"items":[change(&updated[0],json!({"name":"Must rollback"})),change(&before[0],json!({"name":"Stale"}))]}))).await?;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(catalog(&panel, &cookie).await?, updated);
    let after: Value =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM accesses a WHERE user_id=$1 AND node_id=$2")
            .bind(user)
            .bind(first)
            .fetch_one(&pool)
            .await?;
    assert_eq!(after, identity);
    let private_after: String = sqlx::query_scalar("SELECT private_key FROM nodes WHERE id=$1")
        .bind(first)
        .fetch_one(&pool)
        .await?;
    assert_eq!(private_after, private);
    Ok(())
}

#[sqlx::test]
async fn concurrent_catalog_edits_and_legacy_node_edits_cannot_overwrite_stale_forms(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Host").await?;
    let node = id(&panel.create_node(&cookie, server, "Original").await?)?;
    let rows = catalog(&panel, &cookie).await?;
    let path = format!("{ROOT}/node-catalog/batch");
    let a = panel.admin(
        Method::POST,
        &path,
        &cookie,
        Some(json!({"items":[change(&rows[0],json!({"name":"A"}))]})),
    );
    let b = panel.admin(
        Method::POST,
        &path,
        &cookie,
        Some(json!({"items":[change(&rows[0],json!({"name":"B"}))]})),
    );
    let (a, b) = tokio::join!(a, b);
    let statuses = [a?.status(), b?.status()];
    assert_eq!(statuses.iter().filter(|v| v.is_success()).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|v| **v == StatusCode::CONFLICT)
            .count(),
        1
    );
    let before = catalog(&panel, &cookie).await?;
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/nodes/{node}"),
        Some(json!({"settings":{"tcp_keep_alive_seconds":60}})),
    )
    .await?;
    let response = panel
        .admin(
            Method::POST,
            &path,
            &cookie,
            Some(json!({"items":[change(&before[0],json!({"name":"Stale settings"}))]})),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    Ok(())
}

#[sqlx::test]
async fn external_metadata_survives_refresh_and_deletion_preserves_immutable_history(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (_source, node, version) = external(&panel, &cookie, &pool).await?;
    let rows = catalog(&panel, &cookie).await?;
    assert_eq!(rows[0]["server_id"], Value::Null);
    ensure!(!json!(rows).to_string().contains("test-catalog-secret"));
    call(&panel,&cookie,Method::POST,"/node-catalog/batch",Some(json!({"items":[change(&rows[0],json!({"name":"Local alias","enabled":false,"tags":["Airport"]}))]}))).await?;
    sqlx::query("UPDATE singbox_external_nodes SET name='Provider renamed' WHERE id=$1")
        .bind(node)
        .execute(&pool)
        .await?;
    let rows = catalog(&panel, &cookie).await?;
    assert_eq!(rows[0]["name"], "Local alias");
    assert_eq!(rows[0]["original_name"], "Provider renamed");
    assert_eq!(rows[0]["available"], false);
    assert_eq!(rows[0]["version_id"], version);
    call(
        &panel,
        &cookie,
        Method::DELETE,
        "/node-catalog/batch",
        Some(json!({"items":[change(&rows[0],json!({}))]})),
    )
    .await?;
    assert!(catalog(&panel, &cookie).await?.is_empty());
    let retained: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM singbox_external_node_versions WHERE id=$1")
            .bind(version)
            .fetch_one(&pool)
            .await?;
    assert_eq!(retained, 1);
    // A refresh must not resurrect a locally removed resource.
    sqlx::query("UPDATE singbox_external_nodes SET present=TRUE,name='Refreshed' WHERE id=$1")
        .bind(node)
        .execute(&pool)
        .await?;
    assert!(catalog(&panel, &cookie).await?.is_empty());
    Ok(())
}

#[sqlx::test]
async fn deletion_references_and_invalid_metadata_roll_back_all_items(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Host").await?;
    let direct = id(&panel.create_node(&cookie, server, "Managed").await?)?;
    let (source, node, version) = external(&panel, &cookie, &pool).await?;
    let user = id(&panel.create_user(&cookie, "External user").await?)?;
    sqlx::query("INSERT INTO singbox_external_accesses(user_id,external_node_id,source_id,identity_epoch,node_version_id,update_mode,created_at) VALUES($1,$2,$3,1,$4,'pinned',0)").bind(user).bind(node).bind(source).bind(version).execute(&pool).await?;
    let rows = catalog(&panel, &cookie).await?;
    let response = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/node-catalog/batch"),
            &cookie,
            Some(json!({"items":rows.iter().map(|v|change(v,json!({}))).collect::<Vec<_>>()})),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(catalog(&panel, &cookie).await?, rows);
    let invalid=panel.admin(Method::POST,&format!("{ROOT}/node-catalog/batch"),&cookie,Some(json!({"items":[change(&rows[0],json!({"name":"Should rollback"})),change(&rows[1],json!({"tags":["x".repeat(65)]}))]}))).await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(catalog(&panel, &cookie).await?, rows);
    let name: String = sqlx::query_scalar("SELECT name FROM nodes WHERE id=$1")
        .bind(direct)
        .fetch_one(&pool)
        .await?;
    assert_eq!(name, "Managed");
    Ok(())
}

#[sqlx::test]
async fn cloning_recreates_runtime_identities_and_never_copies_grants(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Host").await?;
    panel.enable_plugin(&cookie, server).await?;
    let user = id(&panel.create_user(&cookie, "User").await?)?;
    for protocol in ["vless-reality", "shadowsocks2022", "snell-v6", "hysteria2"] {
        let mut config = json!({"type":protocol});
        if protocol == "hysteria2" {
            config["tls"] =
                json!({"mode":"acme","email":"admin@example.com","challenge":"http-01"});
        }
        let sni = if matches!(protocol, "shadowsocks2022" | "snell-v6") {
            ""
        } else {
            "www.example.com"
        };
        let original=call(&panel,&cookie,Method::POST,"/nodes",Some(json!({"name":protocol,"server_id":server,"public_host":"proxy.example.com","sni":sni,"protocol_config":config,"settings":if protocol=="hysteria2" { json!({"hysteria2":{"obfs_enabled":true}}) } else { json!({}) }}))).await?;
        let node = id(&original)?;
        panel.grant(&cookie, user, node).await?;
        let previous = catalog(&panel, &cookie)
            .await?
            .into_iter()
            .find(|value| value["kind"] == "direct" && value["id"] == node)
            .context("source catalog entry")?;
        call(
            &panel,
            &cookie,
            Method::PATCH,
            &format!("/nodes/{node}"),
            Some(json!({"settings":{"public_port":24443}})),
        )
        .await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(&pool)
            .await?;
        let stale = panel
            .admin(
                Method::POST,
                &format!("{ROOT}/nodes/{node}/clone"),
                &cookie,
                Some(
                    json!({"revision":previous["revision"],"server_id":server,"name":"Stale copy"}),
                ),
            )
            .await?;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(&pool)
            .await?;
        assert_eq!(after, count, "a stale clone must not create any node");
        let current = catalog(&panel, &cookie)
            .await?
            .into_iter()
            .find(|value| value["kind"] == "direct" && value["id"] == node)
            .context("updated source catalog entry")?;
        let cloned = call(
            &panel,
            &cookie,
            Method::POST,
            &format!("/nodes/{node}/clone"),
            Some(json!({"revision":current["revision"],"server_id":server,"name":"Copy"})),
        )
        .await?;
        assert_ne!(cloned["id"], node);
        assert_ne!(cloned["port"], original["port"]);
        assert_eq!(cloned["protocol"], protocol);
        assert_eq!(cloned["settings"]["public_port"], 24443);
        let original_private:Value=sqlx::query_scalar("SELECT jsonb_build_object('private_key',private_key,'protocol',protocol_config,'settings',settings) FROM nodes WHERE id=$1").bind(node).fetch_one(&pool).await?;
        let cloned_private:Value=sqlx::query_scalar("SELECT jsonb_build_object('private_key',private_key,'protocol',protocol_config,'settings',settings) FROM nodes WHERE id=$1").bind(id(&cloned)?).fetch_one(&pool).await?;
        match protocol {
            "vless-reality" => assert_ne!(
                original_private["private_key"],
                cloned_private["private_key"]
            ),
            "shadowsocks2022" => assert_ne!(
                original_private["protocol"]["password"],
                cloned_private["protocol"]["password"]
            ),
            "snell-v6" => assert_ne!(
                original_private["protocol"]["psk"],
                cloned_private["protocol"]["psk"]
            ),
            "hysteria2" => assert_ne!(
                original_private["settings"]["hysteria2"]["obfs_password"],
                cloned_private["settings"]["hysteria2"]["obfs_password"]
            ),
            _ => unreachable!(),
        }
        let grants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses WHERE node_id=$1")
            .bind(id(&cloned)?)
            .fetch_one(&pool)
            .await?;
        assert_eq!(grants, 0);
        assert!(cloned.get("private_key").is_none());
    }
    Ok(())
}

#[sqlx::test]
async fn external_distribution_toggle_preserves_frozen_paths_and_dependency_guards(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (source, node, version) = external(&panel, &cookie, &pool).await?;
    let server = panel.create_server(&cookie, "Entry host").await?;
    let entry = id(&panel.create_node(&cookie, server, "Entry").await?)?;
    let chain:i64=sqlx::query_scalar("INSERT INTO singbox_chains(name,entry_node_id,path_kind) VALUES('Frozen path',$1,'mixed') RETURNING id").bind(entry).fetch_one(&pool).await?;
    sqlx::query("INSERT INTO singbox_chain_versions(chain_id,generation,path_json,semantic_hash,networks,stage,created_at,updated_at) VALUES($1,1,'{\"fixture\":true}','fixture','{}','failed',0,0)").bind(chain).execute(&pool).await?;
    sqlx::query("INSERT INTO singbox_chain_hops(chain_id,generation,position,kind,source_id,external_node_id,external_version_id,update_mode) VALUES($1,1,0,'subscription',$2,$3,$4,'pinned')").bind(chain).bind(source).bind(node).bind(version).execute(&pool).await?;
    let rows = catalog(&panel, &cookie).await?;
    let external_row = rows
        .iter()
        .find(|v| v["kind"] == "external")
        .context("external")?;
    call(
        &panel,
        &cookie,
        Method::POST,
        "/node-catalog/batch",
        Some(json!({"items":[change(external_row,json!({"enabled":false}))]})),
    )
    .await?;
    let mut connection = pool.acquire().await?;
    let frozen = sinan_panel::plugins::singbox::sources::load_version_on(
        &mut connection,
        source,
        node,
        version,
        true,
    )
    .await?;
    assert_eq!(frozen.node_version_id, version);
    drop(connection);
    let rows = catalog(&panel, &cookie).await?;
    let external_row = rows
        .iter()
        .find(|v| v["kind"] == "external")
        .context("external")?;
    let denied = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/node-catalog/batch"),
            &cookie,
            Some(json!({"items":[change(external_row,json!({}))]})),
        )
        .await?;
    assert_eq!(denied.status(), StatusCode::CONFLICT);
    let chain_row = rows
        .iter()
        .find(|v| v["kind"] == "chain")
        .context("chain")?;
    call(
        &panel,
        &cookie,
        Method::DELETE,
        "/node-catalog/batch",
        Some(json!({"items":[change(chain_row,json!({}))]})),
    )
    .await?;
    let rows = catalog(&panel, &cookie).await?;
    assert_eq!(rows.len(), 1);
    call(
        &panel,
        &cookie,
        Method::DELETE,
        "/node-catalog/batch",
        Some(json!({"items":[change(&rows[0],json!({}))]})),
    )
    .await?;
    let snapshot: Value = sqlx::query_scalar(
        "SELECT path_json FROM singbox_chain_versions WHERE chain_id=$1 AND generation=1",
    )
    .bind(chain)
    .fetch_one(&pool)
    .await?;
    assert_eq!(snapshot, json!({"fixture":true}));
    Ok(())
}

#[sqlx::test]
async fn catalog_entity_changes_invalidate_original_resource_cas_without_publishing_metadata(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Entry host").await?;
    let direct = id(&panel.create_node(&cookie, server, "Direct").await?)?;
    let entry = id(&panel.create_node(&cookie, server, "Legacy entry").await?)?;
    let exit_server = panel.create_server(&cookie, "Exit host").await?;
    let exit = id(&panel
        .create_node(&cookie, exit_server, "Legacy exit")
        .await?)?;
    let chain = id(&panel
        .import_legacy_chain(&cookie, "Legacy chain", entry, exit)
        .await?)?;
    let history: Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(v) ORDER BY generation) FROM singbox_ordered_chain_versions v WHERE chain_id=$1")
        .bind(chain).fetch_one(&pool).await?;
    sqlx::query("UPDATE servers SET dirty_at=NULL")
        .execute(&pool)
        .await?;
    let rows = catalog(&panel, &cookie).await?;
    let direct_row = rows
        .iter()
        .find(|v| v["kind"] == "direct" && v["id"] == direct)
        .context("direct catalog")?;
    call(&panel, &cookie, Method::PATCH, "/node-catalog/batch", Some(json!({"items":[change(direct_row,json!({"tags":["Metadata only"],"note":"Retain CAS"}))]}))).await?;
    let revision: i64 = sqlx::query_scalar("SELECT resource_revision FROM nodes WHERE id=$1")
        .bind(direct)
        .fetch_one(&pool)
        .await?;
    assert_eq!(revision, 1);
    let dirty: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM servers WHERE dirty_at IS NOT NULL")
        .fetch_one(&pool)
        .await?;
    assert_eq!(dirty, 0, "metadata does not schedule a runtime publication");
    for (kind, identity) in [("direct", direct), ("chain", chain)] {
        for fields in [
            json!({"name":format!("Catalog {kind}")}),
            json!({"enabled":false}),
        ] {
            let before = call(
                &panel,
                &cookie,
                Method::GET,
                &format!("/ordered-proxy-resources/{kind}/{identity}"),
                None,
            )
            .await?;
            let rows = catalog(&panel, &cookie).await?;
            let row = rows
                .iter()
                .find(|v| v["kind"] == kind && v["id"] == identity)
                .context("catalog entity")?;
            call(
                &panel,
                &cookie,
                Method::PATCH,
                "/node-catalog/batch",
                Some(json!({"items":[change(row,fields)]})),
            )
            .await?;
            let current = call(
                &panel,
                &cookie,
                Method::GET,
                &format!("/ordered-proxy-resources/{kind}/{identity}"),
                None,
            )
            .await?;
            assert_eq!(
                current["settings_revision"].as_i64(),
                before["settings_revision"].as_i64().map(|v| v + 1)
            );
            let stale = panel.admin(Method::PATCH, &format!("{ROOT}/ordered-proxy-resources/{kind}/{identity}"), &cookie,
                Some(json!({"request_id":Uuid::new_v4(),"settings_revision":before["settings_revision"],"name":"Stale rich editor"}))).await?;
            assert_eq!(stale.status(), StatusCode::CONFLICT);
            assert_eq!(
                call(
                    &panel,
                    &cookie,
                    Method::GET,
                    &format!("/ordered-proxy-resources/{kind}/{identity}"),
                    None
                )
                .await?,
                current
            );
        }
    }
    let retained: Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(v) ORDER BY generation) FROM singbox_ordered_chain_versions v WHERE chain_id=$1")
        .bind(chain).fetch_one(&pool).await?;
    assert_eq!(retained, history);
    Ok(())
}

#[sqlx::test]
async fn catalog_deletion_preserves_damaged_cleanup_owners_and_old_entry_policy_guards(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Entry host").await?;
    let entry = id(&panel.create_node(&cookie, server, "Retained entry").await?)?;
    let free = id(&panel.create_node(&cookie, server, "Free direct").await?)?;
    let exit_server = panel.create_server(&cookie, "Exit host").await?;
    let exit = id(&panel
        .create_node(&cookie, exit_server, "Retained hop")
        .await?)?;
    let chain = id(&panel
        .import_legacy_chain(&cookie, "Retiring owner", entry, exit)
        .await?)?;
    // TEST_ONLY receipt history remains independently bound to the saved owner.
    let request_id = Uuid::new_v4();
    sqlx::query("INSERT INTO singbox_ordered_chain_creation_requests(request_id,request_sha256,receipt,created_at) VALUES($1,$2,$3,0)")
        .bind(request_id).bind("0".repeat(64)).bind(json!({"request_id":request_id,"chain_ids":[chain],"entry_node_ids":[entry]})).execute(&pool).await?;
    let receipt: Value = sqlx::query_scalar(
        "SELECT to_jsonb(r) FROM singbox_ordered_chain_creation_requests r WHERE request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await?;
    // TEST_ONLY old immutable hop identities survive damaged generation pointers.
    sqlx::query("UPDATE singbox_chains SET path_kind='ordered',exit_node_id=NULL,relay_uuid=NULL,deleted_at=1,phase='retiring',desired_generation=99,applied_generation=NULL,candidate_generation=99 WHERE id=$1").bind(chain).execute(&pool).await?;
    let history: Value = sqlx::query_scalar("SELECT jsonb_build_object('chain',to_jsonb(c),'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY generation) FROM singbox_ordered_chain_versions v WHERE v.chain_id=c.id),'hops',(SELECT jsonb_agg(to_jsonb(h) ORDER BY generation,position) FROM singbox_ordered_chain_hops h WHERE h.chain_id=c.id)) FROM singbox_chains c WHERE c.id=$1")
        .bind(chain).fetch_one(&pool).await?;
    let locked = call(
        &panel,
        &cookie,
        Method::GET,
        &format!("/nodes/{exit}"),
        None,
    )
    .await?;
    assert_eq!(locked["configuration_locked"], true);
    let endpoint_change = panel
        .admin(
            Method::PATCH,
            &format!("{ROOT}/nodes/{exit}"),
            &cookie,
            Some(json!({"public_host":"stale-reuse.example.com"})),
        )
        .await?;
    assert_eq!(endpoint_change.status(), StatusCode::CONFLICT);
    let rows = catalog(&panel, &cookie).await?;
    assert_eq!(
        rows.iter()
            .find(|v| v["kind"] == "direct" && v["id"] == exit)
            .context("damaged retained hop")?["entry_eligible"],
        false
    );
    let items: Vec<_> = rows
        .iter()
        .filter(|v| v["kind"] == "direct" && (v["id"] == free || v["id"] == exit))
        .map(|v| change(v, json!({})))
        .collect();
    assert_eq!(items.len(), 2);
    let denied = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/node-catalog/batch"),
            &cookie,
            Some(json!({"items":items})),
        )
        .await?;
    assert_eq!(denied.status(), StatusCode::CONFLICT);
    let error: Value = denied.json().await?;
    assert_eq!(
        error["references"]["chains"],
        json!([{
            "id":chain,"name":"Retiring owner","role":"exit",
            "generation":1,"hop_position":1,"state":"unresolved"
        }])
    );
    assert!(!error.to_string().contains("private_key"));
    assert_eq!(catalog(&panel, &cookie).await?, rows);
    let retained: Value = sqlx::query_scalar("SELECT jsonb_build_object('chain',to_jsonb(c),'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY generation) FROM singbox_ordered_chain_versions v WHERE v.chain_id=c.id),'hops',(SELECT jsonb_agg(to_jsonb(h) ORDER BY generation,position) FROM singbox_ordered_chain_hops h WHERE h.chain_id=c.id)) FROM singbox_chains c WHERE c.id=$1")
        .bind(chain).fetch_one(&pool).await?;
    assert_eq!(retained, history);
    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(r) FROM singbox_ordered_chain_creation_requests r WHERE request_id=$1"
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await?,
        receipt
    );
    // Confirmed retirement releases the saved hop; history itself stays immutable.
    sqlx::query("UPDATE singbox_chains SET phase='retired' WHERE id=$1")
        .bind(chain)
        .execute(&pool)
        .await?;
    let current = catalog(&panel, &cookie).await?;
    let exit_row = current
        .iter()
        .find(|v| v["kind"] == "direct" && v["id"] == exit)
        .context("confirmed retired hop")?;
    call(
        &panel,
        &cookie,
        Method::DELETE,
        "/node-catalog/batch",
        Some(json!({"items":[change(exit_row,json!({}))]})),
    )
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT to_jsonb(r) FROM singbox_ordered_chain_creation_requests r WHERE request_id=$1"
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await?,
        receipt
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM singbox_ordered_chain_hops WHERE chain_id=$1"
        )
        .bind(chain)
        .fetch_one(&pool)
        .await?,
        1
    );
    let numeric_entry = id(&panel.create_node(&cookie, server, "Numeric entry").await?)?;
    let numeric: i64 = sqlx::query_scalar("INSERT INTO singbox_chains(name,entry_node_id,path_kind) VALUES('Numeric damaged policy',$1,'mixed') RETURNING id").bind(numeric_entry).fetch_one(&pool).await?;
    // Preserved legacy references require the same bounded public error as rich deletion.
    for index in 0..40 {
        let policy: i64 =
            sqlx::query_scalar("INSERT INTO singbox_policy_groups(name) VALUES($1) RETURNING id")
                .bind(format!("TEST_ONLY policy {index}\n{}", "x".repeat(140)))
                .fetch_one(&pool)
                .await?;
        sqlx::query("INSERT INTO singbox_policy_nodes(group_id,node_id) VALUES($1,$2)")
            .bind(policy)
            .bind(numeric_entry)
            .execute(&pool)
            .await?;
    }
    let rows = catalog(&panel, &cookie).await?;
    let chain_row = rows
        .iter()
        .find(|v| v["kind"] == "chain" && v["id"] == numeric)
        .context("numeric chain")?;
    let free_row = rows
        .iter()
        .find(|v| v["kind"] == "direct" && v["id"] == free)
        .context("free direct")?;
    let denied = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/node-catalog/batch"),
            &cookie,
            Some(json!({"items":[change(free_row,json!({})),change(chain_row,json!({}))]})),
        )
        .await?;
    assert_eq!(denied.status(), StatusCode::CONFLICT);
    let error: Value = denied.json().await?;
    let policies = error["references"]["policies"]
        .as_array()
        .context("bounded policy references")?;
    assert_eq!(policies.len(), 32);
    for policy in policies {
        let name = policy["name"].as_str().context("public name")?;
        assert!(name.chars().count() <= 128 && !name.chars().any(char::is_control));
    }
    assert_eq!(error["references"]["chains"], json!([]));
    assert!(!error.to_string().contains("private_key"));
    assert_eq!(catalog(&panel, &cookie).await?, rows);
    Ok(())
}

#[sqlx::test]
async fn catalog_chain_policy_conflict_returns_public_references_before_batch_mutation(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Entry host").await?;
    let entry = id(&panel.create_node(&cookie, server, "Policy entry").await?)?;
    let free = id(&panel.create_node(&cookie, server, "Free direct").await?)?;
    let exit_server = panel.create_server(&cookie, "Exit host").await?;
    let exit = id(&panel
        .create_node(&cookie, exit_server, "Shared exit")
        .await?)?;
    let chain = id(&panel
        .import_legacy_chain(&cookie, "Protected chain", entry, exit)
        .await?)?;
    let policy: i64 = sqlx::query_scalar(
        "INSERT INTO singbox_policy_groups(name) VALUES('Protected policy') RETURNING id",
    )
    .fetch_one(&pool)
    .await?;
    sqlx::query("INSERT INTO singbox_policy_chains(group_id,chain_id) VALUES($1,$2)")
        .bind(policy)
        .bind(chain)
        .execute(&pool)
        .await?;
    let rows = catalog(&panel, &cookie).await?;
    let free_row = rows
        .iter()
        .find(|value| value["kind"] == "direct" && value["id"] == free)
        .context("free resource")?;
    let chain_row = rows
        .iter()
        .find(|value| value["kind"] == "chain" && value["id"] == chain)
        .context("protected chain resource")?;
    let response = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/node-catalog/batch"),
            &cookie,
            Some(json!({"items":[change(free_row,json!({})),change(chain_row,json!({}))]})),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error: Value = response.json().await?;
    assert_eq!(
        error["references"]["policies"],
        json!([{
            "id":policy,"name":"Protected policy"
        }])
    );
    assert_eq!(error["references"]["chains"], json!([]));
    assert!(!error.to_string().contains("private_key"));
    assert_eq!(catalog(&panel, &cookie).await?, rows);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM nodes WHERE id=ANY($1) AND deleted_at IS NULL",
        )
        .bind(vec![entry, free, exit])
        .fetch_one(&pool)
        .await?,
        3
    );
    Ok(())
}
