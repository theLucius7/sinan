#![forbid(unsafe_code)]

mod business_support;
#[allow(dead_code)]
#[path = "ordered_paths/support.rs"]
mod ordered_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result, ensure};
use business_support::{TestPanel, id};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{AppState, agent_api, runtime_control};
use sinan_protocol::*;
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::ops::Deref;
use uuid::Uuid;

const ROOT: &str = "/api/plugins/sing-box";

struct ControlledPanel(TestPanel);

impl Deref for ControlledPanel {
    type Target = TestPanel;
    fn deref(&self) -> &TestPanel {
        &self.0
    }
}

impl ControlledPanel {
    /// TEST_ONLY device capabilities and platform facts; no native binary is executed.
    async fn create_server(&self, cookie: &str, name: &str) -> Result<i64> {
        let server = self.0.create_server(cookie, name).await?;
        sqlx::query("UPDATE servers SET capabilities=$2,static_info=$3 WHERE id=$1")
            .bind(server)
            .bind(json!([RUNTIME_CHECKPOINT_CAPABILITY,RUNTIME_RECOVERY_BARRIER_CAPABILITY,RUNTIME_PATH_PROBE_CAPABILITY]))
            .bind(json!({"os":"linux","arch":sinan_protocol::release::native_arch()?,"libc":"gnu","runtime_libc":"gnu"}))
            .execute(&self.state.pool).await?;
        Ok(server)
    }
}

async fn controlled_panel(pool: PgPool) -> Result<ControlledPanel> {
    let panel = TestPanel::start_with_public_url(pool, Some("https://panel.example")).await?;
    let binary = b"TEST_ONLY native binary never executed";
    let archive = release_fixture::archive("sing-box", binary)?;
    release_fixture::write(
        &panel.state.config.data_dir,
        "sing-box",
        "1.14.2",
        "sing-box",
        &archive,
        binary,
        "tar.gz",
    )?;
    Ok(ControlledPanel(panel))
}

/// Drive product publication and exact digest-bound TEST_ONLY receipts, never coarse SQL health.
async fn advance_phase(panel: &TestPanel, chain: i64, terminal: &str) -> Result<Vec<String>> {
    let mut phases = Vec::new();
    for _ in 0..32 {
        let phase: String = sqlx::query_scalar("SELECT phase FROM singbox_chains WHERE id=$1")
            .bind(chain)
            .fetch_one(&panel.state.pool)
            .await?;
        phases.push(phase.clone());
        if phase == terminal {
            return Ok(phases);
        }
        panel.publish_now().await?;
        ordered_support::confirm_devices(&panel.state).await?;
        sinan_panel::plugins::singbox::ordered_paths::reconcile_pending(&panel.state).await?;
        ordered_support::finish_controls(&panel.state, true).await?;
        sinan_panel::plugins::singbox::ordered_paths::reconcile_pending(&panel.state).await?;
    }
    anyhow::bail!("controlled chain {chain} did not reach {terminal}; phases: {phases:?}")
}

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
    ensure!(status.is_success(), "{path} returned {status}");
    if status == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }
    Ok(response.json().await?)
}

async fn batch(panel: &TestPanel, cookie: &str, body: Value) -> Result<(StatusCode, Value)> {
    let response = panel
        .admin(
            Method::POST,
            &format!("{ROOT}/chains/ordered-batch"),
            cookie,
            Some(body),
        )
        .await?;
    let status = response.status();
    let body = response.text().await?;
    Ok((
        status,
        serde_json::from_str(&body).unwrap_or_else(|_| json!({"error":body})),
    ))
}

fn new_entry(name: &str, server: i64, exit: i64, port: Option<i64>) -> Value {
    json!({
        "name":name,
        "entry":{"mode":"new","server_id":server,"public_host":"entry.example.com","sni":"www.example.com","port":port},
        "hops":[{"kind":"managed","node_id":exit}]
    })
}

fn existing_entry(name: &str, entry: i64, exit: i64) -> Value {
    json!({"name":name,"entry":{"mode":"existing","node_id":entry},"hops":[{"kind":"managed","node_id":exit}]})
}

fn request(items: Vec<Value>) -> Value {
    json!({"request_id":Uuid::new_v4(),"items":items})
}

fn ids(value: &Value, field: &str) -> Result<Vec<i64>> {
    value[field]
        .as_array()
        .context("response ID array")?
        .iter()
        .map(|value| value.as_i64().context("response integer ID"))
        .collect()
}

fn resource<'a>(list: &'a Value, kind: &str, identity: i64) -> Result<&'a Value> {
    list.as_array()
        .context("resource list")?
        .iter()
        .find(|value| value["kind"] == kind && value["id"] == identity)
        .context("typed resource")
}

async fn policy(
    panel: &TestPanel,
    cookie: &str,
    name: &str,
    nodes: &[i64],
    chains: &[i64],
) -> Result<i64> {
    id(&call(
        panel,
        cookie,
        Method::POST,
        "/policy-groups",
        Some(json!({"name":name,"node_ids":nodes,"chain_ids":chains})),
    )
    .await?)
}

async fn memberships(panel: &TestPanel, cookie: &str, user: i64, groups: &[i64]) -> Result<()> {
    call(
        panel,
        cookie,
        Method::PUT,
        &format!("/users/{user}/policy-groups"),
        Some(json!({"group_ids":groups})),
    )
    .await?;
    Ok(())
}

async fn clean_servers(pool: &PgPool) -> Result<()> {
    sqlx::query("UPDATE servers SET dirty_at=NULL")
        .execute(pool)
        .await?;
    Ok(())
}

async fn state(pool: &PgPool) -> Result<Value> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object('nodes',(SELECT COUNT(*) FROM nodes),'chains',(SELECT COUNT(*) FROM singbox_chains),'active_nodes',(SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL),'grants',(SELECT COUNT(*) FROM accesses),'versions',(SELECT COUNT(*) FROM singbox_ordered_chain_versions),'hops',(SELECT COUNT(*) FROM singbox_ordered_chain_hops),'endpoint_versions',(SELECT COUNT(*) FROM singbox_managed_endpoint_versions),'runtime_requirements',(SELECT COUNT(*) FROM singbox_chain_runtime_requirements),'receipts',(SELECT COUNT(*) FROM singbox_ordered_chain_creation_requests),'servers',(SELECT jsonb_agg(jsonb_build_array(id,dirty_at) ORDER BY id) FROM servers))",
    )
    .fetch_one(pool)
    .await?)
}

async fn save_usage(pool: &PgPool, server: i64, user: i64, node: i64) -> Result<()> {
    let epoch = Uuid::new_v4();
    sqlx::query("INSERT INTO usage_batches(server_id,epoch,seq,payload_hash) VALUES($1,$2,1,'TEST_ONLY-usage-hash')")
        .bind(server)
        .bind(epoch)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO usage_records(server_id,epoch,seq,stat_name,user_id,node_id,uplink,downlink,period_start,period_end) VALUES($1,$2,1,$3,$4,$5,20,30,100,101)")
        .bind(server)
        .bind(epoch)
        .bind(format!("u{user}_n{node}"))
        .bind(user)
        .bind(node)
        .execute(pool)
        .await?;
    Ok(())
}

async fn usage_identity(pool: &PgPool) -> Result<Value> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY server_id,epoch,seq,stat_name),'[]'::jsonb) FROM usage_records r",
    )
    .fetch_one(pool)
    .await?)
}

async fn public_subscription(panel: &TestPanel, user: &Value) -> Result<Value> {
    panel.publish_now().await?;
    ordered_support::confirm_devices(&panel.state).await?;
    let token = user["subscription_token"]
        .as_str()
        .context("existing subscription token")?;
    let path = format!("/sub/{token}");
    assert_eq!(
        user["subscription_url"],
        format!("{}{path}", panel.state.config.public_url)
    );
    Ok(panel
        .client
        .get(format!("{}{path}?format=singbox", panel.base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn no_private_fields(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (name, child) in fields {
                assert!(
                    ![
                        "private_key",
                        "relay_uuid",
                        "credential",
                        "password",
                        "psk",
                        "subscription_token",
                        "protocol_config",
                    ]
                    .contains(&name.as_str())
                );
                no_private_fields(child);
            }
        }
        Value::Array(values) => values.iter().for_each(no_private_fields),
        _ => {}
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn catalog_has_typed_ids_distinct_grant_counts_and_preserves_existing_subscriptions(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let exit_server = panel.create_server(&cookie, "Exit server").await?;
    let exit = id(&panel
        .create_node(&cookie, exit_server, "Shared exit")
        .await?)?;
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/nodes/{exit}"),
        Some(json!({"settings":{"public_port":8443}})),
    )
    .await?;
    let entry_server = panel.create_server(&cookie, "Entry server").await?;
    panel.enable_plugin(&cookie, entry_server).await?;
    let legacy = panel.create_user(&cookie, "Existing subscriber").await?;
    let legacy_id = id(&legacy)?;
    let grant = panel.grant(&cookie, legacy_id, exit).await?;
    save_usage(&pool, exit_server, legacy_id, exit).await?;
    let history = usage_identity(&pool).await?;
    let subscription = public_subscription(&panel, &legacy).await?;
    let old_node: Value = sqlx::query_scalar("SELECT to_jsonb(n) FROM nodes n WHERE id=$1")
        .bind(exit)
        .fetch_one(&pool)
        .await?;

    let (status, created) = batch(
        &panel,
        &cookie,
        request(vec![new_entry("Managed route", entry_server, exit, None)]),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    let chain = ids(&created, "chain_ids")?[0];
    let entry = ids(&created, "entry_node_ids")?[0];
    for (kind, identity) in [("direct", exit), ("chain", chain)] {
        for method in [Method::GET, Method::DELETE] {
            assert_eq!(
                panel
                    .client
                    .request(
                        method,
                        format!(
                            "{}{ROOT}/ordered-proxy-resources/{kind}/{identity}",
                            panel.base
                        )
                    )
                    .send()
                    .await?
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    // Independent identity spaces deliberately have the same first numeric ID.
    assert_eq!(chain, exit);
    let first = policy(&panel, &cookie, "First", &[exit], &[chain]).await?;
    let second = policy(&panel, &cookie, "Second", &[exit], &[chain]).await?;
    let member = id(&panel.create_user(&cookie, "Union member").await?)?;
    panel.grant(&cookie, member, exit).await?;
    memberships(&panel, &cookie, member, &[first, second]).await?;
    let other = id(&panel.create_user(&cookie, "Policy member").await?)?;
    memberships(&panel, &cookie, other, &[first]).await?;
    let deleted = id(&panel.create_user(&cookie, "Deleted member").await?)?;
    panel.grant(&cookie, deleted, exit).await?;
    memberships(&panel, &cookie, deleted, &[first]).await?;
    sqlx::query("UPDATE users SET deleted_at=1 WHERE id=$1")
        .bind(deleted)
        .execute(&pool)
        .await?;
    let phases = advance_phase(&panel, chain, "applied").await?;
    assert!(phases.iter().any(|phase| phase == "preparing_entry"));
    assert!(phases.iter().any(|phase| phase == "switching_entry"));

    assert_eq!(
        panel
            .client
            .get(format!("{}{ROOT}/ordered-proxy-resources", panel.base))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let list = call(
        &panel,
        &cookie,
        Method::GET,
        "/ordered-proxy-resources",
        None,
    )
    .await?;
    assert_eq!(list.as_array().context("list")?.len(), 2);
    let direct = resource(&list, "direct", exit)?;
    let route = resource(&list, "chain", chain)?;
    assert_eq!(direct["user_count"], 3);
    assert_eq!(route["user_count"], 2);
    assert_eq!(direct["policy_group_ids"], json!([first, second]));
    assert_eq!(route["policy_group_ids"], json!([first, second]));
    assert_eq!(direct["exit"], Value::Null);
    assert_eq!(
        direct["chain_refs"],
        json!([{"id":chain,"name":"Managed route","role":"exit","generation":1,"hop_position":1,"state":"applied"}])
    );
    assert_eq!(route["entry"]["id"], entry);
    assert_eq!(route["exit"]["id"], exit);
    assert_eq!(route["path_kind"], "ordered");
    assert_eq!(route["hops"][0]["node_id"], exit);
    assert_eq!(route["path_state"]["applied_generation"], 1);
    assert_eq!(route["path_state"]["minimum_generation"], 1);
    assert_eq!(route["path_state"]["probe"]["state"], "verified");
    assert!(route["path_state"]["candidate_generation"].is_null());
    assert_eq!(route["available"], true);
    assert_eq!(route["unavailable_reasons"], json!([]));
    assert_eq!(route["entry"]["server_name"], "Entry server");
    assert_eq!(route["exit"]["protocol"], "vless-reality");
    assert_eq!(route["exit"]["public_port"], 8443);
    assert_eq!(route["exit"]["port"], old_node["port"]);
    assert_eq!(route["entry"]["public_port"], route["entry"]["port"]);
    assert_eq!(route["entry"]["online"], false);
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/direct/{exit}"),
            None
        )
        .await?,
        *direct
    );
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None
        )
        .await?,
        *route
    );
    assert_eq!(
        panel
            .admin(
                Method::GET,
                &format!("{ROOT}/ordered-proxy-resources/direct/{entry}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    no_private_fields(&list);
    let relay: Uuid = sqlx::query_scalar("SELECT relay_uuid FROM singbox_ordered_chain_hops WHERE chain_id=$1 AND generation=1 AND position=1")
        .bind(chain)
        .fetch_one(&pool)
        .await?;
    let serialized = list.to_string();
    for secret in [
        old_node["private_key"].as_str().context("test node key")?,
        legacy["subscription_token"]
            .as_str()
            .context("test token")?,
        grant["uuid"].as_str().context("test grant")?,
        &relay.to_string(),
    ] {
        assert!(!serialized.contains(secret));
    }
    let current_node: Value = sqlx::query_scalar("SELECT to_jsonb(n) FROM nodes n WHERE id=$1")
        .bind(exit)
        .fetch_one(&pool)
        .await?;
    assert_eq!(current_node, old_node);
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/users/{legacy_id}"),
            None
        )
        .await?,
        legacy
    );
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/users/{legacy_id}/accesses"),
            None
        )
        .await?[0]["uuid"],
        grant["uuid"]
    );
    assert_eq!(usage_identity(&pool).await?, history);
    assert_eq!(public_subscription(&panel, &legacy).await?, subscription);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_middle_failure_rolls_back_entries_chains_and_dirty_markers(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let entry_server = panel.create_server(&cookie, "Entry").await?;
    panel.enable_plugin(&cookie, entry_server).await?;
    let exit_server = panel.create_server(&cookie, "Exit").await?;
    let exit = id(&panel.create_node(&cookie, exit_server, "Exit").await?)?;
    clean_servers(&pool).await?;
    let before = state(&pool).await?;
    let body = request(vec![
        new_entry("First", entry_server, exit, Some(24443)),
        new_entry("Conflicting second", entry_server, exit, Some(24443)),
        new_entry("Third", entry_server, exit, None),
    ]);
    assert_eq!(
        batch(&panel, &cookie, body.clone()).await?.0,
        StatusCode::CONFLICT
    );
    assert_eq!(state(&pool).await?, before);
    let mut corrected = body;
    corrected["items"][1]["entry"]["port"] = json!(24444);
    let (status, created) = batch(&panel, &cookie, corrected).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(ids(&created, "chain_ids")?.len(), 3);
    let chain_names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM singbox_chains ORDER BY id")
            .fetch_all(&pool)
            .await?;
    assert_eq!(chain_names, vec!["First", "Conflicting second", "Third"]);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_same_request_replays_normalized_body_and_rejects_changed_order(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let entry_server = panel.create_server(&cookie, "Entry").await?;
    panel.enable_plugin(&cookie, entry_server).await?;
    let exit_server = panel.create_server(&cookie, "Exit").await?;
    let exit = id(&panel.create_node(&cookie, exit_server, "Exit").await?)?;
    let body = request(vec![
        new_entry(" First ", entry_server, exit, None),
        new_entry("Second", entry_server, exit, None),
    ]);
    let (left, right) = tokio::join!(
        batch(&panel, &cookie, body.clone()),
        batch(&panel, &cookie, body.clone())
    );
    let (left_status, created) = left?;
    let (right_status, replay) = right?;
    assert!(
        (left_status == StatusCode::CREATED && right_status == StatusCode::OK)
            || (right_status == StatusCode::CREATED && left_status == StatusCode::OK)
    );
    assert_eq!(created, replay);
    assert_eq!(created["request_id"], body["request_id"]);
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM singbox_chains ORDER BY id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(names, vec!["First", "Second"]);
    clean_servers(&pool).await?;
    let before = state(&pool).await?;
    let mut normalized = body.clone();
    normalized["items"][0]["name"] = json!("First");
    normalized["items"][0]["entry"]
        .as_object_mut()
        .context("entry")?
        .remove("port");
    let (status, value) = batch(&panel, &cookie, normalized).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, created);
    assert_eq!(state(&pool).await?, before);
    let mut changed = body.clone();
    changed["items"].as_array_mut().context("items")?.reverse();
    assert_eq!(
        batch(&panel, &cookie, changed).await?.0,
        StatusCode::CONFLICT
    );
    let mut changed = body;
    changed["items"][0]["name"] = json!("Different");
    assert_eq!(
        batch(&panel, &cookie, changed).await?.0,
        StatusCode::CONFLICT
    );
    assert_eq!(state(&pool).await?, before);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_batches_allocate_unique_auto_ports_without_partial_reservations(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let entry_server = panel.create_server(&cookie, "Entry").await?;
    panel.enable_plugin(&cookie, entry_server).await?;
    let exit_server = panel.create_server(&cookie, "Exit").await?;
    let exit = id(&panel
        .create_node(&cookie, exit_server, "Shared exit")
        .await?)?;
    let body = |prefix: &str| {
        request(vec![
            new_entry(&format!("{prefix} one"), entry_server, exit, None),
            new_entry(&format!("{prefix} two"), entry_server, exit, None),
        ])
    };
    let (one, two, three) = tokio::join!(
        batch(&panel, &cookie, body("One")),
        batch(&panel, &cookie, body("Two")),
        batch(&panel, &cookie, body("Three"))
    );
    let mut all_nodes = BTreeSet::new();
    let mut all_chains = BTreeSet::new();
    for response in [one?, two?, three?] {
        assert_eq!(response.0, StatusCode::CREATED);
        all_nodes.extend(ids(&response.1, "entry_node_ids")?);
        all_chains.extend(ids(&response.1, "chain_ids")?);
    }
    assert_eq!(all_nodes.len(), 6);
    assert_eq!(all_chains.len(), 6);
    let ports: Vec<i32> = sqlx::query_scalar(
        "SELECT port FROM nodes WHERE server_id=$1 AND deleted_at IS NULL ORDER BY port",
    )
    .bind(entry_server)
    .fetch_all(&pool)
    .await?;
    assert_eq!(ports, vec![20000, 20001, 20002, 20003, 20004, 20005]);
    let before = state(&pool).await?;
    for invalid in [0, 65536, 18085] {
        assert_eq!(
            batch(
                &panel,
                &cookie,
                request(vec![new_entry(
                    "Invalid",
                    entry_server,
                    exit,
                    Some(invalid)
                )])
            )
            .await?
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state(&pool).await?, before);
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_rejects_unauthorized_entries_and_invalid_managed_topologies(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let a = panel.create_server(&cookie, "A").await?;
    let b = panel.create_server(&cookie, "B").await?;
    let c = panel.create_server(&cookie, "C").await?;
    let na = id(&panel.create_node(&cookie, a, "A").await?)?;
    let na2 = id(&panel.create_node(&cookie, a, "A direct").await?)?;
    let na3 = id(&panel.create_node(&cookie, a, "A policy").await?)?;
    let nb = id(&panel.create_node(&cookie, b, "B").await?)?;
    let nc = id(&panel.create_node(&cookie, c, "C").await?)?;
    let user = id(&panel.create_user(&cookie, "Existing user").await?)?;
    panel.grant(&cookie, user, na2).await?;
    policy(&panel, &cookie, "Existing direct policy", &[na3], &[]).await?;
    let snell = id(&call(
        &panel,
        &cookie,
        Method::POST,
        "/nodes",
        Some(json!({"name":"Non Reality","server_id":c,"public_host":"snell.example.com","protocol_config":{"type":"snell-v6"}})),
    )
    .await?)?;
    let disabled = id(&panel.create_node(&cookie, c, "Disabled").await?)?;
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/nodes/{disabled}"),
        Some(json!({"enabled":false})),
    )
    .await?;
    let deleted = id(&panel.create_node(&cookie, c, "Deleted").await?)?;
    call(
        &panel,
        &cookie,
        Method::DELETE,
        &format!("/nodes/{deleted}"),
        None,
    )
    .await?;
    let pending_server = panel.create_server(&cookie, "Pending retirement").await?;
    let pending = id(&panel
        .create_node(&cookie, pending_server, "Pending retirement")
        .await?)?;
    sqlx::query("INSERT INTO server_retirements(server_id,request_id,status,requested_at) VALUES($1,$2,'pending',1)")
        .bind(pending_server)
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await?;
    let retired_server = panel.create_server(&cookie, "Retired").await?;
    let retired = id(&panel
        .create_node(&cookie, retired_server, "Retired")
        .await?)?;
    sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
        .bind(retired_server)
        .execute(&pool)
        .await?;
    let no_plugin = panel.create_server(&cookie, "Never enabled").await?;
    let legacy_server = panel.create_server(&cookie, "Legacy configuration").await?;
    let legacy_node = id(&panel
        .create_node(&cookie, legacy_server, "Preserved legacy")
        .await?)?;
    sqlx::query("UPDATE server_plugins SET enabled=FALSE WHERE server_id=$1 AND plugin='sing-box'")
        .bind(legacy_server)
        .execute(&pool)
        .await?;
    clean_servers(&pool).await?;
    let before = state(&pool).await?;
    for (item, expected) in [
        (
            existing_entry("Direct bypass", na2, nb),
            StatusCode::CONFLICT,
        ),
        (
            existing_entry("Policy bypass", na3, nb),
            StatusCode::CONFLICT,
        ),
        // A path cannot return to its own entry, even before entry-role reservation.
        (existing_entry("Same node", na, na), StatusCode::BAD_REQUEST),
        (
            existing_entry("Same server", na, na2),
            StatusCode::BAD_REQUEST,
        ),
        (
            existing_entry("Public address loop", legacy_node, nb),
            StatusCode::BAD_REQUEST,
        ),
        (
            existing_entry("Non Reality entry", snell, nb),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_entry("Non Reality exit", a, snell, None),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_entry("Disabled exit", a, disabled, None),
            StatusCode::BAD_REQUEST,
        ),
        (
            existing_entry("Disabled entry", disabled, nb),
            StatusCode::BAD_REQUEST,
        ),
        (
            existing_entry("Deleted entry", deleted, nb),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_entry("Deleted exit", a, deleted, None),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_entry("Retired exit", a, retired, None),
            StatusCode::CONFLICT,
        ),
        (
            new_entry("Retiring exit", a, pending, None),
            StatusCode::CONFLICT,
        ),
        (
            new_entry("Retired entry", retired_server, nb, None),
            StatusCode::CONFLICT,
        ),
        (
            new_entry("Retiring entry", pending_server, nb, None),
            StatusCode::CONFLICT,
        ),
        (
            new_entry("Never enabled entry", no_plugin, nb, None),
            StatusCode::CONFLICT,
        ),
        (
            existing_entry("Missing entry", i64::MAX, nb),
            StatusCode::BAD_REQUEST,
        ),
        (
            new_entry("Missing server", i64::MAX, nb, None),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            batch(&panel, &cookie, request(vec![item])).await?.0,
            expected
        );
        assert_eq!(state(&pool).await?, before);
    }
    // Different server IDs still need distinct public endpoints: the default
    // first nodes otherwise both point to proxy.example.com:20000.
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/nodes/{nb}"),
        Some(json!({"public_host":"exit-b.example.com"})),
    )
    .await?;
    // Preserved nodes keep legacy enablement even when the explicit row is disabled.
    let (status, created) = batch(
        &panel,
        &cookie,
        request(vec![existing_entry(
            "Legacy compatibility",
            legacy_node,
            nb,
        )]),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    call(
        &panel,
        &cookie,
        Method::POST,
        "/chains",
        Some(json!({"name":"AB","entry_node_id":na,"exit_node_id":nb})),
    )
    .await?;
    let before = state(&pool).await?;
    for item in [
        existing_entry("Cycle", nb, na),
        existing_entry("Nested entry", nb, nc),
        existing_entry("Nested exit", nc, na),
        existing_entry("Repeated entry", na, nc),
        new_entry("New nested exit", c, na, None),
    ] {
        assert_eq!(
            batch(&panel, &cookie, request(vec![item])).await?.0,
            StatusCode::CONFLICT
        );
        assert_eq!(state(&pool).await?, before);
    }
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("{ROOT}/users/{user}/accesses"),
                &cookie,
                Some(json!({"node_id":na}))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .admin(
                Method::POST,
                &format!("{ROOT}/policy-groups"),
                &cookie,
                Some(json!({"name":"Entry bypass","node_ids":[na],"chain_ids":[]}))
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_limits_and_unsupported_paths_fail_before_mutating_existing_business(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let a = panel.create_server(&cookie, "Entry").await?;
    panel.enable_plugin(&cookie, a).await?;
    let b = panel.create_server(&cookie, "Exit").await?;
    let exit = id(&panel.create_node(&cookie, b, "Exit").await?)?;
    clean_servers(&pool).await?;
    let before = state(&pool).await?;
    let valid = request(vec![new_entry("Valid", a, exit, None)]);
    assert_eq!(
        panel
            .client
            .post(format!("{}{ROOT}/chains/ordered-batch", panel.base))
            .json(&valid)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut repeated_hop = valid.clone();
    repeated_hop["items"][0]["hops"] =
        json!([{"kind":"managed","node_id":exit},{"kind":"managed","node_id":exit}]);
    let mut too_many_hops = valid.clone();
    too_many_hops["items"][0]["hops"] = json!(vec![json!({"kind":"managed","node_id":exit}); 9]);
    let mut subscription_hop = valid.clone();
    subscription_hop["items"][0]["hops"] = json!([{"kind":"subscription","node_id":exit}]);
    let mut missing_hop = valid.clone();
    missing_hop["items"][0]["hops"] = json!([]);
    let mut unknown_field = valid.clone();
    unknown_field["items"][0]["entry"]["password"] = json!("TEST_ONLY-forbidden");
    let mut invalid_request = valid;
    invalid_request["request_id"] = json!("not-a-uuid");
    for invalid in [
        request(vec![]),
        request(vec![new_entry("Too many", a, exit, None); 33]),
        repeated_hop,
        too_many_hops,
        subscription_hop,
        missing_hop,
        unknown_field,
        invalid_request,
    ] {
        assert!(batch(&panel, &cookie, invalid).await?.0.is_client_error());
        assert_eq!(state(&pool).await?, before);
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn resource_delete_preserves_shared_exit_history_and_deleted_request_replay(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let a = panel.create_server(&cookie, "Entry").await?;
    panel.enable_plugin(&cookie, a).await?;
    let b = panel.create_server(&cookie, "Exit").await?;
    let exit = id(&panel.create_node(&cookie, b, "Shared exit").await?)?;
    let legacy = panel.create_user(&cookie, "Direct subscriber").await?;
    let legacy_id = id(&legacy)?;
    let direct_grant = panel.grant(&cookie, legacy_id, exit).await?;
    let exit_before: Value = sqlx::query_scalar("SELECT to_jsonb(n) FROM nodes n WHERE id=$1")
        .bind(exit)
        .fetch_one(&pool)
        .await?;
    let body = request(vec![
        new_entry("First", a, exit, None),
        new_entry("Second", a, exit, None),
    ]);
    let (status, created) = batch(&panel, &cookie, body.clone()).await?;
    assert_eq!(status, StatusCode::CREATED);
    let chains = ids(&created, "chain_ids")?;
    let entries = ids(&created, "entry_node_ids")?;
    let first = chains[0];
    let group = policy(&panel, &cookie, "In use", &[], &[first]).await?;
    let user = id(&panel.create_user(&cookie, "Chain subscriber").await?)?;
    memberships(&panel, &cookie, user, &[group]).await?;
    advance_phase(&panel, first, "applied").await?;
    advance_phase(&panel, chains[1], "applied").await?;
    save_usage(&pool, a, user, entries[0]).await?;
    save_usage(&pool, b, legacy_id, exit).await?;
    let history = usage_identity(&pool).await?;
    let before = state(&pool).await?;
    let blocked = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/ordered-proxy-resources/chain/{first}"),
            &cookie,
            None,
        )
        .await?;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    let references: Value = blocked.json().await?;
    no_private_fields(&references);
    assert_eq!(
        references["references"]["policies"],
        json!([{"id":group,"name":"In use"}])
    );
    assert_eq!(references["references"]["chains"], json!([]));
    assert_eq!(state(&pool).await?, before);
    for path in [
        format!("/nodes/{exit}"),
        format!("/proxy-resources/direct/{exit}"),
        format!("/ordered-proxy-resources/direct/{exit}"),
        format!("/nodes/{}", entries[0]),
    ] {
        let blocked = panel
            .admin(Method::DELETE, &format!("{ROOT}{path}"), &cookie, None)
            .await?;
        assert_eq!(blocked.status(), StatusCode::CONFLICT);
        let references: Value = blocked.json().await?;
        no_private_fields(&references);
        assert_eq!(references["references"]["policies"], json!([]));
        assert!(
            references["references"]["chains"]
                .as_array()
                .context("chain references")?
                .iter()
                .any(|reference| reference["id"] == first)
        );
        let expected_role = if path == format!("/nodes/{}", entries[0]) {
            "entry"
        } else {
            "exit"
        };
        assert!(
            references["references"]["chains"]
                .as_array()
                .context("chain references")?
                .iter()
                .all(|reference| reference["role"] == expected_role)
        );
    }
    assert_eq!(state(&pool).await?, before);
    call(
        &panel,
        &cookie,
        Method::PUT,
        &format!("/policy-groups/{group}"),
        Some(json!({"name":"Empty","node_ids":[],"chain_ids":[]})),
    )
    .await?;
    call(
        &panel,
        &cookie,
        Method::DELETE,
        &format!("/ordered-proxy-resources/chain/{first}"),
        None,
    )
    .await?;
    let retiring: String = sqlx::query_scalar("SELECT phase FROM singbox_chains WHERE id=$1")
        .bind(first)
        .fetch_one(&pool)
        .await?;
    assert_eq!(retiring, "retiring");
    let protected = panel
        .admin(
            Method::DELETE,
            &format!("{ROOT}/ordered-proxy-resources/direct/{exit}"),
            &cookie,
            None,
        )
        .await?;
    assert_eq!(protected.status(), StatusCode::CONFLICT);
    let cleanup_refs: Value = protected.json().await?;
    assert!(
        cleanup_refs["references"]["chains"]
            .as_array()
            .context("pending cleanup references")?
            .iter()
            .any(|reference| reference["id"] == first)
    );
    advance_phase(&panel, first, "retired").await?;
    let deleted: Option<i64> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id=$1")
        .bind(entries[0])
        .fetch_one(&pool)
        .await?;
    assert!(deleted.is_some());
    let accesses: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses WHERE node_id=$1")
        .bind(entries[0])
        .fetch_one(&pool)
        .await?;
    assert_eq!(accesses, 0);
    let exit_after: Value = sqlx::query_scalar("SELECT to_jsonb(n) FROM nodes n WHERE id=$1")
        .bind(exit)
        .fetch_one(&pool)
        .await?;
    assert_eq!(exit_after, exit_before);
    assert_eq!(usage_identity(&pool).await?, history);
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/users/{legacy_id}"),
            None
        )
        .await?,
        legacy
    );
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/users/{legacy_id}/accesses"),
            None
        )
        .await?[0]["uuid"],
        direct_grant["uuid"]
    );
    let before_replay = state(&pool).await?;
    let (status, replay) = batch(&panel, &cookie, body.clone()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay, created);
    assert_eq!(state(&pool).await?, before_replay);
    assert_eq!(
        panel
            .admin(
                Method::GET,
                &format!("{ROOT}/ordered-proxy-resources/chain/{first}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    let retained = call(
        &panel,
        &cookie,
        Method::GET,
        &format!("/ordered-proxy-resources/chain/{}", chains[1]),
        None,
    )
    .await?;
    assert_eq!(retained["available"], true);
    assert_eq!(retained["path_kind"], "ordered");
    // The old relationship endpoint cannot partially detach a new ordered path.
    let before_detach = state(&pool).await?;
    assert_eq!(
        panel
            .admin(
                Method::DELETE,
                &format!("{ROOT}/chains/{}", chains[1]),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(state(&pool).await?, before_detach);
    call(
        &panel,
        &cookie,
        Method::DELETE,
        &format!("/ordered-proxy-resources/chain/{}", chains[1]),
        None,
    )
    .await?;
    advance_phase(&panel, chains[1], "retired").await?;
    let removed: Option<i64> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id=$1")
        .bind(entries[1])
        .fetch_one(&pool)
        .await?;
    assert!(removed.is_some());
    // Explicitly imported legacy relationships still detach without deleting the entry.
    let compatibility_entry = id(&panel
        .create_node(&cookie, a, "Legacy detachable entry")
        .await?)?;
    let compatibility_chain = id(&panel
        .import_legacy_chain(
            &cookie,
            "Imported legacy relationship",
            compatibility_entry,
            exit,
        )
        .await?)?;
    call(
        &panel,
        &cookie,
        Method::DELETE,
        &format!("/chains/{compatibility_chain}"),
        None,
    )
    .await?;
    let retained: Option<i64> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id=$1")
        .bind(compatibility_entry)
        .fetch_one(&pool)
        .await?;
    assert_eq!(retained, None);
    let direct = call(
        &panel,
        &cookie,
        Method::GET,
        &format!("/ordered-proxy-resources/direct/{compatibility_entry}"),
        None,
    )
    .await?;
    assert_eq!(direct["kind"], "direct");
    let before_replay = state(&pool).await?;
    assert_eq!(
        batch(&panel, &cookie, body).await?,
        (StatusCode::OK, created)
    );
    assert_eq!(state(&pool).await?, before_replay);
    assert_eq!(usage_identity(&pool).await?, history);
    let policy = policy(&panel, &cookie, "Direct protected", &[exit], &[]).await?;
    for path in [
        format!("/nodes/{exit}"),
        format!("/proxy-resources/direct/{exit}"),
        format!("/ordered-proxy-resources/direct/{exit}"),
    ] {
        let blocked = panel
            .admin(Method::DELETE, &format!("{ROOT}{path}"), &cookie, None)
            .await?;
        assert_eq!(blocked.status(), StatusCode::CONFLICT);
        let references: Value = blocked.json().await?;
        assert_eq!(
            references["references"]["policies"],
            json!([{"id":policy,"name":"Direct protected"}])
        );
        assert_eq!(references["references"]["chains"], json!([]));
        no_private_fields(&references);
    }
    assert_eq!(usage_identity(&pool).await?, history);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn damaged_chains_stay_readable_and_cleanable_without_exposing_private_configuration(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let a = panel.create_server(&cookie, "Entry").await?;
    let b = panel.create_server(&cookie, "Exit").await?;
    let entry = id(&panel.create_node(&cookie, a, "Existing entry").await?)?;
    let orphan_old = id(&panel.create_node(&cookie, a, "Old cleanup").await?)?;
    let orphan_numeric = id(&panel
        .create_node(&cookie, a, "Numeric resource cleanup")
        .await?)?;
    let orphan_new = id(&panel.create_node(&cookie, a, "Resource cleanup").await?)?;
    let exit = id(&panel.create_node(&cookie, b, "Existing exit").await?)?;
    let imported = panel
        .import_legacy_chain(&cookie, "Historical chain", entry, exit)
        .await?;
    let chain = id(&imported)?;
    assert_eq!(imported["entry_node_id"], entry);
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None
        )
        .await?["path_kind"],
        "legacy"
    );
    let original_settings: Value = sqlx::query_scalar("SELECT settings FROM nodes WHERE id=$1")
        .bind(exit)
        .fetch_one(&pool)
        .await?;
    let original_protocol: Value =
        sqlx::query_scalar("SELECT protocol_config FROM nodes WHERE id=$1")
            .bind(exit)
            .fetch_one(&pool)
            .await?;
    let snell = json!({"type":"snell-v6","psk":"TEST_ONLY-hidden-proxy-resource-credential"});
    // A type mismatch cannot enter this database; preserve and prove that constraint.
    let mismatch = sqlx::query("UPDATE nodes SET protocol_config=$2 WHERE id=$1")
        .bind(exit)
        .bind(&snell)
        .execute(&pool)
        .await
        .expect_err("database must reject a mismatched protocol type");
    let mismatch = mismatch
        .as_database_error()
        .context("database constraint error")?;
    assert_eq!(mismatch.code().as_deref(), Some("23514"));
    assert_eq!(mismatch.constraint(), Some("nodes_protocol_config_check"));
    let retained: Value = sqlx::query_scalar("SELECT protocol_config FROM nodes WHERE id=$1")
        .bind(exit)
        .fetch_one(&pool)
        .await?;
    assert_eq!(retained, original_protocol);
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None
        )
        .await?["available"],
        true
    );
    // A legal struct variant gives a direct-resource baseline for parsing failures.
    sqlx::query("UPDATE nodes SET protocol='snell-v6',protocol_config=$2 WHERE id=$1")
        .bind(exit)
        .bind(&snell)
        .execute(&pool)
        .await?;
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/direct/{exit}"),
            None
        )
        .await?["available"],
        true
    );
    // Matching SQL type tags do not guarantee required fields deserialize correctly.
    for config in [
        json!({"type":"snell-v6","private_key":"TEST_ONLY-hidden"}),
        json!({"type":"snell-v6","psk":42}),
    ] {
        sqlx::query("UPDATE nodes SET protocol_config=$2 WHERE id=$1")
            .bind(exit)
            .bind(config)
            .execute(&pool)
            .await?;
        let list = call(
            &panel,
            &cookie,
            Method::GET,
            "/ordered-proxy-resources",
            None,
        )
        .await?;
        let route = resource(&list, "chain", chain)?;
        assert_eq!(route["available"], false);
        // Desired immutable input stays Reality while live metadata reports damage.
        assert_eq!(route["exit"]["protocol"], "vless-reality");
        assert!(
            route["unavailable_reasons"]
                .as_array()
                .context("protocol reasons")?
                .iter()
                .any(|value| value
                    .as_str()
                    .is_some_and(|text| text.contains("第 1 跳协议参数")))
        );
        assert_eq!(resource(&list, "direct", exit)?["available"], false);
        assert_eq!(resource(&list, "direct", orphan_new)?["available"], true);
        let detail = call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None,
        )
        .await?;
        assert_eq!(detail, *route);
        no_private_fields(&list);
        assert!(!list.to_string().contains("TEST_ONLY-hidden"));
    }
    sqlx::query("UPDATE nodes SET protocol='vless-reality',protocol_config=$2 WHERE id=$1")
        .bind(exit)
        .bind(&original_protocol)
        .execute(&pool)
        .await?;
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None
        )
        .await?["available"],
        true
    );
    // A damaged private settings document must not break the public management projection.
    sqlx::query("UPDATE nodes SET settings=$2 WHERE id=$1")
        .bind(exit)
        .bind(json!({"public_port":"TEST_ONLY-invalid"}))
        .execute(&pool)
        .await?;
    let route = call(
        &panel,
        &cookie,
        Method::GET,
        &format!("/ordered-proxy-resources/chain/{chain}"),
        None,
    )
    .await?;
    assert_eq!(route["id"], chain);
    assert_eq!(route["available"], false);
    assert!(
        !route["unavailable_reasons"]
            .as_array()
            .context("damaged settings reasons")?
            .is_empty()
    );
    no_private_fields(&route);
    assert!(!route.to_string().contains("TEST_ONLY-hidden"));
    sqlx::query("UPDATE nodes SET settings=$2 WHERE id=$1")
        .bind(exit)
        .bind(original_settings)
        .execute(&pool)
        .await?;
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None
        )
        .await?["available"],
        true
    );
    sqlx::query("UPDATE nodes SET enabled=FALSE,deleted_at=1,protocol='snell-v6',protocol_config=$2 WHERE id=$1")
        .bind(exit)
        .bind(snell)
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
        .bind(b)
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE server_plugins SET enabled=FALSE WHERE server_id=$1 AND plugin='sing-box'")
        .bind(b)
        .execute(&pool)
        .await?;
    let list = call(
        &panel,
        &cookie,
        Method::GET,
        "/ordered-proxy-resources",
        None,
    )
    .await?;
    let route = resource(&list, "chain", chain)?;
    assert_eq!(route["available"], false);
    assert_eq!(route["exit"]["id"], exit);
    assert_eq!(route["exit"]["node_deleted"], true);
    assert_eq!(route["exit"]["server_deleted"], true);
    // This flag describes preserved configuration evidence, not retirement eligibility.
    assert_eq!(route["exit"]["plugin_enabled"], true);
    let reasons = route["unavailable_reasons"]
        .as_array()
        .context("unavailable reasons")?;
    assert!(reasons.len() >= 3);
    assert!(
        reasons
            .iter()
            .all(|value| value.as_str().is_some_and(|text| !text.is_empty()))
    );
    assert!(
        list.as_array()
            .context("list")?
            .iter()
            .all(|value| !(value["kind"] == "direct" && value["id"] == exit))
    );
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-proxy-resources/chain/{chain}"),
            None
        )
        .await?,
        *route
    );
    no_private_fields(&list);
    call(
        &panel,
        &cookie,
        Method::DELETE,
        &format!("/ordered-proxy-resources/chain/{chain}"),
        None,
    )
    .await?;
    let deleted: Option<i64> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id=$1")
        .bind(entry)
        .fetch_one(&pool)
        .await?;
    assert!(deleted.is_some());
    assert_eq!(
        panel
            .admin(
                Method::GET,
                &format!("{ROOT}/ordered-proxy-resources/chain/{chain}"),
                &cookie,
                None
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
        .bind(a)
        .execute(&pool)
        .await?;
    for (node, path) in [
        (orphan_old, format!("/nodes/{orphan_old}")),
        (
            orphan_numeric,
            format!("/proxy-resources/direct/{orphan_numeric}"),
        ),
        (
            orphan_new,
            format!("/ordered-proxy-resources/direct/{orphan_new}"),
        ),
    ] {
        assert_eq!(
            panel
                .admin(
                    Method::GET,
                    &format!("{ROOT}/ordered-proxy-resources/direct/{node}"),
                    &cookie,
                    None
                )
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
        call(&panel, &cookie, Method::DELETE, &path, None).await?;
        let deleted: Option<i64> = sqlx::query_scalar("SELECT deleted_at FROM nodes WHERE id=$1")
            .bind(node)
            .fetch_one(&pool)
            .await?;
        assert!(deleted.is_some());
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn retired_node_cleanup_keeps_damaged_ordered_owners_and_bounded_public_references(
    pool: PgPool,
) -> Result<()> {
    let panel = controlled_panel(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let a = panel.create_server(&cookie, "Entry").await?;
    panel.enable_plugin(&cookie, a).await?;
    let b = panel.create_server(&cookie, "Exit").await?;
    let exit = id(&panel.create_node(&cookie, b, "Shared exit").await?)?;
    let body = request(vec![new_entry("Retained owner", a, exit, None)]);
    let (status, created) = batch(&panel, &cookie, body.clone()).await?;
    assert_eq!(status, StatusCode::CREATED);
    let chain = ids(&created, "chain_ids")?[0];
    let entry = ids(&created, "entry_node_ids")?[0];
    // TEST_ONLY desired metadata points to a missing immutable version. The
    // surviving candidate still owns the dedicated entry on a retired server.
    sqlx::query("UPDATE singbox_chains SET desired_generation=99 WHERE id=$1")
        .bind(chain)
        .execute(&pool)
        .await?;
    sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
        .bind(a)
        .execute(&pool)
        .await?;
    let before = state(&pool).await?;
    let paths = [
        format!("/nodes/{entry}"),
        format!("/proxy-resources/direct/{entry}"),
        format!("/ordered-proxy-resources/direct/{entry}"),
    ];
    for path in &paths {
        let response = panel
            .admin(Method::DELETE, &format!("{ROOT}{path}"), &cookie, None)
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let error: Value = response.json().await?;
        no_private_fields(&error);
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|value| value.contains("仍被"))
        );
        assert_eq!(error["references"]["policies"], json!([]));
        assert_eq!(
            error["references"]["chains"],
            json!([{
                "id":chain,
                "name":"Retained owner",
                "role":"entry",
                "generation":1,
                "hop_position":null,
                "state":"candidate"
            }, {
                "id":chain,
                "name":"Retained owner",
                "role":"entry",
                "generation":99,
                "hop_position":null,
                "state":"unresolved"
            }])
        );
    }
    assert_eq!(state(&pool).await?, before);
    assert_eq!(
        batch(&panel, &cookie, body.clone()).await?,
        (StatusCode::OK, created)
    );
    let mut new_request = body;
    new_request["request_id"] = json!(Uuid::new_v4());
    assert_eq!(
        batch(&panel, &cookie, new_request).await?.0,
        StatusCode::CONFLICT
    );
    assert_eq!(state(&pool).await?, before);
    // TEST_ONLY corrupt the remaining pointer too, without altering immutable
    // history. Missing projections must not free an unresolved entry owner.
    sqlx::query("UPDATE singbox_chains SET candidate_generation=99 WHERE id=$1")
        .bind(chain)
        .execute(&pool)
        .await?;
    let before = state(&pool).await?;
    for path in &paths {
        let response = panel
            .admin(Method::DELETE, &format!("{ROOT}{path}"), &cookie, None)
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let error: Value = response.json().await?;
        no_private_fields(&error);
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|value| value.contains("仍被"))
        );
        assert_eq!(error["references"]["policies"], json!([]));
        assert_eq!(
            error["references"]["chains"],
            json!([{
                "id":chain,"name":"Retained owner","role":"entry",
                "generation":99,"hop_position":null,"state":"unresolved"
            }])
        );
    }
    assert_eq!(state(&pool).await?, before);
    // Missing selected versions retain the raw hop with an actionable owner,
    // across the old, numeric and ordered direct-node deletion endpoints.
    for path in [
        format!("/nodes/{exit}"),
        format!("/proxy-resources/direct/{exit}"),
        format!("/ordered-proxy-resources/direct/{exit}"),
    ] {
        let response = panel
            .admin(Method::DELETE, &format!("{ROOT}{path}"), &cookie, None)
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let error: Value = response.json().await?;
        no_private_fields(&error);
        assert_eq!(error["references"]["policies"], json!([]));
        assert_eq!(
            error["references"]["chains"],
            json!([{
                "id":chain,"name":"Retained owner","role":"exit",
                "generation":1,"hop_position":1,"state":"unresolved"
            }])
        );
    }
    assert_eq!(state(&pool).await?, before);
    let generations: Vec<i64> = sqlx::query_scalar(
        "SELECT generation FROM singbox_ordered_chain_versions WHERE chain_id=$1 ORDER BY generation",
    )
    .bind(chain)
    .fetch_all(&pool)
    .await?;
    assert_eq!(generations, vec![1]);
    // Preserved/corrupt policy references must block deletion without producing
    // an unbounded response or leaking private endpoint configuration.
    for index in 0..40 {
        let policy: i64 =
            sqlx::query_scalar("INSERT INTO singbox_policy_groups(name) VALUES($1) RETURNING id")
                .bind(format!("TEST_ONLY public policy {index}"))
                .fetch_one(&pool)
                .await?;
        sqlx::query("INSERT INTO singbox_policy_nodes(group_id,node_id) VALUES($1,$2)")
            .bind(policy)
            .bind(entry)
            .execute(&pool)
            .await?;
    }
    let before = state(&pool).await?;
    for path in &paths {
        let response = panel
            .admin(Method::DELETE, &format!("{ROOT}{path}"), &cookie, None)
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let error: Value = response.json().await?;
        no_private_fields(&error);
        assert_eq!(
            error["references"]["policies"]
                .as_array()
                .context("bounded policies")?
                .len(),
            32
        );
        assert_eq!(
            error["references"]["chains"],
            json!([{
                "id":chain,"name":"Retained owner","role":"entry",
                "generation":99,"hop_position":null,"state":"unresolved"
            }])
        );
    }
    assert_eq!(state(&pool).await?, before);
    Ok(())
}
