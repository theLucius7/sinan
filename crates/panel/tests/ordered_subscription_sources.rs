#![forbid(unsafe_code)]

mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::plugins::singbox::subscription_sources::worker;
use sqlx::PgPool;
use uuid::Uuid;

const ROOT: &str = "/api/plugins/sing-box";

async fn call(
    panel: &TestPanel,
    cookie: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
    expected: StatusCode,
) -> Result<Value> {
    let response = panel
        .admin(method, &format!("{ROOT}{path}"), cookie, body)
        .await?;
    ensure!(
        response.status() == expected,
        "unexpected status for {path}: {} (expected {expected})",
        response.status()
    );
    if expected == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }
    Ok(response.json().await?)
}

fn source_id(receipt: &Value) -> Result<i64> {
    receipt["source_id"].as_i64().context("source ID")
}
fn job_id(receipt: &Value) -> Result<&str> {
    receipt["job_id"].as_str().context("job ID")
}
fn proxy(name: &str, host: &str, password: &str) -> Value {
    json!({"type":"socks","tag":name,"server":host,"server_port":1080,"version":"5","username":"TEST_ONLY-user","password":password})
}
fn config(nodes: Vec<Value>) -> String {
    json!({"outbounds":nodes}).to_string()
}
fn inline_request(name: &str, content: &str) -> Value {
    json!({"request_id":Uuid::new_v4(),"name":name,"input":{"kind":"inline","content":content}})
}

async fn inline(panel: &TestPanel, cookie: &str, content: &str) -> Result<Value> {
    let receipt = call(
        panel,
        cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request("Imported source", content)),
        StatusCode::ACCEPTED,
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    Ok(receipt)
}

async fn get(panel: &TestPanel, cookie: &str, id: i64, suffix: &str) -> Result<Value> {
    call(
        panel,
        cookie,
        Method::GET,
        &format!("/ordered-subscription-sources/{id}{suffix}"),
        None,
        StatusCode::OK,
    )
    .await
}

async fn update_content(
    panel: &TestPanel,
    cookie: &str,
    id: i64,
    revision: i64,
    content: &str,
    action: &str,
) -> Result<Value> {
    call(panel,cookie,Method::PATCH,&format!("/ordered-subscription-sources/{id}"),Some(json!({"request_id":Uuid::new_v4(),"settings_revision":revision,"input":{"kind":"inline","content":content,"identity_action":action}})),StatusCode::OK).await
}

fn no_secrets(value: &Value) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                assert!(
                    ![
                        "url",
                        "auth_headers",
                        "content",
                        "normalized_config",
                        "password",
                        "username",
                        "uuid",
                        "client_key",
                        "private_key",
                        "raw_digest",
                        "content_digest",
                        "identity_fingerprint",
                        "identity_key",
                        "provider_metadata_id"
                    ]
                    .contains(&key.as_str()),
                    "private field escaped: {key}"
                );
                no_secrets(child);
            }
        }
        Value::Array(values) => values.iter().for_each(no_secrets),
        Value::String(value) => assert!(
            !value.contains("TEST_ONLY-password")
                && !value.contains("TEST_ONLY-token")
                && !value.contains("TEST_ONLY-user")
        ),
        _ => {}
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn four_formats_keep_equivalent_private_semantics_and_public_supported_preview(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let uri = "socks5://TEST_ONLY-user:TEST_ONLY-password@proxy.example.com:1080#Imported";
    let yaml = "proxies:\n  - name: Imported\n    type: socks5\n    server: proxy.example.com\n    port: 1080\n    username: TEST_ONLY-user\n    password: TEST_ONLY-password\n    udp: true\n";
    let formats = [
        ("uri_list", uri.to_owned()),
        ("base64_uri_list", STANDARD.encode(uri)),
        (
            "sing_box_json",
            config(vec![proxy(
                "Imported",
                "proxy.example.com",
                "TEST_ONLY-password",
            )]),
        ),
        ("clash_yaml", yaml.into()),
    ];
    let mut normalized = Vec::new();
    for (format, body) in formats {
        let receipt = inline(&panel, &cookie, &body).await?;
        let id = source_id(&receipt)?;
        let source = get(&panel, &cookie, id, "").await?;
        assert_eq!(source["latest_success"]["format"], format);
        assert_eq!(source["counts"]["supported"], 1);
        let page = get(&panel, &cookie, id, "/nodes").await?;
        assert_eq!(page["nodes"].as_array().context("nodes")?.len(), 1);
        assert_eq!(page["nodes"][0]["selectable"], true);
        let node = Uuid::parse_str(page["nodes"][0]["version_id"].as_str().context("version")?)?;
        normalized.push(
            sqlx::query_scalar::<_, Value>(
                "SELECT normalized_config FROM singbox_ordered_external_node_versions WHERE id=$1",
            )
            .bind(node)
            .fetch_one(&pool)
            .await?,
        );
        no_secrets(&source);
        no_secrets(&page);
    }
    assert!(normalized.windows(2).all(|values| values[0] == values[1]));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nodes")
            .fetch_one(&pool)
            .await?,
        0
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn identities_survive_rename_reorder_and_credentials_but_not_changed_endpoints(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let receipt = inline(
        &panel,
        &cookie,
        &config(vec![
            proxy("A", "a.example.com", "TEST_ONLY-password-A"),
            proxy("B", "b.example.com", "TEST_ONLY-password-B"),
        ]),
    )
    .await?;
    let id = source_id(&receipt)?;
    let original = get(&panel, &cookie, id, "/nodes").await?;
    let nodes = original["nodes"].as_array().context("nodes")?;
    let old_a = nodes
        .iter()
        .find(|node| node["server"] == "a.example.com")
        .context("A")?;
    let old_b = nodes
        .iter()
        .find(|node| node["server"] == "b.example.com")
        .context("B")?;
    let next = update_content(
        &panel,
        &cookie,
        id,
        1,
        &config(vec![
            proxy("Renamed B", "b.example.com", "TEST_ONLY-password-rotated"),
            proxy("Renamed A", "a.example.com", "TEST_ONLY-password-A"),
        ]),
        "update",
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let current = get(&panel, &cookie, id, "/nodes").await?;
    for old in [old_a, old_b] {
        let now = current["nodes"]
            .as_array()
            .context("nodes")?
            .iter()
            .find(|node| node["server"] == old["server"])
            .context("same endpoint")?;
        assert_eq!(now["id"], old["id"]);
        assert_ne!(now["version_id"], old["version_id"]);
    }
    let old_revision = original["success_revision"]["id"]
        .as_str()
        .context("old revision")?;
    let history = get(
        &panel,
        &cookie,
        id,
        &format!("/revisions/{old_revision}/nodes"),
    )
    .await?;
    assert!(
        history["nodes"]
            .as_array()
            .context("history")?
            .iter()
            .all(|node| node["selectable"] == false)
    );
    assert!(
        history["nodes"]
            .as_array()
            .context("history")?
            .iter()
            .any(|node| node["name"] == "A")
    );
    update_content(
        &panel,
        &cookie,
        id,
        next["settings_revision"].as_i64().context("revision")?,
        &config(vec![proxy(
            "Renamed A",
            "new.example.com",
            "TEST_ONLY-password-A",
        )]),
        "update",
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let changed = get(&panel, &cookie, id, "/nodes").await?;
    assert_eq!(changed["nodes"][0]["server"], "new.example.com");
    assert_ne!(changed["nodes"][0]["id"], old_a["id"]);
    for old in [old_a, old_b] {
        let missing = changed["nodes"]
            .as_array()
            .context("nodes")?
            .iter()
            .find(|node| node["id"] == old["id"])
            .context("retained missing")?;
        assert_eq!(missing["present_in_latest"], false);
        assert_eq!(missing["selectable"], false);
        assert!(!missing["reasons"].as_array().context("reason")?.is_empty());
    }
    assert_eq!(get(&panel, &cookie, id, "").await?["counts"]["missing"], 2);
    no_secrets(&changed);
    update_content(&panel, &cookie, id, 3, &config(Vec::new()), "update").await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let empty = get(&panel, &cookie, id, "/nodes").await?;
    assert_eq!(empty["success_revision"]["counts"]["supported"], 0);
    assert_eq!(empty["success_revision"]["counts"]["missing"], 3);
    assert!(
        empty["nodes"]
            .as_array()
            .context("retained history")?
            .iter()
            .all(|node| node["present_in_latest"] == false && node["selectable"] == false)
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_endpoint_accounts_are_ambiguous_and_replacement_preserves_old_epoch_history(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let original = inline(
        &panel,
        &cookie,
        &config(vec![proxy(
            "Same name",
            "proxy.example.com",
            "TEST_ONLY-password-original",
        )]),
    )
    .await?;
    let id = source_id(&original)?;
    let before = get(&panel, &cookie, id, "/nodes").await?;
    let bound = before["nodes"][0]["id"].clone();
    update_content(
        &panel,
        &cookie,
        id,
        1,
        &config(vec![
            proxy("Same name", "proxy.example.com", "TEST_ONLY-password-1"),
            proxy("Same name", "proxy.example.com", "TEST_ONLY-password-2"),
        ]),
        "update",
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let ambiguous = get(&panel, &cookie, id, "/nodes").await?;
    let rows = ambiguous["nodes"].as_array().context("nodes")?;
    assert_eq!(
        rows.iter()
            .filter(|node| node["identity_state"] == "ambiguous")
            .count(),
        2
    );
    assert!(rows.iter().all(|node| node["selectable"] == false));
    assert!(
        rows.iter()
            .any(|node| node["id"] == bound && node["present_in_latest"] == false)
    );
    let replaced = update_content(
        &panel,
        &cookie,
        id,
        2,
        &config(vec![proxy(
            "Same name",
            "proxy.example.com",
            "TEST_ONLY-password-1",
        )]),
        "replace",
    )
    .await?;
    assert_eq!(replaced["identity_epoch"], 2);
    let pending = get(&panel, &cookie, id, "").await?;
    assert_eq!(pending["latest_success"]["identity_epoch"], 1);
    assert_eq!(pending["last_attempt_at"], Value::Null);
    assert_eq!(pending["last_error"], Value::Null);
    assert!(
        pending["stale_reason"]
            .as_str()
            .context("stale explanation")?
            .contains("来源已更换")
    );
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let new = get(&panel, &cookie, id, "/nodes").await?;
    assert_eq!(new["nodes"].as_array().context("nodes")?.len(), 1);
    assert_eq!(new["nodes"][0]["identity_epoch"], 2);
    assert_ne!(new["nodes"][0]["id"], bound);
    let revisions = get(&panel, &cookie, id, "/revisions").await?;
    assert_eq!(
        revisions["revisions"]
            .as_array()
            .context("revisions")?
            .len(),
        3
    );
    assert_eq!(
        revisions["revisions"][0]["id"],
        new["success_revision"]["id"]
    );
    let old = before["success_revision"]["id"]
        .as_str()
        .context("revision")?;
    let historical = get(&panel, &cookie, id, &format!("/revisions/{old}/nodes")).await?;
    assert_eq!(historical["nodes"][0]["id"], bound);
    assert_eq!(historical["nodes"][0]["selectable"], false);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn parse_failures_and_unsupported_nodes_do_not_become_successful_connections(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let receipt = inline(
        &panel,
        &cookie,
        &config(vec![proxy(
            "Working",
            "proxy.example.com",
            "TEST_ONLY-password",
        )]),
    )
    .await?;
    let id = source_id(&receipt)?;
    let before = get(&panel, &cookie, id, "").await?;
    let mutation = update_content(
        &panel,
        &cookie,
        id,
        1,
        "{\"outbounds\":[],\"outbounds\":[]}",
        "update",
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let job = call(
        &panel,
        &cookie,
        Method::GET,
        &format!("/ordered-subscription-source-jobs/{}", job_id(&mutation)?),
        None,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(job["status"], "failed");
    assert_eq!(job["error"]["stage"], "parse");
    let failed = get(&panel, &cookie, id, "").await?;
    assert_eq!(failed["latest_success"], before["latest_success"]);
    assert_eq!(failed["last_success_at"], before["last_success_at"]);
    assert!(failed["last_error"].is_object());
    assert!(failed["stale_reason"].is_string());
    assert_eq!(
        get(&panel, &cookie, id, "/nodes").await?["nodes"][0]["selectable"],
        true
    );
    update_content(&panel,&cookie,id,2,&config(vec![proxy("Working","proxy.example.com","TEST_ONLY-password"),json!({"type":"future-proxy","server":"unknown.example.com","server_port":443,"password":"TEST_ONLY-password-unknown"})]),"update").await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let partial = get(&panel, &cookie, id, "/nodes").await?;
    assert_eq!(partial["success_revision"]["counts"]["supported"], 1);
    assert_eq!(partial["success_revision"]["counts"]["unsupported"], 1);
    let unsupported = partial["nodes"]
        .as_array()
        .context("nodes")?
        .iter()
        .find(|node| node["supported"] == false)
        .context("unsupported preserved")?;
    assert_eq!(unsupported["selectable"], false);
    assert!(
        !unsupported["reasons"]
            .as_array()
            .context("reason")?
            .is_empty()
    );
    assert_eq!(unsupported["identity_state"], "unresolved");
    assert_eq!(partial["success_revision"]["counts"]["ambiguous"], 0);
    no_secrets(&failed);
    no_secrets(&job);
    no_secrets(&partial);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn metadata_cas_queued_cancel_archive_and_reactivation_keep_same_epoch_success(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let draft = call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request(
            "Initial",
            &config(vec![proxy(
                "Working",
                "proxy.example.com",
                "TEST_ONLY-password",
            )]),
        )),
        StatusCode::ACCEPTED,
    )
    .await?;
    let id = source_id(&draft)?;
    let renamed = call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/ordered-subscription-sources/{id}"),
        Some(json!({"request_id":Uuid::new_v4(),"settings_revision":1,"name":"Renamed"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(renamed["identity_epoch"], 1);
    assert!(renamed["job_id"].is_string());
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::GET,
            &format!("/ordered-subscription-source-jobs/{}", job_id(&draft)?),
            None,
            StatusCode::OK
        )
        .await?["status"],
        "superseded"
    );
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let old_success = get(&panel, &cookie, id, "").await?["latest_success"].clone();
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/ordered-subscription-sources/{id}"),
        Some(json!({"request_id":Uuid::new_v4(),"settings_revision":1,"name":"stale"})),
        StatusCode::CONFLICT,
    )
    .await?;
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/ordered-subscription-sources/{id}"),
        Some(json!({"request_id":Uuid::new_v4(),"settings_revision":2,"name":"Metadata only"})),
        StatusCode::OK,
    )
    .await?;
    let metadata = get(&panel, &cookie, id, "").await?;
    assert_eq!(metadata["latest_success"], old_success);
    assert_eq!(metadata["settings_revision"], 3);
    assert_eq!(metadata["identity_epoch"], 1);
    assert_eq!(metadata["stale_reason"], Value::Null);
    assert_eq!(
        get(&panel, &cookie, id, "/nodes").await?["nodes"][0]["selectable"],
        true
    );
    let queued = update_content(
        &panel,
        &cookie,
        id,
        3,
        &config(vec![proxy(
            "Working",
            "proxy.example.com",
            "TEST_ONLY-password-rotated",
        )]),
        "update",
    )
    .await?;
    let path = format!(
        "/ordered-subscription-source-jobs/{}/cancel",
        job_id(&queued)?
    );
    let cancelled = call(&panel, &cookie, Method::POST, &path, None, StatusCode::OK).await?;
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(
        call(&panel, &cookie, Method::POST, &path, None, StatusCode::OK).await?,
        cancelled
    );
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/ordered-subscription-sources/{id}"),
        Some(json!({"request_id":Uuid::new_v4(),"settings_revision":4,"archived":true})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        get(&panel, &cookie, id, "/nodes").await?["nodes"][0]["selectable"],
        false
    );
    call(
        &panel,
        &cookie,
        Method::POST,
        &format!("/ordered-subscription-sources/{id}/refresh"),
        Some(json!({"settings_revision":5})),
        StatusCode::CONFLICT,
    )
    .await?;
    call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/ordered-subscription-sources/{id}"),
        Some(json!({"request_id":Uuid::new_v4(),"settings_revision":5,"archived":false})),
        StatusCode::OK,
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    assert_eq!(
        get(&panel, &cookie, id, "/nodes").await?["nodes"][0]["selectable"],
        true
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn source_receipts_are_atomic_concurrent_and_survive_tombstone_without_revival(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let body = inline_request(
        "Idempotent",
        &config(vec![proxy(
            "Working",
            "proxy.example.com",
            "TEST_ONLY-password",
        )]),
    );
    let path = format!("{ROOT}/ordered-subscription-sources");
    let (a, b) = tokio::join!(
        panel.admin(Method::POST, &path, &cookie, Some(body.clone())),
        panel.admin(Method::POST, &path, &cookie, Some(body.clone()))
    );
    let a = a?;
    let b = b?;
    assert!(matches!(
        (a.status(), b.status()),
        (StatusCode::ACCEPTED, StatusCode::OK) | (StatusCode::OK, StatusCode::ACCEPTED)
    ));
    let first: Value = a.json().await?;
    let second: Value = b.json().await?;
    assert_eq!(first, second);
    let id = source_id(&first)?;
    let mut conflict = body.clone();
    conflict["name"] = json!("Other request");
    call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(conflict),
        StatusCode::CONFLICT,
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM singbox_ordered_external_node_versions")
            .fetch_one(&pool)
            .await?;
    assert_eq!(versions, 1);
    let mutation = json!({"request_id":Uuid::new_v4(),"settings_revision":1,"name":"Changed"});
    let changed = call(
        &panel,
        &cookie,
        Method::PATCH,
        &format!("/ordered-subscription-sources/{id}"),
        Some(mutation.clone()),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::PATCH,
            &format!("/ordered-subscription-sources/{id}"),
            Some(mutation.clone()),
            StatusCode::OK
        )
        .await?,
        changed
    );
    call(
        &panel,
        &cookie,
        Method::DELETE,
        &format!("/ordered-subscription-sources/{id}"),
        Some(json!({"settings_revision":2})),
        StatusCode::NO_CONTENT,
    )
    .await?;
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::POST,
            "/ordered-subscription-sources",
            Some(body),
            StatusCode::OK
        )
        .await?,
        first
    );
    assert_eq!(
        call(
            &panel,
            &cookie,
            Method::PATCH,
            &format!("/ordered-subscription-sources/{id}"),
            Some(mutation),
            StatusCode::OK
        )
        .await?,
        changed
    );
    call(
        &panel,
        &cookie,
        Method::GET,
        &format!("/ordered-subscription-sources/{id}"),
        None,
        StatusCode::NOT_FOUND,
    )
    .await?;
    assert!(
        call(
            &panel,
            &cookie,
            Method::GET,
            "/ordered-subscription-sources",
            None,
            StatusCode::OK
        )
        .await?
        .as_array()
        .context("list")?
        .is_empty()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM singbox_ordered_external_node_versions")
            .fetch_one(&pool)
            .await?,
        versions
    );
    assert_eq!(
        sqlx::query_scalar::<_, Value>(
            "SELECT input_config FROM singbox_ordered_subscription_sources WHERE id=$1"
        )
        .bind(id)
        .fetch_one(&pool)
        .await?,
        json!({})
    );
    let version: Uuid =
        sqlx::query_scalar("SELECT id FROM singbox_ordered_external_node_versions LIMIT 1")
            .fetch_one(&pool)
            .await?;
    let error = sqlx::query(
        "UPDATE singbox_ordered_external_node_versions SET supported=FALSE WHERE id=$1",
    )
    .bind(version)
    .execute(&pool)
    .await
    .expect_err("immutable snapshot");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn url_secrets_write_only_auth_replacement_and_refresh_deduplicate_with_static_errors(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let body = json!({"request_id":Uuid::new_v4(),"name":"URL source","input":{"kind":"url","url":"https://feeds.example.com/TEST_ONLY-token?token=TEST_ONLY-token","auth_headers":{"Authorization":"Bearer TEST_ONLY-token"}}});
    let created = call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(body),
        StatusCode::ACCEPTED,
    )
    .await?;
    let id = source_id(&created)?;
    let source = get(&panel, &cookie, id, "").await?;
    assert_eq!(source["host"], "feeds.example.com");
    assert_eq!(source["auth_configured"], true);
    assert_eq!(source["refresh_interval_secs"], 86400);
    no_secrets(&source);
    let duplicate = call(
        &panel,
        &cookie,
        Method::POST,
        &format!("/ordered-subscription-sources/{id}/refresh"),
        Some(json!({"settings_revision":1})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["id"], created["job_id"]);
    sqlx::query("UPDATE singbox_ordered_subscription_sources SET last_attempt_at=1,last_error=$2 WHERE id=$1")
        .bind(id).bind(json!({"stage":"fetch","kind":"http_403","message":"测试来源返回禁止访问","http_status":403})).execute(&pool).await?;
    let changed=call(&panel,&cookie,Method::PATCH,&format!("/ordered-subscription-sources/{id}"),Some(json!({"request_id":Uuid::new_v4(),"settings_revision":1,"input":{"kind":"url","auth_headers":{"action":"replace","value":{"Cookie":"TEST_ONLY-token"}}}})),StatusCode::OK).await?;
    assert_eq!(changed["identity_epoch"], 2);
    call(&panel,&cookie,Method::PATCH,&format!("/ordered-subscription-sources/{id}"),Some(json!({"request_id":Uuid::new_v4(),"settings_revision":2,"input":{"kind":"url","auth_headers":{"action":"clear"}}})),StatusCode::OK).await?;
    let clear = get(&panel, &cookie, id, "").await?;
    assert_eq!(clear["auth_configured"], false);
    assert_eq!(clear["identity_epoch"], 3);
    assert_eq!(clear["last_error"], Value::Null);
    assert_eq!(clear["last_attempt_at"], Value::Null);
    no_secrets(&clear);
    for headers in [
        json!({"User-Agent":"TEST_ONLY-token"}),
        json!({"Authorization":"TEST_ONLY-token\r\n"}),
        json!({"Authorization":""}),
    ] {
        let response=call(&panel,&cookie,Method::POST,"/ordered-subscription-sources",Some(json!({"request_id":Uuid::new_v4(),"name":"Invalid","input":{"kind":"url","url":"https://feeds.example.com/TEST_ONLY-token","auth_headers":headers}})),StatusCode::BAD_REQUEST).await?;
        no_secrets(&response);
    }
    for secret in [
        json!({"kind":"TEST_ONLY-token","content":"TEST_ONLY-password"}),
        json!({"kind":"inline","content":"TEST_ONLY-password","TEST_ONLY-token":true}),
    ] {
        let response = call(
            &panel,
            &cookie,
            Method::POST,
            "/ordered-subscription-sources",
            Some(json!({"request_id":Uuid::new_v4(),"name":"Invalid","input":secret})),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        no_secrets(&response);
    }
    let duplicate_create = r#"{"request_id":"00000000-0000-4000-8000-000000000099","name":"Raw duplicate","input":{"kind":"url","url":"https://feeds.example.com/TEST_ONLY-token","auth_headers":{"Authorization":"Bearer TEST_ONLY-token","Authorization":"Bearer TEST_ONLY-password"}}}"#;
    let duplicate_patch = r#"{"request_id":"00000000-0000-4000-8000-000000000098","settings_revision":3,"input":{"kind":"url","auth_headers":{"action":"replace","value":{"Authorization":"Bearer TEST_ONLY-token","authorization":"Bearer TEST_ONLY-password"}}}}"#;
    for (method, path, body) in [
        (
            Method::POST,
            format!("{ROOT}/ordered-subscription-sources"),
            duplicate_create,
        ),
        (
            Method::PATCH,
            format!("{ROOT}/ordered-subscription-sources/{id}"),
            duplicate_patch,
        ),
    ] {
        let response = panel
            .client
            .request(method, format!("{}{path}", panel.base))
            .header(reqwest::header::COOKIE, &cookie)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: Value = response.json().await?;
        assert_eq!(error["error"], "来源请求格式无效，请检查字段及类型");
        no_secrets(&error);
    }
    assert_eq!(get(&panel, &cookie, id, "").await?["settings_revision"], 3);
    let rejected = call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request(
            "https://feeds.example.com/TEST_ONLY-token",
            "x",
        )),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    no_secrets(&rejected);
    let maximum_content = "x".repeat(2 * 1024 * 1024);
    let maximum = call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request("Maximum inline body", &maximum_content)),
        StatusCode::ACCEPTED,
    )
    .await?;
    let stored_bytes: i32 = sqlx::query_scalar(
        "SELECT octet_length(input_config->>'content') FROM singbox_ordered_subscription_sources WHERE id=$1",
    )
    .bind(source_id(&maximum)?)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored_bytes, 2 * 1024 * 1024);
    no_secrets(&get(&panel, &cookie, source_id(&maximum)?, "").await?);
    let oversized = call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request("Too big", &"x".repeat(2 * 1024 * 1024 + 1))),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    no_secrets(&oversized);
    let over_http = call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request(
            "HTTP body",
            &"x".repeat(3 * 1024 * 1024 + 1),
        )),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await?;
    no_secrets(&over_http);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn source_capacity_is_explicit_and_latest_batch_precedes_missing_history(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let first = inline(
        &panel,
        &cookie,
        &config(vec![proxy(
            "Missing old",
            "old.example.com",
            "TEST_ONLY-password",
        )]),
    )
    .await?;
    let id = source_id(&first)?;
    update_content(
        &panel,
        &cookie,
        id,
        1,
        &config(vec![proxy(
            "Current",
            "current.example.com",
            "TEST_ONLY-password",
        )]),
        "update",
    )
    .await?;
    worker::run_once(&panel.state)
        .await
        .map_err(|_| anyhow::anyhow!("source worker failed"))?;
    let page = get(&panel, &cookie, id, "/nodes").await?;
    assert_eq!(page["nodes"][0]["present_in_latest"], true);
    assert_eq!(page["nodes"][0]["server"], "current.example.com");
    assert_eq!(page["nodes"][1]["present_in_latest"], false);
    sqlx::query("INSERT INTO singbox_ordered_subscription_sources(name,kind,input_config,refresh_interval_secs,created_at,updated_at) SELECT 'Capacity fixture '||v,'inline',jsonb_build_object('kind','inline','content','TEST_ONLY-content'),0,1,1 FROM generate_series(1,127) v").execute(&pool).await?;
    let list = call(
        &panel,
        &cookie,
        Method::GET,
        "/ordered-subscription-sources",
        None,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(list.as_array().context("list")?.len(), 128);
    call(
        &panel,
        &cookie,
        Method::POST,
        "/ordered-subscription-sources",
        Some(inline_request(
            "Over limit",
            "socks5://proxy.example.com:1080",
        )),
        StatusCode::CONFLICT,
    )
    .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM singbox_ordered_subscription_sources WHERE deleted_at IS NULL"
        )
        .fetch_one(&pool)
        .await?,
        128
    );
    Ok(())
}
