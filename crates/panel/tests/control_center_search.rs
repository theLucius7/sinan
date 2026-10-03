#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode, header};
use serde_json::{Value, json};
use sinan_panel::{
    AppState,
    auth::{hash_token, random_token},
    config::Config,
    router,
};
use sinan_protocol::now_timestamp;
use sqlx::PgPool;
use std::{net::SocketAddr, path::PathBuf};
use tokio::{net::TcpListener, task::JoinHandle};
use uuid::Uuid;

const READ_CAPABILITIES: &[&str] = &[
    "servers:read",
    "monitoring:read",
    "terminal:read",
    "files:read",
    "services:read",
    "diagnostics:read",
    "network:read",
    "dns:read",
    "proxy:read",
    "operations:read",
    "recovery:read",
    "cloud:read",
    "security:read",
];

struct Panel {
    pool: PgPool,
    base: String,
    client: Client,
    directory: PathBuf,
    task: JoinHandle<()>,
}

impl Panel {
    async fn start(pool: PgPool) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen = listener.local_addr()?;
        let base = format!("http://{listen}");
        let directory = std::env::temp_dir().join(format!("sinan-search-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let state = AppState::new(
            pool.clone(),
            Config {
                database_url: String::new(),
                listen,
                public_url: base.clone(),
                data_dir: directory.clone(),
                admin_password: Some("search-test-password".into()),
            },
        )
        .await?;
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("search test panel");
        });
        Ok(Self {
            pool,
            base,
            client: Client::builder().no_proxy().build()?,
            directory,
            task,
        })
    }

    async fn session(&self, actor: i64) -> Result<String> {
        let token = random_token();
        sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
            .bind(hash_token(&token))
            .bind(actor)
            .bind(now_timestamp() + 3600)
            .execute(&self.pool)
            .await?;
        Ok(format!("sinan_session={token}"))
    }

    async fn server(&self, name: &str, info: Value) -> Result<i64> {
        Ok(sqlx::query_scalar("INSERT INTO servers(name,static_info,static_info_received_at) VALUES($1,$2,$3) RETURNING id")
            .bind(name).bind(info).bind(now_timestamp()).fetch_one(&self.pool).await?)
    }

    async fn viewer(&self, grants: &[i64], capabilities: &[&str]) -> Result<i64> {
        let actor: i64 = sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id")
            .fetch_one(&self.pool).await?;
        sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,$2,'搜索只读','viewer',false,$3,0,0)")
            .bind(actor).bind(format!("search-viewer-{actor}")).bind(json!(capabilities))
            .execute(&self.pool).await?;
        for server in grants {
            sqlx::query(
                "INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)",
            )
            .bind(actor)
            .bind(server)
            .execute(&self.pool)
            .await?;
        }
        Ok(actor)
    }

    async fn token(
        &self,
        actor: i64,
        servers: &[i64],
        all_servers: bool,
        capabilities: &[&str],
    ) -> Result<String> {
        let token = format!("sinan_api_{}", random_token());
        sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,$2,$3,'search fixture',$4,$5,$6,$7,0)")
            .bind(Uuid::new_v4()).bind(actor).bind(hash_token(&token)).bind(json!(capabilities))
            .bind(json!(servers)).bind(all_servers).bind(now_timestamp() + 3600)
            .execute(&self.pool).await?;
        Ok(token)
    }

    async fn search(&self, cookie: &str, query: &str) -> Result<Value> {
        Ok(self
            .client
            .get(format!("{}/api/control-center/search", self.base))
            .header(header::COOKIE, cookie)
            .query(&[("q", query)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn search_token(&self, token: &str, query: &str) -> Result<Value> {
        Ok(self
            .client
            .get(format!("{}/api/control-center/search", self.base))
            .bearer_auth(token)
            .query(&[("q", query)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn plan(&self, name: &str, source: i64, receiver: Option<i64>) -> Result<(Uuid, Value)> {
        let check = match receiver {
            Some(server) => throughput(server),
            None => json!({"kind":"cpu","tool_version":"1.0.20","threads":1,"duration_secs":1}),
        };
        let plan = json!({"name":name,"budget":budget(),"schedule":null,
                          "steps":[{"name":"fixture","source":{"kind":"server","server_id":source},
                                    "check":check,"stop_on_failure":true}]});
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO network_workbench_plans(id,name,definition,created_at,updated_at) VALUES($1,$2,$3,0,0)")
            .bind(id).bind(name).bind(json!({"plan":plan,"actor":1})).execute(&self.pool).await?;
        Ok((id, plan))
    }

    async fn run(
        &self,
        plan_id: Option<Uuid>,
        plan: Value,
        source: i64,
        check: Value,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let snapshot = json!({"plan":plan,"executions":[[{
            "schema":1,"source_server":source,"target":null,"check":check,"budget":budget(),
            "role":format!("source:{source}"),"source_label":format!("服务器 {source}")
        }]]});
        sqlx::query("INSERT INTO network_workbench_runs(id,plan_id,snapshot,status,actor,created_at,updated_at) VALUES($1,$2,$3,'queued','1',0,0)")
            .bind(id).bind(plan_id).bind(snapshot).execute(&self.pool).await?;
        Ok(id)
    }

    async fn document(&self, kind: &str, config: Value) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO network_documents(id,kind,config,created_at,updated_at) VALUES($1,$2,$3,0,0)")
            .bind(id).bind(kind).bind(config).execute(&self.pool).await?;
        Ok(id)
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn budget() -> Value {
    json!({"duration_secs":60,"memory_bytes":67108864,"disk_bytes":134217728,
           "traffic_bytes":268435456,"rate_bps":20000000,"concurrency":1,
           "cpu_percent":20,"pause_on_service_error":true})
}

fn throughput(receiver: i64) -> Value {
    json!({"kind":"throughput","client_mode":"managed","receiver_server":receiver,
           "receiver_host":"192.0.2.2","port":5201,"family":"ipv4","direction":"forward",
           "protocol":"tcp","streams":1,"duration_secs":1,"rate_bps":1000000,
           "tool_version":"3.16","latency_target":null})
}

fn items(value: &Value) -> Result<&Vec<Value>> {
    value["results"].as_array().context("search result array")
}

fn category<'a>(value: &'a Value, kind: &str) -> Result<&'a Value> {
    value["categories"]
        .as_array()
        .context("search categories")?
        .iter()
        .find(|entry| entry["kind"] == kind)
        .context("search category")
}

#[sqlx::test]
async fn owner_parses_and_executes_every_search_category_on_empty_tables(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let value = panel
        .search(&panel.session(1).await?, "search-empty-category-fixture")
        .await?;
    let expected = [
        "server",
        "ip",
        "ip-observation",
        "ip-quality",
        "diagnostic-task",
        "test-plan",
        "test-run",
        "dns-rule",
        "network-document",
        "node",
        "proxy-user",
        "command-task",
        "fleet-task",
        "operation-task",
        "operation-schedule",
        "remediation-rule",
        "maintenance",
        "incident",
        "probe-rule",
        "alert-rule",
        "latency-task",
    ];
    assert_eq!(
        value["categories"]
            .as_array()
            .context("all categories")?
            .len(),
        expected.len()
    );
    for kind in expected {
        assert_eq!(category(&value, kind)?["returned"], 0, "{kind}");
        assert_eq!(category(&value, kind)?["truncated"], false, "{kind}");
    }
    assert!(items(&value)?.is_empty());
    assert_eq!(value["limited"], false);
    assert!(value.get("sampled_at").is_none());
    assert!(value["served_at"].as_i64().is_some());
    Ok(())
}

#[sqlx::test]
async fn scoped_ip_filter_precedes_limit_and_preserves_observation_sources(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    for n in 1..=45 {
        panel
            .server(
                &format!("hidden {n}"),
                json!({"ip_addresses":[format!("203.0.113.{n}")]}),
            )
            .await?;
    }
    let mut addresses = (1..=25).map(|n| format!("192.0.2.{n}")).collect::<Vec<_>>();
    addresses.push("203.0.113.250".into());
    let allowed = panel
        .server(
            "allowed",
            json!({"ip_addresses":addresses,
        "interface_addresses":{"eth0":["203.0.113.250"]},
        "discovered_public_ips":["203.0.113.250"]}),
        )
        .await?;
    let actor = panel.viewer(&[allowed], &["servers:read"]).await?;
    let cookie = panel.session(actor).await?;
    let value = panel.search(&cookie, "203.0.113.").await?;
    let rows = items(&value)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["server_id"], allowed);
    assert_eq!(rows[0]["address"], "203.0.113.250");
    assert_eq!(
        rows[0]["sources"]
            .as_array()
            .context("deduplicated IP sources")?
            .len(),
        3
    );
    assert!(rows[0]["sampled_at"].is_null());
    assert!(rows[0]["received_at"].as_i64().is_some());
    assert_eq!(category(&value, "ip")?["truncated"], false);
    let limited = panel.search(&cookie, "192.0.2.").await?;
    assert_eq!(items(&limited)?.len(), 20);
    assert!(
        items(&limited)?
            .iter()
            .all(|row| row["server_id"] == allowed)
    );
    assert_eq!(category(&limited, "ip")?["truncated"], true);
    assert_eq!(limited["limited"], true);
    Ok(())
}

#[sqlx::test]
async fn viewer_and_owner_tokens_keep_capability_and_server_intersections(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("scope-needle-first", json!({})).await?;
    let second = panel.server("scope-needle-second", json!({})).await?;
    sqlx::query("INSERT INTO users(name,subscription_token) VALUES('scope-needle-proxy','secret-subscription-fixture')")
        .execute(&panel.pool).await?;
    let viewer = panel.viewer(&[first], READ_CAPABILITIES).await?;
    let owner_token = panel.token(1, &[first], false, &["servers:read"]).await?;
    let viewer_token = panel
        .token(
            viewer,
            &[first, second],
            false,
            &["servers:read", "proxy:read"],
        )
        .await?;
    let viewer_global_token = panel
        .token(viewer, &[], true, &["servers:read", "proxy:read"])
        .await?;
    for token in [&owner_token, &viewer_token, &viewer_global_token] {
        let value = panel.search_token(token, "scope-needle").await?;
        assert_eq!(items(&value)?.len(), 1);
        assert_eq!(items(&value)?[0]["id"], first);
        assert!(
            !value["categories"]
                .as_array()
                .context("token categories")?
                .iter()
                .any(|entry| entry["kind"] == "proxy-user" || entry["kind"] == "node")
        );
        assert!(!serde_json::to_string(&value)?.contains("secret-subscription-fixture"));
    }
    let owner = panel
        .search(&panel.session(1).await?, "scope-needle")
        .await?;
    assert!(
        items(&owner)?
            .iter()
            .any(|item| item["kind"] == "proxy-user")
    );
    sqlx::query("UPDATE management_api_tokens SET revoked_at=$1 WHERE token_hash=$2")
        .bind(now_timestamp())
        .bind(hash_token(&owner_token))
        .execute(&panel.pool)
        .await?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/control-center/search", panel.base))
            .bearer_auth(owner_token)
            .query(&[("q", "scope-needle")])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[sqlx::test]
async fn runs_include_frozen_plan_checks_execution_checks_and_linked_plan_scope(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("source", json!({})).await?;
    let second = panel.server("receiver", json!({})).await?;
    let actor = panel.viewer(&[first], READ_CAPABILITIES).await?;
    let cookie = panel.session(actor).await?;
    let (hidden_plan_id, hidden_plan) = panel
        .plan("scope-run-hidden-plan", first, Some(second))
        .await?;
    let cpu = json!({"kind":"cpu","tool_version":"1.0.20","threads":1,"duration_secs":1});
    panel
        .run(Some(hidden_plan_id), hidden_plan, first, cpu.clone())
        .await?;
    let (_, plain_plan) = panel.plan("scope-run-frozen-visible", first, None).await?;
    panel
        .run(None, plain_plan.clone(), first, throughput(second))
        .await?;
    let mut route_plan = plain_plan.clone();
    route_plan["name"] = json!("scope-run-reverse-hidden");
    route_plan["steps"][0]["check"] = json!({"kind":"route","target_id":Uuid::new_v4(),
        "family":"ipv4","protocol":"tcp","port":443,"tool":"nexttrace",
        "tool_version":"1.3.6","max_hops":8,"reverse_server":second});
    panel
        .run(None, route_plan.clone(), first, cpu.clone())
        .await?;
    panel
        .run(
            None,
            plain_plan.clone(),
            first,
            route_plan["steps"][0]["check"].clone(),
        )
        .await?;
    panel
        .run(Some(hidden_plan_id), plain_plan.clone(), first, cpu.clone())
        .await?;
    let visible = panel
        .run(None, plain_plan.clone(), first, cpu.clone())
        .await?;
    let historical = panel.run(None, plain_plan, first, cpu).await?;
    sqlx::query("INSERT INTO network_workbench_results(id,run_id,step_index,server_id,role,status,created_at,updated_at) VALUES($1,$2,0,$3,'historical-receiver','succeeded',0,0)")
        .bind(Uuid::new_v4()).bind(historical).bind(second).execute(&panel.pool).await?;
    let value = panel.search(&cookie, "scope-run").await?;
    let runs = items(&value)?
        .iter()
        .filter(|row| row["kind"] == "test-run")
        .collect::<Vec<_>>();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["id"], visible.to_string());
    assert_eq!(runs[0]["server_ids"], json!([first]));
    assert!(
        !items(&value)?
            .iter()
            .any(|row| row["id"] == hidden_plan_id.to_string())
    );
    let owner = panel.search(&panel.session(1).await?, "scope-run").await?;
    assert_eq!(
        items(&owner)?
            .iter()
            .filter(|row| row["kind"] == "test-run")
            .count(),
        7
    );
    Ok(())
}

#[sqlx::test]
async fn network_document_dependencies_and_operations_targets_require_all_grants(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("allowed", json!({})).await?;
    let second = panel.server("hidden", json!({})).await?;
    let actor = panel.viewer(&[first], READ_CAPABILITIES).await?;
    let cookie = panel.session(actor).await?;
    let domain = panel.document("domain", json!({"kind":"domain","name":"scope-doc-hidden.example",
        "server_ids":[second],"ddns_rule_ids":[],"applications":[],"maintainer":"operator","notes":""})).await?;
    panel.document("certificate", json!({"kind":"certificate","name":"scope-doc-certificate",
        "domain_ids":[domain],"maintainer":"operator","issuer":"external",
        "targets":[{"server_id":first,"service":"app.service","domain":"scope-doc-hidden.example","port":443}],
        "renewal":{"mode":"external","responsibility":"operator"}})).await?;
    panel
        .document(
            "forwarding",
            json!({"kind":"forwarding","name":"scope-doc-forwarding",
        "server_id":first,"listen_address":"127.0.0.1","listen_port":18080,
        "target_address":"192.0.2.2","target_port":80,"protocol":"tcp","owner":"external",
        "enabled":false,"dependency_ids":[domain]}),
        )
        .await?;
    let visible = panel
        .document(
            "endpoint",
            json!({"kind":"endpoint","name":"scope-doc-visible",
        "server_id":first,"listen_address":"127.0.0.1","public_address":null,
        "port":8080,"protocol":"tcp","owner":"external","notes":""}),
        )
        .await?;
    let docs = panel.search(&cookie, "scope-doc").await?;
    assert_eq!(items(&docs)?.len(), 1);
    assert_eq!(items(&docs)?[0]["id"], visible.to_string());
    let plan = json!({"name":"scope-job","steps":[{"kind":"system_snapshot","service":null,"timeout_secs":30}],
        "batch_size":1,"concurrency":1,"pause_between_batches":true,"max_duration_secs":60});
    for targets in [vec![first, second], vec![first]] {
        sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,'scope-job',1,$2,$3,'queued',0,0,$4,'fixture')")
            .bind(Uuid::new_v4()).bind(json!({"plan":plan})).bind(targets)
            .bind(now_timestamp() + 3600).execute(&panel.pool).await?;
    }
    let jobs = panel.search(&cookie, "scope-job").await?;
    assert_eq!(items(&jobs)?.len(), 1);
    assert_eq!(items(&jobs)?[0]["server_ids"], json!([first]));
    Ok(())
}

#[sqlx::test]
async fn empty_server_scopes_match_shared_workbench_and_document_read_handlers(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let actor = panel.viewer(&[], READ_CAPABILITIES).await?;
    let cookie = panel.session(actor).await?;
    let token = panel.token(actor, &[], false, READ_CAPABILITIES).await?;
    let target = Uuid::new_v4();
    let check = json!({"kind":"tcp","target_id":target,"port":443,"family":"ipv4","samples":1});
    let plan = json!({"name":"shared-empty-plan","budget":budget(),"schedule":null,
        "steps":[{"name":"panel","source":{"kind":"panel"},"check":check,"stop_on_failure":true}]});
    let plan_id = Uuid::new_v4();
    sqlx::query("INSERT INTO network_workbench_plans(id,name,definition,created_at,updated_at) VALUES($1,'shared-empty-plan',$2,0,0)")
        .bind(plan_id).bind(json!({"plan":plan,"actor":1})).execute(&panel.pool).await?;
    let run_id = Uuid::new_v4();
    let snapshot = json!({"plan":plan,"executions":[[{
        "schema":1,"source_server":null,"target":null,"check":check,"budget":budget(),
        "role":"source:panel","source_label":"面板"
    }]]});
    sqlx::query("INSERT INTO network_workbench_runs(id,plan_id,snapshot,status,actor,created_at,updated_at) VALUES($1,$2,$3,'queued','1',0,0)")
        .bind(run_id).bind(plan_id).bind(snapshot).execute(&panel.pool).await?;
    let document_id = panel
        .document(
            "endpoint",
            json!({"kind":"endpoint","name":"shared-empty-endpoint",
        "server_id":null,"listen_address":"127.0.0.1","public_address":null,
        "port":8080,"protocol":"tcp","owner":"external","notes":""}),
        )
        .await?;
    sqlx::query("INSERT INTO users(name,subscription_token) VALUES('shared-empty-proxy','shared-empty-secret')")
        .execute(&panel.pool).await?;
    for value in [
        panel.search(&cookie, "shared-empty").await?,
        panel.search_token(&token, "shared-empty").await?,
    ] {
        assert_eq!(items(&value)?.len(), 3);
        for expected in [plan_id, run_id, document_id] {
            assert!(
                items(&value)?
                    .iter()
                    .any(|row| row["id"] == expected.to_string())
            );
        }
        assert!(!items(&value)?.iter().any(|row| row["kind"] == "proxy-user"));
    }
    for path in [
        "/api/network-workbench/plans".to_owned(),
        format!("/api/network-workbench/runs/{run_id}"),
        format!("/api/network-configuration/documents/{document_id}"),
    ] {
        assert_eq!(
            panel
                .client
                .get(format!("{}{path}", panel.base))
                .header(header::COOKIE, &cookie)
                .send()
                .await?
                .status(),
            StatusCode::OK,
            "session {path}"
        );
        assert_eq!(
            panel
                .client
                .get(format!("{}{path}", panel.base))
                .bearer_auth(&token)
                .send()
                .await?
                .status(),
            StatusCode::OK,
            "token {path}"
        );
    }
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/plugins/sing-box/users", panel.base))
            .header(header::COOKIE, cookie)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[sqlx::test]
async fn database_query_errors_return_failure_instead_of_empty_search_results(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let cookie = panel.session(1).await?;
    sqlx::query("ALTER TABLE server_ip_quality RENAME TO search_fixture_missing_ip_quality")
        .execute(&panel.pool)
        .await?;
    let response = panel
        .client
        .get(format!("{}/api/control-center/search", panel.base))
        .header(header::COOKIE, cookie)
        .query(&[("q", "database-failure")])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json().await?;
    assert!(body.get("results").is_none());
    sqlx::query("ALTER TABLE search_fixture_missing_ip_quality RENAME TO server_ip_quality")
        .execute(&panel.pool)
        .await?;
    Ok(())
}
