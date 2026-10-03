#![forbid(unsafe_code)]
mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use business_support::TestPanel;
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use sinan_panel::auth::{hash_token, random_token};
use sinan_protocol::now_timestamp;
use sqlx::PgPool;
use uuid::Uuid;

fn domain(server: i64) -> Value {
    json!({"kind":"domain","name":"network.example.com","server_ids":[server],"ddns_rule_ids":[],"applications":[],"maintainer":"TEST_ONLY","notes":""})
}
fn forwarding(server: i64, address: &str) -> Value {
    json!({"kind":"forwarding","name":"TEST_ONLY forwarding","server_id":server,"listen_address":address,"listen_port":18080,"target_address":"127.0.0.1","target_port":8080,"protocol":"tcp","owner":"sinan","enabled":true,"dependency_ids":[]})
}

#[sqlx::test]
async fn revisions_and_wildcard_listeners_preserve_existing_configuration(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "TEST_ONLY network").await?;
    let created: Value = panel
        .admin(
            Method::POST,
            "/api/network-configuration/documents",
            &cookie,
            Some(json!({"config":forwarding(server,"0.0.0.0")})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = created["id"].as_str().context("document ID")?;
    let conflict = panel
        .admin(
            Method::POST,
            "/api/network-configuration/documents",
            &cookie,
            Some(json!({"config":forwarding(server,"127.0.0.1")})),
        )
        .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let mut replacement = created["config"].clone();
    replacement["target_port"] = 8081.into();
    let stale = panel
        .admin(
            Method::PUT,
            &format!("/api/network-configuration/documents/{id}"),
            &cookie,
            Some(json!({"config":replacement,"revision":0})),
        )
        .await?;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let after: Value = panel
        .admin(
            Method::GET,
            &format!("/api/network-configuration/documents/{id}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(after["config"]["target_port"], 8080);
    assert_eq!(after["revision"], 1);
    let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM fleet_operations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        operations, 0,
        "saving or previewing a configuration must not dispatch work"
    );
    Ok(())
}

#[sqlx::test]
async fn old_server_history_is_hidden_after_scope_changes(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let owner = panel.admin_cookie().await?;
    let first = panel.create_server(&owner, "TEST_ONLY old scope").await?;
    let second = panel
        .create_server(&owner, "TEST_ONLY visible scope")
        .await?;
    let created: Value = panel
        .admin(
            Method::POST,
            "/api/network-configuration/documents",
            &owner,
            Some(json!({"config":domain(first)})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let id = created["id"].as_str().context("document ID")?;
    panel
        .admin(
            Method::PUT,
            &format!("/api/network-configuration/documents/{id}"),
            &owner,
            Some(json!({"config":domain(second),"revision":1})),
        )
        .await?
        .error_for_status()?;
    let actor:i64=sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id").fetch_one(&pool).await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,'network-viewer','网络只读','viewer',false,'[\"network:read\"]',0,0)").bind(actor).execute(&pool).await?;
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(actor)
        .bind(second)
        .execute(&pool)
        .await?;
    let token = random_token();
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
        .bind(hash_token(&token))
        .bind(actor)
        .bind(now_timestamp() + 3600)
        .execute(&pool)
        .await?;
    let cookie = format!("sinan_session={token}");
    let history: Vec<Value> = panel
        .admin(
            Method::GET,
            &format!("/api/network-configuration/documents/{id}/history"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["revision"], 2);
    assert_eq!(history[0]["config"]["server_ids"], json!([second]));
    Ok(())
}

#[sqlx::test]
async fn api_tokens_cannot_leave_server_operations_without_token_identity(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel
        .create_server(&cookie, "TEST_ONLY token scope")
        .await?;
    let token = format!("sinan_api_{}", random_token());
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'TEST_ONLY network token','[\"network:read\"]',$3,false,$4,0)").bind(Uuid::new_v4()).bind(hash_token(&token)).bind(json!([server])).bind(now_timestamp()+3600).execute(&pool).await?;
    let response = panel
        .client
        .post(format!(
            "{}/api/network-configuration/servers/{server}/inventory",
            panel.base
        ))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM fleet_operations")
            .fetch_one(&pool)
            .await?,
        0
    );
    Ok(())
}
