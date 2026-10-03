#![forbid(unsafe_code)]
mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;

const TOKEN: &str = "TEST_ONLY_CLOUDFLARE_TOKEN";

async fn prove_cookie(pool: &PgPool, cookie: &str) -> Result<()> {
    let token = cookie
        .strip_prefix("sinan_session=")
        .context("test session cookie")?;
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3) ON CONFLICT(session_hash) DO UPDATE SET verified_at=$2,expires_at=$3")
        .bind(sinan_panel::auth::hash_token(token)).bind(now).bind(now + 300).execute(pool).await?;
    Ok(())
}

fn input(server: i64) -> Value {
    json!({"config":{"name":"测试解析","server_id":server,"zone_id":"00000000000000000000000000000001","record_name":"Node.EXAMPLE.com.","record_type":"A","ttl":300,"proxied":false,"interval_secs":300,"enabled":false},"api_token":TOKEN})
}

#[sqlx::test]
async fn dual_stack_creation_is_atomic_and_redacts_all_provider_credentials(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    prove_cookie(&pool, &cookie).await?;
    let server = panel.create_server(&cookie, "TEST_ONLY dual stack").await?;
    panel
        .admin(
            Method::POST,
            &format!("/api/plugins/ddns/servers/{server}/enable"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    let path = "/api/plugins/ddns/rules/dual-stack";
    assert_eq!(
        panel
            .admin(Method::POST, path, "", Some(input(server)))
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for provider in ["cloudflare", "tencent", "aliyun", "huawei"] {
        let mut body = input(server);
        body["config"]["provider"] = provider.into();
        if provider != "cloudflare" {
            body.as_object_mut().unwrap().remove("api_token");
            body["access_key_id"] = "TEST_ONLY_ACCESS_ID".into();
            body["access_key_secret"] = "TEST_ONLY_ACCESS_SECRET".into();
            if provider != "huawei" {
                body["config"]["zone_id"] = "example.com".into();
            }
        }
        let response = panel
            .admin(Method::POST, path, &cookie, Some(body.clone()))
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let result: Value = response.json().await?;
        let rules = result["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["config"]["record_type"], "A");
        assert_eq!(rules[1]["config"]["record_type"], "AAAA");
        for rule in rules {
            assert_eq!(rule["config"]["provider"], provider);
            assert_eq!(rule["config"]["server_id"], server);
            assert_eq!(rule["token_configured"], true);
            assert!(!rule.to_string().contains("TEST_ONLY_ACCESS"));
            assert!(!rule.to_string().contains(TOKEN));
        }
        // Leave the second family in place: a conflicting AAAA must roll back the new A.
        panel
            .admin(
                Method::DELETE,
                &format!(
                    "/api/plugins/ddns/rules/{}",
                    rules[0]["id"].as_str().unwrap()
                ),
                &cookie,
                None,
            )
            .await?
            .error_for_status()?;
        assert_eq!(
            panel
                .admin(Method::POST, path, &cookie, Some(body))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM ddns_rules WHERE config->>'provider'=$1")
                .bind(provider)
                .fetch_one(&pool)
                .await?;
        assert_eq!(remaining, 1);
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM ddns_rules WHERE config->>'record_type'='A'"
        )
        .fetch_one(&pool)
        .await?,
        0
    );
    Ok(())
}

#[sqlx::test]
async fn dual_stack_reserves_two_slots_and_a_single_family_still_uses_one(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "TEST_ONLY capacity").await?;
    panel
        .admin(
            Method::POST,
            &format!("/api/plugins/ddns/servers/{server}/enable"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    for i in 0..31 {
        let mut body = input(server);
        body["config"]["record_name"] = format!("node{i}.example.com").into();
        panel
            .admin(Method::POST, "/api/plugins/ddns/rules", &cookie, Some(body))
            .await?
            .error_for_status()?;
    }
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/plugins/ddns/rules/dual-stack",
                &cookie,
                Some(input(server))
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ddns_rules")
            .fetch_one(&pool)
            .await?,
        31
    );
    sqlx::query("DELETE FROM ddns_rules WHERE config->>'record_name'='node30.example.com'")
        .execute(&pool)
        .await?;
    panel
        .admin(
            Method::POST,
            "/api/plugins/ddns/rules/dual-stack",
            &cookie,
            Some(input(server)),
        )
        .await?
        .error_for_status()?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM ddns_rules")
            .fetch_one(&pool)
            .await?,
        32
    );
    Ok(())
}

#[sqlx::test]
async fn administrator_crud_redacts_credentials_guards_revisions_and_never_deletes_remote_dns(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "TEST_ONLY DNS").await?;
    let body = input(server);
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/plugins/ddns/rules",
                &cookie,
                Some(body.clone())
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    panel
        .admin(
            Method::POST,
            &format!("/api/plugins/ddns/servers/{server}/enable"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    for method in [Method::GET, Method::POST] {
        assert_eq!(
            panel
                .client
                .request(method, format!("{}/api/plugins/ddns/rules", panel.base))
                .json(&body)
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = panel
        .admin(
            Method::POST,
            "/api/plugins/ddns/rules",
            &cookie,
            Some(body.clone()),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let rule: Value = response.json().await?;
    assert!(!rule.to_string().contains(TOKEN));
    assert!(rule.get("api_token").is_none());
    assert_eq!(rule["token_configured"], true);
    assert_eq!(rule["config"]["record_name"], "node.example.com");
    let path = format!("/api/plugins/ddns/rules/{}", rule["id"].as_str().unwrap());
    for (method, suffix) in [
        (Method::PATCH, ""),
        (Method::DELETE, ""),
        (Method::POST, "/sync"),
    ] {
        assert_eq!(
            panel
                .client
                .request(method, format!("{}{path}{suffix}", panel.base))
                .json(&body)
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        panel
            .admin(
                Method::POST,
                "/api/plugins/ddns/rules",
                &cookie,
                Some(body.clone())
            )
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let mut edit = json!({"config":rule["config"],"revision":1});
    edit["config"]["proxied"] = true.into();
    let updated: Value = panel
        .admin(Method::PATCH, &path, &cookie, Some(edit.clone()))
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(updated["config"]["ttl"], 1);
    assert_eq!(updated["revision"], 2);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT api_token FROM ddns_rules")
            .fetch_one(&pool)
            .await?,
        TOKEN
    );
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(edit.clone()))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    edit["revision"] = 2.into();
    edit["config"]["record_name"] = "other.example.com".into();
    assert_eq!(
        panel
            .admin(Method::PATCH, &path, &cookie, Some(edit))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        panel
            .admin(Method::POST, &format!("{path}/sync"), &cookie, None)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let edit =
        json!({"config":updated["config"],"revision":2,"api_token":"TEST_ONLY_REPLACEMENT_TOKEN"});
    let response: Value = panel
        .admin(Method::PATCH, &path, &cookie, Some(edit))
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(!response.to_string().contains("REPLACEMENT_TOKEN"));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT api_token FROM ddns_rules")
            .fetch_one(&pool)
            .await?,
        "TEST_ONLY_REPLACEMENT_TOKEN"
    );
    let session_token = cookie
        .strip_prefix("sinan_session=")
        .context("test session cookie")?;
    sqlx::query("DELETE FROM administrator_reauth WHERE session_hash=$1")
        .bind(sinan_panel::auth::hash_token(session_token))
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::DELETE, &path, &cookie, None)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    prove_cookie(&pool, &cookie).await?;
    sqlx::query("UPDATE ddns_rules SET lease_until=$1")
        .bind(sinan_protocol::now_timestamp() + 60)
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::DELETE, &path, &cookie, None)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE ddns_rules SET lease_until=0")
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::DELETE, &path, &cookie, None)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let rules: Vec<Value> = panel
        .admin(Method::GET, "/api/plugins/ddns/rules", &cookie, None)
        .await?
        .json()
        .await?;
    assert!(rules.is_empty());
    Ok(())
}

#[sqlx::test]
async fn only_new_static_reports_are_fresh_and_missing_public_ip_never_contacts_provider(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "TEST_ONLY IP").await?;
    panel
        .admin(
            Method::POST,
            &format!("/api/plugins/ddns/servers/{server}/enable"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    let mut body = input(server);
    body["config"]["enabled"] = true.into();
    let rule: Value = panel
        .admin(Method::POST, "/api/plugins/ddns/rules", &cookie, Some(body))
        .await?
        .error_for_status()?
        .json()
        .await?;
    let path = format!(
        "/api/plugins/ddns/rules/{}/sync",
        rule["id"].as_str().unwrap()
    );
    // No background worker runs in this fixture. This manual sync must stop
    // locally, even though the rule contains a syntactically valid test token.
    let response: Value = panel
        .admin(Method::POST, &path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(response["error_code"], "server_offline");
    assert!(response["ip_received_at"].is_null());
    let info: sinan_protocol::StaticInfo = serde_json::from_value(
        json!({"hostname":"test","os":"test","arch":"x86_64","cpu_model":"test","cpu_cores":1,"memory_total":1,"ip_addresses":["192.0.2.1"]}),
    )?;
    sinan_panel::agent_api::process_message(
        &panel.state,
        server,
        sinan_protocol::Message::TelemetryStatic(info.clone()),
    )
    .await?;
    let at: Option<i64> =
        sqlx::query_scalar("SELECT static_info_received_at FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&pool)
            .await?;
    assert!(at.is_some());
    sqlx::query("UPDATE servers SET static_info_received_at=NULL,deleted_at=1 WHERE id=$1")
        .bind(server)
        .execute(&pool)
        .await?;
    sinan_panel::agent_api::process_message(
        &panel.state,
        server,
        sinan_protocol::Message::TelemetryStatic(info),
    )
    .await?;
    assert!(
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT static_info_received_at FROM servers WHERE id=$1"
        )
        .bind(server)
        .fetch_one(&pool)
        .await?
        .is_none()
    );
    Ok(())
}

#[sqlx::test]
async fn multicloud_credentials_are_write_only_rotated_together_and_default_lines_are_unique(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "TEST_ONLY multicloud").await?;
    panel
        .admin(
            Method::POST,
            &format!("/api/plugins/ddns/servers/{server}/enable"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    for provider in ["tencent", "aliyun", "huawei"] {
        let mut body = input(server);
        body.as_object_mut().unwrap().remove("api_token");
        body["config"]["provider"] = provider.into();
        body["access_key_id"] = "TEST_ONLY_ACCESS_ID".into();
        body["access_key_secret"] = "TEST_ONLY_ACCESS_SECRET".into();
        if provider != "huawei" {
            body["config"]["zone_id"] = "example.com".into();
        }
        let response = panel
            .admin(
                Method::POST,
                "/api/plugins/ddns/rules",
                &cookie,
                Some(body.clone()),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let rule: Value = response.json().await?;
        assert!(!rule.to_string().contains("TEST_ONLY_ACCESS"));
        assert!(!rule.to_string().contains("access_key"));
        assert_eq!(
            rule["config"]["line"],
            match provider {
                "tencent" => "0",
                "aliyun" => "default",
                _ => "",
            }
        );
        assert_eq!(
            panel
                .admin(Method::POST, "/api/plugins/ddns/rules", &cookie, Some(body))
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        let path = format!("/api/plugins/ddns/rules/{}", rule["id"].as_str().unwrap());
        let mut edit =
            json!({"config":rule["config"],"revision":1,"access_key_id":"TEST_ONLY_NEW_ID"});
        assert_eq!(
            panel
                .admin(Method::PATCH, &path, &cookie, Some(edit.clone()))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        edit["access_key_secret"] = "TEST_ONLY_NEW_SECRET".into();
        let updated: Value = panel
            .admin(Method::PATCH, &path, &cookie, Some(edit))
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(updated["revision"], 2);
        assert!(!updated.to_string().contains("TEST_ONLY_NEW"));
        let edit = json!({"config":updated["config"],"revision":2});
        panel
            .admin(Method::PATCH, &path, &cookie, Some(edit))
            .await?
            .error_for_status()?;
    }
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM ddns_rules WHERE access_key_secret='TEST_ONLY_NEW_SECRET' AND api_token=''").fetch_one(&pool).await?,3);
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn upgrade_keeps_cloudflare_tokens_history_and_all_original_migration_checksums(
    pool: PgPool,
) -> Result<()> {
    use sqlx::migrate::Migrator;
    use std::borrow::Cow;
    use uuid::Uuid;
    let migrations = sqlx::migrate!();
    let previous = Migrator {
        migrations: Cow::Owned(
            migrations
                .iter()
                .filter(|m| m.version <= 35)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    previous.run(&pool).await?;
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY old DDNS') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let config = input(server)["config"].clone();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token,record_id,last_ip,last_success_at) VALUES($1,$2,$3,$4,'record2','192.0.2.1',123)").bind(id).bind(server).bind(&config).bind(TOKEN).execute(&pool).await?;
    let before: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await?;
    migrations.run(&pool).await?;
    migrations.run(&pool).await?;
    let after:(Value,String,String,String,i64,String,String)=sqlx::query_as("SELECT config,api_token,record_id,last_ip,last_success_at,access_key_id,access_key_secret FROM ddns_rules WHERE id=$1").bind(id).fetch_one(&pool).await?;
    assert_eq!(
        after,
        (
            config,
            TOKEN.into(),
            "record2".into(),
            "192.0.2.1".into(),
            123,
            String::new(),
            String::new()
        )
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT version,checksum FROM _sqlx_migrations WHERE version<=35 ORDER BY version"
        )
        .fetch_all(&pool)
        .await?,
        before
    );
    Ok(())
}
