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
        let directory = std::env::temp_dir().join(format!("sinan-control-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let state = AppState::new(
            pool.clone(),
            Config {
                database_url: String::new(),
                listen,
                public_url: base.clone(),
                data_dir: directory.clone(),
                admin_password: Some("control-test-password".into()),
            },
        )
        .await?;
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("test panel");
        });
        Ok(Self {
            pool,
            base,
            client: Client::builder().no_proxy().build()?,
            directory,
            task,
        })
    }
    async fn session(&self, actor: i64, recent: bool) -> Result<String> {
        let token = random_token();
        let hash = hash_token(&token);
        let now = now_timestamp();
        sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
            .bind(&hash)
            .bind(actor)
            .bind(now + 3600)
            .execute(&self.pool)
            .await?;
        if recent {
            sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)").bind(hash).bind(now).bind(now+300).execute(&self.pool).await?;
        }
        Ok(format!("sinan_session={token}"))
    }
    async fn server(&self, name: &str) -> Result<i64> {
        Ok(
            sqlx::query_scalar("INSERT INTO servers(name) VALUES($1) RETURNING id")
                .bind(name)
                .fetch_one(&self.pool)
                .await?,
        )
    }
    async fn viewer(&self, server: i64) -> Result<i64> {
        let actor:i64=sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id").fetch_one(&self.pool).await?;
        sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,'viewer','只读','viewer',false,'[\"servers:read\"]',0,0)").bind(actor).execute(&self.pool).await?;
        sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
            .bind(actor)
            .bind(server)
            .execute(&self.pool)
            .await?;
        Ok(actor)
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[sqlx::test]
async fn cloud_resources_apply_scope_before_limit_and_keep_token_intersection(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("allowed cloud host").await?;
    let second = panel.server("unassigned cloud host").await?;
    let viewer = panel.viewer(first).await?;
    sqlx::query(
        "UPDATE administrator_profiles SET capabilities='[\"cloud:read\"]' WHERE admin_id=$1",
    )
    .bind(viewer)
    .execute(&panel.pool)
    .await?;
    let account = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret) VALUES($1,'cloud scope fixture','fixture-only','fixture-only')")
        .bind(account).execute(&panel.pool).await?;
    sqlx::query("UPDATE alicloud_accounts SET balance='{}',balance_error='fixture-account-global-error' WHERE id=$1")
        .bind(account).execute(&panel.pool).await?;
    sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) SELECT gen_random_uuid(),$1,'a hidden','ecs','example-region','i-hidden-'||n FROM generate_series(1,510) n")
        .bind(account).execute(&panel.pool).await?;
    sqlx::query("INSERT INTO operations_cloud_links(resource_id,server_id,updated_at,updated_by) SELECT id,$1,0,1 FROM alicloud_resources WHERE account_id=$2")
        .bind(second).bind(account).execute(&panel.pool).await?;
    let visible = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'z allowed','ecs','example-region','i-allowed')")
        .bind(visible).bind(account).execute(&panel.pool).await?;
    sqlx::query("INSERT INTO operations_cloud_links(resource_id,server_id,updated_at,updated_by) VALUES($1,$2,0,1)")
        .bind(visible).bind(first).execute(&panel.pool).await?;
    let cookie = panel.session(viewer, false).await?;
    let response: Value = panel
        .client
        .get(format!("{}/api/operations/cloud", panel.base))
        .header(header::COOKIE, cookie)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let resources = response["resources"]
        .as_array()
        .context("cloud resources")?;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], visible.to_string());
    assert!(resources[0]["balance"].is_null());
    assert!(resources[0]["balance_error"].is_null());
    assert_eq!(resources[0]["balance_scope"], "resource_only");
    let token = format!("sinan_api_{}", random_token());
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'cloud scope','[\"cloud:read\"]',$3,false,$4,0)")
        .bind(Uuid::new_v4()).bind(hash_token(&token)).bind(json!([first])).bind(now_timestamp()+3600).execute(&panel.pool).await?;
    let response: Value = panel
        .client
        .get(format!("{}/api/operations/cloud", panel.base))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let resources = response["resources"]
        .as_array()
        .context("token cloud resources")?;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], visible.to_string());
    assert!(resources[0]["balance"].is_null());
    assert!(resources[0]["balance_error"].is_null());
    let retired = panel.server("retired cloud host").await?;
    sqlx::query("UPDATE servers SET deleted_at=$2 WHERE id=$1")
        .bind(retired)
        .bind(now_timestamp())
        .execute(&panel.pool)
        .await?;
    let response = panel
        .client
        .post(format!(
            "{}/api/operations/cloud/{visible}/link",
            panel.base
        ))
        .header(header::COOKIE, panel.session(1, true).await?)
        .header(header::ORIGIN, &panel.base)
        .json(&json!({"server_id":retired,"purchase_reference":"","notes":""}))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let linked: i64 =
        sqlx::query_scalar("SELECT server_id FROM operations_cloud_links WHERE resource_id=$1")
            .bind(visible)
            .fetch_one(&panel.pool)
            .await?;
    assert_eq!(linked, first);
    Ok(())
}

#[sqlx::test]
async fn scoped_viewer_cannot_read_other_servers_or_mutate(pool: PgPool) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("allowed").await?;
    let second = panel.server("unassigned").await?;
    let viewer = panel.viewer(first).await?;
    let cookie = panel.session(viewer, false).await?;
    let values: Vec<Value> = panel
        .client
        .get(format!("{}/api/servers", panel.base))
        .header(header::COOKIE, &cookie)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"], first);
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/servers/{second}", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        panel
            .client
            .patch(format!("{}/api/servers/{first}", panel.base))
            .header(header::COOKIE, &cookie)
            .json(&json!({"name":"forbidden"}))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/settings", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let name: String = sqlx::query_scalar("SELECT name FROM servers WHERE id=$1")
        .bind(first)
        .fetch_one(&panel.pool)
        .await?;
    assert_eq!(name, "allowed");
    Ok(())
}

#[sqlx::test]
async fn owner_api_token_retains_capability_and_server_limits(pool: PgPool) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("allowed").await?;
    let second = panel.server("unassigned").await?;
    let token = format!("sinan_api_{}", random_token());
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'read-only','[\"servers:read\"]',$3,false,$4,0)").bind(Uuid::new_v4()).bind(hash_token(&token)).bind(json!([first])).bind(now_timestamp()+3600).execute(&panel.pool).await?;
    let values: Vec<Value> = panel
        .client
        .get(format!("{}/api/servers", panel.base))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"], first);
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/servers/{second}", panel.base))
            .bearer_auth(&token)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        panel
            .client
            .post(format!("{}/api/servers", panel.base))
            .bearer_auth(&token)
            .json(&json!({"name":"forbidden"}))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/settings", panel.base))
            .bearer_auth(&token)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        panel
            .client
            .get(format!(
                "{}/api/control-center/preferences/favorite",
                panel.base
            ))
            .bearer_auth(&token)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/security/totp", panel.base))
            .bearer_auth(&token)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE management_api_tokens SET revoked_at=$1")
        .bind(now_timestamp())
        .execute(&panel.pool)
        .await?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/servers", panel.base))
            .bearer_auth(&token)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[sqlx::test]
async fn proof_is_session_bound_and_preference_conflicts_preserve_values(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let stale = panel.session(1, false).await?;
    let recent = panel.session(1, true).await?;
    let body = json!({"name":"limited","capabilities":["servers:read"],"server_ids":[],"all_servers":false,"expires_at":now_timestamp()+3600});
    assert_eq!(
        panel
            .client
            .post(format!("{}/api/control-center/tokens", panel.base))
            .header(header::COOKIE, &stale)
            .json(&body)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = panel
        .client
        .post(format!("{}/api/control-center/tokens", panel.base))
        .header(header::COOKIE, &recent)
        .json(&body)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = response.json().await?;
    let issued = value["token"].as_str().context("issued token")?.to_owned();
    assert!(issued.starts_with("sinan_api_"));
    let url = format!("{}/api/control-center/preferences/view:servers", panel.base);
    assert_eq!(
        panel
            .client
            .put(&url)
            .header(header::COOKIE, &recent)
            .json(&json!({"value":{"sort":"name"},"expected_revision":0}))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        panel
            .client
            .put(&url)
            .header(header::COOKIE, &recent)
            .json(&json!({"value":{"sort":"cpu"},"expected_revision":0}))
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let value: Value = panel
        .client
        .get(&url)
        .header(header::COOKIE, &recent)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(value["value"]["sort"], "name");
    let audit: Vec<Value> = panel
        .client
        .get(format!("{}/api/control-center/audit", panel.base))
        .header(header::COOKIE, &recent)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(!serde_json::to_string(&audit)?.contains(&issued));
    Ok(())
}

#[sqlx::test]
async fn authorization_changes_revoke_existing_credentials_and_protect_the_last_owner(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let first = panel.server("first").await?;
    let second = panel.server("second").await?;
    let viewer = panel.viewer(first).await?;
    let owner = panel.session(1, true).await?;
    let session = panel.session(viewer, false).await?;
    let token = format!("sinan_api_{}", random_token());
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,$2,$3,'viewer','[\"servers:read\"]',$4,false,$5,0)")
        .bind(Uuid::new_v4()).bind(viewer).bind(hash_token(&token)).bind(json!([first])).bind(now_timestamp()+3600).execute(&panel.pool).await?;
    let update = json!({"login_name":"viewer","display_name":"只读","role":"viewer","enabled":true,"all_servers":false,"capabilities":["servers:read"],"server_ids":[second],"password":null,"expected_revision":1});
    let url = format!("{}/api/control-center/administrators/{viewer}", panel.base);
    assert_eq!(
        panel
            .client
            .put(&url)
            .header(header::COOKIE, &owner)
            .json(&update)
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/servers", panel.base))
            .header(header::COOKIE, &session)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/servers", panel.base))
            .bearer_auth(&token)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .put(&url)
            .header(header::COOKIE, &owner)
            .json(&update)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let last_owner = json!({"login_name":"admin","display_name":"所有者","role":"viewer","enabled":true,"all_servers":false,"capabilities":["servers:read"],"server_ids":[first],"password":null,"expected_revision":1});
    assert_eq!(
        panel
            .client
            .put(format!(
                "{}/api/control-center/administrators/1",
                panel.base
            ))
            .header(header::COOKIE, &owner)
            .json(&last_owner)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let role: String =
        sqlx::query_scalar("SELECT role FROM administrator_profiles WHERE admin_id=1")
            .fetch_one(&panel.pool)
            .await?;
    assert_eq!(role, "owner");
    let response = panel
        .client
        .post(format!("{}/api/login", panel.base))
        .json(&json!({"login_name":"viewer","password":"control-test-password"}))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let authenticated: Value = response.json().await?;
    assert_eq!(authenticated["id"], viewer);
    assert_eq!(
        panel
            .client
            .post(format!("{}/api/login", panel.base))
            .json(&json!({"login_name":"viewer","password":"wrong-sensitive-password"}))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let audits: Vec<Value> = sqlx::query_scalar(
        "SELECT request_diff || result FROM management_audit WHERE action='login'",
    )
    .fetch_all(&panel.pool)
    .await?;
    assert!(audits.iter().any(|value| value["phase"] == "authenticated"));
    assert!(
        audits
            .iter()
            .any(|value| value["phase"] == "authentication-denied")
    );
    let serialized = serde_json::to_string(&audits)?;
    assert!(!serialized.contains("control-test-password"));
    assert!(!serialized.contains("wrong-sensitive-password"));
    Ok(())
}
