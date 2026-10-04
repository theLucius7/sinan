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
use sinan_protocol::{
    fleet::{AccessPolicy, TERMINAL_CAPABILITY},
    now_timestamp,
};
use sqlx::{PgPool, Row};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
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
        let directory =
            std::env::temp_dir().join(format!("sinan-terminal-access-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let state = AppState::new(
            pool.clone(),
            Config {
                database_url: String::new(),
                listen,
                public_url: base.clone(),
                data_dir: directory.clone(),
                admin_password: Some("TEST_ONLY terminal access password".into()),
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
    async fn session(&self, admin: i64) -> Result<String> {
        let token = random_token();
        let hash = hash_token(&token);
        let now = now_timestamp();
        sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
            .bind(&hash)
            .bind(admin)
            .bind(now + 3600)
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)").bind(hash).bind(now).bind(now+300).execute(&self.pool).await?;
        Ok(format!("sinan_session={token}"))
    }
    async fn fixture(&self) -> Result<(i64, i64, String, Uuid)> {
        let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,capabilities) VALUES('TEST_ONLY terminal server',$1) RETURNING id").bind(json!([TERMINAL_CAPABILITY])).fetch_one(&self.pool).await?;
        let policy = AccessPolicy {
            terminal_accounts: vec!["test_account".into()],
            ..AccessPolicy::default()
        };
        sqlx::query("INSERT INTO fleet_profiles(server_id,policy) VALUES($1,$2)")
            .bind(server)
            .bind(json!(policy))
            .execute(&self.pool)
            .await?;
        let second: i64 = sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id").fetch_one(&self.pool).await?;
        sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,capabilities,created_at,updated_at) VALUES($1,'terminal_operator','TEST_ONLY operator','operator','[\"terminal:read\",\"terminal:write\"]',0,0)").bind(second).execute(&self.pool).await?;
        sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
            .bind(second)
            .bind(server)
            .execute(&self.pool)
            .await?;
        let cookie = self.session(1).await?;
        let created: Value = self
            .client
            .post(format!(
                "{}/api/servers/{server}/fleet/terminals",
                self.base
            ))
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, &self.base)
            .json(&json!({"account":"test_account","columns":80,"rows":24,"timeout_secs":300}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let id = Uuid::parse_str(created["id"].as_str().context("terminal id")?)?;
        sqlx::query("INSERT INTO fleet_terminal_outputs(session_id,sequence,data,digest,created_at) VALUES($1,1,'TEST_ONLY private terminal output','TEST_ONLY digest',$2)").bind(id).bind(now_timestamp()).execute(&self.pool).await?;
        Ok((server, second, cookie, id))
    }
    async fn input(&self, cookie: &str, id: Uuid, data: &str) -> Result<reqwest::Response> {
        Ok(self
            .client
            .post(format!("{}/api/fleet/terminals/{id}/input", self.base))
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, &self.base)
            .json(&json!({"data":data,"columns":80,"rows":24}))
            .send()
            .await?)
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[sqlx::test]
async fn output_and_input_bind_the_originating_admin_session_but_emergency_close_remains_scoped(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let (server, second, cookie, id) = panel.fixture().await?;
    let other = panel.session(second).await?;
    let new_session = panel.session(1).await?;
    for unauthorized in [&other, &new_session] {
        assert_eq!(
            panel
                .client
                .get(format!("{}/api/fleet/terminals/{id}", panel.base))
                .header(header::COOKIE, unauthorized)
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            panel
                .input(unauthorized, id, "TEST_ONLY rejected input")
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let token = format!("sinan_api_{}", random_token());
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,expires_at,created_at) VALUES($1,1,$2,'TEST_ONLY terminal token','[\"terminal:read\",\"terminal:write\"]',$3,$4,0)").bind(Uuid::new_v4()).bind(hash_token(&token)).bind(json!([server])).bind(now_timestamp()+3600).execute(&panel.pool).await?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/fleet/terminals/{id}", panel.base))
            .bearer_auth(&token)
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let sequence: i64 =
        sqlx::query_scalar("SELECT input_sequence FROM fleet_terminal_sessions WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.pool)
            .await?;
    assert_eq!(sequence, 0);
    let owned: Value = panel
        .client
        .get(format!("{}/api/fleet/terminals/{id}", panel.base))
        .header(header::COOKIE, &cookie)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        owned["output"][0]["data"],
        "TEST_ONLY private terminal output"
    );
    let metadata: Vec<Value> = panel
        .client
        .get(format!(
            "{}/api/servers/{server}/fleet/terminals",
            panel.base
        ))
        .header(header::COOKIE, &other)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(metadata.len(), 1);
    assert!(metadata[0].get("admin_session_hash").is_none());
    assert!(metadata[0].get("policy").is_none());
    assert_eq!(
        panel
            .client
            .delete(format!("{}/api/fleet/terminals/{id}", panel.base))
            .header(header::COOKIE, &other)
            .header(header::ORIGIN, &panel.base)
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let row = sqlx::query("SELECT close_requested,status FROM fleet_terminal_sessions WHERE id=$1")
        .bind(id)
        .fetch_one(&panel.pool)
        .await?;
    assert!(row.get::<bool, _>("close_requested"));
    assert_eq!(row.get::<String, _>("status"), "queued");
    Ok(())
}

#[sqlx::test]
async fn terminal_audit_excludes_input_and_current_account_revocation_prevents_queueing(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let (server, _, cookie, id) = panel.fixture().await?;
    let sentinel = "TEST_ONLY typed PTY password sentinel";
    panel
        .input(&cookie, id, sentinel)
        .await?
        .error_for_status()?;
    let stored: String = sqlx::query_scalar(
        "SELECT data FROM fleet_terminal_inputs WHERE session_id=$1 AND sequence=1",
    )
    .bind(id)
    .fetch_one(&panel.pool)
    .await?;
    assert_eq!(stored, sentinel);
    let audits: Vec<Value> =
        sqlx::query_scalar("SELECT request_diff FROM management_audit WHERE object_path=$1")
            .bind(format!("/api/fleet/terminals/{id}/input"))
            .fetch_all(&panel.pool)
            .await?;
    assert_eq!(audits[0]["requested"]["data"], "[已脱敏]");
    assert_eq!(audits[0]["requested"]["columns"], 80);
    assert!(!serde_json::to_string(&audits)?.contains(sentinel));
    sqlx::query("UPDATE fleet_profiles SET policy=jsonb_set(policy,'{terminal_accounts}','[]') WHERE server_id=$1").bind(server).execute(&panel.pool).await?;
    assert_eq!(
        panel
            .input(&cookie, id, "TEST_ONLY revoked account input")
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let sequence: i64 =
        sqlx::query_scalar("SELECT input_sequence FROM fleet_terminal_sessions WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.pool)
            .await?;
    assert_eq!(sequence, 1);
    sqlx::query("UPDATE fleet_profiles SET policy=jsonb_set(policy,'{terminal_accounts}','[\"test_account\"]') WHERE server_id=$1").bind(server).execute(&panel.pool).await?;
    sqlx::query("UPDATE servers SET capabilities='[]' WHERE id=$1")
        .bind(server)
        .execute(&panel.pool)
        .await?;
    assert_eq!(
        panel
            .input(&cookie, id, "TEST_ONLY removed capability input")
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fleet_terminal_inputs WHERE session_id=$1")
            .bind(id)
            .fetch_one(&panel.pool)
            .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[sqlx::test]
async fn contended_authorization_fails_promptly_without_terminal_or_secret_audit_mutations(
    pool: PgPool,
) -> Result<()> {
    let panel = Panel::start(pool).await?;
    let (server, _, cookie, id) = panel.fixture().await?;
    let hash = hash_token(
        cookie
            .strip_prefix("sinan_session=")
            .context("session cookie")?,
    );
    let before: Value =
        sqlx::query_scalar("SELECT to_jsonb(s) FROM fleet_terminal_sessions s WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.pool)
            .await?;
    let output_before: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(o) FROM fleet_terminal_outputs o WHERE session_id=$1 ORDER BY sequence",
    )
    .bind(id)
    .fetch_all(&panel.pool)
    .await?;
    let events_before: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM fleet_events e WHERE server_id=$1 ORDER BY occurred_at,id",
    )
    .bind(server)
    .fetch_all(&panel.pool)
    .await?;
    let sentinel = "TEST_ONLY contended PTY secret sentinel";
    for (label, statement) in [
        (
            "profile",
            "SELECT admin_id FROM administrator_profiles WHERE admin_id=1 FOR UPDATE",
        ),
        (
            "session",
            "SELECT admin_id FROM sessions WHERE token_hash=$1 FOR UPDATE",
        ),
        (
            "reauthentication",
            "SELECT verified_at FROM administrator_reauth WHERE session_hash=$1 FOR UPDATE",
        ),
    ] {
        let mut held = panel.pool.begin().await?;
        let query = sqlx::query(statement);
        if label == "profile" {
            query.fetch_one(&mut *held).await?;
        } else {
            query.bind(&hash).fetch_one(&mut *held).await?;
        }
        let response =
            tokio::time::timeout(Duration::from_secs(5), panel.input(&cookie, id, sentinel))
                .await
                .context("terminal authorization contention must be bounded")??;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{label}");
        let error: Value = response.json().await?;
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|error| error.contains("正在变更")),
            "{label}: {error}"
        );
        let after: Value =
            sqlx::query_scalar("SELECT to_jsonb(s) FROM fleet_terminal_sessions s WHERE id=$1")
                .bind(id)
                .fetch_one(&panel.pool)
                .await?;
        assert_eq!(
            after, before,
            "{label}: terminal state must remain unchanged"
        );
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM fleet_terminal_inputs WHERE session_id=$1")
                .bind(id)
                .fetch_one(&panel.pool)
                .await?;
        assert_eq!(count, 0, "{label}: no input may be queued");
        let output_after: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(o) FROM fleet_terminal_outputs o WHERE session_id=$1 ORDER BY sequence")
            .bind(id).fetch_all(&panel.pool).await?;
        assert_eq!(
            output_after, output_before,
            "{label}: private output must remain unchanged"
        );
        let events_after: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(e) FROM fleet_events e WHERE server_id=$1 ORDER BY occurred_at,id",
        )
        .bind(server)
        .fetch_all(&panel.pool)
        .await?;
        assert_eq!(
            events_after, events_before,
            "{label}: no fleet event may be committed"
        );
        let audits: Vec<Value> =
            sqlx::query_scalar("SELECT request_diff FROM management_audit WHERE object_path=$1")
                .bind(format!("/api/fleet/terminals/{id}/input"))
                .fetch_all(&panel.pool)
                .await?;
        assert!(
            audits
                .iter()
                .all(|audit| audit["requested"]["data"] == "[已脱敏]")
        );
        assert!(
            !serde_json::to_string(&audits)?.contains(sentinel),
            "{label}: no secret audit payload may be committed"
        );
        held.rollback().await?;
    }
    // A denied request must not leave a poisoned or queued terminal operation.
    panel
        .input(&cookie, id, "TEST_ONLY input after contention ended")
        .await?
        .error_for_status()?;
    let sequence: i64 =
        sqlx::query_scalar("SELECT input_sequence FROM fleet_terminal_sessions WHERE id=$1")
            .bind(id)
            .fetch_one(&panel.pool)
            .await?;
    assert_eq!(sequence, 1);
    Ok(())
}
