#![forbid(unsafe_code)]

mod release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, Response, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_panel::{AppState, config::Config, router};
use sinan_protocol::{
    AuthChallenge, AuthResponse, EnrollRequest, EnrollResponse, Envelope, Hello, HelloAck,
    Manifest, PROTOCOL_VERSION, StaticInfo, now_timestamp,
};
use sqlx::PgPool;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use uuid::Uuid;

const PASSWORD: &str = "foundation-test-password";
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct TestPanel {
    state: AppState,
    client: Client,
    base: String,
    directory: PathBuf,
    task: JoinHandle<()>,
}

impl TestPanel {
    async fn start(pool: PgPool) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen = listener.local_addr()?;
        let base = format!("http://{listen}");
        let directory = std::env::temp_dir().join(format!("sinan-foundation-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory)?;
        let directory = directory.canonicalize()?;
        let config = Config {
            database_url: String::new(),
            listen,
            public_url: base.clone(),
            data_dir: directory.clone(),
            admin_password: Some(PASSWORD.into()),
        };
        let mut state = AppState::new(pool, config).await?;
        state.release_keys = Some(std::sync::Arc::new(release_support::trusted_keys()));
        let app = router(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("test HTTP server");
        });
        Ok(Self {
            state,
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()?,
            base,
            directory,
            task,
        })
    }

    async fn login(&self, password: &str) -> Result<Response> {
        Ok(self
            .client
            .post(format!("{}/api/login", self.base))
            .json(&json!({"password": password}))
            .send()
            .await?)
    }

    async fn admin_cookie(&self) -> Result<String> {
        let response = self.login(PASSWORD).await?;
        assert!(response.status().is_success());
        session_cookie(&response)
    }

    async fn create_server(&self, cookie: &str, name: &str) -> Result<i64> {
        let response = self
            .client
            .post(format!("{}/api/servers", self.base))
            .header(header::COOKIE, cookie)
            .json(&json!({"name": name}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let server: Value = response.json().await?;
        server["id"].as_i64().context("server id")
    }

    async fn token(&self, cookie: &str, server_id: i64) -> Result<String> {
        let response = self
            .client
            .post(format!("{}/api/servers/{server_id}/enrollment", self.base))
            .header(header::COOKIE, cookie)
            .send()
            .await?;
        assert!(response.status().is_success());
        let value: Value = response.json().await?;
        assert!(
            value["expires_at"].as_i64().context("token expiry")? > sinan_protocol::now_timestamp()
        );
        let token = value["token"].as_str().context("enrollment token")?;
        Ok(token.to_string())
    }

    async fn enroll(&self, request: &EnrollRequest) -> Result<Response> {
        Ok(self
            .client
            .post(format!("{}/api/agent/v1/enroll", self.base))
            .json(request)
            .send()
            .await?)
    }

    async fn connect(&self) -> Result<(Socket, AuthChallenge)> {
        let url = format!("{}/api/agent/v1/ws", self.base.replacen("http", "ws", 1));
        let (mut socket, _) = connect_async(url).await?;
        let envelope = receive_envelope(&mut socket).await?;
        assert_eq!(envelope.message_type, "auth.challenge");
        Ok((socket, envelope.to_payload()?))
    }

    async fn authenticated_device(
        &self,
        cookie: &str,
        name: &str,
    ) -> Result<(i64, Socket, HelloAck)> {
        let server_id = self.create_server(cookie, name).await?;
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        self.enroll(&enrollment(self.token(cookie, server_id).await?, &key))
            .await?
            .error_for_status()?;
        let (mut socket, challenge) = self.connect().await?;
        send_envelope(
            &mut socket,
            Envelope::new(
                "auth.response",
                signed_response(server_id, &challenge.nonce, &key),
            )?,
        )
        .await?;
        let ack = receive_envelope(&mut socket).await?;
        assert_eq!(ack.message_type, "hello.ack");
        send_envelope(
            &mut socket,
            Envelope::new(
                "hello",
                Hello {
                    agent_version: "foundation-test".into(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: vec![
                        sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY.into(),
                    ],
                    applied: BTreeMap::new(),
                },
            )?,
        )
        .await?;
        self.wait_signature_capability(server_id).await?;
        Ok((server_id, socket, ack.to_payload()?))
    }

    async fn wait_signature_capability(&self, server_id: i64) -> Result<()> {
        timeout(Duration::from_secs(5), async {
            loop {
                let capabilities: serde_json::Value =
                    sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1")
                        .bind(server_id)
                        .fetch_one(&self.state.pool)
                        .await?;
                if capabilities.as_array().is_some_and(|values| {
                    values.iter().any(|value| {
                        value == sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY
                    })
                }) {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        Ok(())
    }
}

impl Drop for TestPanel {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn session_cookie(response: &Response) -> Result<String> {
    response
        .headers()
        .get(header::SET_COOKIE)
        .context("session Set-Cookie header")?
        .to_str()?
        .split(';')
        .next()
        .map(str::to_owned)
        .context("session cookie")
}

fn enrollment(token: String, key: &SigningKey) -> EnrollRequest {
    EnrollRequest {
        token,
        device_public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        static_info: StaticInfo {
            arch: Some("amd64".into()),
            hostname: Some("foundation-test".into()),
            ..StaticInfo::default()
        },
    }
}

fn signed_response(server_id: i64, nonce: &str, key: &SigningKey) -> AuthResponse {
    AuthResponse {
        server_id,
        signature: URL_SAFE_NO_PAD.encode(key.sign(nonce.as_bytes()).to_bytes()),
    }
}

async fn send_envelope(socket: &mut Socket, envelope: Envelope) -> Result<()> {
    socket
        .send(Message::Text(serde_json::to_string(&envelope)?.into()))
        .await?;
    Ok(())
}

async fn receive_envelope(socket: &mut Socket) -> Result<Envelope> {
    timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await.context("WebSocket ended")?? {
                Message::Text(text) => return Ok(serde_json::from_str(&text)?),
                Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
                Message::Pong(_) => {}
                other => bail!("expected envelope, got {other:?}"),
            }
        }
    })
    .await?
}

async fn expect_rejected(socket: &mut Socket) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Close(_)) | Err(_) => return Ok(()),
                Ok(Message::Text(text)) => bail!("rejected authentication returned data: {text}"),
                _ => {}
            }
        }
        Ok(())
    })
    .await?
}

#[sqlx::test(migrations = "./migrations")]
async fn admin_sessions_are_scoped_expiring_and_not_reset_on_restart(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    for path in [
        "/api/me",
        "/api/servers",
        "/api/artifacts",
        "/api/agent/v1/manifest",
    ] {
        assert_eq!(
            panel
                .client
                .get(format!("{}{path}", panel.base))
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        panel.login("incorrect-password").await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = panel.login(PASSWORD).await?;
    assert!(response.status().is_success());
    let attributes = response.headers()[header::SET_COOKIE].to_str()?;
    assert!(attributes.contains("HttpOnly"));
    assert!(attributes.contains("SameSite=Strict"));
    assert!(attributes.contains("Path=/"));
    let cookie = session_cookie(&response)?;
    assert!(
        panel
            .client
            .get(format!("{}/api/me", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status()
            .is_success()
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let mut restarted_config = (*panel.state.config).clone();
    restarted_config.admin_password = Some("replacement-must-not-reset-password".into());
    AppState::new(pool.clone(), restarted_config).await?;
    assert!(panel.login(PASSWORD).await?.status().is_success());
    assert_eq!(
        panel
            .login("replacement-must-not-reset-password")
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    sqlx::query("UPDATE sessions SET expires_at = 0 WHERE admin_id IS NOT NULL")
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/me", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let cookie = panel.admin_cookie().await?;
    assert!(
        panel
            .client
            .post(format!("{}/api/logout", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status()
            .is_success()
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/me", panel.base))
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn server_crud_and_enrollment_consumption_are_atomic(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel.create_server(&cookie, "Before rename").await?;
    let url = format!("{}/api/servers/{server_id}", panel.base);
    assert!(
        panel
            .client
            .patch(&url)
            .header(header::COOKIE, &cookie)
            .json(&json!({"name": "After rename"}))
            .send()
            .await?
            .status()
            .is_success()
    );
    let server: Value = panel
        .client
        .get(&url)
        .header(header::COOKIE, &cookie)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(server["name"], "After rename");
    let token = panel.token(&cookie, server_id).await?;
    let first_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let second_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let first_request = enrollment(token.clone(), &first_key);
    let second_request = enrollment(token, &second_key);
    let (first, second) = tokio::join!(panel.enroll(&first_request), panel.enroll(&second_request));
    let first = first?;
    let second = second?;
    assert_ne!(first.status().is_success(), second.status().is_success());
    let (winner, rejected) = if first.status().is_success() {
        (first, second)
    } else {
        (second, first)
    };
    assert!(rejected.status().is_client_error());
    assert_eq!(winner.json::<EnrollResponse>().await?.server_id, server_id);
    assert!(
        panel
            .enroll(&first_request)
            .await?
            .status()
            .is_client_error()
    );
    assert!(
        panel
            .client
            .delete(&url)
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status()
            .is_success()
    );
    assert_eq!(
        panel
            .client
            .get(&url)
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_keys_do_not_consume_tokens_and_expired_tokens_cannot_enroll(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel.create_server(&cookie, "Invalid key case").await?;
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut request = enrollment(panel.token(&cookie, server_id).await?, &key);
    let public_key = request.device_public_key.clone();
    request.device_public_key = URL_SAFE_NO_PAD.encode([0_u8; 31]);
    assert_eq!(
        panel.enroll(&request).await?.status(),
        StatusCode::BAD_REQUEST
    );
    request.device_public_key = URL_SAFE_NO_PAD.encode([0_u8; 32]);
    assert_eq!(
        panel.enroll(&request).await?.status(),
        StatusCode::BAD_REQUEST
    );
    request.device_public_key = public_key;
    assert_eq!(
        panel
            .enroll(&request)
            .await?
            .error_for_status()?
            .json::<EnrollResponse>()
            .await?
            .server_id,
        server_id
    );

    let expired_server = panel.create_server(&cookie, "Expired token case").await?;
    let expired_request = enrollment(panel.token(&cookie, expired_server).await?, &key);
    sqlx::query("UPDATE enrollment_tokens SET expires_at = 0 WHERE server_id = $1")
        .bind(expired_server)
        .execute(&pool)
        .await?;
    assert!(
        panel
            .enroll(&expired_request)
            .await?
            .status()
            .is_client_error()
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn bundle_download_preserves_bytes_and_cannot_cross_server_identity(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let (server_id, mut socket, ack) = panel.authenticated_device(&cookie, "Bundle owner").await?;
    let other_id = panel.create_server(&cookie, "Other bundle owner").await?;
    let bundle = "{\n  \"files\": {\"config.json\": \"{}\\n\"}\n}\n";
    let digest = format!("{:x}", Sha256::digest(bundle.as_bytes()));
    for (owner, rev) in [(server_id, 1_i64), (other_id, 99_i64)] {
        sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,created_at) VALUES($1,'singbox',$2,$3,$4,$5)")
            .bind(owner).bind(rev).bind(bundle).bind(&digest)
            .bind(sinan_protocol::now_timestamp()).execute(&pool).await?;
    }
    let own_url = format!("{}/api/agent/v1/bundles/1", panel.base);
    assert_eq!(
        panel.client.get(&own_url).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = panel
        .client
        .get(&own_url)
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = response.bytes().await?;
    assert_eq!(bytes.as_ref(), bundle.as_bytes());
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), digest);
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/agent/v1/bundles/99", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    socket.close(None).await?;
    timeout(Duration::from_secs(5), async {
        while panel
            .state
            .connections
            .read()
            .await
            .contains_key(&server_id)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    panel
        .client
        .delete(format!("{}/api/servers/{server_id}", panel.base))
        .header(header::COOKIE, &cookie)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        panel
            .client
            .get(&own_url)
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn websocket_challenges_are_connection_bound_and_sessions_expire(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool.clone()).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel.create_server(&cookie, "Authenticated agent").await?;
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    panel
        .enroll(&enrollment(panel.token(&cookie, server_id).await?, &key))
        .await?
        .error_for_status()?;

    let (mut first, first_challenge) = panel.connect().await?;
    let (mut replay, second_challenge) = panel.connect().await?;
    assert_ne!(first_challenge.nonce, second_challenge.nonce);
    let response = signed_response(server_id, &first_challenge.nonce, &key);
    send_envelope(&mut replay, Envelope::new("auth.response", &response)?).await?;
    expect_rejected(&mut replay).await?;

    let (mut unknown, challenge) = panel.connect().await?;
    send_envelope(
        &mut unknown,
        Envelope::new(
            "auth.response",
            signed_response(i64::MAX, &challenge.nonce, &key),
        )?,
    )
    .await?;
    expect_rejected(&mut unknown).await?;

    let auth_started_at = now_timestamp();
    // Hold only this isolated test database's session inserts. Observe the
    // blocked INSERT before crossing a second, so scheduler timing cannot hide
    // separate clock reads for the stored expiry and the hello.ack timestamp.
    let mut blocker = pool.begin().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *blocker)
        .await?;
    sqlx::query("LOCK TABLE sessions IN SHARE MODE")
        .execute(&mut *blocker)
        .await?;
    send_envelope(&mut first, Envelope::new("auth.response", response)?).await?;
    timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='relation'
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
                 AND relation='sessions'::regclass AND mode='RowExclusiveLock' AND NOT granted
                 AND $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid)
            .fetch_one(&pool)
            .await?;
            if waiting {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("authentication INSERT did not wait on the test session lock")??;
    let blocked_second = sinan_protocol::now_timestamp();
    timeout(Duration::from_secs(3), async {
        while sinan_protocol::now_timestamp() <= blocked_second {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("Unix clock did not advance while authentication was blocked")?;
    blocker.commit().await?;
    let ack = receive_envelope(&mut first).await?;
    let ack_received_at = now_timestamp();
    assert_eq!(ack.message_type, "hello.ack");
    let ack: HelloAck = ack.to_payload()?;
    assert_eq!(ack.session_expires_at - ack.server_time, 3600);
    // Storage and acknowledgement share one issuance snapshot even across a second.
    let issued_at = ack.session_expires_at - 3600;
    assert!((auth_started_at..=ack_received_at).contains(&issued_at));
    assert!((issued_at..=ack_received_at).contains(&ack.server_time));
    let stored_expiry: i64 = sqlx::query_scalar(
        "SELECT expires_at FROM sessions WHERE token_hash = $1 AND server_id = $2",
    )
    .bind(sinan_panel::auth::hash_token(&ack.session_token))
    .bind(server_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(ack.session_expires_at, stored_expiry);
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    send_envelope(
        &mut first,
        Envelope::new(
            "hello",
            Hello {
                agent_version: "foundation-test".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: vec![sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY.into()],
                applied: BTreeMap::new(),
            },
        )?,
    )
    .await?;
    panel.wait_signature_capability(server_id).await?;
    let manifest: Manifest = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(manifest.rev, 0);
    assert!(manifest.modules.is_empty());
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/me", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    send_envelope(
        &mut first,
        Envelope::new("future.unknown", json!({"extension": true}))?,
    )
    .await?;
    first
        .send(Message::Ping(b"still-connected".as_slice().into()))
        .await?;
    timeout(Duration::from_secs(5), async {
        loop {
            match first
                .next()
                .await
                .context("authenticated WebSocket ended")??
            {
                Message::Ping(bytes) => first.send(Message::Pong(bytes)).await?,
                Message::Pong(bytes) if bytes.as_ref() == b"still-connected" => break,
                other => bail!("expected heartbeat pong, got {other:?}"),
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    sqlx::query("UPDATE sessions SET expires_at = 0 WHERE server_id = $1")
        .bind(server_id)
        .execute(&pool)
        .await?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn panel_never_serves_agent_binaries_even_with_a_live_token(pool: PgPool) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel.create_server(&cookie, "Bootstrap device").await?;
    let token = panel.token(&cookie, server_id).await?;
    let binary = b"test-agent-artifact";
    let artifact_dir = release_fixture::write(
        &panel.directory,
        "agent",
        version,
        "sinan-agent",
        binary,
        binary,
        "raw",
    )?;
    let bootstrap_url = format!("{}/api/bootstrap/{version}/amd64", panel.base);
    assert!(
        panel
            .client
            .get(&bootstrap_url)
            .send()
            .await?
            .status()
            .is_client_error()
    );
    assert_eq!(
        panel
            .client
            .get(&bootstrap_url)
            .query(&[("token", "invalid")])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = panel
        .client
        .get(&bootstrap_url)
        .query(&[("token", &token)])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let install = panel
        .client
        .get(format!("{}/install.sh", panel.base))
        .query(&[("token", &token)])
        .send()
        .await?;
    assert_eq!(install.status(), StatusCode::OK);
    assert_eq!(install.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(install.headers()[header::CONTENT_TYPE], "application/json");
    let installation: Value = install.json().await?;
    assert_eq!(installation["version"], "latest");
    assert!(installation["tag"].is_null());
    assert_eq!(installation["platform"], "unix");
    assert_eq!(installation["target"], "auto");
    assert_eq!(
        installation["bootstrap_url"],
        sinan_panel::installation::bootstrap_url()
    );
    let install_command = installation["install_command"].as_str().unwrap();
    assert!(install_command.contains("https://api.github.com/repos/theLucius7/sinan/git/blobs/"));
    assert!(install_command.contains("sha256sum -c"));
    assert!(install_command.contains("--version") && install_command.contains("latest"));
    assert!(!install_command.contains("sudo sinan-bootstrap"));
    assert_eq!(
        panel
            .client
            .get(format!("{}/install.sh", panel.base))
            .query(&[("token", token.as_str()), ("agent_version", "99.0.0")])
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let issued: Value = panel
        .client
        .post(format!("{}/api/servers/{server_id}/enrollment", panel.base))
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, &panel.base)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(
        issued["install_command"]
            .as_str()
            .unwrap()
            .contains(issued["installation"]["bootstrap_url"].as_str().unwrap())
    );
    assert_eq!(
        issued["install_command"],
        issued["installation"]["install_command"]
    );
    let missing = panel
        .client
        .get(format!("{}/api/bootstrap/99.0.0/arm64", panel.base))
        .query(&[("token", &token)])
        .send()
        .await?;
    assert_eq!(missing.status(), StatusCode::CONFLICT);
    let missing: Value = missing.json().await?;
    let message = missing["error"].as_str().unwrap();
    assert!(message.contains("GitHub"));
    assert!(message.contains("面板不再提供"));
    assert_eq!(
        panel
            .client
            .get(format!(
                "{}/api/bootstrap/%2e%2e%2fsecret/amd64",
                panel.base
            ))
            .query(&[("token", &token)])
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        panel
            .client
            .get(format!(
                "{}/api/agent/v1/artifacts/agent/{version}/amd64",
                panel.base
            ))
            .query(&[("token", &token)])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    std::fs::write(artifact_dir.join("amd64"), b"corrupted-test-artifact")?;
    let catalogue: Value = panel
        .client
        .get(format!("{}/api/bootstrap/versions", panel.base))
        .query(&[("token", token.as_str()), ("target", "linux-gnu-amd64")])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(catalogue["versions"][0]["targets"], json!(["amd64"]));
    assert_eq!(catalogue["versions"][0]["cached_targets"], json!([]));
    // The catalogue must still reject tampering with its complete signed proof.
    let metadata = artifact_dir
        .parent()
        .context("component directory")?
        .parent()
        .context("release directory")?
        .join("release.json");
    let original = std::fs::read(&metadata)?;
    std::fs::write(&metadata, b"tampered release metadata")?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/bootstrap/versions", panel.base))
            .query(&[("token", &token)])
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    std::fs::write(metadata, original)?;
    std::fs::write(artifact_dir.join("amd64"), binary)?;
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    panel
        .enroll(&enrollment(token.clone(), &key))
        .await?
        .error_for_status()?;
    assert_eq!(
        panel
            .client
            .get(&bootstrap_url)
            .query(&[("token", &token)])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/install.sh", panel.base))
            .query(&[("token", &token)])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let (_, _socket, ack) = panel
        .authenticated_device(&cookie, "Authenticated download")
        .await?;
    let response = panel
        .client
        .get(format!(
            "{}/api/agent/v1/artifacts/agent/{version}/amd64",
            panel.base
        ))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_agent_versions_require_admin_or_live_enrollment_and_match_platforms(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "Version choices").await?;
    let token = panel.token(&cookie, server).await?;
    let mut artifacts = Vec::new();
    for target in [
        "amd64",
        "arm64",
        "windows-amd64",
        "macos-arm64",
        "freebsd-arm64",
    ] {
        let binary_name = if target.starts_with("windows-") {
            "sinan-agent.exe"
        } else {
            "sinan-agent"
        };
        let bytes = format!("fixture Agent {target}").into_bytes();
        let mut entry =
            release_support::entry("agent", "0.3.0", binary_name, "raw", &bytes, &bytes);
        entry.arch = target.into();
        entry.asset_name = sinan_protocol::release::canonical_asset_name(&entry)?;
        artifacts.push((entry, bytes));
    }
    let directory = release_fixture::write_entries(&panel.directory, artifacts)?;
    // Only one target is cached; all signed identities remain installable from GitHub.
    for target in ["amd64", "windows-amd64", "macos-arm64", "freebsd-arm64"] {
        std::fs::remove_file(directory.join("agent/0.3.0").join(target))?;
    }
    std::fs::write(
        directory.join("inventory.json"),
        serde_json::to_vec(&json!({"paths":["agent/0.3.0/arm64"]}))?,
    )?;
    let admin_url = format!("{}/api/artifacts/agent-versions", panel.base);
    let bootstrap_url = format!("{}/api/bootstrap/versions", panel.base);
    assert_eq!(
        panel.client.get(&admin_url).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .get(&admin_url)
            .query(&[("token", token.as_str())])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .get(&admin_url)
            .header(header::COOKIE, &cookie)
            .query(&[("token", token.as_str())])
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        panel
            .client
            .get(&bootstrap_url)
            .query(&[("token", "invalid")])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .get(&bootstrap_url)
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = panel
        .client
        .get(&admin_url)
        .header(header::COOKIE, &cookie)
        .query(&[("platform", "unix"), ("target", "auto")])
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let catalogue: Value = response.json().await?;
    assert_eq!(
        catalogue["policy"],
        json!({
            "default_version": "latest",
            "selection": "highest_stable_signed_protocol_compatible_for_target",
            "minimum_version": "0.3.0"
        })
    );
    assert_eq!(
        catalogue["versions"][0]["targets"],
        json!(["amd64", "arm64", "freebsd-arm64", "macos-arm64"])
    );
    assert_eq!(catalogue["versions"][0]["cached_targets"], json!(["arm64"]));
    for (target, platform, expected) in [
        ("linux-gnu-amd64", "unix", json!(["amd64"])),
        ("linux-musl-arm64", "unix", json!(["arm64"])),
        ("windows-amd64", "windows", json!(["windows-amd64"])),
        ("macos-arm64", "unix", json!(["macos-arm64"])),
        ("freebsd-arm64", "unix", json!(["freebsd-arm64"])),
    ] {
        let response = panel
            .client
            .get(&bootstrap_url)
            .query(&[
                ("token", token.as_str()),
                ("target", target),
                ("platform", platform),
            ])
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let catalogue: Value = response.json().await?;
        assert_eq!(catalogue["versions"][0]["targets"], expected);
        assert_eq!(catalogue["versions"][0]["version"], "0.3.0");
        assert_eq!(catalogue["versions"][0]["tag"], "agent-v0.3.0");
    }
    for (version, target, platform, expected) in [
        ("99.0.0", "linux-musl-amd64", "unix", "尚未导入"),
        ("0.3.0", "macos-arm64", "windows", "该平台可安装的制品"),
    ] {
        let response = panel
            .client
            .get(&bootstrap_url)
            .query(&[
                ("token", token.as_str()),
                ("agent_version", version),
                ("target", target),
                ("platform", platform),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let refusal: Value = response.json().await?;
        assert!(refusal["error"].as_str().unwrap().contains(expected));
        assert!(refusal["versions"].is_null());
    }
    for (name, value) in [("target", "riscv64"), ("platform", "unsupported")] {
        assert_eq!(
            panel
                .client
                .get(&admin_url)
                .header(header::COOKIE, &cookie)
                .query(&[(name, value)])
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            panel
                .client
                .get(&bootstrap_url)
                .query(&[("token", token.as_str()), (name, value)])
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let token_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM enrollment_tokens WHERE server_id=$1")
            .bind(server)
            .fetch_one(&panel.state.pool)
            .await?;
    for (platform, target) in [
        ("unsupported", "auto"),
        ("unix", "riscv64"),
        ("unix", "windows-amd64"),
        ("windows", "macos-arm64"),
    ] {
        assert_eq!(
            panel
                .client
                .post(format!("{}/api/servers/{server}/enrollment", panel.base))
                .header(header::COOKIE, &cookie)
                .header(header::ORIGIN, &panel.base)
                .query(&[("platform", platform), ("agent_target", target)])
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM enrollment_tokens WHERE server_id=$1")
                .bind(server)
                .fetch_one(&panel.state.pool)
                .await?;
        assert_eq!(after, token_count, "invalid options must not issue a token");
    }
    for (platform, target, version) in [
        ("unix", "linux-gnu-amd64", "latest"),
        ("unix", "macos-arm64", "0.3.0"),
        ("unix", "freebsd-arm64", "0.3.0"),
        ("windows", "windows-amd64", "0.3.0"),
    ] {
        let issued: Value = panel
            .client
            .post(format!("{}/api/servers/{server}/enrollment", panel.base))
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, &panel.base)
            .query(&[
                ("platform", platform),
                ("agent_target", target),
                ("agent_version", version),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let installation = &issued["installation"];
        assert_eq!(installation["platform"], platform);
        assert_eq!(installation["target"], target);
        assert_eq!(installation["version"], version);
        if version == "latest" {
            assert!(installation["tag"].is_null());
        } else {
            assert_eq!(installation["tag"], "agent-v0.3.0");
        }
        let command = issued["install_command"]
            .as_str()
            .context("installation command")?;
        assert!(!command.contains('\n'), "the command must fit one line");
        assert_eq!(command, installation["install_command"]);
        assert!(command.contains(if platform == "windows" {
            "powershell"
        } else {
            "sh -c"
        }));
    }
    sqlx::query("UPDATE enrollment_tokens SET expires_at=0 WHERE server_id=$1")
        .bind(server)
        .execute(&panel.state.pool)
        .await?;
    assert_eq!(
        panel
            .client
            .get(&bootstrap_url)
            .query(&[("token", token.as_str())])
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        panel
            .client
            .get(&admin_url)
            .header(header::COOKIE, &cookie)
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn installation_uses_independent_trusted_contract_and_preserves_server_mirror(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server_id = panel
        .create_server(&cookie, "Signed installer compatibility")
        .await?;
    let token = panel.token(&cookie, server_id).await?;
    let binary = b"TEST ONLY Agent bytes never executed";
    let artifact = release_fixture::write(
        &panel.directory,
        "agent",
        "0.3.0",
        "sinan-agent",
        binary,
        binary,
        "raw",
    )?;
    let release = panel.directory.join("artifacts/releases/agent-v0.3.0");
    let marker = b"# SINAN_BOOTSTRAP_AGENT_SOURCE=preloaded-github-v1";
    // The pinned bootstrap runs its own trusted executor, so legacy release scripts
    // are signed evidence rather than the execution contract for new enrollment.
    for installer in [
        b"#!/bin/sh\nexit 0\n".to_vec(),
        [marker.as_slice(), b"\n", marker.as_slice(), b"\n"].concat(),
    ] {
        release_fixture::replace_signed_installer(&release, &installer)?;
        let response = panel
            .client
            .get(format!("{}/install.sh", panel.base))
            .query(&[("token", &token)])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let installation: Value = response.json().await?;
        assert_eq!(installation["version"], "latest");
        assert!(installation["tag"].is_null());
        assert_eq!(
            installation["bootstrap_url"],
            sinan_panel::installation::bootstrap_url()
        );
        let command = installation["install_command"].as_str().unwrap();
        assert!(command.contains(installation["bootstrap_url"].as_str().unwrap()));
        assert!(command.contains("sha256sum -c"));
        assert!(!command.contains("/install.sh"));
        let issued: Value = panel
            .client
            .post(format!("{}/api/servers/{server_id}/enrollment", panel.base))
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, &panel.base)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert!(issued["install_command"].is_string());
        assert!(issued["warning"].is_null());
    }
    let installer = [b"#!/bin/sh\n".as_slice(), marker.as_slice(), b"\nexit 0\n"].concat();
    release_fixture::replace_signed_installer(&release, &installer)?;
    // GitHub Agent downloads use signed metadata rather than a local payload.
    for arch in ["amd64", "arm64"] {
        std::fs::remove_file(artifact.join(arch))?;
    }
    sqlx::query("UPDATE servers SET asset_settings = jsonb_set(asset_settings, '{agent_mirror}', to_jsonb($2::text)) WHERE id = $1")
        .bind(server_id).bind("https://mirror.example.com").execute(&panel.state.pool).await?;
    let response = panel
        .client
        .get(format!("{}/install.sh", panel.base))
        .query(&[("token", &token)])
        .send()
        .await?
        .error_for_status()?;
    let installation: Value = response.json().await?;
    let command = installation["install_command"].as_str().unwrap();
    assert!(command.contains("--mirror"));
    assert!(command.contains("https://mirror.example.com"));
    std::fs::write(
        release.join("install.sh"),
        [installer, b"tampered".to_vec()].concat(),
    )?;
    assert_eq!(
        panel
            .client
            .get(format!("{}/install.sh", panel.base))
            .query(&[("token", &token)])
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    // Signed but incompatible Agent identities must not produce a command.
    let wrong_version =
        release_support::entry("agent", "0.3.1", "sinan-agent", "raw", binary, binary);
    let wrong_name =
        release_support::entry("agent", "0.3.0", "another-binary", "raw", binary, binary);
    let archive = release_fixture::archive("sinan-agent", binary)?;
    let wrong_format =
        release_support::entry("agent", "0.3.0", "sinan-agent", "tar.gz", &archive, binary);
    let mut oversized =
        release_support::entry("agent", "0.3.0", "sinan-agent", "raw", binary, binary);
    oversized.archive_size = 128 * 1024 * 1024 + 1;
    oversized.binary_size = oversized.archive_size;
    for entry in [wrong_version, wrong_name, wrong_format, oversized] {
        let bytes = if entry.format == "tar.gz" {
            archive.clone()
        } else {
            binary.to_vec()
        };
        release_fixture::write_entries(&panel.directory, vec![(entry, bytes)])?;
        assert_eq!(
            panel
                .client
                .get(format!("{}/install.sh", panel.base))
                .query(&[("token", &token)])
                .send()
                .await?
                .status(),
            StatusCode::CONFLICT
        );
    }
    Ok(())
}
