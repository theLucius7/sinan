use super::*;
use axum::{Router, body::Body, http::Request as HttpRequest};
use std::sync::{Arc, Mutex};
use tokio::{net::TcpListener, sync::Notify};

struct Fixture {
    state: AppState,
    headers: HeaderMap,
    account: Account,
}

async fn fixture(pool: sqlx::PgPool) -> Fixture {
    let state = AppState::new(
        pool,
        crate::config::Config {
            database_url: String::new(),
            listen: "127.0.0.1:0".parse().unwrap(),
            public_url: "http://127.0.0.1:19283".into(),
            data_dir: std::path::PathBuf::from("/TEST_ONLY_not_written"),
            admin_password: Some("TEST_ONLY_dns_intent_password".into()),
        },
    )
    .await
    .unwrap();
    let account = tests::account();
    sqlx::query("INSERT INTO credential_entries(id,name,kind,key_id,nonce,ciphertext,version,enabled,created_at,updated_at) VALUES($1,'TEST_ONLY DNS','dns','TEST_ONLY_key',$2,$3,1,true,0,0)")
        .bind(account.config.credential_id).bind(vec![0u8;12]).bind(vec![0u8;16])
        .execute(&state.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO dns_accounts(id,config,revision,created_at,updated_at) VALUES($1,$2,1,0,0)",
    )
    .bind(account.id)
    .bind(json!(account.config))
    .execute(&state.pool)
    .await
    .unwrap();
    let token = format!("TEST_ONLY_{}", Uuid::new_v4());
    let hash = crate::auth::hash_token(&token);
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,1,$2)")
        .bind(&hash)
        .bind(now + 600)
        .execute(&state.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)",
    )
    .bind(hash)
    .bind(now)
    .bind(now + 300)
    .execute(&state.pool)
    .await
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("sinan_session={token}").parse().unwrap(),
    );
    Fixture {
        state,
        headers,
        account,
    }
}

async fn intent(fixture: &Fixture) -> (Uuid, Uuid) {
    let preview = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    let request = tests::request();
    let mut tx = fixture.state.pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    sqlx::query("INSERT INTO dns_record_previews(id,account_id,account_revision,request,snapshot,created_at,expires_at) VALUES($1,$2,1,$3,'null',$4,$5)")
        .bind(preview).bind(fixture.account.id).bind(json!(request)).bind(now).bind(now+300)
        .execute(&mut *tx).await.unwrap();
    let operation = reserve(
        &mut tx,
        &fixture.account,
        &request,
        Value::Null,
        Origin {
            administrator: 1,
            credential_version: 1,
            preview: Some(preview),
            rollback: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE dns_record_previews SET applied_at=$2 WHERE id=$1")
        .bind(preview)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (preview, operation)
}

async fn history(fixture: &Fixture, operation: Uuid) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(h) FROM dns_record_history h WHERE id=$1")
        .bind(operation)
        .fetch_one(&fixture.state.pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn committed_unsent_intent_consumes_preview_blocks_writes_and_reconciles_without_provider(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let (preview, operation) = intent(&fixture).await;
    let entry = history(&fixture, operation).await;
    assert_eq!(entry["status"], "unknown");
    assert_eq!(entry["requested_by"], 1);
    assert_eq!(entry["credential_version"], 1);
    assert_eq!(entry["preview_id"], preview.to_string());
    assert_eq!(entry["account_snapshot"], json!(fixture.account.config));
    assert!(entry["write_started_at"].is_null());
    let applied: Option<i64> =
        sqlx::query_scalar("SELECT applied_at FROM dns_record_previews WHERE id=$1")
            .bind(preview)
            .fetch_one(&fixture.state.pool)
            .await
            .unwrap();
    assert!(applied.is_some());
    let mut tx = fixture.state.pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    assert!(matches!(
        idle(&mut tx, fixture.account.id).await,
        Err(ApiError::Conflict(_))
    ));
    tx.commit().await.unwrap();
    let result = super::super::dns_record_reconcile::reconcile(
        State(fixture.state.clone()),
        fixture.headers.clone(),
        Path((fixture.account.id, operation)),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(result["status"], "blocked");
    assert_eq!(result["dns_written"], false);
    assert_eq!(result["ownership_confirmed"], false);
    assert_eq!(
        history(&fixture, operation).await["error_code"],
        "not_submitted"
    );
    assert!(
        perform(
            &fixture.state,
            &fixture.headers,
            fixture.account.id,
            operation
        )
        .await
        .is_err()
    );
    let mut tx = fixture.state.pool.begin().await.unwrap();
    idle(&mut tx, fixture.account.id).await.unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test]
async fn active_writer_prevents_reconciliation_and_retention_never_removes_uncertain_identity(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let (_, operation) = intent(&fixture).await;
    let mut writer = fixture.state.pool.begin().await.unwrap();
    lock(&mut writer).await.unwrap();
    let result = super::super::dns_record_reconcile::reconcile(
        State(fixture.state.clone()),
        fixture.headers.clone(),
        Path((fixture.account.id, operation)),
    )
    .await;
    assert!(matches!(result, Err(ApiError::Busy)));
    writer.commit().await.unwrap();
    sqlx::query("UPDATE dns_record_history SET occurred_at=-1 WHERE id=$1")
        .bind(operation)
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    for index in 0..260 {
        sqlx::query("INSERT INTO dns_record_history(id,account_id,account_revision,request,status,occurred_at) VALUES($1,$2,1,$3,'blocked',$4)")
            .bind(Uuid::new_v4()).bind(fixture.account.id).bind(json!(tests::request())).bind(i64::from(index))
            .execute(&fixture.state.pool).await.unwrap();
    }
    let mut tx = fixture.state.pool.begin().await.unwrap();
    prune(&mut tx, fixture.account.id).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(history(&fixture, operation).await["status"], "unknown");
    let mut tx = fixture.state.pool.begin().await.unwrap();
    assert!(idle(&mut tx, fixture.account.id).await.is_err());
    tx.commit().await.unwrap();
}

#[sqlx::test]
async fn finalization_rollback_keeps_attempt_marker_and_blocks_replay(pool: sqlx::PgPool) {
    let fixture = fixture(pool).await;
    let (_, operation) = intent(&fixture).await;
    mark_started(&fixture.state.pool, fixture.account.id, operation)
        .await
        .unwrap();
    assert!(
        mark_started(&fixture.state.pool, fixture.account.id, operation)
            .await
            .is_err()
    );
    let mut tx = fixture.state.pool.begin().await.unwrap();
    finish(
        &mut tx,
        fixture.account.id,
        operation,
        Some(json!({"id":"TEST_ONLY_receipt"})),
        "applied",
        None,
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    let entry = history(&fixture, operation).await;
    assert_eq!(entry["status"], "unknown");
    assert!(entry["write_started_at"].as_i64().is_some());
    assert!(entry["observed"].is_null());
    assert!(
        perform(
            &fixture.state,
            &fixture.headers,
            fixture.account.id,
            operation
        )
        .await
        .is_err()
    );
    let mut tx = fixture.state.pool.begin().await.unwrap();
    assert!(idle(&mut tx, fixture.account.id).await.is_err());
    tx.commit().await.unwrap();
}

struct Delayed {
    data: Arc<Mutex<tests::Data>>,
    written: Notify,
    reply: Notify,
}
async fn delayed(
    State(delayed): State<Arc<Delayed>>,
    request: HttpRequest<Body>,
) -> axum::http::Response<Body> {
    let mutation = request.method() != reqwest::Method::GET;
    let response = tests::handle(State(delayed.data.clone()), request).await;
    if mutation {
        delayed.written.notify_one();
        delayed.reply.notified().await;
    }
    response
}

#[sqlx::test]
async fn dropped_caller_after_actual_provider_write_keeps_intent_and_blocks_new_preview_and_rollback(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let (_, operation) = intent(&fixture).await;
    let delayed_state = Arc::new(Delayed {
        data: Arc::new(Mutex::new(tests::Data::default())),
        written: Notify::new(),
        reply: Notify::new(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new()
        .fallback(delayed)
        .with_state(delayed_state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let state = fixture.state.clone();
    let headers = fixture.headers.clone();
    let account_id = fixture.account.id;
    let client = RecordClient::local(super::super::model::Provider::Cloudflare, &endpoint);
    let caller = tokio::spawn(async move {
        perform_with(&state, &headers, account_id, operation, Some(client)).await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        delayed_state.written.notified(),
    )
    .await
    .unwrap();
    let stored = history(&fixture, operation).await;
    assert_eq!(stored["status"], "unknown");
    assert!(stored["write_started_at"].as_i64().is_some());
    assert_eq!(delayed_state.data.lock().unwrap().writes, 1);
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    delayed_state.reply.notify_one();
    let mut tx = fixture.state.pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    for (preview, rollback) in [(Some(Uuid::new_v4()), None), (None, Some(Uuid::new_v4()))] {
        assert!(
            reserve(
                &mut tx,
                &fixture.account,
                &tests::request(),
                Value::Null,
                Origin {
                    administrator: 1,
                    credential_version: 1,
                    preview,
                    rollback
                }
            )
            .await
            .is_err()
        );
    }
    tx.commit().await.unwrap();
    let client = RecordClient::local(super::super::model::Provider::Cloudflare, &endpoint);
    let owner = dns_accounts::zone(&client, &fixture.account, &tests::request().zone_id)
        .await
        .unwrap();
    let (status, observed) = super::super::dns_record_reconcile::observe(
        &client,
        &tests::request(),
        &Value::Null,
        &Value::Null,
        &owner,
    )
    .await
    .unwrap();
    assert_eq!(status, "observed");
    assert_eq!(observed["content"], "TEST_ONLY value");
    assert_eq!(delayed_state.data.lock().unwrap().writes, 1);
    server.abort();
}

#[sqlx::test]
async fn revoked_actor_changed_account_or_rotated_credential_blocks_before_any_provider_request(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let data = Arc::new(Mutex::new(tests::Data::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new()
        .fallback(tests::handle)
        .with_state(data.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    for changed in ["actor", "account", "credential", "proof"] {
        let (_, operation) = intent(&fixture).await;
        match changed {
            "actor" => {
                sqlx::query("UPDATE administrator_profiles SET enabled=false WHERE admin_id=1")
                    .execute(&fixture.state.pool)
                    .await
                    .unwrap();
            }
            "account" => {
                sqlx::query("UPDATE dns_accounts SET revision=2 WHERE id=$1")
                    .bind(fixture.account.id)
                    .execute(&fixture.state.pool)
                    .await
                    .unwrap();
            }
            "credential" => {
                sqlx::query("UPDATE credential_entries SET version=2 WHERE id=$1")
                    .bind(fixture.account.config.credential_id)
                    .execute(&fixture.state.pool)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::query("UPDATE administrator_reauth SET expires_at=0")
                    .execute(&fixture.state.pool)
                    .await
                    .unwrap();
            }
        }
        let result = perform_with(
            &fixture.state,
            &fixture.headers,
            fixture.account.id,
            operation,
            Some(RecordClient::local(
                super::super::model::Provider::Cloudflare,
                &endpoint,
            )),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(result["status"], "blocked", "{changed}");
        assert!(
            history(&fixture, operation).await["write_started_at"].is_null(),
            "{changed}"
        );
        assert_eq!(data.lock().unwrap().writes, 0, "{changed}");
        assert_eq!(data.lock().unwrap().requests, 0, "{changed}");
        sqlx::query("UPDATE administrator_profiles SET enabled=true WHERE admin_id=1")
            .execute(&fixture.state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE dns_accounts SET revision=1 WHERE id=$1")
            .bind(fixture.account.id)
            .execute(&fixture.state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE credential_entries SET version=1 WHERE id=$1")
            .bind(fixture.account.config.credential_id)
            .execute(&fixture.state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE administrator_reauth SET expires_at=$1")
            .bind(sinan_protocol::now_timestamp() + 300)
            .execute(&fixture.state.pool)
            .await
            .unwrap();
    }
    server.abort();
}

#[sqlx::test]
async fn rollback_original_is_consumed_with_the_durable_intent_even_when_no_write_is_sent(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let original = Uuid::new_v4();
    let observed = json!({"id":"00000000000000000000000000000002","name":"_service.example.com","type":"TXT","content":"TEST_ONLY value","ttl":300});
    sqlx::query("INSERT INTO dns_record_history(id,account_id,account_revision,request,previous,observed,status,occurred_at) VALUES($1,$2,1,$3,'null',$4,'applied',0)")
        .bind(original).bind(fixture.account.id).bind(json!(tests::request())).bind(observed)
        .execute(&fixture.state.pool).await.unwrap();
    let result = super::super::dns_record_rollback::rollback(
        State(fixture.state.clone()),
        fixture.headers.clone(),
        Path((fixture.account.id, original)),
        Json(serde_json::from_value(json!({"confirmed":true})).unwrap()),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(result["status"], "blocked");
    let operation = Uuid::parse_str(result["history_id"].as_str().unwrap()).unwrap();
    let stored = history(&fixture, operation).await;
    assert_eq!(stored["rollback_of"], original.to_string());
    assert!(stored["write_started_at"].is_null());
    assert!(
        history(&fixture, original).await["rollback_started_at"]
            .as_i64()
            .is_some()
    );
    assert!(matches!(
        super::super::dns_record_rollback::rollback(
            State(fixture.state.clone()),
            fixture.headers.clone(),
            Path((fixture.account.id, original)),
            Json(serde_json::from_value(json!({"confirmed":true})).unwrap()),
        )
        .await,
        Err(ApiError::NotFound)
    ));
}

#[sqlx::test]
async fn history_requires_both_original_and_current_scope_and_missing_legacy_scope_fails_closed(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let old_server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY original') RETURNING id")
            .fetch_one(&fixture.state.pool)
            .await
            .unwrap();
    let new_server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY current') RETURNING id")
            .fetch_one(&fixture.state.pool)
            .await
            .unwrap();
    let mut old_scope = fixture.account.config.clone();
    old_scope.server_ids = vec![old_server];
    let mut current_scope = fixture.account.config.clone();
    current_scope.server_ids = vec![new_server];
    sqlx::query("UPDATE dns_accounts SET config=$2,revision=2 WHERE id=$1")
        .bind(fixture.account.id)
        .bind(json!(current_scope))
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    let old = Uuid::new_v4();
    let same_scope = Uuid::new_v4();
    let legacy = Uuid::new_v4();
    for (id, snapshot, revision) in [
        (old, Some(json!(old_scope)), 1i64),
        (same_scope, Some(json!(current_scope)), 1),
        (legacy, None, 2),
    ] {
        sqlx::query("INSERT INTO dns_record_history(id,account_id,account_revision,request,previous,observed,status,occurred_at,account_snapshot,write_started_at) VALUES($1,$2,$3,$4,'null',$5,'unknown',0,$6,1)")
            .bind(id).bind(fixture.account.id).bind(revision).bind(json!(tests::request()))
            .bind(json!({"id":"TEST_ONLY_record","content":"TEST_ONLY private TXT"})).bind(snapshot)
            .execute(&fixture.state.pool).await.unwrap();
    }
    let operator: i64 = sqlx::query_scalar(
        "INSERT INTO admins(password_hash) VALUES('TEST_ONLY_not_used') RETURNING id",
    )
    .fetch_one(&fixture.state.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,'TEST_ONLY_dns_operator','测试 DNS 操作员','operator',false,'[\"dns:read\",\"dns:write\"]',0,0)")
        .bind(operator).execute(&fixture.state.pool).await.unwrap();
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(operator)
        .bind(new_server)
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    let hash = crate::auth::hash_token("TEST_ONLY_operator_session");
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
        .bind(&hash)
        .bind(operator)
        .bind(now + 600)
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)",
    )
    .bind(hash)
    .bind(now)
    .bind(now + 300)
    .execute(&fixture.state.pool)
    .await
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "sinan_session=TEST_ONLY_operator_session".parse().unwrap(),
    );
    let visible = super::super::dns_records::history(
        State(fixture.state.clone()),
        headers.clone(),
        Path(fixture.account.id),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0]["id"], same_scope.to_string());
    let result = super::super::dns_record_reconcile::reconcile(
        State(fixture.state.clone()),
        headers.clone(),
        Path((fixture.account.id, old)),
    )
    .await;
    assert!(matches!(result, Err(ApiError::Forbidden(_))));
    sqlx::query("UPDATE dns_record_history SET status='applied' WHERE id=$1")
        .bind(old)
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    assert!(matches!(
        super::super::dns_record_rollback::rollback(
            State(fixture.state.clone()),
            headers.clone(),
            Path((fixture.account.id, old)),
            Json(serde_json::from_value(json!({"confirmed":true})).unwrap()),
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));
    let global = super::super::dns_records::history(
        State(fixture.state.clone()),
        fixture.headers.clone(),
        Path(fixture.account.id),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(global.len(), 3);
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(operator)
        .bind(old_server)
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    let visible = super::super::dns_records::history(
        State(fixture.state.clone()),
        headers.clone(),
        Path(fixture.account.id),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(visible.len(), 2);
    assert!(
        visible
            .iter()
            .all(|entry| entry["id"] != legacy.to_string())
    );
    sqlx::query("DELETE FROM administrator_server_grants WHERE admin_id=$1 AND server_id=$2")
        .bind(operator)
        .bind(new_server)
        .execute(&fixture.state.pool)
        .await
        .unwrap();
    assert!(
        super::super::dns_records::history(
            State(fixture.state.clone()),
            headers,
            Path(fixture.account.id)
        )
        .await
        .is_err()
    );
}

#[sqlx::test]
async fn another_account_cannot_bypass_uncertain_owner_or_record_identity(pool: sqlx::PgPool) {
    let fixture = fixture(pool).await;
    let (_, operation) = intent(&fixture).await;
    mark_started(&fixture.state.pool, fixture.account.id, operation)
        .await
        .unwrap();
    let mut alias = tests::account();
    alias.config.credential_id = fixture.account.config.credential_id;
    sqlx::query(
        "INSERT INTO dns_accounts(id,config,revision,created_at,updated_at) VALUES($1,$2,1,0,0)",
    )
    .bind(alias.id)
    .bind(json!(alias.config))
    .execute(&fixture.state.pool)
    .await
    .unwrap();
    let mut tx = fixture.state.pool.begin().await.unwrap();
    lock(&mut tx).await.unwrap();
    idle(&mut tx, alias.id).await.unwrap();
    assert!(
        reserve(
            &mut tx,
            &alias,
            &tests::request(),
            Value::Null,
            Origin {
                administrator: 1,
                credential_version: 1,
                preview: Some(Uuid::new_v4()),
                rollback: None
            }
        )
        .await
        .is_err()
    );
    let mut other_owner = tests::request();
    other_owner.record["name"] = "_other.example.com".into();
    reserve(
        &mut tx,
        &alias,
        &other_owner,
        Value::Null,
        Origin {
            administrator: 1,
            credential_version: 1,
            preview: Some(Uuid::new_v4()),
            rollback: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[sqlx::test]
async fn repeated_read_only_create_observations_never_become_a_write_receipt_or_clear_the_gate(
    pool: sqlx::PgPool,
) {
    let fixture = fixture(pool).await;
    let (_, operation) = intent(&fixture).await;
    mark_started(&fixture.state.pool, fixture.account.id, operation)
        .await
        .unwrap();
    let observed = json!({"id":"00000000000000000000000000000002","name":"_service.example.com","type":"TXT","content":"TEST_ONLY value","ttl":300});
    let data = Arc::new(Mutex::new(tests::Data {
        record: Some(observed.clone()),
        ..tests::Data::default()
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new()
        .fallback(tests::handle)
        .with_state(data.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = RecordClient::local(super::super::model::Provider::Cloudflare, &endpoint);
    for _ in 0..3 {
        let entry: Intent = sqlx::query_as("SELECT * FROM dns_record_history WHERE id=$1")
            .bind(operation)
            .fetch_one(&fixture.state.pool)
            .await
            .unwrap();
        let receipt = super::super::dns_record_reconcile::provider_receipt(&entry);
        assert!(receipt.is_null());
        let (status, value) = super::super::dns_record_reconcile::observe(
            &client,
            &tests::request(),
            &Value::Null,
            &receipt,
            "example.com",
        )
        .await
        .unwrap();
        assert_eq!(status, "observed");
        sqlx::query("UPDATE dns_record_history SET status=$2,observed=$3 WHERE id=$1")
            .bind(operation)
            .bind(status)
            .bind(value)
            .execute(&fixture.state.pool)
            .await
            .unwrap();
        let mut tx = fixture.state.pool.begin().await.unwrap();
        assert!(idle(&mut tx, fixture.account.id).await.is_err());
        tx.commit().await.unwrap();
    }
    assert_eq!(data.lock().unwrap().writes, 0);
    server.abort();
}
