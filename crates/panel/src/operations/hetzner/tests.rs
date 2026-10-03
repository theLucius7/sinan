use super::*;
use crate::{auth::hash_token, config::Config};
use sqlx::PgPool;
use std::path::PathBuf;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn account(pool: &PgPool) -> anyhow::Result<Uuid> {
    sqlx::query("INSERT INTO admins(id,password_hash) VALUES(1,'TEST_ONLY not a login password') ON CONFLICT DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,created_at,updated_at) VALUES(1,'admin','TEST_ONLY owner','owner',true,0,0) ON CONFLICT DO NOTHING")
        .execute(pool).await?;
    let credential = Uuid::new_v4();
    sqlx::query("INSERT INTO credential_entries(id,name,kind,key_id,nonce,ciphertext,created_at,updated_at) VALUES($1,'TEST_ONLY synthetic cloud credential','cloud','TEST_ONLY',$2,$3,0,0)")
        .bind(credential).bind(vec![0u8; 12]).bind(b"TEST_ONLY encrypted-fixture-placeholder".as_slice()).execute(pool).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_hetzner_accounts(id,name,credential_id,created_at,updated_at,updated_by) VALUES($1,'TEST_ONLY account',$2,0,0,1)")
        .bind(id).bind(credential).execute(pool).await?;
    Ok(id)
}

fn server(id: &str, status: &str) -> client::RemoteServer {
    client::RemoteServer {
        cloud_id: id.into(),
        name: format!("TEST_ONLY {id}"),
        snapshot: json!({"status":status,"ipv4":"192.0.2.1"}),
    }
}

async fn record(
    pool: &PgPool,
    account: Uuid,
    inventory: client::Inventory,
) -> anyhow::Result<Value> {
    let refresh = Uuid::new_v4();
    sqlx::query("UPDATE operations_hetzner_accounts SET refresh_id=$2,refresh_started_at=$3,last_attempt_at=$3 WHERE id=$1")
        .bind(account).bind(refresh).bind(now_timestamp()).execute(pool).await?;
    Ok(store::persist(pool, account, refresh, now_timestamp(), &inventory).await?)
}

#[sqlx::test]
async fn partial_inventory_keeps_evidence_and_complete_inventory_alone_confirms_absence(
    pool: PgPool,
) -> anyhow::Result<()> {
    let account = account(&pool).await?;
    let first = record(
        &pool,
        account,
        client::Inventory {
            servers: vec![server("101", "running"), server("102", "off")],
            complete: true,
            pages: 1,
            error_code: None,
        },
    )
    .await?;
    assert_eq!(first["complete"], true);
    let missing: Uuid = sqlx::query_scalar(
        "SELECT id FROM operations_hetzner_resources WHERE account_id=$1 AND cloud_id='102'",
    )
    .bind(account)
    .fetch_one(&pool)
    .await?;
    let linked: i64 = sqlx::query_scalar(
        "INSERT INTO servers(name) VALUES('TEST_ONLY linked cloud server') RETURNING id",
    )
    .fetch_one(&pool)
    .await?;
    sqlx::query("UPDATE operations_hetzner_resources SET last_seen_at=100,verified_at=100,server_id=$2,notes='TEST_ONLY retained link' WHERE id=$1")
        .bind(missing).bind(linked).execute(&pool).await?;
    sqlx::query("UPDATE operations_hetzner_accounts SET last_read_at=100 WHERE id=$1")
        .bind(account)
        .execute(&pool)
        .await?;
    let partial = record(
        &pool,
        account,
        client::Inventory {
            servers: vec![server("101", "off")],
            complete: false,
            pages: 1,
            error_code: Some("http_5xx".into()),
        },
    )
    .await?;
    assert_eq!(partial["last_read_at"], 100);
    let missing_row = sqlx::query("SELECT * FROM operations_hetzner_resources WHERE id=$1")
        .bind(missing)
        .fetch_one(&pool)
        .await?;
    assert_eq!(missing_row.get::<String, _>("presence"), "unknown");
    assert_eq!(missing_row.get::<i64, _>("verified_at"), 100);
    assert_eq!(missing_row.get::<i64, _>("last_seen_at"), 100);
    assert_eq!(missing_row.get::<Value, _>("snapshot")["status"], "off");
    assert_eq!(missing_row.get::<Option<i64>, _>("server_id"), Some(linked));
    let complete = record(
        &pool,
        account,
        client::Inventory {
            servers: vec![server("101", "running")],
            complete: true,
            pages: 1,
            error_code: None,
        },
    )
    .await?;
    assert!(complete["last_read_at"].as_i64().unwrap() > 100);
    let missing_row = sqlx::query("SELECT * FROM operations_hetzner_resources WHERE id=$1")
        .bind(missing)
        .fetch_one(&pool)
        .await?;
    assert_eq!(missing_row.get::<String, _>("presence"), "absent");
    assert!(missing_row.get::<i64, _>("verified_at") > 100);
    assert_eq!(missing_row.get::<i64, _>("last_seen_at"), 100);
    assert_eq!(missing_row.get::<Option<String>, _>("error_code"), None);
    assert_eq!(
        missing_row.get::<String, _>("notes"),
        "TEST_ONLY retained link"
    );
    record(
        &pool,
        account,
        client::Inventory {
            servers: Vec::new(),
            complete: true,
            pages: 1,
            error_code: None,
        },
    )
    .await?;
    let present: i64 = sqlx::query_scalar("SELECT count(*) FROM operations_hetzner_resources WHERE account_id=$1 AND presence<>'absent'")
        .bind(account).fetch_one(&pool).await?;
    assert_eq!(present, 0);
    let stale_refresh = Uuid::new_v4();
    assert!(matches!(
        store::persist(
            &pool,
            account,
            stale_refresh,
            now_timestamp(),
            &client::Inventory {
                servers: vec![server("103", "running")],
                complete: true,
                pages: 1,
                error_code: None,
            }
        )
        .await,
        Err(ApiError::Conflict(_))
    ));
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_hetzner_resources WHERE account_id=$1")
            .bind(account)
            .fetch_one(&pool)
            .await?;
    assert_eq!(total, 2);
    Ok(())
}

#[sqlx::test]
async fn scoped_cloud_access_cannot_take_over_unlinked_or_move_resources_to_ungranted_servers(
    pool: PgPool,
) -> anyhow::Result<()> {
    let account = account(&pool).await?;
    let directory = Directory(
        std::env::temp_dir().join(format!("sinan-hetzner-scope-test-{}", Uuid::new_v4())),
    );
    std::fs::create_dir(&directory.0)?;
    let state = AppState::new(
        pool.clone(),
        Config {
            database_url: String::new(),
            listen: "127.0.0.1:0".parse()?,
            public_url: "http://127.0.0.1".into(),
            data_dir: directory.0.clone(),
            admin_password: None,
        },
    )
    .await?;
    let permitted: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY granted') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let excluded: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY excluded') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let actor: i64 = sqlx::query_scalar(
        "INSERT INTO admins(password_hash) VALUES('TEST_ONLY operator') RETURNING id",
    )
    .fetch_one(&pool)
    .await?;
    sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,'TEST_ONLY_scoped','TEST_ONLY scoped','operator',false,'[\"cloud:read\",\"cloud:write\"]',0,0)")
        .bind(actor).execute(&pool).await?;
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
        .bind(actor)
        .bind(permitted)
        .execute(&pool)
        .await?;
    let session = "TEST_ONLY_hetzner_scope_session";
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
        .bind(hash_token(session))
        .bind(actor)
        .bind(now_timestamp() + 600)
        .execute(&pool)
        .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        format!("sinan_session={session}").parse()?,
    );
    record(
        &pool,
        account,
        client::Inventory {
            servers: vec![
                server("1", "running"),
                server("2", "running"),
                server("3", "running"),
            ],
            complete: true,
            pages: 1,
            error_code: None,
        },
    )
    .await?;
    sqlx::query("UPDATE operations_hetzner_resources SET server_id=CASE cloud_id WHEN '1' THEN $2 WHEN '2' THEN $3 ELSE NULL END WHERE account_id=$1")
        .bind(account).bind(permitted).bind(excluded).execute(&pool).await?;
    let linked: Uuid = sqlx::query_scalar(
        "SELECT id FROM operations_hetzner_resources WHERE account_id=$1 AND cloud_id='1'",
    )
    .bind(account)
    .fetch_one(&pool)
    .await?;
    let unlinked: Uuid = sqlx::query_scalar(
        "SELECT id FROM operations_hetzner_resources WHERE account_id=$1 AND cloud_id='3'",
    )
    .bind(account)
    .fetch_one(&pool)
    .await?;
    let Json(list) = resources(State(state.clone()), headers.clone()).await?;
    assert_eq!(list["resources"].as_array().unwrap().len(), 1);
    assert_eq!(list["resources"][0]["id"], linked.to_string());
    assert!(resource_value(&state, &headers, linked).await.is_ok());
    assert!(matches!(
        resource_value(&state, &headers, unlinked).await,
        Err(ApiError::Forbidden(_))
    ));
    assert!(matches!(
        accounts(State(state.clone()), headers.clone()).await,
        Err(ApiError::Forbidden(_))
    ));
    assert!(matches!(
        link(
            State(state.clone()),
            headers.clone(),
            Path(linked),
            Json(LinkInput {
                server_id: Some(permitted),
                notes: String::new()
            })
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));
    sqlx::query(
        "INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3)",
    )
    .bind(hash_token(session))
    .bind(now_timestamp())
    .bind(now_timestamp() + 300)
    .execute(&pool)
    .await?;
    assert!(matches!(
        link(
            State(state.clone()),
            headers.clone(),
            Path(linked),
            Json(LinkInput {
                server_id: Some(excluded),
                notes: String::new()
            })
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));
    assert!(matches!(
        link(
            State(state.clone()),
            headers.clone(),
            Path(unlinked),
            Json(LinkInput {
                server_id: Some(permitted),
                notes: String::new()
            })
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));
    let unchanged: Option<i64> =
        sqlx::query_scalar("SELECT server_id FROM operations_hetzner_resources WHERE id=$1")
            .bind(linked)
            .fetch_one(&pool)
            .await?;
    assert_eq!(unchanged, Some(permitted));
    let api_token = "sinan_api_TEST_ONLY_hetzner_scope";
    sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'TEST_ONLY scoped token','[\"cloud:read\",\"cloud:write\"]',$3,false,$4,0)")
        .bind(Uuid::new_v4()).bind(hash_token(api_token)).bind(json!([permitted])).bind(now_timestamp()+600).execute(&pool).await?;
    let mut token_headers = HeaderMap::new();
    token_headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {api_token}").parse()?,
    );
    let Json(list) = resources(State(state.clone()), token_headers.clone()).await?;
    assert_eq!(list["resources"].as_array().unwrap().len(), 1);
    assert!(matches!(
        link(
            State(state),
            token_headers,
            Path(linked),
            Json(LinkInput {
                server_id: None,
                notes: String::new()
            })
        )
        .await,
        Err(ApiError::Forbidden(_))
    ));
    Ok(())
}

#[test]
fn credential_requires_provider_and_rejects_header_control_characters() {
    assert!(
        token(&json!({"provider":"hetzner","api_token":"TEST_ONLY_opaque_api_token"})).is_some()
    );
    assert!(
        token(&json!({"provider":"alicloud","api_token":"TEST_ONLY_opaque_api_token"})).is_none()
    );
    assert!(token(&json!({"provider":"hetzner","api_token":"TEST_ONLY_opaque_api_token\r\nInjected: true"})).is_none());
    assert_eq!(provider()["remote_writes"], false);
    assert_eq!(provider()["billing"], false);
}
