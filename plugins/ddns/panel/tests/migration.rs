use super::*;
use crate::{auth, config::Config};
use axum::http::header;
use sqlx::PgPool;

async fn fixture(pool: PgPool) -> (AppState, HeaderMap, i64, i64, Vec<Selection>) {
    let state = AppState::new(
        pool.clone(),
        Config {
            database_url: String::new(),
            listen: "127.0.0.1:8080".parse().unwrap(),
            public_url: "http://127.0.0.1:8080".into(),
            data_dir: std::env::temp_dir(),
            admin_password: Some("TEST_ONLY migration password".into()),
        },
    )
    .await
    .unwrap();
    let token = format!("TEST_ONLY_{}", Uuid::new_v4());
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,1,$2)")
        .bind(auth::hash_token(&token))
        .bind(now + 600)
        .execute(&pool)
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("sinan_session={token}").parse().unwrap(),
    );
    let source: i64 = sqlx::query_scalar("INSERT INTO servers(name,last_seen,static_info_received_at) VALUES('TEST_ONLY source',$1,$1) RETURNING id")
        .bind(now).fetch_one(&pool).await.unwrap();
    let target: i64 = sqlx::query_scalar("INSERT INTO servers(name,last_seen,static_info_received_at) VALUES('TEST_ONLY target',$1,$1) RETURNING id")
        .bind(now).fetch_one(&pool).await.unwrap();
    super::super::settings::set_enabled(&pool, source, true)
        .await
        .unwrap();
    super::super::settings::set_enabled(&pool, target, true)
        .await
        .unwrap();
    let mut rules = Vec::new();
    for number in 1..=2 {
        let id = Uuid::new_v4();
        let config = json!({"name":format!("TEST_ONLY rule {number}"),"server_id":source,
            "zone_id":"00000000000000000000000000000001","record_name":format!("node{number}.example.com"),
            "record_type":"A","ttl":300,"proxied":false,"interval_secs":300,"enabled":true});
        sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token) VALUES($1,$2,$3,'TEST_ONLY_TOKEN_VALUE')")
            .bind(id).bind(source).bind(config).execute(&pool).await.unwrap();
        rules.push(Selection {
            id,
            revision: 1,
            config: None,
        });
    }
    (state, headers, source, target, rules)
}

async fn prove(state: &AppState, headers: &HeaderMap) {
    let token = headers[header::COOKIE]
        .to_str()
        .unwrap()
        .strip_prefix("sinan_session=")
        .unwrap();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO administrator_reauth(session_hash,verified_at,expires_at) VALUES($1,$2,$3) ON CONFLICT(session_hash) DO UPDATE SET expires_at=$3")
        .bind(auth::hash_token(token)).bind(now).bind(now+300).execute(&state.pool).await.unwrap();
}

#[sqlx::test]
async fn migration_requires_recent_proof_and_rejects_the_whole_batch_when_a_revision_changes(
    pool: PgPool,
) {
    let (state, headers, source, target, mut rules) = fixture(pool.clone()).await;
    let response = preview(
        State(state.clone()),
        headers.clone(),
        Json(PreviewRequest {
            target_server_id: target,
            rules: rules.clone(),
        }),
    )
    .await
    .unwrap();
    let id: Uuid = response.0["preview_id"].as_str().unwrap().parse().unwrap();
    assert!(
        apply(
            State(state.clone()),
            headers.clone(),
            Json(ApplyRequest {
                preview_id: id,
                confirmed: true
            })
        )
        .await
        .is_err()
    );
    prove(&state, &headers).await;
    sqlx::query("UPDATE ddns_rules SET revision=2 WHERE id=$1")
        .bind(rules[1].id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        apply(
            State(state.clone()),
            headers.clone(),
            Json(ApplyRequest {
                preview_id: id,
                confirmed: true
            })
        )
        .await
        .is_err()
    );
    let bindings: Vec<i64> = sqlx::query_scalar("SELECT server_id FROM ddns_rules")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(bindings.iter().all(|server| *server == source));
    rules[1].revision = 2;
    let response = preview(
        State(state.clone()),
        headers.clone(),
        Json(PreviewRequest {
            target_server_id: target,
            rules,
        }),
    )
    .await
    .unwrap();
    let id: Uuid = response.0["preview_id"].as_str().unwrap().parse().unwrap();
    let result = apply(
        State(state.clone()),
        headers.clone(),
        Json(ApplyRequest {
            preview_id: id,
            confirmed: true,
        }),
    )
    .await
    .unwrap();
    assert_eq!(result.0["dns_written"], false);
    assert_eq!(result.0["agent_identity_copied"], false);
    assert_eq!(result.0["rules"].as_array().unwrap().len(), 2);
    assert!(!result.0.to_string().contains("TEST_ONLY_TOKEN_VALUE"));
    assert!(
        apply(
            State(state),
            headers,
            Json(ApplyRequest {
                preview_id: id,
                confirmed: true
            })
        )
        .await
        .is_err()
    );
    let bindings: Vec<i64> = sqlx::query_scalar("SELECT server_id FROM ddns_rules")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(bindings.iter().all(|server| *server == target));
}

#[sqlx::test]
async fn expired_preview_and_scoped_administrator_cannot_migrate_ungranted_server(pool: PgPool) {
    let (state, headers, source, target, rules) = fixture(pool.clone()).await;
    let response = preview(
        State(state.clone()),
        headers.clone(),
        Json(PreviewRequest {
            target_server_id: target,
            rules: rules.clone(),
        }),
    )
    .await
    .unwrap();
    let id: Uuid = response.0["preview_id"].as_str().unwrap().parse().unwrap();
    prove(&state, &headers).await;
    sqlx::query("UPDATE ddns_migration_previews SET expires_at=0 WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        apply(
            State(state.clone()),
            headers.clone(),
            Json(ApplyRequest {
                preview_id: id,
                confirmed: true
            })
        )
        .await
        .is_err()
    );
    sqlx::query("UPDATE administrator_profiles SET role='operator',all_servers=false,capabilities='[\"dns:write\"]' WHERE admin_id=1").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES(1,$1)")
        .bind(source)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        preview(
            State(state),
            headers,
            Json(PreviewRequest {
                target_server_id: target,
                rules
            })
        )
        .await
        .is_err()
    );
    let bindings: Vec<i64> = sqlx::query_scalar("SELECT server_id FROM ddns_rules")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(bindings.iter().all(|server| *server == source));
}

#[sqlx::test]
async fn domain_batch_edit_resets_record_identity_and_keeps_old_history(pool: PgPool) {
    let (state, headers, _, target, mut selections) = fixture(pool.clone()).await;
    prove(&state, &headers).await;
    for selection in &mut selections {
        let mut config = load(&pool, selection.id).await.unwrap().config;
        config.record_name = config.record_name.replace("example.com", "example.net");
        config.enabled = false;
        selection.config = Some(config);
        sqlx::query("UPDATE ddns_rules SET record_id='TEST_ONLY_previous_record',last_ip='192.0.2.1' WHERE id=$1").bind(selection.id).execute(&pool).await.unwrap();
    }
    let result = preview(
        State(state.clone()),
        headers.clone(),
        Json(PreviewRequest {
            target_server_id: target,
            rules: selections.clone(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(result.0["items"][0]["desired_config"]["enabled"], false);
    let preview_id = result.0["preview_id"].as_str().unwrap().parse().unwrap();
    let _ = apply(
        State(state.clone()),
        headers.clone(),
        Json(ApplyRequest {
            preview_id,
            confirmed: true,
        }),
    )
    .await
    .unwrap();
    for selection in selections {
        let rule = load(&pool, selection.id).await.unwrap();
        assert!(rule.config.record_name.ends_with("example.net"));
        assert!(!rule.config.enabled);
        assert!(rule.record_id.is_none());
        assert!(rule.last_ip.is_none());
        assert_eq!(rule.revision, 2);
    }
}

#[sqlx::test]
async fn changing_dns_provider_without_a_new_credential_reference_is_blocked(pool: PgPool) {
    let (state, headers, _, target, mut selections) = fixture(pool.clone()).await;
    let mut config = load(&pool, selections[0].id).await.unwrap().config;
    config.provider = model::Provider::Tencent;
    config.zone_id = "example.com".into();
    config.line = "0".into();
    selections[0].config = Some(config);
    assert!(
        preview(
            State(state),
            headers,
            Json(PreviewRequest {
                target_server_id: target,
                rules: selections
            })
        )
        .await
        .is_err()
    );
}
