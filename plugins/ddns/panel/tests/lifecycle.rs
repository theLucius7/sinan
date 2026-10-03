use super::{
    provider::{Mock, record},
    *,
};
use crate::plugins::ddns::{history, lifecycle, model::AddressSource, worker};

#[test]
fn manual_sources_do_not_depend_on_agent_freshness_but_keep_lifecycle_guards() {
    let mut config = config();
    config.address_source = AddressSource::Manual;
    config.manual_ip = Some(public_ip(8).to_string());
    config.normalize().unwrap();
    let mut info = Observation {
        name: "TEST_ONLY manual".into(),
        static_info: Value::Null,
        static_info_received_at: None,
        last_seen: None,
        deleted_at: None,
        retiring: false,
        plugin_enabled: true,
    };
    assert_eq!(info.select(&config, None, 10000), Ok(public_ip(8)));
    config.record_type = "AAAA".into();
    assert!(config.normalize().is_err());
    config.record_type = "A".into();
    for invalid in ["127.0.0.1", "192.0.2.1", "10.0.0.1", "invalid"] {
        config.manual_ip = Some(invalid.into());
        assert!(config.normalize().is_err());
    }
    config.manual_ip = Some(public_ip(8).to_string());
    info.retiring = true;
    assert_eq!(info.select(&config, None, 10000), Err("server_retired"));
    info.retiring = false;
    info.plugin_enabled = false;
    assert_eq!(info.select(&config, None, 10000), Err("plugin_disabled"));
}

#[tokio::test]
async fn provider_preview_never_writes_and_rollback_refuses_modified_remote_record() {
    let mock = Mock::start().await;
    let mut rule = rule();
    rule.config.adopt_existing = true;
    mock.data.lock().unwrap().records.push(record());
    let snapshot = mock.client.inspect(&rule).await.unwrap().unwrap();
    assert_eq!(snapshot.values, ["192.0.2.10"]);
    assert_eq!(mock.writes(), 0);
    mock.data.lock().unwrap().records[0]["ttl"] = 600.into();
    let error = mock
        .client
        .reconcile_expected_guarded(
            &rule,
            "192.0.2.11".parse().unwrap(),
            Some(&snapshot),
            || async { Ok(()) },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "remote_changed");
    assert_eq!(mock.writes(), 0);
    let changed = mock.client.inspect(&rule).await.unwrap().unwrap();
    assert!(lifecycle::expected_matches(Some(&changed), Some(&snapshot)).is_err());
    assert!(lifecycle::expected_matches(None, Some(&snapshot)).is_err());
}

#[tokio::test]
async fn guarded_value_restore_preserves_external_comment_and_records_exact_snapshots() {
    let mock = Mock::start().await;
    let mut rule = rule();
    rule.config.adopt_existing = true;
    mock.data.lock().unwrap().records.push(record());
    let before = mock.client.inspect(&rule).await.unwrap().unwrap();
    let written = mock
        .client
        .reconcile_expected_guarded(
            &rule,
            "192.0.2.11".parse().unwrap(),
            Some(&before),
            || async { Ok(()) },
        )
        .await
        .unwrap();
    let after = history::observed(
        &rule,
        "192.0.2.11".parse().unwrap(),
        &written,
        Some(&before),
    );
    assert_eq!(after.marker, before.marker);
    assert_eq!(
        mock.client.inspect(&rule).await.unwrap(),
        Some(after.clone())
    );
    mock.client
        .reconcile_expected_guarded(
            &rule,
            "192.0.2.10".parse().unwrap(),
            Some(&after),
            || async { Ok(()) },
        )
        .await
        .unwrap();
    assert_eq!(mock.client.inspect(&rule).await.unwrap(), Some(before));
    assert_eq!(mock.writes(), 2);
}

#[sqlx::test]
async fn history_completion_is_atomic_bounded_redacted_and_survives_rule_removal(
    pool: sqlx::PgPool,
) {
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY history') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut rule = rule();
    rule.config.server_id = server;
    let lease = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ddns_rules(id,server_id,config,api_token,lease_id) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(rule.id)
    .bind(server)
    .bind(json!(rule.config))
    .bind(TOKEN)
    .bind(lease)
    .execute(&pool)
    .await
    .unwrap();
    worker::complete(&pool, &rule, lease, Err("network_error".into()))
        .await
        .unwrap();
    let entries = history::list(&pool, rule.id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].error_code.as_deref(), Some("network_error"));
    assert!(!serde_json::to_string(&entries).unwrap().contains(TOKEN));
    worker::complete(&pool, &rule, lease, Err("network_error".into()))
        .await
        .unwrap();
    assert_eq!(history::list(&pool, rule.id).await.unwrap().len(), 1);
    for index in 0..260 {
        let mut tx = pool.begin().await.unwrap();
        history::append(
            &mut tx,
            history::Entry {
                id: Uuid::new_v4(),
                rule_id: rule.id,
                server_id: rule.config.server_id,
                revision: 1,
                operation: "check".into(),
                desired_ip: None,
                previous: None,
                observed: None,
                status: "checked".into(),
                error_code: None,
                occurred_at: 1000 + index,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(history::list(&pool, rule.id).await.unwrap().len(), 256);
    sqlx::query("DELETE FROM ddns_rules WHERE id=$1")
        .bind(rule.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(history::list(&pool, rule.id).await.unwrap().len(), 256);
}

#[sqlx::test]
async fn rollback_rechecks_provider_and_pauses_automatic_reconciliation(pool: sqlx::PgPool) {
    use crate::plugins::ddns::{load, rollback, settings};
    let now = sinan_protocol::now_timestamp();
    let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,static_info,last_seen,static_info_received_at) VALUES('TEST_ONLY rollback',$1,$2,$2) RETURNING id")
        .bind(json!({"ip_addresses":[public_ip(9)]})).bind(now).fetch_one(&pool).await.unwrap();
    settings::set_enabled(&pool, server, true).await.unwrap();
    let mut rule = rule();
    rule.config.server_id = server;
    rule.config.adopt_existing = true;
    sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token) VALUES($1,$2,$3,$4)")
        .bind(rule.id)
        .bind(server)
        .bind(json!(rule.config))
        .bind(TOKEN)
        .execute(&pool)
        .await
        .unwrap();
    let mock = Mock::start().await;
    let mut original = record();
    original["content"] = public_ip(1).to_string().into();
    mock.data.lock().unwrap().records.push(original);
    worker::sync_with(&pool, rule.id, false, &mock.client)
        .await
        .unwrap();
    let entries = history::list(&pool, rule.id).await.unwrap();
    assert_eq!(
        entries[0].previous.as_ref().unwrap().values,
        [public_ip(1).to_string()]
    );
    let result = rollback::rollback_with(
        &pool,
        rule.id,
        rollback::Request {
            revision: 1,
            history_id: entries[0].id,
            confirmed: true,
        },
        &mock.client,
    )
    .await
    .unwrap();
    assert_eq!(result["status"], "rolled_back");
    assert_eq!(
        mock.data.lock().unwrap().records[0]["content"],
        public_ip(1).to_string()
    );
    assert!(!load(&pool, rule.id).await.unwrap().config.enabled);
    worker::sync_with(&pool, rule.id, false, &mock.client)
        .await
        .unwrap();
    assert_eq!(mock.writes(), 2);
    // An external writer changes the record; retrying the historical rollback must stop.
    mock.data.lock().unwrap().records[0]["content"] = public_ip(8).to_string().into();
    let row = load(&pool, rule.id).await.unwrap();
    let result = rollback::rollback_with(
        &pool,
        rule.id,
        rollback::Request {
            revision: row.revision,
            history_id: entries[0].id,
            confirmed: true,
        },
        &mock.client,
    )
    .await
    .unwrap();
    assert_eq!(result["error_code"], "remote_changed");
    assert_eq!(mock.writes(), 2);
    assert_eq!(
        mock.data.lock().unwrap().records[0]["content"],
        public_ip(8).to_string()
    );
}

#[test]
fn credential_payloads_validate_provider_and_never_serialize_secret_fields() {
    use crate::plugins::ddns::{credentials, model::Provider};
    let mut rule = rule();
    rule.config.credential_id = Some(Uuid::new_v4());
    credentials::populate(
        &mut rule,
        &json!({"provider":"cloudflare","api_token":TOKEN}),
    )
    .unwrap();
    assert_eq!(rule.api_token, TOKEN);
    assert!(!serde_json::to_string(&rule).unwrap().contains(TOKEN));
    assert!(
        credentials::populate(&mut rule, &json!({"provider":"aliyun","api_token":TOKEN})).is_err()
    );
    rule.config.provider = Provider::Aliyun;
    credentials::populate(&mut rule, &json!({"provider":"aliyun","access_key_id":"TEST_ONLY_KEY_ID","access_key_secret":"TEST_ONLY_KEY_SECRET"})).unwrap();
    let encoded = serde_json::to_string(&rule).unwrap();
    assert!(!encoded.contains("TEST_ONLY_KEY_ID") && !encoded.contains("TEST_ONLY_KEY_SECRET"));
    assert!(rule.api_token.is_empty());
    assert!(credentials::populate(&mut rule, &json!({"access_key_id":"short"})).is_err());
}

#[sqlx::test]
async fn unavailable_credential_reference_stops_before_provider_io_instead_of_using_legacy_secret(
    pool: sqlx::PgPool,
) {
    use crate::plugins::ddns::{load, settings};
    let now = sinan_protocol::now_timestamp();
    let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,static_info,last_seen,static_info_received_at) VALUES('TEST_ONLY credential failure',$1,$2,$2) RETURNING id")
        .bind(json!({"ip_addresses":[public_ip(9)]})).bind(now).fetch_one(&pool).await.unwrap();
    settings::set_enabled(&pool, server, true).await.unwrap();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO credential_entries(id,name,kind,key_id,nonce,ciphertext,created_at,updated_at) VALUES($1,'TEST_ONLY missing key','dns',$2,$3,$4,$5,$5)")
        .bind(id).bind(format!("TEST_ONLY_MISSING_{}", Uuid::new_v4())).bind(vec![0u8;12]).bind(vec![0u8;32]).bind(now)
        .execute(&pool).await.unwrap();
    let mut rule = rule();
    rule.config.server_id = server;
    rule.config.credential_id = Some(id);
    sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token) VALUES($1,$2,$3,$4)")
        .bind(rule.id)
        .bind(server)
        .bind(json!(rule.config))
        .bind(TOKEN)
        .execute(&pool)
        .await
        .unwrap();
    let mock = Mock::start().await;
    worker::sync_with(&pool, rule.id, false, &mock.client)
        .await
        .unwrap();
    assert!(mock.data.lock().unwrap().requests.is_empty());
    assert_eq!(
        load(&pool, rule.id).await.unwrap().error_code.as_deref(),
        Some("credential_unavailable")
    );
    assert_eq!(
        history::list(&pool, rule.id).await.unwrap()[0]
            .error_code
            .as_deref(),
        Some("credential_unavailable")
    );
}

#[test]
fn interface_and_discovery_sources_do_not_fall_back_to_merged_or_manual_addresses() {
    let now = 10000;
    let info = Observation {
        name: "TEST_ONLY provenance".into(),
        static_info: json!({"ip_addresses":[public_ip(1)],"interface_addresses":{"wan0":[public_ip(8)],"lan0":["10.0.0.1"]},"discovered_public_ips":[public_ip(9)]}),
        static_info_received_at: Some(now),
        last_seen: Some(now),
        deleted_at: None,
        retiring: false,
        plugin_enabled: true,
    };
    let mut config = config();
    config.address_source = AddressSource::Interface;
    config.interface_name = Some("wan0".into());
    config.normalize().unwrap();
    assert_eq!(info.select(&config, None, now), Ok(public_ip(8)));
    config.interface_name = Some("lan0".into());
    assert_eq!(info.select(&config, None, now), Err("no_public_ip"));
    config.interface_name = Some("missing".into());
    assert_eq!(info.select(&config, None, now), Err("source_unavailable"));
    config.address_source = AddressSource::Discovered;
    config.normalize().unwrap();
    assert_eq!(info.select(&config, None, now), Ok(public_ip(9)));
    let mut old = info;
    old.static_info = json!({"ip_addresses":[public_ip(1)]});
    assert_eq!(old.select(&config, None, now), Err("source_unavailable"));
}
