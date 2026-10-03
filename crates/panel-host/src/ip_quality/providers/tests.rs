use super::*;
use crate::ip_quality::{CACHE_SECS, cache, queries::query_sources};
use anyhow::Result;
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;
#[path = "fixture.rs"]
mod fixture;
use fixture::{FIXTURE_KEY, Source, official_body};

#[test]
fn registry_has_real_origins_and_credentials_never_enter_descriptions() {
    for key in [None, Some(""), Some(" "), Some("bad\nkey"), Some("bad key")] {
        let registry = ProviderRegistry::configured(key);
        let descriptions = registry.descriptions();
        assert_eq!(descriptions.len(), 5);
        assert_eq!(descriptions[0].provider, "check-place");
        assert_eq!(descriptions[0].kind, "aggregator");
        assert_eq!(descriptions[0].databases.len(), 7);
        assert_eq!(registry.enabled().count(), 1);
        assert!(!descriptions[1].enabled);
        assert!(descriptions[1].reason.is_some());
        assert!(!descriptions[2].enabled);
        assert_eq!(descriptions[2].execution, "node");
        assert_eq!(descriptions[3].provider, "ipregistry-node");
        assert_eq!(descriptions[4].provider, "dbip-node");
        for description in &descriptions[3..] {
            assert!(!description.enabled);
            assert_eq!(description.execution, "node");
            assert_eq!(description.databases.len(), 1);
        }
    }
    let registry = ProviderRegistry::configured(Some(FIXTURE_KEY));
    assert_eq!(registry.enabled().count(), 2);
    assert!(registry.descriptions()[1].enabled);
    assert!(
        !serde_json::to_string(&registry.descriptions())
            .unwrap()
            .contains(FIXTURE_KEY)
    );
    let Some(Adapter::AbuseIpDb { key, .. }) = registry.providers[1].adapter.as_ref() else {
        panic!("official adapter")
    };
    assert!(key.is_sensitive());
    assert_eq!(key.to_str().unwrap(), FIXTURE_KEY);
}

#[test]
fn node_sources_are_described_by_actual_entrypoint_without_becoming_panel_queries() {
    let registry = ProviderRegistry::configured(Some(FIXTURE_KEY));
    assert_eq!(registry.enabled().count(), 2);
    assert!(
        registry
            .enabled()
            .all(|provider| provider.execution == "panel")
    );
    let prepared = node_descriptions(true, None);
    let aggregator = prepared
        .iter()
        .find(|provider| provider.provider == "ipquality-node/check-place-aggregator")
        .unwrap();
    assert_eq!(aggregator.databases.len(), 7);
    assert!(aggregator.enabled);
    assert!(
        prepared
            .iter()
            .all(|provider| provider.execution == "node" && provider.kind == "node_self")
    );
    for provider in prepared.iter().filter(|provider| {
        provider.provider.ends_with("-not-configured") || provider.provider.ends_with("-disabled")
    }) {
        assert!(!provider.enabled);
        assert!(provider.reason.is_some());
    }
    let unavailable = node_descriptions(false, Some("TEST_ONLY missing signed artifact"));
    assert!(unavailable.iter().all(|provider| !provider.enabled));
    assert!(
        !serde_json::to_string(&prepared)
            .unwrap()
            .contains(FIXTURE_KEY)
    );
}

#[test]
fn official_response_requires_identity_and_preserves_only_documented_fields() {
    let ip = "2001:db8::1";
    let mut body = official_body(ip);
    body["data"]["ipAddress"] = json!("2001:db8:0:0:0:0:0:1");
    let fields = official_fields(&body, ip).unwrap();
    assert_eq!(fields.len(), 5);
    assert_eq!(
        fields
            .iter()
            .find(|field| field.label == "Tor")
            .unwrap()
            .value,
        json!(false)
    );
    assert_eq!(fields.last().unwrap().value, json!(0));
    for changed in [
        json!(null),
        json!({}),
        json!({"data":{}}),
        json!({"errors":[{"detail":"fixture"}],"data":body["data"]}),
        json!({"success":false,"data":body["data"]}),
    ] {
        assert_eq!(
            official_fields(&changed, ip).unwrap_err().kind,
            QueryErrorKind::SchemaMismatch
        );
    }
    for (field, value) in [
        ("ipAddress", json!("192.0.2.1")),
        ("isPublic", json!(false)),
        ("isPublic", json!(null)),
        ("ipVersion", json!(4)),
        ("ipVersion", json!("6")),
        ("success", json!(false)),
    ] {
        let mut changed = body.clone();
        changed["data"][field] = value;
        assert!(official_fields(&changed, ip).is_err(), "{field}");
    }
    for value in [
        json!(null),
        json!(false),
        json!("0"),
        json!(-1),
        json!(101),
        json!(0.5),
    ] {
        let mut changed = body.clone();
        changed["data"]["abuseConfidenceScore"] = value;
        changed["data"]["isTor"] = json!(null);
        let fields = official_fields(&changed, ip).unwrap();
        assert!(
            !fields
                .iter()
                .any(|field| field.label.starts_with("滥用置信度") || field.label == "Tor")
        );
    }
    let fields = official_fields(
        &json!({"data":{"ipAddress":ip,"isPublic":true,"ipVersion":6,"abuseConfidenceScore":0}}),
        ip,
    )
    .unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].value, json!(0));
}

#[test]
fn official_response_accepts_empty_errors_and_rejects_failed_envelope_markers() {
    let ip = "192.0.2.1";
    for empty in [json!(null), json!([]), json!({})] {
        let mut body = official_body(ip);
        body["errors"] = empty.clone();
        body["data"]["errors"] = empty;
        let fields = official_fields(&body, ip).unwrap();
        assert_eq!(fields.last().unwrap().value, json!(0));
    }
    for errors in [
        json!([{"detail":"fixture denied"}]),
        json!({"detail":"fixture denied"}),
        json!("false"),
        json!(false),
    ] {
        for nested in [false, true] {
            let mut body = official_body(ip);
            if nested {
                body["data"]["errors"] = errors.clone();
            } else {
                body["errors"] = errors.clone();
            }
            assert_eq!(
                official_fields(&body, ip).unwrap_err().kind,
                QueryErrorKind::SchemaMismatch
            );
        }
    }
    for (field, value) in [
        ("success", json!(null)),
        ("success", json!("true")),
        ("status", json!("pending")),
        ("error", json!("fixture unavailable")),
    ] {
        let mut body = official_body(ip);
        body["data"][field] = value;
        assert_eq!(
            official_fields(&body, ip).unwrap_err().kind,
            QueryErrorKind::SchemaMismatch
        );
    }
}

async fn query(source: &Source, configured: bool, ips: &[String], at: i64) -> Vec<IpQuality> {
    let mut values = query_sources(
        &source.client(),
        &source.registry(configured),
        ips,
        true,
        Duration::from_secs(4),
    )
    .await;
    for entry in &mut values {
        entry.checked_at = at;
        entry.last_attempt_at = Some(at);
        for data in &mut entry.databases {
            data.attempted_at = Some(at);
            data.last_success_at = (data.status == "succeeded").then_some(at);
            data.fresh_until = data.last_success_at.map(|at| at + CACHE_SECS);
        }
    }
    values
}

#[tokio::test]
async fn official_requests_use_fixed_read_only_contract_and_disabled_sources_send_nothing() {
    let source = Source::start().await;
    let ips = vec!["192.0.2.1".into(), "2001:db8::1".into()];
    let values = query(&source, true, &ips, 1).await;
    assert_eq!(values.len(), 4);
    assert!(values.iter().all(|value| value.status == "succeeded"));
    assert_eq!(source.observations().len(), 16);
    let observations = source.observations();
    let official: Vec<_> = observations
        .iter()
        .filter(|request| request.path == "/api/v2/check")
        .collect();
    assert_eq!(official.len(), 2);
    for request in official {
        assert_eq!(request.method, reqwest::Method::GET);
        assert_eq!(request.query.len(), 2);
        assert!(!request.raw_query.contains(FIXTURE_KEY));
        if request.query["ipAddress"].contains(':') {
            assert!(request.raw_query.contains("%3A"));
        }
        assert_eq!(request.query["maxAgeInDays"], "30");
        assert!(ips.contains(&request.query["ipAddress"]));
        assert_eq!(request.headers["key"], FIXTURE_KEY);
        assert_eq!(request.headers["accept"], "application/json");
        assert!(!request.headers.contains_key("user-agent"));
    }
    for request in observations
        .iter()
        .filter(|request| request.path != "/api/v2/check")
    {
        assert!(!request.headers.contains_key("key"));
        assert!(!request.headers.contains_key("user-agent"));
    }
    assert!(
        !serde_json::to_string(&values)
            .unwrap()
            .contains(FIXTURE_KEY)
    );
    let before = source.observations().len();
    let disabled = query(&source, false, &ips, 2).await;
    assert_eq!(disabled.len(), 2);
    assert!(disabled.iter().all(|value| value.provider == "check-place"));
    let after = source.observations();
    assert_eq!(after.len() - before, 14);
    assert!(
        after[before..]
            .iter()
            .all(|request| request.path != "/api/v2/check")
    );
    let before = after.len();
    let local = vec!["127.0.0.1".into(), "10.0.0.1".into()];
    let rejected = query(&source, true, &local, 3).await;
    assert_eq!(source.observations().len(), before);
    assert!(
        rejected
            .iter()
            .flat_map(|value| &value.databases)
            .all(|entry| entry.error_kind == Some(QueryErrorKind::NotPublic))
    );
}

#[tokio::test]
async fn all_origins_share_one_deadline_without_retries_or_redirects() {
    let source = Source::start().await;
    let ips = vec!["192.0.2.1".into()];
    for (mode, kind) in [
        (1, QueryErrorKind::Http403),
        (2, QueryErrorKind::Http429),
        (3, QueryErrorKind::Timeout),
        (4, QueryErrorKind::NonJson),
        (5, QueryErrorKind::SchemaMismatch),
        (6, QueryErrorKind::SchemaMismatch),
        (7, QueryErrorKind::HttpOther),
        (8, QueryErrorKind::ResponseLimit),
        (9, QueryErrorKind::SchemaMismatch),
    ] {
        source.mode(mode);
        let before = source.observations().len();
        let values = query(&source, true, &ips, mode as i64).await;
        let official = values
            .iter()
            .find(|value| value.provider == "abuseipdb-api")
            .unwrap();
        assert_eq!(official.databases[0].error_kind, Some(kind), "mode {mode}");
        assert!(official.databases[0].fields.is_empty());
        assert_eq!(
            source.observations().len() - before,
            8,
            "requests cannot retry or follow redirects"
        );
    }
    source.aggregate_mode(2);
    source.mode(3);
    let before = source.observations().len();
    let started = std::time::Instant::now();
    let values = query_sources(
        &source.client(),
        &source.registry(true),
        &ips,
        true,
        Duration::from_millis(25),
    )
    .await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(source.observations().len() - before <= 4);
    let official = values
        .iter()
        .find(|value| value.provider == "abuseipdb-api")
        .unwrap();
    assert_eq!(
        official.databases[0].error_kind,
        Some(QueryErrorKind::NotAttempted)
    );
    assert_eq!(official.databases[0].attempted_at, None);
    assert_eq!(official.databases[0].elapsed_ms, None);
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn official_cache_is_independent_and_disabled_history_survives_restart(
    pool: PgPool,
) -> Result<()> {
    let source = Source::start().await;
    let ips = vec!["192.0.2.1".into(), "2001:db8::1".into()];
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO servers(name,static_info) VALUES('provider fixture',$1) RETURNING id",
    )
    .bind(json!({"ip_addresses":ips}))
    .fetch_one(&pool)
    .await?;
    let at = sinan_protocol::now_timestamp() - 360;
    cache::persist(&pool, id, &query(&source, true, &ips, at).await).await?;
    let initial = cache::read(&pool, id, &ips).await?;
    assert_eq!(initial.len(), 4);
    for (mode, kind) in [
        (1, QueryErrorKind::Http403),
        (2, QueryErrorKind::Http429),
        (3, QueryErrorKind::Timeout),
        (4, QueryErrorKind::NonJson),
        (5, QueryErrorKind::SchemaMismatch),
        (6, QueryErrorKind::SchemaMismatch),
    ] {
        source.mode(mode);
        cache::persist(
            &pool,
            id,
            &query(&source, true, &ips, at + mode as i64).await,
        )
        .await?;
        let read = cache::read(&pool, id, &ips).await?;
        for entry in &read {
            if entry.provider == "check-place" {
                assert!(
                    entry
                        .databases
                        .iter()
                        .all(|data| data.status == "succeeded")
                );
                continue;
            }
            let before = initial
                .iter()
                .find(|before| before.ip == entry.ip && before.provider == entry.provider)
                .unwrap();
            assert_eq!(entry.status, "failed");
            assert_eq!(entry.databases[0].error_kind, Some(kind));
            assert_eq!(
                serde_json::to_value(&entry.databases[0].fields)?,
                serde_json::to_value(&before.databases[0].fields)?
            );
            assert_eq!(entry.last_success_at, Some(at));
            assert_eq!(entry.fresh_until, before.fresh_until);
            assert!(entry.databases[0].historical);
        }
    }
    source.mode(0);
    source.aggregate_mode(1);
    cache::persist(&pool, id, &query(&source, true, &ips, at + 10).await).await?;
    let read = cache::read(&pool, id, &ips).await?;
    for entry in read {
        assert_eq!(
            entry.status,
            if entry.provider == "check-place" {
                "failed"
            } else {
                "succeeded"
            }
        );
    }
    source.aggregate_mode(0);
    cache::persist(&pool, id, &query(&source, false, &ips[..1], at + 20).await).await?;
    let reopened = PgPoolOptions::new()
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let mut history = cache::read(&reopened, id, &ips).await?;
    reopened.close().await;
    source.registry(false).mark_availability(&mut history);
    assert_eq!(history.len(), 4);
    for entry in &history {
        for data in &entry.databases {
            if entry.provider == "abuseipdb-api" {
                assert_eq!(data.available, Some(false));
                assert!(data.historical);
                assert!(data.unavailable_reason.as_ref().unwrap().contains("未配置"));
                assert_eq!(data.last_attempt_at, Some(at + 10));
                assert_eq!(data.last_success_at, Some(at + 10));
                assert_eq!(data.fields.last().unwrap().value, json!(0));
            } else {
                assert_eq!(data.available, Some(true));
            }
        }
    }
    let (first, second) = tokio::join!(
        cache::begin_refresh(&pool, id, at + 120),
        cache::begin_refresh(&pool, id, at + 120)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(first.is_ok() || matches!(first, Err(crate::error::ApiError::Conflict(_))));
    assert!(second.is_ok() || matches!(second, Err(crate::error::ApiError::Conflict(_))));
    Ok(())
}
