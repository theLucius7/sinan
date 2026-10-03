use super::*;
use crate::ip_quality::{QueryErrorKind, query_all};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use reqwest::Client;
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::task::JoinHandle;

struct Source {
    origin: String,
    mode: Arc<AtomicUsize>,
    client: Client,
    task: JoinHandle<()>,
}

impl Source {
    async fn start() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let mode = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/{ip}",
                get(
                    |State(mode): State<Arc<AtomicUsize>>,
                     Query(query): Query<BTreeMap<String, String>>| async move {
                        match mode.load(Ordering::SeqCst) {
                            1 => (StatusCode::FORBIDDEN, "fixture denied").into_response(),
                            2 => (StatusCode::TOO_MANY_REQUESTS, "fixture limited").into_response(),
                            3 => {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                Json(json!({})).into_response()
                            }
                            4 if query.get("db").is_none_or(|database| database != "ipapi") => {
                                (StatusCode::FORBIDDEN, "fixture partial").into_response()
                            }
                            5 => Json(json!({"success":false,"fraud_score":0,"proxy":false}))
                                .into_response(),
                            6 => Json(Value::Null).into_response(),
                            7 => Json(json!({})).into_response(),
                            8 => Json(json!({
                                "ASN":{"AutonomousSystemNumber":false},
                                "company":{"abuser_score":true},
                                "scamalytics":{"scamalytics_score":false},
                                "data":{"abuseConfidenceScore":false},
                                "fraud_score":" ","proxy":0,"is_proxy":"false",
                                "threat":{"is_proxy":null}
                            }))
                            .into_response(),
                            9 => Json(json!({"errors":[{"detail":"fixture denied"}],"data":{"abuseConfidenceScore":0},"fraud_score":0,"proxy":false}))
                                .into_response(),
                            13 if query.get("db").is_some_and(|database| database == "abuseipdb") => {
                                Json(json!({"errors":[{"detail":"fixture denied"}],"data":{"abuseConfidenceScore":0}}))
                                    .into_response()
                            }
                            mode => Json(json!({
                                "ASN":{"AutonomousSystemNumber":64500},
                                "company":{"abuser_score":if mode==4 {7} else {0}},
                                "scamalytics":{"scamalytics_score":0},
                                "data":match mode {
                                    10 => json!({"success":false,"abuseConfidenceScore":0}),
                                    11 => json!({"errors":[{"detail":"fixture unavailable"}],"abuseConfidenceScore":0}),
                                    12 => json!({"abuseConfidenceScore":73}),
                                    _ => json!({"abuseConfidenceScore":0}),
                                },
                                "fraud_score":0,"proxy":false,"is_proxy":false,
                                "threat":{"is_proxy":false}
                            }))
                            .into_response(),
                        }
                    },
                ),
            )
            .with_state(mode.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        Ok(Self {
            origin,
            mode,
            client,
            task,
        })
    }

    async fn query(&self, ips: &[String], at: i64) -> Vec<IpQuality> {
        let timeout_client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let client = if self.mode.load(Ordering::SeqCst) == 3 {
            &timeout_client
        } else {
            &self.client
        };
        let mut values = query_all(client, &self.origin, ips, true).await;
        // Fix only the clock to make persistence ordering and expiry deterministic.
        for entry in &mut values {
            entry.checked_at = at;
            entry.last_attempt_at = Some(at);
            for dataset in &mut entry.databases {
                dataset.attempted_at = Some(at);
                dataset.last_success_at = (dataset.status == "succeeded").then_some(at);
                dataset.fresh_until = dataset.last_success_at.map(|at| at + CACHE_SECS);
            }
        }
        values
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO servers(name,static_info) VALUES('cache fixture',$1) RETURNING id",
    )
    .bind(json!({"ip_addresses":["192.0.2.1"]}))
    .fetch_one(pool)
    .await?)
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn success_survives_real_403_429_timeout_and_a_new_pool(pool: PgPool) -> Result<()> {
    let id = server(&pool).await?;
    let source = Source::start().await?;
    let ips = ["192.0.2.1".into()];
    let at = now_timestamp() - 120;
    persist(&pool, id, &source.query(&ips, at).await).await?;
    let initial = read(&pool, id, &ips).await?.remove(0);
    assert_eq!(initial.status, "succeeded");
    assert_eq!(initial.last_success_at, Some(at));
    assert_eq!(initial.fresh_until, Some(at + CACHE_SECS));
    assert!(initial.databases.iter().all(|dataset| !dataset.historical));
    for (mode, kind) in [
        (1, QueryErrorKind::Http403),
        (2, QueryErrorKind::Http429),
        (3, QueryErrorKind::Timeout),
    ] {
        source.mode.store(mode, Ordering::SeqCst);
        persist(&pool, id, &source.query(&ips, at + mode as i64).await).await?;
        let reopened = PgPool::connect_with((*pool.connect_options()).clone()).await?;
        let failed = read(&reopened, id, &ips).await?.remove(0);
        reopened.close().await;
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.last_attempt_at, Some(at + mode as i64));
        assert_eq!(failed.last_success_at, Some(at));
        assert_eq!(failed.fresh_until, initial.fresh_until);
        assert_eq!(failed.expires_at, initial.expires_at);
        for (dataset, before) in failed.databases.iter().zip(&initial.databases) {
            assert_eq!(dataset.status, "failed");
            assert_eq!(dataset.error_kind, Some(kind));
            assert_eq!(dataset.last_error.as_ref().unwrap().kind, Some(kind));
            assert_eq!(encode(&dataset.fields)?, encode(&before.fields)?);
            assert_eq!(dataset.last_success_at, before.last_success_at);
            assert_eq!(dataset.fresh_until, before.fresh_until);
            assert!(dataset.historical);
        }
    }
    assert_eq!(initial.databases[6].fields[0].value, json!(0));
    assert_eq!(initial.databases[6].fields[1].value, json!(false));
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn partial_datasets_providers_and_old_ips_remain_independent(pool: PgPool) -> Result<()> {
    let id = server(&pool).await?;
    let source = Source::start().await?;
    let ips = ["192.0.2.1".into(), "2001:db8::1".into()];
    let at = now_timestamp() - 120;
    let initial = source.query(&ips, at).await;
    persist(&pool, id, &initial).await?;
    let mut other = initial[0].clone();
    other.provider = "provider-fixture".into();
    other.databases[0].fields[0].value = json!(64501);
    persist(&pool, id, &[other]).await?;
    source.mode.store(4, Ordering::SeqCst);
    persist(&pool, id, &source.query(&ips[..1], at + 10).await).await?;
    let mixed = read(&pool, id, &ips).await?;
    assert_eq!(mixed.len(), 3);
    let current = mixed
        .iter()
        .find(|entry| entry.ip == ips[0] && entry.provider == "check-place")
        .unwrap();
    assert_eq!(current.status, "partial");
    assert_eq!(current.databases[1].status, "succeeded");
    assert_eq!(current.databases[1].last_success_at, Some(at + 10));
    assert_eq!(current.databases[1].fields[0].value, json!(7));
    assert!(!current.databases[1].historical);
    assert!(
        current
            .databases
            .iter()
            .enumerate()
            .all(|(index, dataset)| index == 1
                || (dataset.historical && dataset.last_success_at == Some(at)))
    );
    let alternate = mixed
        .iter()
        .find(|entry| entry.provider == "provider-fixture")
        .unwrap();
    assert_eq!(alternate.last_attempt_at, Some(at));
    assert_eq!(alternate.databases[0].fields[0].value, json!(64501));
    let ipv6 = mixed.iter().find(|entry| entry.ip == ips[1]).unwrap();
    assert_eq!(ipv6.last_attempt_at, Some(at));
    source.mode.store(0, Ordering::SeqCst);
    let new_ips = ["192.0.2.2".into()];
    persist(&pool, id, &source.query(&new_ips, at + 20).await).await?;
    assert_eq!(read(&pool, id, &new_ips).await?.len(), 1);
    assert_eq!(read(&pool, id, &ips).await?.len(), 3);
    // A delayed earlier result must not replace the later partial attempt.
    persist(&pool, id, &initial).await?;
    let after = read(&pool, id, &ips[..1]).await?;
    assert_eq!(
        after
            .iter()
            .find(|entry| entry.provider == "check-place")
            .unwrap()
            .status,
        "partial"
    );
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn migration_preserves_old_payload_success_and_unknown_times(pool: PgPool) -> Result<()> {
    sqlx::raw_sql(include_str!(
        "../../../../panel/migrations/0001_initial.sql"
    ))
    .execute(&pool)
    .await?;
    sqlx::raw_sql(include_str!(
        "../../../../panel/migrations/0003_node_quality.sql"
    ))
    .execute(&pool)
    .await?;
    let id = server(&pool).await?;
    let old = json!({"ip":"192.0.2.1","checked_at":1000,"expires_at":2000,"status":"partial","databases":[
        {"database":"ipqualityscore","label":"old success","status":"succeeded","fields":[{"label":"risk","value":0},{"label":"proxy","value":false}],"error":null},
        {"database":"ipapi","label":"old error","status":"failed","fields":[],"error":"old failure"}
    ]});
    sqlx::query("INSERT INTO server_ip_quality(server_id,ip,payload,checked_at) VALUES($1,'192.0.2.1',$2,1000)").bind(id).bind(&old).execute(&pool).await?;
    sqlx::raw_sql(include_str!(
        "../../../../panel/migrations/0008_ip_provider_cache.sql"
    ))
    .execute(&pool)
    .await?;
    let unchanged: Value =
        sqlx::query_scalar("SELECT payload FROM server_ip_quality WHERE server_id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(unchanged, old);
    let migrated = read(&pool, id, &["192.0.2.1".into()]).await?.remove(0);
    assert_eq!(migrated.last_success_at, Some(1000));
    assert_eq!(migrated.last_attempt_at, Some(1000));
    assert_eq!(migrated.fresh_until, None);
    assert_eq!(migrated.databases[0].fields[0].value, json!(0));
    assert_eq!(migrated.databases[0].fields[1].value, json!(false));
    assert!(migrated.databases[0].historical);
    assert_eq!(migrated.databases[0].last_attempt_at, None);
    assert_eq!(migrated.databases[0].fresh_until, Some(2000));
    assert!(migrated.databases[1].fields.is_empty());
    assert_eq!(migrated.databases[1].last_success_at, None);
    assert_eq!(
        migrated.databases[1].last_error.as_ref().unwrap().kind,
        None
    );
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn concurrent_admission_and_an_interrupted_refresh_use_durable_locks(
    pool: PgPool,
) -> Result<()> {
    let id = server(&pool).await?;
    let now = now_timestamp();
    let (first, second) =
        tokio::join!(begin_refresh(&pool, id, now), begin_refresh(&pool, id, now));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(
        first.as_ref().err().or(second.as_ref().err()),
        Some(ApiError::Conflict(_))
    ));
    // Simulate process exit without clearing the persisted admission lease.
    let reopened = PgPool::connect_with((*pool.connect_options()).clone()).await?;
    assert!(matches!(
        begin_refresh(&reopened, id, now + 60).await,
        Err(ApiError::Conflict(_))
    ));
    begin_refresh(&reopened, id, now + 61).await?;
    let cleared = sqlx::query("UPDATE servers SET quality_refresh_started=NULL WHERE id=$1 AND quality_refresh_started=$2").bind(id).bind(now).execute(&pool).await?;
    assert_eq!(cleared.rows_affected(), 0);
    sqlx::query("UPDATE servers SET quality_refresh_started=NULL WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await?;
    let mut failed = query_all(
        &Client::new(),
        "http://source.invalid",
        &["192.0.2.1".into()],
        false,
    )
    .await;
    failed[0].checked_at = now + 61;
    failed[0].last_attempt_at = Some(now + 61);
    for dataset in &mut failed[0].databases {
        dataset.attempted_at = Some(now + 61);
    }
    persist(&pool, id, &failed).await?;
    assert!(matches!(
        begin_refresh(&reopened, id, now + 62).await,
        Err(ApiError::Conflict(_))
    ));
    begin_refresh(&reopened, id, now + 122).await?;
    reopened.close().await;
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn a_deleted_server_cannot_replace_its_durable_cache(pool: PgPool) -> Result<()> {
    let id = server(&pool).await?;
    let source = Source::start().await?;
    let ips = ["192.0.2.1".into()];
    let at = now_timestamp();
    persist(&pool, id, &source.query(&ips, at).await).await?;
    sqlx::query("UPDATE servers SET deleted_at=$2 WHERE id=$1")
        .bind(id)
        .bind(at)
        .execute(&pool)
        .await?;
    source.mode.store(1, Ordering::SeqCst);
    assert!(matches!(
        persist(&pool, id, &source.query(&ips, at + 1).await).await,
        Err(ApiError::NotFound)
    ));
    assert_eq!(read(&pool, id, &ips).await?[0].status, "succeeded");
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn a_waiting_batch_keeps_real_attempt_times_and_never_invents_a_first_attempt(
    pool: PgPool,
) -> Result<()> {
    let id = server(&pool).await?;
    let source = Source::start().await?;
    let ips = ["192.0.2.1".into()];
    let at = now_timestamp() - 120;
    let initial = source.query(&ips, at).await;
    persist(&pool, id, &initial).await?;
    let mut waiting = initial[0].clone();
    waiting.checked_at = at + 10;
    waiting.last_attempt_at = None;
    waiting.status = "failed".into();
    for dataset in &mut waiting.databases {
        dataset.status = "failed".into();
        dataset.fields.clear();
        dataset.error = Some("fixture request never started".into());
        dataset.error_kind = Some(QueryErrorKind::NotAttempted);
        dataset.attempted_at = None;
        dataset.last_attempt_at = None;
        dataset.elapsed_ms = None;
        dataset.last_success_at = None;
        dataset.fresh_until = None;
    }
    persist(&pool, id, &[waiting.clone()]).await?;
    let saved = read(&pool, id, &ips).await?.remove(0);
    assert_eq!(saved.checked_at, at + 10);
    assert_eq!(saved.last_attempt_at, Some(at));
    assert_eq!(saved.last_success_at, Some(at));
    assert!(saved.databases.iter().all(|dataset| {
        dataset.attempted_at.is_none()
            && dataset.last_attempt_at == Some(at)
            && dataset.historical
            && !dataset.fields.is_empty()
    }));

    waiting.ip = "192.0.2.2".into();
    for dataset in &mut waiting.databases {
        dataset.target_ip = Some(waiting.ip.clone());
    }
    persist(&pool, id, &[waiting]).await?;
    let unknown = read(&pool, id, &["192.0.2.2".into()]).await?.remove(0);
    assert_eq!(unknown.last_attempt_at, None);
    assert_eq!(unknown.last_success_at, None);
    assert!(
        unknown
            .databases
            .iter()
            .all(|dataset| { dataset.last_attempt_at.is_none() && dataset.fields.is_empty() })
    );
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn uncertain_payloads_never_replace_valid_zero_false_or_become_current_success(
    pool: PgPool,
) -> Result<()> {
    let id = server(&pool).await?;
    let source = Source::start().await?;
    let ips = ["192.0.2.1".into()];
    let at = now_timestamp() - 120;
    persist(&pool, id, &source.query(&ips, at).await).await?;
    let initial = read(&pool, id, &ips).await?.remove(0);
    for (index, mode) in [5, 6, 7, 8, 9, 1, 2, 3].into_iter().enumerate() {
        source.mode.store(mode, Ordering::SeqCst);
        let queried = source.query(&ips, at + index as i64 + 20).await;
        assert_eq!(queried[0].status, "failed");
        assert!(
            queried[0]
                .databases
                .iter()
                .all(|database| database.fields.is_empty())
        );
        persist(&pool, id, &queried).await?;
        let reopened = PgPool::connect_with((*pool.connect_options()).clone()).await?;
        let history = read(&reopened, id, &ips).await?.remove(0);
        reopened.close().await;
        assert_eq!(history.last_success_at, initial.last_success_at);
        assert_eq!(history.fresh_until, initial.fresh_until);
        assert!(
            history
                .databases
                .iter()
                .all(|database| database.status == "failed" && database.historical)
        );
        assert_eq!(history.databases[6].fields[0].value, json!(0));
        assert_eq!(history.databases[6].fields[1].value, json!(false));
    }
    let fresh_ips = ["192.0.2.2".into()];
    for (index, mode) in [5, 6, 7, 8, 9].into_iter().enumerate() {
        source.mode.store(mode, Ordering::SeqCst);
        persist(
            &pool,
            id,
            &source.query(&fresh_ips, at + 100 + index as i64).await,
        )
        .await?;
        let unknown = read(&pool, id, &fresh_ips).await?.remove(0);
        assert_eq!(unknown.last_success_at, None);
        assert!(
            unknown
                .databases
                .iter()
                .all(|database| database.fields.is_empty()
                    && !database.historical
                    && database.last_success_at.is_none())
        );
    }
    // Old parser snapshots are kept on disk but invalid field types are not presented as facts.
    let invalid = json!({"database":"ipqualityscore","label":"old","status":"succeeded","fields":[
        {"label":"欺诈评分（上游原值）","value":false},
        {"label":"代理","value":0},{"label":"旧空白","value":" "},{"label":"旧null","value":null}
    ],"error":null});
    sqlx::query("UPDATE server_ip_quality_datasets SET success_payload=$2 WHERE server_id=$1 AND database='ipqualityscore'")
        .bind(id).bind(&invalid).execute(&pool).await?;
    let unknown = read(&pool, id, &ips).await?.remove(0);
    assert!(unknown.databases[6].fields.is_empty());
    assert!(!unknown.databases[6].historical);
    let untouched:Value=sqlx::query_scalar("SELECT success_payload FROM server_ip_quality_datasets WHERE server_id=$1 AND database='ipqualityscore'").bind(id).fetch_one(&pool).await?;
    assert_eq!(untouched, invalid);
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn failed_abuseipdb_envelope_preserves_history_without_hiding_other_views(
    pool: PgPool,
) -> Result<()> {
    let id = server(&pool).await?;
    let source = Source::start().await?;
    let ips = ["192.0.2.1".into()];
    let at = now_timestamp() - 120;
    source.mode.store(12, Ordering::SeqCst);
    persist(&pool, id, &source.query(&ips, at).await).await?;
    let initial = read(&pool, id, &ips).await?.remove(0);
    let saved = &initial.databases[3];
    assert_eq!(saved.database, "abuseipdb");
    assert_eq!(saved.fields[0].value, json!(73));
    for (index, mode) in [13, 10, 11].into_iter().enumerate() {
        source.mode.store(mode, Ordering::SeqCst);
        let queried = source.query(&ips, at + index as i64 + 20).await;
        assert_eq!(queried[0].status, "partial");
        assert_eq!(queried[0].databases[3].status, "failed");
        assert_eq!(
            queried[0].databases[3].error_kind,
            Some(QueryErrorKind::SchemaMismatch)
        );
        assert!(queried[0].databases[3].fields.is_empty());
        persist(&pool, id, &queried).await?;
        let reopened = PgPool::connect_with((*pool.connect_options()).clone()).await?;
        let history = read(&reopened, id, &ips).await?.remove(0);
        reopened.close().await;
        let failed = &history.databases[3];
        assert_eq!(failed.status, "failed");
        assert!(failed.historical);
        assert_eq!(failed.fields[0].value, json!(73));
        assert_eq!(failed.last_success_at, saved.last_success_at);
        assert_eq!(failed.fresh_until, saved.fresh_until);
        assert_eq!(
            failed.last_error.as_ref().unwrap().kind,
            Some(QueryErrorKind::SchemaMismatch)
        );
        assert!(history.databases.iter().enumerate().all(|(i, dataset)| {
            i == 3 || (dataset.status == "succeeded" && !dataset.historical)
        }));
        let unknown_ips = ["192.0.2.2".into()];
        persist(
            &pool,
            id,
            &source.query(&unknown_ips, at + index as i64 + 30).await,
        )
        .await?;
        let unknown = read(&pool, id, &unknown_ips).await?.remove(0);
        assert!(unknown.databases[3].fields.is_empty());
        assert_eq!(unknown.databases[3].last_success_at, None);
        assert!(!unknown.databases[3].historical);
    }
    Ok(())
}
