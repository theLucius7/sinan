use super::*;
use serde_json::{Value, json};

fn snapshot() -> fetch::FetchedRates {
    fetch::FetchedRates {
        rates: BTreeMap::from([
            ("CNY".into(), 1.0),
            ("USD".into(), 0.2),
            ("EUR".into(), 0.15),
        ]),
        dates: BTreeMap::from([
            ("USD".into(), "2026-10-01".into()),
            ("EUR".into(), "2026-10-01".into()),
        ]),
        source: "frankfurter",
    }
}

fn now() -> i64 {
    fetch::date_day("2026-10-02").unwrap() * DAY
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn cache_starts_unknown_and_failed_refresh_preserves_the_real_snapshot(
    pool: PgPool,
) -> anyhow::Result<()> {
    let now = now();
    let view = current_at(&pool, now).await?;
    assert_eq!(view.status, "unavailable");
    assert_eq!(view.rates, BTreeMap::from([("CNY".into(), 1.0)]));
    assert!(view.fetched_at.is_none());
    let lease = claim(&pool, now, false).await?.unwrap();
    complete(&pool, lease, now, Ok(snapshot())).await?;
    let fresh = current_at(&pool, now).await?;
    assert_eq!(fresh.status, "fresh");
    assert_eq!(fresh.next_refresh_at, now + DAY);
    assert!(claim(&pool, now + 60, false).await?.is_none());
    let lease = claim(&pool, now + DAY, false).await?.unwrap();
    complete(&pool, lease, now + DAY, Err("download_failed")).await?;
    let stale = current_at(&pool, now + DAY).await?;
    assert_eq!(stale.status, "stale");
    assert_eq!(stale.fetched_at, Some(now));
    assert_eq!(stale.rates, fresh.rates);
    assert_eq!(stale.next_refresh_at, now + DAY + 3600);
    assert_eq!(stale.error_code.as_deref(), Some("download_failed"));
    assert!(claim(&pool, now + DAY + 3599, false).await?.is_none());
    assert!(claim(&pool, now + DAY + 3600, false).await?.is_some());
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn concurrent_and_restarted_workers_cannot_publish_a_superseded_fetch(
    pool: PgPool,
) -> anyhow::Result<()> {
    let now = now();
    let (one, two) = tokio::join!(claim(&pool, now, true), claim(&pool, now, true));
    let one = one?;
    let two = two?;
    assert_ne!(one.is_some(), two.is_some());
    let old = one.or(two).unwrap();
    assert!(claim(&pool, now + 29, true).await?.is_none());
    // A crashed request leaves a persisted retry delay for ordinary workers.
    assert!(claim(&pool, now + 31, false).await?.is_none());
    let new = claim(&pool, now + 3600, false).await?.unwrap();
    complete(&pool, old, now + 3601, Ok(snapshot())).await?;
    assert_eq!(current_at(&pool, now + 3601).await?.status, "unavailable");
    complete(&pool, new, now + 3602, Ok(snapshot())).await?;
    complete(&pool, old, now + 3603, Err("download_failed")).await?;
    let view = current_at(&pool, now + 3603).await?;
    assert_eq!(view.status, "fresh");
    assert_eq!(view.fetched_at, Some(now + 3602));
    assert!(view.error_code.is_none());
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn manual_refresh_is_throttled_and_background_reads_do_not_download(
    pool: PgPool,
) -> anyhow::Result<()> {
    refresh_with(&pool, true, || async { Ok(snapshot()) }).await?;
    refresh_with(&pool, false, || async {
        panic!("fresh cache must not download")
    })
    .await?;
    assert!(matches!(
        refresh_with(&pool, true, || async {
            panic!("throttled request must not download")
        })
        .await,
        Err(ApiError::Busy)
    ));
    let value = serde_json::to_value(current(&pool).await?)?;
    for key in ["lease_id", "lease_until", "authorization", "url"] {
        assert!(value.get(key).is_none());
    }
    assert_eq!(value["source_url"], "https://frankfurter.dev/");
    Ok(())
}

#[sqlx::test(migrations = "../panel/migrations")]
async fn wall_clock_rollback_never_labels_future_fetches_or_dates_as_fresh(
    pool: PgPool,
) -> anyhow::Result<()> {
    let now = now();
    let lease = claim(&pool, now, false).await?.unwrap();
    complete(&pool, lease, now, Ok(snapshot())).await?;
    let rolled_back = current_at(&pool, now - 1).await?;
    assert_eq!(rolled_back.status, "stale");
    assert_eq!(rolled_back.fetched_at, Some(now));
    assert_eq!(rolled_back.rates["USD"], 0.2);
    sqlx::query("UPDATE exchange_rates SET fetched_at=$1,rate_date='2026-10-03' WHERE singleton")
        .bind(now)
        .execute(&pool)
        .await?;
    assert_eq!(current_at(&pool, now).await?.status, "stale");
    Ok(())
}

#[test]
fn rates_use_a_coherent_base_real_dates_and_no_invented_currency_defaults() {
    let value = json!([
        {"date":"2026-09-30","base":"CNY","quote":"USD","rate":0.2},
        {"date":"2026-10-01","base":"CNY","quote":"EUR","rate":0.15},
    ]);
    let result = fetch::parse(&value, now(), true).unwrap();
    assert_eq!(result.rates.len(), 3);
    assert_eq!(result.rates["CNY"], 1.0);
    assert!(!result.rates.contains_key("GBP"));
    assert_eq!(result.dates["USD"], "2026-09-30");
    for (key, bad) in [
        ("base", json!("USD")),
        ("quote", json!("US")),
        ("quote", json!("usd")),
        ("rate", json!(0)),
        ("rate", json!(-1)),
        ("rate", json!("0.2")),
        ("date", json!("2026-02-30")),
        ("date", json!("2026-10-03")),
        ("date", json!("2025-10-01")),
    ] {
        let mut invalid = value.clone();
        invalid[0][key] = bad;
        assert!(fetch::parse(&invalid, now(), true).is_err(), "{key}");
    }
    let mut duplicate = value.clone();
    duplicate.as_array_mut().unwrap().push(value[0].clone());
    assert!(fetch::parse(&duplicate, now(), true).is_err());
    assert_eq!(fetch::date_day("1970-01-01"), Some(0));
    assert_eq!(
        fetch::date_day("2000-03-01").unwrap() - fetch::date_day("2000-02-28").unwrap(),
        2
    );
    assert_eq!(
        fetch::date_day("2100-03-01").unwrap() - fetch::date_day("2100-02-28").unwrap(),
        1
    );
    let legacy =
        json!({"amount":1,"base":"CNY","date":"2026-10-01","rates":{"USD":0.2,"EUR":0.15}});
    assert_eq!(
        fetch::parse(&legacy, now(), false).unwrap().source,
        "frankfurter-ecb"
    );
    let mut invalid = legacy;
    invalid["amount"] = Value::from(2);
    assert!(fetch::parse(&invalid, now(), false).is_err());
}
