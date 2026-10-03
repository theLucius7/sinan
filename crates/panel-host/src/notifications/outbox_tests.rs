use super::*;
use crate::notifications::{events, lock_settings};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[sqlx::test(migrations = "../panel/migrations")]
async fn retry_delay_starts_after_delivery_finishes_instead_of_the_maintenance_tick(
    pool: PgPool,
) -> anyhow::Result<()> {
    use std::sync::atomic::AtomicI64;
    let settings = Settings {
        telegram_enabled: true,
        telegram_chat_id: "-100000".into(),
        telegram_token: "123:TEST_ONLY_SECRET_00000000000".into(),
        ..Default::default()
    };
    sqlx::query("UPDATE panel_settings SET settings=$1")
        .bind(serde_json::to_value(&settings)?)
        .execute(&pool)
        .await?;
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('retry time fixture') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let event: i64 = sqlx::query_scalar("INSERT INTO server_alert_events(server_id,server_name,opened_at) VALUES($1,'fixture',1) RETURNING id")
        .bind(server).fetch_one(&pool).await?;
    let mut tx = pool.begin().await?;
    events::enqueue(&mut tx, &settings, event, "offline", 100).await?;
    tx.commit().await?;
    let timestamp = Arc::new(AtomicI64::new(100));
    let clock = {
        let timestamp = timestamp.clone();
        move || timestamp.load(Ordering::SeqCst)
    };
    dispatch_with_clock(
        &pool,
        |_, _, _| {
            let timestamp = timestamp.clone();
            async move {
                timestamp.store(108, Ordering::SeqCst);
                Err(telegram::Failure {
                    message: "limited".into(),
                    retry_after: Some(123),
                })
            }
        },
        clock,
    )
    .await?;
    let row: (i64, i64, i32) =
        sqlx::query_as("SELECT last_attempt_at,next_attempt_at,attempts FROM notification_outbox")
            .fetch_one(&pool)
            .await?;
    assert_eq!(row, (100, 231, 1));
    Ok(())
}
#[sqlx::test(migrations = "../panel/migrations")]
async fn outbox_retries_in_order_and_concurrent_workers_do_not_duplicate(
    pool: PgPool,
) -> anyhow::Result<()> {
    let config = Settings {
        telegram_enabled: true,
        telegram_chat_id: "-100000".into(),
        telegram_token: "123:TEST_ONLY_SECRET_00000000000".into(),
        ..Default::default()
    };
    sqlx::query("UPDATE panel_settings SET settings=$1")
        .bind(serde_json::to_value(config)?)
        .execute(&pool)
        .await?;
    let id: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('outbox fixture') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let event: i64 = sqlx::query_scalar("INSERT INTO server_alert_events(server_id,server_name,last_seen,opened_at,resolved_at,resolution) VALUES($1,'outbox fixture',0,1,2,'recovered') RETURNING id").bind(id).fetch_one(&pool).await?;
    let mut tx = pool.begin().await?;
    let settings = lock_settings(&mut tx).await?;
    events::enqueue(&mut tx, &settings, event, "offline", 100).await?;
    events::enqueue(&mut tx, &settings, event, "recovery", 100).await?;
    tx.commit().await?;
    dispatch_with(&pool, 100, |_, _, _| async {
        Err(telegram::Failure {
            message: "temporary failure".into(),
            retry_after: Some(123),
        })
    })
    .await?;
    let rows: Vec<(String, i32, i64)> = sqlx::query_as(
        "SELECT status,attempts,next_attempt_at FROM notification_outbox ORDER BY id",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        rows,
        vec![("pending".into(), 1, 223), ("pending".into(), 0, 100)]
    );
    let count = Arc::new(AtomicUsize::new(0));
    let send = |_: Settings, _: String, _: String| {
        let count = count.clone();
        async move {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok(())
        }
    };
    let (a, b) = tokio::join!(
        dispatch_with(&pool, 223, send),
        dispatch_with(&pool, 223, send)
    );
    a?;
    b?;
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status FROM notification_outbox ORDER BY id")
            .fetch_all(&pool)
            .await?;
    assert_eq!(statuses, vec!["sent", "sent"]);
    dispatch_with(&pool, 500, send).await?;
    assert_eq!(count.load(Ordering::SeqCst), 2);
    Ok(())
}
#[sqlx::test(migrations = "../panel/migrations")]
async fn channels_retry_independently_and_stop_after_the_bounded_attempts(
    pool: PgPool,
) -> anyhow::Result<()> {
    let config = Settings {
        telegram_enabled: true,
        telegram_chat_id: "-100000".into(),
        telegram_token: "123:TEST_ONLY_SECRET_00000000000".into(),
        webhook: Some(webhook::Config {
            enabled: true,
            preset: webhook::Preset::Custom,
            url: "https://example.invalid/notify".into(),
            headers: String::new(),
            body: webhook::DEFAULT_BODY.into(),
        }),
        ..Default::default()
    };
    sqlx::query("UPDATE panel_settings SET settings=$1")
        .bind(serde_json::to_value(&config)?)
        .execute(&pool)
        .await?;
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('channel fixture') RETURNING id")
            .fetch_one(&pool)
            .await?;
    let event: i64 = sqlx::query_scalar("INSERT INTO server_alert_events(server_id,server_name,opened_at) VALUES($1,'channel fixture',1) RETURNING id").bind(server).fetch_one(&pool).await?;
    let mut tx = pool.begin().await?;
    events::enqueue(&mut tx, &config, event, "offline", 100).await?;
    events::enqueue(&mut tx, &config, event, "recovery", 100).await?;
    tx.commit().await?;
    let telegram = Arc::new(AtomicUsize::new(0));
    let webhook = Arc::new(AtomicUsize::new(0));
    dispatch_with(&pool, 100, |_, channel, _| {
        let telegram = telegram.clone();
        let webhook = webhook.clone();
        async move {
            if channel == "telegram" {
                telegram.fetch_add(1, Ordering::SeqCst);
                Err(telegram::Failure {
                    message: "temporary failure".into(),
                    retry_after: Some(123),
                })
            } else {
                webhook.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    })
    .await?;
    assert_eq!(telegram.load(Ordering::SeqCst), 1);
    assert_eq!(webhook.load(Ordering::SeqCst), 2);
    dispatch_with(&pool, 223, |_, channel, _| {
        let telegram = telegram.clone();
        let webhook = webhook.clone();
        async move {
            if channel == "telegram" {
                telegram.fetch_add(1, Ordering::SeqCst);
            } else {
                webhook.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    })
    .await?;
    assert_eq!(telegram.load(Ordering::SeqCst), 3);
    assert_eq!(webhook.load(Ordering::SeqCst), 2);
    sqlx::query("UPDATE notification_outbox SET status='pending',attempts=7,next_attempt_at=300 WHERE channel='telegram' AND kind='offline'").execute(&pool).await?;
    dispatch_with(&pool, 300, |_, _, _| async {
        Err(telegram::Failure {
            message: "failed".into(),
            retry_after: None,
        })
    })
    .await?;
    let row: (String,i32,Option<i64>,Option<i64>) = sqlx::query_as("SELECT status,attempts,last_attempt_at,delivered_at FROM notification_outbox WHERE channel='telegram' AND kind='offline'").fetch_one(&pool).await?;
    assert_eq!(row, ("failed".into(), 8, Some(300), None));
    dispatch_with(&pool, 10000, |_, _, _| async {
        panic!("exhausted or successful notifications must not be retried")
    })
    .await?;
    Ok(())
}
