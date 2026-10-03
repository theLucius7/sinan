use super::{
    aggregate::{HistoryPoint, combine},
    persistence::{self, DAY_MS, RAW_MS, REPLAY_MS},
    *,
};
use sqlx::PgPool;
use std::time::Duration;

pub async fn maintain(pool: &PgPool) -> ApiResult<()> {
    maintain_at(pool, now_millis(), Duration::from_secs(2)).await
}

pub async fn maintain_at(pool: &PgPool, now: i64, budget: Duration) -> ApiResult<()> {
    // Separate budgets keep old bootstrap/rollup work from starving expiry.
    for phase in 0..3 {
        let work = async {
            let retention = storage::read_policy(pool).await?.history_retention_days;
            match phase {
                0 => cleanup(pool, now, retention).await,
                1 => compact(pool, now, retention).await,
                _ => bootstrap(pool).await,
            }
        };
        if let Ok(result) = tokio::time::timeout(budget / 3, work).await {
            result?;
        }
    }
    Ok(())
}

async fn bounded_transaction(pool: &PgPool) -> ApiResult<sqlx::Transaction<'_, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='1500ms'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn bootstrap(pool: &PgPool) -> ApiResult<()> {
    // Each pass is bounded and uses the same server lock order as ingestion.
    for _ in 0..8 {
        let mut tx = bounded_transaction(pool).await?;
        let server: Option<i64> = sqlx::query_scalar("SELECT id FROM servers WHERE NOT EXISTS(SELECT 1 FROM telemetry_history_initialized h WHERE h.server_id=servers.id) ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED")
            .fetch_optional(&mut *tx)
            .await?;
        let Some(server) = server else { break };
        persistence::initialized(&mut tx, server).await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn compact(pool: &PgPool, now: i64, retention: i32) -> ApiResult<()> {
    let cutoff = now - i64::from(retention) * DAY_MS;
    for (source, target, age) in [
        (300_i32, 3600_i32, 30 * DAY_MS),
        (60, 300, REPLAY_MS + 60_000),
    ] {
        let interval = i64::from(target) * 1000;
        let end = (now - age).div_euclid(interval) * interval;
        let rows=sqlx::query("SELECT server_id,(bucket_at/$3)*$3 AS target FROM telemetry_history WHERE resolution_secs=$1 AND bucket_at<$2 AND bucket_at>=$4 GROUP BY server_id,target ORDER BY target LIMIT 64").bind(source).bind(end).bind(interval).bind(cutoff.div_euclid(interval)*interval).fetch_all(pool).await?;
        for row in rows {
            let server: i64 = row.get("server_id");
            let bucket: i64 = row.get("target");
            let mut tx = bounded_transaction(pool).await?;
            if sqlx::query("SELECT id FROM servers WHERE id=$1 FOR UPDATE SKIP LOCKED")
                .bind(server)
                .fetch_optional(&mut *tx)
                .await?
                .is_none()
            {
                continue;
            }
            let values:Vec<serde_json::Value>=sqlx::query_scalar("SELECT summary FROM telemetry_history WHERE server_id=$1 AND resolution_secs=$2 AND bucket_at>=$3 AND bucket_at<$4 ORDER BY bucket_at").bind(server).bind(source).bind(bucket).bind(bucket+interval).fetch_all(&mut *tx).await?;
            let points = values
                .into_iter()
                .map(serde_json::from_value::<HistoryPoint>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::from)?;
            for point in combine(points, interval) {
                persistence::merge(&mut tx, server, target, point).await?;
            }
            sqlx::query("DELETE FROM telemetry_history WHERE server_id=$1 AND resolution_secs=$2 AND bucket_at>=$3 AND bucket_at<$4").bind(server).bind(source).bind(bucket).bind(bucket+interval).execute(&mut *tx).await?;
            tx.commit().await?;
        }
    }
    Ok(())
}

async fn cleanup(pool: &PgPool, now: i64, retention: i32) -> ApiResult<()> {
    let cutoff = now - i64::from(retention) * DAY_MS;
    let targets = [
        (
            "telemetry_samples",
            "sampled_at",
            (now - RAW_MS).div_euclid(60_000) * 60_000,
            true,
        ),
        (
            "telemetry_receipts",
            "sampled_at",
            now - REPLAY_MS - 60_000,
            false,
        ),
        (
            "telemetry_history",
            "bucket_at",
            cutoff.div_euclid(3_600_000) * 3_600_000,
            false,
        ),
        ("metrics_minutely", "bucket", now / 1000 - 7 * 86400, true),
    ];
    let mut done = [false; 4];
    for _ in 0..10 {
        for (index, (table, column, limit, protect)) in targets.iter().enumerate() {
            if done[index] {
                continue;
            }
            let initialized = if *protect {
                format!(
                    " AND EXISTS(SELECT 1 FROM telemetry_history_initialized i WHERE i.server_id={table}.server_id)"
                )
            } else {
                String::new()
            };
            let statement = format!(
                "DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE {column}<$1{initialized} ORDER BY {column} LIMIT 2000 FOR UPDATE SKIP LOCKED)"
            );
            let mut tx = bounded_transaction(pool).await?;
            done[index] = sqlx::query(&statement)
                .bind(limit)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                < 2000;
            tx.commit().await?;
            tokio::task::yield_now().await;
        }
        if done.iter().all(|done| *done) {
            break;
        }
    }
    Ok(())
}
