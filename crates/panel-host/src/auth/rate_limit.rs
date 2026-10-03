use crate::error::{ApiError, ApiResult};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Row};
use std::net::{IpAddr, SocketAddr};

pub(crate) async fn consume(pool: &PgPool, peer: SocketAddr) -> ApiResult<()> {
    let ip = match peer.ip() {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    };
    let scope = format!("peer:{ip}");
    let mut tx = pool.begin().await?;
    let global = sqlx::query(
        "SELECT window_start, attempts FROM auth_rate_limits WHERE scope = 'global' FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let now = now_timestamp();
    sqlx::query("DELETE FROM auth_rate_limits WHERE scope <> 'global' AND window_start <= $1")
        .bind(now - 120)
        .execute(&mut *tx)
        .await?;
    let global_start: i64 = global.try_get("window_start")?;
    let global_attempts: i32 = global.try_get("attempts")?;
    let (global_start, global_attempts) = if now - global_start >= 60 {
        (now, 0)
    } else {
        (global_start, global_attempts)
    };
    let row = sqlx::query("SELECT window_start, attempts FROM auth_rate_limits WHERE scope = $1")
        .bind(&scope)
        .fetch_optional(&mut *tx)
        .await?;
    let (start, attempts) = match row {
        Some(row) if now - row.try_get::<i64, _>("window_start")? < 60 => (
            row.try_get::<i64, _>("window_start")?,
            row.try_get::<i32, _>("attempts")?,
        ),
        _ => (now, 0),
    };
    if attempts >= 8 || global_attempts >= 64 {
        tx.commit().await?;
        return Err(ApiError::Busy);
    }
    sqlx::query(
        "UPDATE auth_rate_limits SET window_start = $1, attempts = $2 WHERE scope = 'global'",
    )
    .bind(global_start)
    .bind(global_attempts + 1)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO auth_rate_limits (scope, window_start, attempts) VALUES ($1, $2, $3) ON CONFLICT (scope) DO UPDATE SET window_start = EXCLUDED.window_start, attempts = EXCLUDED.attempts")
        .bind(scope).bind(start).bind(attempts + 1).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../panel/migrations")]
    async fn rejected_peer_cannot_drain_global_budget_and_concurrent_limits_hold(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let first = SocketAddr::from(([192, 0, 2, 1], 10000));
        let second = SocketAddr::from(([192, 0, 2, 2], 20000));
        for _ in 0..8 {
            consume(&pool, first).await?;
        }
        for _ in 0..64 {
            assert!(matches!(consume(&pool, first).await, Err(ApiError::Busy)));
        }
        let spent: i32 =
            sqlx::query_scalar("SELECT attempts FROM auth_rate_limits WHERE scope='global'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(
            spent, 8,
            "rejected requests must not spend the global allowance"
        );
        consume(&pool, second).await?;

        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..9 {
            let pool = pool.clone();
            requests.spawn(async move { consume(&pool, second).await });
        }
        let mut accepted = 0;
        let mut rejected = 0;
        while let Some(result) = requests.join_next().await {
            match result? {
                Ok(()) => accepted += 1,
                Err(ApiError::Busy) => rejected += 1,
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!((accepted, rejected), (7, 2));
        let spent: i32 =
            sqlx::query_scalar("SELECT attempts FROM auth_rate_limits WHERE scope='global'")
                .fetch_one(&pool)
                .await?;
        assert_eq!(
            spent, 16,
            "each of the two peers can spend only eight requests"
        );

        for octet in 3..=66 {
            let pool = pool.clone();
            requests.spawn(async move {
                consume(&pool, SocketAddr::from(([192, 0, 2, octet], 30000))).await
            });
        }
        let mut accepted = 0;
        let mut rejected = 0;
        while let Some(result) = requests.join_next().await {
            match result? {
                Ok(()) => accepted += 1,
                Err(ApiError::Busy) => rejected += 1,
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!((accepted, rejected), (48, 16));
        let spent: i32 =
            sqlx::query_scalar("SELECT attempts FROM auth_rate_limits WHERE scope='global'")
                .fetch_one(&pool)
                .await?;
        let peer_spent: i64 = sqlx::query_scalar(
            "SELECT sum(attempts) FROM auth_rate_limits WHERE scope <> 'global'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!((spent, peer_spent), (64, 64));
        Ok(())
    }
}
