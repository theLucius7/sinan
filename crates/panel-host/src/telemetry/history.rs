use super::{
    aggregate::{HistoryPoint, combine},
    persistence::{self, DAY_MS, RAW_MS},
    *,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// The caller owns the server lock; this reader never acquires another one.
pub async fn read_minutes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    server: i64,
    from: i64,
    to: i64,
) -> ApiResult<Vec<HistoryPoint>> {
    let rows:Vec<serde_json::Value>=sqlx::query_scalar("SELECT summary FROM telemetry_history WHERE server_id=$1 AND resolution_secs=60 AND bucket_at>=$2 AND bucket_at<$3 ORDER BY bucket_at LIMIT 1440")
        .bind(server).bind(from).bind(to).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|value| {
            serde_json::from_value(value)
                .map_err(anyhow::Error::from)
                .map_err(ApiError::from)
        })
        .collect()
}

#[derive(Deserialize)]
pub struct AggregateQuery {
    pub window: Option<String>,
}

#[derive(Serialize)]
pub struct AggregateHistory {
    pub window: String,
    pub from: i64,
    pub to: i64,
    pub bucket_ms: i64,
    pub retention_days: i32,
    pub points: Vec<HistoryPoint>,
}

pub async fn aggregate_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Query(query): Query<AggregateQuery>,
) -> ApiResult<Json<AggregateHistory>> {
    auth::require_admin(&state, &headers).await?;
    read_aggregate(&state, server, query).await
}

pub(crate) async fn read_aggregate(
    state: &AppState,
    server: i64,
    query: AggregateQuery,
) -> ApiResult<Json<AggregateHistory>> {
    let window = query.window.unwrap_or_else(|| "1h".into());
    let (duration, bucket_ms) = match window.as_str() {
        "15m" => (900_000, 2_000),
        "1h" => (3_600_000, 5_000),
        "2h" => (RAW_MS, 10_000),
        "24h" => (DAY_MS, 120_000),
        "7d" => (7 * DAY_MS, 900_000),
        "30d" => (30 * DAY_MS, 3_600_000),
        "90d" => (90 * DAY_MS, 12 * 3_600_000),
        "365d" => (365 * DAY_MS, 24 * 3_600_000),
        _ => return Err(ApiError::BadRequest("历史窗口无效".into())),
    };
    let retention_days = storage::read_policy(&state.pool)
        .await?
        .history_retention_days;
    let to = now_millis();
    let from = to - duration.min(i64::from(retention_days) * DAY_MS);
    let (points, bucket_ms) =
        read_window_with_resolution(&state.pool, server, from, to, bucket_ms).await?;
    Ok(Json(AggregateHistory {
        window,
        from,
        to,
        bucket_ms,
        retention_days,
        points,
    }))
}

pub async fn read_window(
    pool: &PgPool,
    server: i64,
    from: i64,
    to: i64,
    bucket_ms: i64,
) -> ApiResult<Vec<HistoryPoint>> {
    Ok(
        read_window_with_resolution(pool, server, from, to, bucket_ms)
            .await?
            .0,
    )
}

async fn read_window_with_resolution(
    pool: &PgPool,
    server: i64,
    from: i64,
    to: i64,
    mut bucket_ms: i64,
) -> ApiResult<(Vec<HistoryPoint>, i64)> {
    if from < 0 || to < from || to - from > 366 * DAY_MS || bucket_ms < 1000 {
        return Err(ApiError::BadRequest("历史范围无效".into()));
    }
    let now = now_millis();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    persistence::initialized(&mut tx, server).await?;
    // A complete minute is the raw/summary boundary. Never combine both copies
    // of a sample, including when maintenance runs concurrently with a query.
    let boundary = (now - RAW_MS).div_euclid(60_000) * 60_000;
    let raw = bucket_ms < 60_000 && from >= boundary;
    let mut points = Vec::new();
    if raw {
        let rows=sqlx::query("SELECT id,sampled_at,metrics FROM telemetry_samples WHERE server_id=$1 AND sampled_at>=$2 AND sampled_at<=$3 ORDER BY sampled_at,id LIMIT 8001").bind(server).bind(from).bind(to).fetch_all(&mut *tx).await?;
        if rows.len() > 8000 {
            return Err(ApiError::Busy);
        }
        for row in rows {
            points.push(HistoryPoint::sample(
                &persistence::row_sample(&row)?,
                bucket_ms,
            ));
        }
    } else {
        let rows=sqlx::query("SELECT resolution_secs,summary FROM telemetry_history WHERE server_id=$1 AND bucket_at>=$2 AND bucket_at<=$3 ORDER BY bucket_at,resolution_secs LIMIT 30001").bind(server).bind(from.div_euclid(3_600_000)*3_600_000).bind(to).fetch_all(&mut *tx).await?;
        if rows.len() > 30000 {
            return Err(ApiError::Busy);
        }
        for row in rows {
            let mut point: HistoryPoint =
                serde_json::from_value(row.get("summary")).map_err(anyhow::Error::from)?;
            if point.last_sampled_at < from || point.first_sampled_at > to {
                continue;
            }
            bucket_ms = bucket_ms.max(i64::from(row.get::<i32, _>("resolution_secs")) * 1000);
            point.partial |= point.first_sampled_at < from || point.last_sampled_at > to;
            points.push(point);
        }
    }
    tx.commit().await?;
    Ok((combine(points, bucket_ms), bucket_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../panel/migrations")]
    async fn an_old_two_hour_window_reports_real_minute_resolution(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        sqlx::migrate!("../panel/migrations").run(&pool).await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name) VALUES('TEST_ONLY_resolution') RETURNING id",
        )
        .fetch_one(&pool)
        .await?;
        sqlx::query("INSERT INTO telemetry_history_initialized(server_id) VALUES($1)")
            .bind(server)
            .execute(&pool)
            .await?;
        let from = (now_millis() - RAW_MS - 120_000).div_euclid(60_000) * 60_000;
        let sample = TelemetrySample {
            id: uuid::Uuid::new_v4(),
            sampled_at: from + 1000,
            metrics: sinan_protocol::Metrics {
                cpu_percent: Some(20.0),
                ..Default::default()
            },
        };
        let point = HistoryPoint::sample(&sample, 60_000);
        sqlx::query("INSERT INTO telemetry_history(server_id,resolution_secs,bucket_at,summary) VALUES($1,60,$2,$3)").bind(server).bind(from).bind(serde_json::to_value(point)?).execute(&pool).await?;
        let (points, resolution) =
            read_window_with_resolution(&pool, server, from, from + RAW_MS, 10_000).await?;
        assert_eq!(resolution, 60_000);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].sample_count, 1);
        assert_eq!(points[0].metrics["cpu_percent"].avg, 20.0);
        Ok(())
    }
}
