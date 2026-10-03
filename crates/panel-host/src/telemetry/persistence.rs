use super::{aggregate::HistoryPoint, *};
use futures_util::TryStreamExt;
use sqlx::{PgPool, Postgres, QueryBuilder, Transaction};
use std::collections::BTreeMap;

pub(super) const DAY_MS: i64 = 86_400_000;
pub(super) const RAW_MS: i64 = 2 * 3_600_000;
pub(super) const REPLAY_MS: i64 = 7 * DAY_MS;

pub(super) async fn initialized(tx: &mut Transaction<'_, Postgres>, server: i64) -> ApiResult<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM telemetry_history_initialized WHERE server_id=$1)",
    )
    .bind(server)
    .fetch_one(&mut **tx)
    .await?;
    if exists {
        return Ok(());
    }
    let mut points = BTreeMap::<i64, HistoryPoint>::new();
    let mut minutes = HashSet::new();
    {
        let mut rows=sqlx::query("SELECT id,sampled_at,metrics FROM telemetry_samples WHERE server_id=$1 ORDER BY sampled_at,id").bind(server).fetch(&mut **tx);
        while let Some(row) = rows.try_next().await? {
            let sample = row_sample(&row)?;
            let mut point = HistoryPoint::sample(&sample, 60_000);
            point.partial = true;
            minutes.insert(point.bucket_at);
            if let Some(old) = points.get_mut(&point.bucket_at) {
                old.merge(point);
            } else {
                points.insert(point.bucket_at, point);
            }
        }
    }
    // The legacy table holds one real observation per minute, not an average.
    {
        let mut rows = sqlx::query(
            "SELECT sampled_at,metrics FROM metrics_minutely WHERE server_id=$1 ORDER BY bucket",
        )
        .bind(server)
        .fetch(&mut **tx);
        while let Some(row) = rows.try_next().await? {
            let at: i64 = row.get("sampled_at");
            if at <= 0 || minutes.contains(&(at.div_euclid(60_000) * 60_000)) {
                continue;
            }
            let sample = TelemetrySample {
                id: uuid::Uuid::nil(),
                sampled_at: at,
                metrics: serde_json::from_value(row.get("metrics")).map_err(anyhow::Error::from)?,
            };
            let mut point = HistoryPoint::sample(&sample, 60_000);
            point.partial = true;
            points.insert(point.bucket_at, point);
        }
    }
    let points: Vec<_> = points.into_values().collect();
    for chunk in points.chunks(128) {
        let mut query = QueryBuilder::<Postgres>::new(
            "INSERT INTO telemetry_history(server_id,resolution_secs,bucket_at,summary) ",
        );
        let encoded = chunk
            .iter()
            .map(|point| serde_json::to_value(point).map(|value| (point.bucket_at, value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)?;
        query.push_values(&encoded, |mut row, (at, value)| {
            row.push_bind(server)
                .push_bind(60)
                .push_bind(at)
                .push_bind(value);
        });
        query
            .push(" ON CONFLICT DO NOTHING")
            .build()
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO telemetry_history_initialized(server_id) VALUES($1) ON CONFLICT DO NOTHING",
    )
    .bind(server)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) fn row_sample(row: &sqlx::postgres::PgRow) -> ApiResult<TelemetrySample> {
    Ok(TelemetrySample {
        id: row.get("id"),
        sampled_at: row.get("sampled_at"),
        metrics: serde_json::from_value(row.get("metrics")).map_err(anyhow::Error::from)?,
    })
}

pub(super) async fn merge(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    resolution: i32,
    mut point: HistoryPoint,
) -> ApiResult<()> {
    point.bucket_at =
        point.bucket_at.div_euclid(i64::from(resolution) * 1000) * i64::from(resolution) * 1000;
    let previous: Option<serde_json::Value> = sqlx::query_scalar("SELECT summary FROM telemetry_history WHERE server_id=$1 AND resolution_secs=$2 AND bucket_at=$3").bind(server).bind(resolution).bind(point.bucket_at).fetch_optional(&mut **tx).await?;
    if let Some(value) = previous {
        let mut old: HistoryPoint = serde_json::from_value(value).map_err(anyhow::Error::from)?;
        old.merge(point);
        point = old;
    }
    sqlx::query("INSERT INTO telemetry_history(server_id,resolution_secs,bucket_at,summary) VALUES($1,$2,$3,$4) ON CONFLICT(server_id,resolution_secs,bucket_at) DO UPDATE SET summary=EXCLUDED.summary").bind(server).bind(resolution).bind(point.bucket_at).bind(serde_json::to_value(&point).map_err(anyhow::Error::from)?).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn save(
    pool: &PgPool,
    server: i64,
    batch: TelemetryBatch,
    now: i64,
) -> ApiResult<TelemetryAck> {
    let retention = storage::read_policy(pool).await?.history_retention_days;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(server)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    initialized(&mut tx, server).await?;
    let asset: serde_json::Value =
        sqlx::query_scalar("SELECT asset_settings FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&mut *tx)
            .await?;
    let asset: crate::server_assets::AssetSettings =
        serde_json::from_value(asset).map_err(anyhow::Error::from)?;
    let mut ack = Vec::new();
    let mut samples = Vec::new();
    let mut buckets = BTreeMap::<i64, HistoryPoint>::new();
    for sample in batch.samples {
        let value = serde_json::to_value(&sample.metrics).map_err(anyhow::Error::from)?;
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&sample).map_err(anyhow::Error::from)?)
        );
        let added = sqlx::query("INSERT INTO telemetry_receipts(server_id,id,sampled_at,digest) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(server).bind(sample.id).bind(sample.sampled_at).bind(&digest).execute(&mut *tx).await?.rows_affected()>0;
        if !added {
            let old: String = sqlx::query_scalar(
                "SELECT digest FROM telemetry_receipts WHERE server_id=$1 AND id=$2",
            )
            .bind(server)
            .bind(sample.id)
            .fetch_one(&mut *tx)
            .await?;
            if old != digest {
                return Err(ApiError::Conflict("同一遥测标识的内容发生变化".into()));
            }
        } else {
            if sample.sampled_at >= (now - RAW_MS).div_euclid(60_000) * 60_000 {
                sqlx::query("INSERT INTO telemetry_samples(server_id,id,sampled_at,digest,metrics) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(server).bind(sample.id).bind(sample.sampled_at).bind(&digest).bind(&value).execute(&mut *tx).await?;
            }
            sqlx::query("UPDATE servers SET latest_metrics=$2,metrics_sampled_at=$3 WHERE id=$1 AND metrics_sampled_at<$3").bind(server).bind(&value).bind(sample.sampled_at).execute(&mut *tx).await?;
            // Preserve the old last-observation projection for old consumers.
            sqlx::query("INSERT INTO metrics_minutely(server_id,bucket,metrics,sampled_at) VALUES($1,$2,$3,$4) ON CONFLICT(server_id,bucket) DO UPDATE SET metrics=EXCLUDED.metrics,sampled_at=EXCLUDED.sampled_at WHERE metrics_minutely.sampled_at<EXCLUDED.sampled_at").bind(server).bind(sample.sampled_at.div_euclid(60_000)*60).bind(&value).bind(sample.sampled_at).execute(&mut *tx).await?;
            if sample.sampled_at >= now - i64::from(retention) * DAY_MS {
                let point = HistoryPoint::sample_with_scope(&sample, 60_000, &asset);
                if let Some(old) = buckets.get_mut(&point.bucket_at) {
                    old.merge(point);
                } else {
                    buckets.insert(point.bucket_at, point);
                }
            }
            samples.push(sample.clone());
        }
        ack.push(sample.id);
    }
    for point in buckets.into_values() {
        merge(&mut tx, server, 60, point).await?;
    }
    // Exact device counters, replay identity and historical aggregates commit
    // atomically. Aggregated rates are never used to debit network usage.
    crate::server_traffic::ingest(&mut tx, server, &mut samples).await?;
    tx.commit().await?;
    Ok(TelemetryAck { ids: ack })
}
