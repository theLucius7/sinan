use crate::{server_assets::AssetSettings, servers::Server};
use serde::{Deserialize, Serialize};
use sinan_protocol::TelemetrySample;
use sqlx::{FromRow, PgPool, Postgres, QueryBuilder, Transaction};
use std::collections::BTreeMap;

#[derive(Default, Serialize, Deserialize)]
struct Checkpoint {
    sampled_at: i64,
    uptime_secs: Option<u64>,
    interfaces: BTreeMap<String, Counter>,
}

#[derive(Serialize, Deserialize)]
struct Counter {
    received: Option<u64>,
    transmitted: Option<u64>,
}

#[derive(Default)]
struct Daily {
    up: u128,
    down: u128,
    first: i64,
    last: i64,
    incomplete: bool,
}

#[derive(Default, Serialize)]
pub struct TrafficSummary {
    pub correction_id: Option<i64>,
    pub corrected: bool,
    pub cycle_start: i64,
    pub cycle_end: i64,
    pub uploaded: String,
    pub downloaded: String,
    pub used: String,
    pub limit: String,
    pub remaining: Option<String>,
    pub percent: Option<f64>,
    pub exceeded: bool,
    pub observed_from: Option<i64>,
    pub last_sample_at: Option<i64>,
    pub incomplete: bool,
    pub interfaces: Vec<String>,
}

// The caller holds the server row lock and commits this with telemetry and its ACK.
pub async fn ingest(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    samples: &mut [TelemetrySample],
) -> anyhow::Result<()> {
    if samples.is_empty() {
        return Ok(());
    }
    let saved: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT checkpoint FROM server_network_counters WHERE server_id=$1")
            .bind(server)
            .fetch_optional(&mut **tx)
            .await?;
    let mut checkpoint: Checkpoint = saved
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    let mut daily: BTreeMap<(i64, String), Daily> = BTreeMap::new();
    samples.sort_by_key(|sample| (sample.sampled_at, sample.id));
    let previous_at = checkpoint.sampled_at;
    for sample in samples {
        if sample.sampled_at <= checkpoint.sampled_at {
            continue;
        }
        let elapsed = sample.sampled_at - checkpoint.sampled_at;
        let uptime = checkpoint.uptime_secs.zip(sample.metrics.uptime_secs);
        let reboot = uptime.is_some_and(|(old, new)| new < old);
        // Wall-clock corrections can change sampled_at without resetting counters.
        // An uptime/timestamp mismatch alone cannot establish that a reboot occurred.
        let timing_mismatch = uptime.is_some_and(|(old, new)| {
            (i128::from(new) - i128::from(old) - i128::from(elapsed / 1000)).abs() > 5
        });
        let changed = checkpoint
            .interfaces
            .keys()
            .ne(sample.metrics.network_interfaces.keys());
        for (name, counter) in &sample.metrics.network_interfaces {
            let (Some(received), Some(transmitted)) =
                (counter.received_bytes, counter.transmitted_bytes)
            else {
                continue;
            };
            let old = checkpoint
                .interfaces
                .get(name)
                .and_then(|c| c.received.zip(c.transmitted));
            let (down, up, reset) = match old {
                Some((rx, tx)) => (
                    if reboot || received < rx {
                        received
                    } else {
                        received - rx
                    },
                    if reboot || transmitted < tx {
                        transmitted
                    } else {
                        transmitted - tx
                    },
                    reboot || received < rx || transmitted < tx,
                ),
                None => (0, 0, checkpoint.sampled_at > 0),
            };
            let entry = daily
                .entry((sample.sampled_at / 86_400_000 * 86_400, name.clone()))
                .or_default();
            entry.up += u128::from(up);
            entry.down += u128::from(down);
            entry.first = if entry.first == 0 {
                sample.sampled_at
            } else {
                entry.first.min(sample.sampled_at)
            };
            entry.last = entry.last.max(sample.sampled_at);
            entry.incomplete |= reset
                || timing_mismatch
                || (checkpoint.sampled_at > 0 && (elapsed > 300_000 || changed));
        }
        checkpoint = Checkpoint {
            sampled_at: sample.sampled_at,
            uptime_secs: sample.metrics.uptime_secs,
            interfaces: sample
                .metrics
                .network_interfaces
                .iter()
                .map(|(name, counter)| {
                    (
                        name.clone(),
                        Counter {
                            received: counter.received_bytes,
                            transmitted: counter.transmitted_bytes,
                        },
                    )
                })
                .collect(),
        };
    }
    if checkpoint.sampled_at == previous_at {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO server_network_counters(server_id,checkpoint) VALUES($1,$2)
        ON CONFLICT(server_id) DO UPDATE SET checkpoint=EXCLUDED.checkpoint",
    )
    .bind(server)
    .bind(serde_json::to_value(checkpoint)?)
    .execute(&mut **tx)
    .await?;
    // A batch is bounded by the existing 64 samples / 1 MiB limits; aggregate first.
    for chunk in daily.into_iter().collect::<Vec<_>>().chunks(1000) {
        let mut query: QueryBuilder<'_, Postgres> = QueryBuilder::new(
            "INSERT INTO server_network_daily(server_id,day,interface,uploaded,downloaded,first_sample_at,last_sample_at,incomplete) ",
        );
        query.push_values(chunk, |mut row, ((day, interface), value)| {
            row.push_bind(server)
                .push_bind(day)
                .push_bind(interface)
                .push_bind(value.up.to_string())
                .push_unseparated("::numeric")
                .push_bind(value.down.to_string())
                .push_unseparated("::numeric")
                .push_bind(value.first)
                .push_bind(value.last)
                .push_bind(value.incomplete);
        });
        query.push(
            " ON CONFLICT(server_id,day,interface) DO UPDATE SET
            uploaded=server_network_daily.uploaded+EXCLUDED.uploaded,
            downloaded=server_network_daily.downloaded+EXCLUDED.downloaded,
            first_sample_at=LEAST(server_network_daily.first_sample_at,EXCLUDED.first_sample_at),
            last_sample_at=GREATEST(server_network_daily.last_sample_at,EXCLUDED.last_sample_at),
            incomplete=server_network_daily.incomplete OR EXCLUDED.incomplete",
        );
        query.build().execute(&mut **tx).await?;
    }
    Ok(())
}

#[derive(FromRow)]
struct Total {
    id: i64,
    cycle_start: i64,
    cycle_end: i64,
    interface: Option<String>,
    uploaded: Option<String>,
    downloaded: Option<String>,
    first_sample_at: Option<i64>,
    last_sample_at: Option<i64>,
    incomplete: Option<bool>,
}

pub async fn attach(pool: &PgPool, servers: &mut [Server], now: i64) -> anyhow::Result<()> {
    if servers.is_empty() {
        return Ok(());
    }
    let ids: Vec<_> = servers.iter().map(|server| server.id).collect();
    let reset_days: Vec<_> = servers
        .iter()
        .map(|server| i32::from(server.asset_settings.reset_day))
        .collect();
    let totals: Vec<Total> = sqlx::query_as(
        "WITH config AS (
           SELECT id, reset_day, sinan_traffic_cycle_start($2,reset_day) AS cycle_start
           FROM unnest($1::bigint[],$3::integer[]) AS selected(id,reset_day)
         ) SELECT c.id,c.cycle_start,sinan_traffic_cycle_start(c.cycle_start+32*86400,c.reset_day) AS cycle_end,
           d.interface,SUM(d.uploaded)::text AS uploaded,SUM(d.downloaded)::text AS downloaded,
           MIN(d.first_sample_at) AS first_sample_at,MAX(d.last_sample_at) AS last_sample_at,
           BOOL_OR(d.incomplete) AS incomplete
         FROM config c LEFT JOIN server_network_daily d ON d.server_id=c.id
           AND d.day>=c.cycle_start AND d.day<sinan_traffic_cycle_start(c.cycle_start+32*86400,c.reset_day)
         GROUP BY c.id,c.cycle_start,c.reset_day,d.interface ORDER BY c.id,d.interface",
    ).bind(&ids).bind(now).bind(reset_days).fetch_all(pool).await?;
    let mut grouped: BTreeMap<i64, Vec<Total>> = BTreeMap::new();
    for total in totals {
        grouped.entry(total.id).or_default().push(total);
    }
    let corrections: BTreeMap<_, _> = crate::traffic_correction::current(pool, servers, now)
        .await?
        .into_iter()
        .map(|row| (row.server_id, row))
        .collect();
    for server in servers {
        if let Some(rows) = grouped.remove(&server.id) {
            let mut summary = summarize(&server.asset_settings, rows)?;
            if let Some(correction) = corrections.get(&server.id) {
                let up = corrected_total(&summary.uploaded, &correction.uploaded_offset)?;
                let down = corrected_total(&summary.downloaded, &correction.downloaded_offset)?;
                summary.correction_id = Some(correction.id);
                summary.corrected = true;
                summarize_totals(&mut summary, &server.asset_settings, up, down)?;
            }
            server.traffic = Some(summary);
        }
    }
    Ok(())
}

fn summarize(asset: &AssetSettings, rows: Vec<Total>) -> anyhow::Result<TrafficSummary> {
    let mut summary = TrafficSummary {
        limit: asset.traffic_limit.clone(),
        ..Default::default()
    };
    let (mut up, mut down) = (0_u128, 0_u128);
    for row in rows {
        summary.cycle_start = row.cycle_start;
        summary.cycle_end = row.cycle_end;
        let Some(interface) = row.interface.filter(|name| asset.includes(name)) else {
            continue;
        };
        summary.interfaces.push(interface);
        up = up
            .checked_add(row.uploaded.as_deref().unwrap_or("0").parse()?)
            .ok_or_else(|| anyhow::anyhow!("network total overflow"))?;
        down = down
            .checked_add(row.downloaded.as_deref().unwrap_or("0").parse()?)
            .ok_or_else(|| anyhow::anyhow!("network total overflow"))?;
        if let Some(at) = row.first_sample_at {
            summary.observed_from = Some(summary.observed_from.map_or(at, |old| old.min(at)));
        }
        if let Some(at) = row.last_sample_at {
            summary.last_sample_at = Some(summary.last_sample_at.map_or(at, |old| old.max(at)));
        }
        summary.incomplete |= row.incomplete.unwrap_or(false);
    }
    summarize_totals(&mut summary, asset, up, down)?;
    Ok(summary)
}

fn corrected_total(value: &str, offset: &str) -> anyhow::Result<u128> {
    let value: u128 = value.parse()?;
    let offset: i128 = offset.parse()?;
    Ok(if offset < 0 {
        value.saturating_sub(offset.unsigned_abs())
    } else {
        value.saturating_add(offset as u128)
    })
}

fn summarize_totals(
    summary: &mut TrafficSummary,
    asset: &AssetSettings,
    up: u128,
    down: u128,
) -> anyhow::Result<()> {
    let used = asset.traffic_limit_type.used(up, down);
    let limit: u128 = asset.traffic_limit.parse()?;
    summary.uploaded = up.to_string();
    summary.downloaded = down.to_string();
    summary.used = used.to_string();
    if limit > 0 && (summary.observed_from.is_some() || summary.corrected) {
        summary.remaining = Some(limit.saturating_sub(used).to_string());
        summary.percent = Some(used as f64 / limit as f64 * 100.0);
        summary.exceeded = used >= limit;
    }
    Ok(())
}
