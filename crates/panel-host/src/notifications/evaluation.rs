use super::{
    events::{self, Observation},
    resources, rules,
};
use crate::{
    server_traffic,
    servers::{SERVER_COLUMNS, Server},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

pub async fn evaluate(pool: &PgPool, started_at: i64, now: i64) -> anyhow::Result<()> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM servers WHERE deleted_at IS NULL OR EXISTS(SELECT 1 FROM server_alert_events e WHERE e.server_id=servers.id AND e.resolved_at IS NULL) ORDER BY id")
        .fetch_all(pool).await?;
    // Keep telemetry contention local to one server, rather than locking the whole fleet.
    for id in ids {
        let mut tx = pool.begin().await?;
        let settings = super::lock_settings(&mut tx).await?;
        let query = format!(
            "SELECT {SERVER_COLUMNS} FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
        );
        let server: Option<Server> = sqlx::query_as(&query)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(mut server) = server.filter(|_| settings.notification_enabled) else {
            events::close_obsolete(&mut tx, id, &[], now).await?;
            tx.commit().await?;
            continue;
        };
        server.asset_settings.renew(now);
        let mut keep = Vec::new();
        let online = server
            .last_seen
            .is_some_and(|at| at <= now && now.saturating_sub(at) <= 60);
        if settings.offline_alerts && server.asset_settings.offline_notify {
            keep.push("offline".into());
            let threshold = i64::from(settings.offline_minutes) * 60;
            // A clean disconnect backdates last_seen; the threshold counts from the real contact.
            if now.saturating_sub(started_at) >= threshold
                && let Some(seen) = server.last_contact_at.or(server.last_seen)
            {
                // Between the online and offline thresholds, retain the previous state.
                if online || now.saturating_sub(seen) >= threshold {
                    events::observe(
                        &mut tx,
                        &settings,
                        &server,
                        Observation {
                            key: "offline".into(),
                            category: "offline",
                            active: !online,
                            message: format!(
                                "已超过 {} 分钟未收到设备心跳。",
                                settings.offline_minutes
                            ),
                            details: json!({"offline_minutes":settings.offline_minutes}),
                            reminder_until: None,
                        },
                        now,
                    )
                    .await?;
                }
            }
        }
        if settings.expiry_alert_days > 0
            && let Some(expires) = server.asset_settings.expires_at
        {
            let key = format!("expiry:{expires}");
            keep.push(key.clone());
            // Old expired dates stay visible in assets; remind only within a seven-day overdue grace.
            let active = expires - now <= i64::from(settings.expiry_alert_days) * 86400
                && now - expires <= 7 * 86400;
            let message = if expires <= now {
                "服务器到期记录已过期，请检查续费安排。".into()
            } else {
                format!(
                    "预计还有 {} 天到期，请检查续费安排。",
                    (expires - now + 86399) / 86400
                )
            };
            events::observe(
                &mut tx,
                &settings,
                &server,
                Observation {
                    key,
                    category: "expiry",
                    active,
                    message,
                    details: json!({"expires_at":expires}),
                    reminder_until: Some(expires + 8 * 86400),
                },
                now,
            )
            .await?;
        }
        if settings.traffic_alert_percentage > 0 && server.asset_settings.traffic_limit != "0" {
            server_traffic::attach(pool, std::slice::from_mut(&mut server), now).await?;
            if let Some(traffic) = &server.traffic {
                let asset = &server.asset_settings;
                let scope = format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&(
                        asset.reset_day,
                        &asset.network_interface,
                        asset.traffic_limit_type,
                        &asset.traffic_limit
                    ))?)
                );
                let mut milestone = settings.traffic_alert_percentage;
                loop {
                    let key = format!("traffic:{}:{scope}:{milestone}", traffic.cycle_start);
                    keep.push(key.clone());
                    if let Some(percent) = traffic.percent {
                        let used: u128 = traffic.used.parse()?;
                        let limit: u128 = traffic.limit.parse()?;
                        events::observe(&mut tx, &settings, &server, Observation {
                            key, category: "traffic", active: reached(used, limit, milestone),
                            message: format!("本期网卡流量已使用 {percent:.1}%，达到 {milestone}% 提醒线。{}", if traffic.incomplete { "采样存在缺口，用量可能不完整。" } else { "" }),
                            details: json!({"cycle_start":traffic.cycle_start,"cycle_end":traffic.cycle_end,"milestone":milestone,"percent":percent,"used":traffic.used,"limit":traffic.limit,"incomplete":traffic.incomplete}),
                            reminder_until: Some(traffic.cycle_end + 7 * 86400),
                        }, now).await?;
                    }
                    if milestone == 100 {
                        break;
                    }
                    milestone = (milestone + 5).min(100);
                }
            }
        }
        let rules: Vec<_> = rules::read(&mut tx)
            .await?
            .into_iter()
            .filter(|rule| {
                rule.spec.enabled && (rule.spec.all_servers || rule.spec.server_ids.contains(&id))
            })
            .collect();
        let max_window = rules
            .iter()
            .map(|rule| rule.spec.duration_minutes)
            .max()
            .unwrap_or(0);
        let end = now / 60 * 60;
        let samples = if online && max_window > 0 {
            crate::telemetry::read_minutes(
                &mut tx,
                id,
                (end - i64::from(max_window) * 60) * 1000,
                end * 1000,
            )
            .await?
        } else {
            Vec::new()
        };

        for rule in rules {
            let key = format!("resource:{}:{}", rule.id, rule.revision);
            keep.push(key.clone());
            if online
                && let Some((active, value)) = resources::evaluate(
                    &rule.spec,
                    &samples,
                    &server.asset_settings.network_interface,
                    now,
                    server.metrics_sampled_at,
                )
            {
                let unit = rule.spec.metric.unit();
                let aggregation = if rule.spec.aggregation == rules::Aggregation::Continuous {
                    "最低值"
                } else {
                    "平均值"
                };
                events::observe(&mut tx, &settings, &server, Observation {
                    key, category: "resource", active,
                    message: format!("{}：最近 {} 个完整分钟内实际样本的{aggregation} {value:.2} {unit}，阈值 {:.2} {unit}。", rule.spec.name, rule.spec.duration_minutes, rule.spec.threshold),
                    details: json!({"rule_id":rule.id,"revision":rule.revision,"metric":rule.spec.metric,"value":value,"threshold":rule.spec.threshold,"duration_minutes":rule.spec.duration_minutes,"aggregation":rule.spec.aggregation}),
                    reminder_until: None,
                }, now).await?;
            }
        }
        events::close_obsolete(&mut tx, id, &keep, now).await?;
        tx.commit().await?;
    }
    sqlx::query("DELETE FROM server_alert_events WHERE id IN (SELECT e.id FROM server_alert_events e WHERE e.resolved_at<$1 AND NOT EXISTS(SELECT 1 FROM notification_outbox o WHERE o.event_id=e.id AND o.status='pending') ORDER BY e.id LIMIT 500)")
        .bind(now - 90 * 86400).execute(pool).await?;
    sqlx::query("DELETE FROM alert_reminder_receipts WHERE (server_id,source_key) IN (SELECT server_id,source_key FROM alert_reminder_receipts WHERE retain_until<$1 LIMIT 500)")
        .bind(now).execute(pool).await?;
    Ok(())
}

fn reached(used: u128, limit: u128, milestone: u8) -> bool {
    let point = u128::from(milestone);
    let threshold = (limit / 100) * point + ((limit % 100) * point).div_ceil(100);
    limit > 0 && used >= threshold
}

#[cfg(test)]
mod tests {
    #[test]
    fn traffic_thresholds_compare_integer_bytes_without_rounding_or_overflow() {
        let threshold = (u128::MAX / 100) * 80 + ((u128::MAX % 100) * 80).div_ceil(100);
        assert!(!super::reached(threshold - 1, u128::MAX, 80));
        assert!(super::reached(threshold, u128::MAX, 80));
        assert!(!super::reached(u128::MAX - 1, u128::MAX, 100));
        assert!(super::reached(u128::MAX, u128::MAX, 100));
    }
}
