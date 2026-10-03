use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sinan_protocol::{Metrics, TelemetrySample};
use std::collections::BTreeMap;

pub fn network_metric_key(selector: &str, receive: bool) -> String {
    let direction = if receive { "receive" } else { "transmit" };
    format!(
        "selected_network_{direction}:{:x}",
        Sha256::digest(selector.as_bytes())
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MetricAggregate {
    pub count: u64,
    pub avg: f64,
    pub min: f64,
    pub max: f64,
}

impl MetricAggregate {
    fn value(value: f64) -> Self {
        Self {
            count: 1,
            avg: value,
            min: value,
            max: value,
        }
    }
    fn merge(&mut self, other: &Self) {
        let count = self.count + other.count;
        self.avg += (other.avg - self.avg) * (other.count as f64 / count as f64);
        self.count = count;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NetworkCounter {
    pub sampled_at: i64,
    pub received_bytes: Option<String>,
    pub transmitted_bytes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HistoryPoint {
    pub bucket_at: i64,
    pub sample_count: u64,
    pub first_sampled_at: i64,
    pub last_sampled_at: i64,
    pub metrics: BTreeMap<String, MetricAggregate>,
    pub network_counters: BTreeMap<String, NetworkCounter>,
    pub partial: bool,
}

impl HistoryPoint {
    pub(super) fn sample_with_scope(
        sample: &TelemetrySample,
        bucket_ms: i64,
        asset: &crate::server_assets::AssetSettings,
    ) -> Self {
        let mut point = Self::sample(sample, bucket_ms);
        for receive in [true, false] {
            let value = sum_known(
                sample
                    .metrics
                    .network_interfaces
                    .iter()
                    .filter(|(name, _)| asset.includes(name))
                    .map(|(_, network)| {
                        if receive {
                            network.receive_bytes_per_sec
                        } else {
                            network.transmit_bytes_per_sec
                        }
                    }),
            );
            if let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) {
                point.metrics.insert(
                    network_metric_key(&asset.network_interface, receive),
                    MetricAggregate::value(value),
                );
            }
        }
        point
    }

    pub(super) fn sample(sample: &TelemetrySample, bucket_ms: i64) -> Self {
        Self {
            bucket_at: sample.sampled_at.div_euclid(bucket_ms) * bucket_ms,
            sample_count: 1,
            first_sampled_at: sample.sampled_at,
            last_sampled_at: sample.sampled_at,
            metrics: values(&sample.metrics)
                .into_iter()
                .map(|(key, value)| (key, MetricAggregate::value(value)))
                .collect(),
            network_counters: sample
                .metrics
                .network_interfaces
                .iter()
                .map(|(name, network)| {
                    (
                        name.clone(),
                        NetworkCounter {
                            sampled_at: sample.sampled_at,
                            received_bytes: network.received_bytes.map(|value| value.to_string()),
                            transmitted_bytes: network
                                .transmitted_bytes
                                .map(|value| value.to_string()),
                        },
                    )
                })
                .collect(),
            partial: false,
        }
    }

    pub(super) fn merge(&mut self, other: Self) {
        self.sample_count += other.sample_count;
        self.first_sampled_at = self.first_sampled_at.min(other.first_sampled_at);
        self.last_sampled_at = self.last_sampled_at.max(other.last_sampled_at);
        self.partial |= other.partial;
        for (key, value) in other.metrics {
            self.metrics
                .entry(key)
                .and_modify(|old| old.merge(&value))
                .or_insert(value);
        }
        for (name, value) in other.network_counters {
            let replace = self
                .network_counters
                .get(&name)
                .is_none_or(|old| value.sampled_at > old.sampled_at);
            if replace {
                self.network_counters.insert(name, value);
            }
        }
    }
}

fn sum_known(values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    let mut total = 0.0;
    let mut count = 0;
    for value in values {
        total += value?;
        count += 1;
    }
    (count > 0).then_some(total)
}

fn values(metrics: &Metrics) -> BTreeMap<String, f64> {
    let mut result = BTreeMap::new();
    let mut add = |key: &str, value: Option<f64>| {
        if let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) {
            result.insert(key.to_owned(), value);
        }
    };
    for (key, value) in [
        ("cpu_percent", metrics.cpu_percent),
        ("load_1", metrics.load_1),
        ("load_5", metrics.load_5),
        ("load_15", metrics.load_15),
    ] {
        add(key, value);
    }
    for (key, value) in [
        ("memory_used", metrics.memory_used),
        ("disk_used", metrics.disk_used),
        ("swap_used", metrics.swap_used),
        ("swap_total", metrics.swap_total),
        ("processes", metrics.processes),
        ("uptime_secs", metrics.uptime_secs),
        ("tcp_connections", metrics.tcp_connections),
        ("udp_connections", metrics.udp_connections),
    ] {
        add(key, value.map(|value| value as f64));
    }
    for (prefix, used, total) in [
        (
            "memory",
            metrics.memory_used,
            metrics
                .extra
                .get("memory_total")
                .and_then(serde_json::Value::as_u64),
        ),
        (
            "disk",
            metrics.disk_used,
            metrics
                .extra
                .get("disk_total")
                .and_then(serde_json::Value::as_u64),
        ),
        ("swap", metrics.swap_used, metrics.swap_total),
    ] {
        add(&format!("{prefix}_total"), total.map(|value| value as f64));
        add(
            &format!("{prefix}_percent"),
            used.zip(total.filter(|v| *v > 0))
                .map(|(used, total)| used as f64 * 100.0 / total as f64),
        );
    }
    // Loopback is not external throughput. A missing direction makes the total
    // unknown instead of silently summing only the observed subset.
    let interfaces = || {
        metrics
            .network_interfaces
            .iter()
            .filter(|(name, _)| !matches!(name.as_str(), "lo" | "lo0"))
    };
    add(
        "network_receive_bytes_per_sec",
        sum_known(interfaces().map(|(_, n)| n.receive_bytes_per_sec)),
    );
    add(
        "network_transmit_bytes_per_sec",
        sum_known(interfaces().map(|(_, n)| n.transmit_bytes_per_sec)),
    );
    add(
        "disk_read_bytes_per_sec",
        sum_known(metrics.disks.iter().map(|d| d.read_bytes_per_sec)),
    );
    add(
        "disk_write_bytes_per_sec",
        sum_known(metrics.disks.iter().map(|d| d.write_bytes_per_sec)),
    );
    add(
        "disk_read_iops",
        sum_known(metrics.disks.iter().map(|d| d.read_iops)),
    );
    add(
        "disk_write_iops",
        sum_known(metrics.disks.iter().map(|d| d.write_iops)),
    );
    result
}

pub(super) fn combine(
    points: impl IntoIterator<Item = HistoryPoint>,
    bucket_ms: i64,
) -> Vec<HistoryPoint> {
    let mut result = BTreeMap::<i64, HistoryPoint>::new();
    for mut point in points {
        point.bucket_at = point.bucket_at.div_euclid(bucket_ms) * bucket_ms;
        if let Some(old) = result.get_mut(&point.bucket_at) {
            old.merge(point);
        } else {
            result.insert(point.bucket_at, point);
        }
    }
    result.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn selected_network_minimum_is_computed_after_same_sample_sum_and_scopes_do_not_mix() {
        let asset = crate::server_assets::AssetSettings {
            network_interface: "fixture*".into(),
            ..Default::default()
        };
        let make = |at, first, second| TelemetrySample {
            id: Uuid::new_v4(),
            sampled_at: at,
            metrics: Metrics {
                network_interfaces: [
                    (
                        "fixture0".into(),
                        sinan_protocol::NetworkMetrics {
                            receive_bytes_per_sec: Some(first),
                            ..Default::default()
                        },
                    ),
                    (
                        "fixture1".into(),
                        sinan_protocol::NetworkMetrics {
                            receive_bytes_per_sec: Some(second),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
                ..Default::default()
            },
        };
        let mut point = HistoryPoint::sample_with_scope(&make(1000, 0.0, 100.0), 60_000, &asset);
        point.merge(HistoryPoint::sample_with_scope(
            &make(2000, 100.0, 0.0),
            60_000,
            &asset,
        ));
        let key = network_metric_key(&asset.network_interface, true);
        assert_eq!(
            point.metrics[&key],
            MetricAggregate {
                count: 2,
                avg: 100.0,
                min: 100.0,
                max: 100.0
            }
        );
        let changed = crate::server_assets::AssetSettings {
            network_interface: "fixture0".into(),
            ..Default::default()
        };
        point.merge(HistoryPoint::sample_with_scope(
            &make(3000, 0.0, 0.0),
            60_000,
            &changed,
        ));
        assert_eq!(point.sample_count, 3);
        assert_eq!(point.metrics[&key].count, 2);
        assert_ne!(key, network_metric_key(&changed.network_interface, true));
    }

    #[test]
    fn summaries_weight_present_values_and_keep_exact_latest_counters() {
        let sample = |at, cpu| TelemetrySample {
            id: Uuid::new_v4(),
            sampled_at: at,
            metrics: Metrics {
                cpu_percent: cpu,
                ..Default::default()
            },
        };
        let mut first = sample(1000, Some(10.0));
        first.metrics.network_interfaces.insert(
            "eth0".into(),
            sinan_protocol::NetworkMetrics {
                received_bytes: Some(u64::MAX),
                ..Default::default()
            },
        );
        let raw = [
            first,
            sample(2000, None),
            sample(61_000, Some(70.0)),
            sample(62_000, Some(100.0)),
        ];
        let minutes = combine(raw.iter().map(|s| HistoryPoint::sample(s, 60_000)), 60_000);
        let hours = combine(minutes, 3_600_000);
        let value = &hours[0];
        assert_eq!(value.sample_count, 4);
        assert_eq!(
            value.metrics["cpu_percent"],
            MetricAggregate {
                count: 3,
                avg: 60.0,
                min: 10.0,
                max: 100.0
            }
        );
        assert!(!value.metrics.contains_key("network_receive_bytes_per_sec"));
        assert!(!value.metrics.contains_key("memory_percent"));
        assert_eq!(
            value.network_counters["eth0"].received_bytes,
            Some(u64::MAX.to_string())
        );
        assert_eq!(value.last_sampled_at, 62_000);
    }
}
