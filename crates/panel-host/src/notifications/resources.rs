use super::rules::{Aggregation, Metric, Spec};
use crate::telemetry::{HistoryPoint, network_metric_key};

// Minute summaries contain actual samples; legacy last-observation points are partial.
pub(super) fn evaluate(
    spec: &Spec,
    samples: &[HistoryPoint],
    selector: &str,
    now: i64,
    persisted_at: Option<i64>,
) -> Option<(bool, f64)> {
    let end = now.div_euclid(60) * 60_000;
    if persisted_at? < end {
        return None;
    }
    let start = end - i64::from(spec.duration_minutes) * 60_000;
    let (key, scale, percent) = match spec.metric {
        Metric::Cpu => ("cpu_percent".into(), 1.0, true),
        Metric::Memory => ("memory_percent".into(), 1.0, true),
        Metric::Disk => ("disk_percent".into(), 1.0, true),
        Metric::NetIn => (network_metric_key(selector, true), 1_048_576.0, false),
        Metric::NetOut => (network_metric_key(selector, false), 1_048_576.0, false),
    };
    let mut next = start;
    let mut sum = 0.0;
    let mut count = 0_u64;
    let mut minimum = f64::INFINITY;
    for point in samples
        .iter()
        .filter(|point| point.bucket_at >= start && point.bucket_at < end)
    {
        if point.bucket_at != next
            || point.partial
            || point.sample_count == 0
            || point.first_sampled_at < point.bucket_at
            || point.last_sampled_at < point.first_sampled_at
            || point.last_sampled_at >= point.bucket_at + 60_000
        {
            return None;
        }
        let metric = point.metrics.get(&key)?;
        if metric.count != point.sample_count
            || ![metric.avg, metric.min, metric.max]
                .iter()
                .all(|value| value.is_finite() && *value >= 0.0)
            || metric.min > metric.avg
            || metric.avg > metric.max
            || (percent && metric.max > 100.0)
        {
            return None;
        }
        count = count.checked_add(metric.count)?;
        sum += metric.avg * metric.count as f64;
        minimum = minimum.min(metric.min);
        next += 60_000;
    }
    if next != end || count == 0 || !sum.is_finite() {
        return None;
    }
    let value = if spec.aggregation == Aggregation::Continuous {
        minimum
    } else {
        sum / count as f64
    } / scale;
    Some((value >= spec.threshold, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::MetricAggregate;
    use std::collections::BTreeMap;

    fn spec(metric: Metric, aggregation: Aggregation) -> Spec {
        Spec {
            name: "fixture".into(),
            metric,
            threshold: 90.0,
            duration_minutes: 2,
            aggregation,
            all_servers: true,
            enabled: true,
            server_ids: vec![],
        }
    }
    fn point(bucket: i64, key: &str, count: u64, avg: f64, min: f64, max: f64) -> HistoryPoint {
        HistoryPoint {
            bucket_at: bucket,
            sample_count: count,
            first_sampled_at: bucket + 1000,
            last_sampled_at: bucket + 59000,
            metrics: BTreeMap::from([(
                key.into(),
                MetricAggregate {
                    count,
                    avg,
                    min,
                    max,
                },
            )]),
            network_counters: BTreeMap::new(),
            partial: false,
        }
    }
    #[test]
    fn windows_weight_actual_samples_and_continuous_uses_the_real_minimum() {
        let samples = vec![
            point(480000, "cpu_percent", 1, 100.0, 100.0, 100.0),
            point(540000, "cpu_percent", 9, 80.0, 60.0, 100.0),
        ];
        assert_eq!(
            evaluate(
                &spec(Metric::Cpu, Aggregation::Average),
                &samples,
                "",
                615,
                Some(600000)
            ),
            Some((false, 82.0))
        );
        assert_eq!(
            evaluate(
                &spec(Metric::Cpu, Aggregation::Continuous),
                &samples,
                "",
                615,
                Some(600000)
            ),
            Some((false, 60.0))
        );
        assert_eq!(
            evaluate(
                &spec(Metric::Cpu, Aggregation::Average),
                &samples,
                "",
                615,
                Some(599999)
            ),
            None
        );
        assert_eq!(
            evaluate(
                &spec(Metric::Cpu, Aggregation::Average),
                &samples,
                "",
                615,
                None
            ),
            None
        );
    }
    #[test]
    fn missing_partial_invalid_and_changed_scope_points_remain_unknown() {
        let valid = vec![
            point(480000, "cpu_percent", 2, 95.0, 90.0, 100.0),
            point(540000, "cpu_percent", 2, 95.0, 90.0, 100.0),
        ];
        for reason in 0..7 {
            let mut samples = valid.clone();
            match reason {
                0 => {
                    samples.remove(1);
                }
                1 => samples[1].partial = true,
                2 => samples[1].sample_count = 3,
                3 => samples[1].metrics.clear(),
                4 => samples[1].last_sampled_at = 600000,
                5 => samples[1].metrics.get_mut("cpu_percent").unwrap().max = 101.0,
                _ => samples[1].first_sampled_at = 480000,
            }
            assert_eq!(
                evaluate(
                    &spec(Metric::Cpu, Aggregation::Average),
                    &samples,
                    "",
                    615,
                    Some(600000)
                ),
                None
            );
        }
        let selector = "eth*,!eth1";
        let key = network_metric_key(selector, true);
        let samples = vec![
            point(480000, &key, 2, 1048576.0, 524288.0, 1572864.0),
            point(540000, &key, 2, 1048576.0, 524288.0, 1572864.0),
        ];
        assert_eq!(
            evaluate(
                &spec(Metric::NetIn, Aggregation::Average),
                &samples,
                selector,
                615,
                Some(600000)
            ),
            Some((false, 1.0))
        );
        assert_eq!(
            evaluate(
                &spec(Metric::NetIn, Aggregation::Continuous),
                &samples,
                selector,
                615,
                Some(600000)
            ),
            Some((false, 0.5))
        );
        assert_eq!(
            evaluate(
                &spec(Metric::NetIn, Aggregation::Average),
                &samples,
                "eth1",
                615,
                Some(600000)
            ),
            None
        );
    }
}
