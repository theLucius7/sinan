use serde_json::{Value, json};
use std::collections::BTreeMap;
use sysinfo::System;

pub(super) fn processes(system: &System, cpu_ready: bool, elapsed: Option<f64>) -> Value {
    let mut processes:Vec<_>=system.processes().iter().map(|(pid,process)|{
        let id=pid.as_u32();
        let cgroup=std::fs::read_to_string(format!("/proc/{id}/cgroup")).ok().and_then(|text|text.lines().find_map(|line|line.splitn(3,':').nth(2).map(|value|value.trim().chars().take(1024).collect::<String>())));
        let service=cgroup.as_deref().and_then(|group|group.split('/').rev().find(|part|part.ends_with(".service")||part.ends_with(".scope"))).map(str::to_owned);
        let io=process.disk_usage();
        json!({"pid":id,"parent_pid":process.parent().map(|pid|pid.as_u32()),"name":process.name().to_string_lossy(),"cpu_percent":cpu_ready.then_some(process.cpu_usage()),"memory_bytes":process.memory(),"read_bytes":io.total_read_bytes,"written_bytes":io.total_written_bytes,"read_bytes_since_sample":elapsed.map(|_|io.read_bytes),"written_bytes_since_sample":elapsed.map(|_|io.written_bytes),"read_bytes_per_sec":elapsed.map(|seconds|io.read_bytes as f64/seconds),"write_bytes_per_sec":elapsed.map(|seconds|io.written_bytes as f64/seconds),"service":service,"cgroup":cgroup,"container":cgroup.as_deref().is_some_and(|group|group.contains("docker")||group.contains("kubepods")||group.contains("containerd"))})
    }).collect();
    processes.sort_by(|left, right| {
        right["cpu_percent"]
            .as_f64()
            .unwrap_or(0.0)
            .total_cmp(&left["cpu_percent"].as_f64().unwrap_or(0.0))
            .then_with(|| {
                right["memory_bytes"]
                    .as_u64()
                    .cmp(&left["memory_bytes"].as_u64())
            })
    });
    let total = processes.len();
    let mut services: BTreeMap<String, (f64, u64, u64, u64)> = BTreeMap::new();
    for process in &processes {
        let key = process["service"]
            .as_str()
            .unwrap_or(if process["container"].as_bool() == Some(true) {
                "container"
            } else {
                "unattributed"
            })
            .to_owned();
        let group = services.entry(key).or_default();
        group.0 += process["cpu_percent"].as_f64().unwrap_or(0.0);
        group.1 = group
            .1
            .saturating_add(process["memory_bytes"].as_u64().unwrap_or(0));
        group.2 = group
            .2
            .saturating_add(process["read_bytes_since_sample"].as_u64().unwrap_or(0));
        group.3 = group
            .3
            .saturating_add(process["written_bytes_since_sample"].as_u64().unwrap_or(0));
    }
    let services_total = services.len();
    let mut services:Vec<_>=services.into_iter().map(|(name,(cpu,memory,read,written))|json!({"name":name,"cpu_percent":cpu_ready.then_some(cpu),"memory_bytes":memory,"read_bytes_since_sample":elapsed.map(|_|read),"written_bytes_since_sample":elapsed.map(|_|written),"partial":false})).collect();
    services.sort_by(|left, right| {
        right["memory_bytes"]
            .as_u64()
            .cmp(&left["memory_bytes"].as_u64())
    });
    services.truncate(128);
    processes.truncate(64);
    let mut result = json!({"sampled_at":sinan_protocol::telemetry::now_millis(),"total":total,"limit":64,"truncated":total>64,"processes":processes,"services":services,"services_total":services_total,"services_limit":128,"services_truncated":services_total>128,"maximum_bytes":65536});
    while serde_json::to_vec(&result).is_ok_and(|bytes| bytes.len() > 65536) {
        let processes = result["processes"]
            .as_array_mut()
            .expect("process snapshot array");
        if !processes.is_empty() {
            processes.pop();
            result["truncated"] = json!(true);
        } else if let Some(services) = result["services"].as_array_mut()
            && !services.is_empty()
        {
            services.pop();
            result["services_truncated"] = json!(true);
        } else {
            break;
        }
    }
    result
}

#[derive(Default)]
pub(super) struct Pressure {
    last_cpu: Option<Vec<u64>>,
}
impl Pressure {
    pub(super) fn sample(&mut self) -> Value {
        let counters = std::fs::read_to_string("/proc/stat").ok().and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("cpu "))
                .map(|line| {
                    line.split_whitespace()
                        .skip(1)
                        .take(8)
                        .filter_map(|field| field.parse::<u64>().ok())
                        .collect::<Vec<_>>()
                })
        });
        let (steal, iowait) = if let (Some(current), Some(previous)) = (&counters, &self.last_cpu) {
            let differences: Vec<_> = current
                .iter()
                .zip(previous)
                .map(|(current, previous)| current.checked_sub(*previous))
                .collect();
            let total = differences
                .iter()
                .try_fold(0u64, |total, difference| total.checked_add((*difference)?));
            (
                total.filter(|total| *total > 0).and_then(|total| {
                    differences
                        .get(7)
                        .copied()
                        .flatten()
                        .map(|steal| steal as f64 * 100.0 / total as f64)
                }),
                total.filter(|total| *total > 0).and_then(|total| {
                    differences
                        .get(4)
                        .copied()
                        .flatten()
                        .map(|wait| wait as f64 * 100.0 / total as f64)
                }),
            )
        } else {
            (None, None)
        };
        self.last_cpu = counters;
        let mut psi = serde_json::Map::new();
        for resource in ["cpu", "memory", "io"] {
            let value = std::fs::read_to_string(format!("/proc/pressure/{resource}"))
                .ok()
                .map(|text| {
                    text.lines()
                        .map(|line| {
                            let mut fields = line.split_whitespace();
                            let kind = fields.next().unwrap_or("unknown");
                            let values: serde_json::Map<String, Value> = fields
                                .filter_map(|field| {
                                    let (key, value) = field.split_once('=')?;
                                    Some((
                                        key.to_owned(),
                                        value.parse::<f64>().ok().filter(|v| v.is_finite())?.into(),
                                    ))
                                })
                                .collect();
                            (kind.to_owned(), Value::Object(values))
                        })
                        .collect::<serde_json::Map<_, _>>()
                });
            psi.insert(
                resource.into(),
                value.map(Value::Object).unwrap_or(Value::Null),
            );
        }
        let oom_kill = std::fs::read_to_string("/proc/vmstat")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("oom_kill ")?.trim().parse::<u64>().ok())
            });
        json!({"cpu_steal_percent":steal,"io_wait_percent":iowait,"psi":psi,"oom_kill_count":oom_kill,"boot_id":std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok().map(|v|v.trim().to_owned()),"source":if cfg!(target_os="linux"){"linux_procfs"}else{"unavailable"},"unsupported_is_zero":false})
    }
}
