pub(crate) mod cache;
mod disks;
mod hardware;
mod outbox;
mod resources;
pub mod worker;

use sinan_protocol::{DiskMetrics, Metrics, NetworkMetrics, StaticInfo};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Instant,
};
use sysinfo::{Disk, Networks, ProcessRefreshKind, ProcessesToUpdate, System};

type NetworkTotals = BTreeMap<String, (u64, u64)>;
type DiskTotals = BTreeMap<(String, String), (u64, u64)>;

pub struct Collector {
    system: System,
    disks: Vec<Disk>,
    networks: Networks,
    last_cpu: Option<Instant>,
    pressure: resources::Pressure,
    last_network: Option<(Instant, NetworkTotals)>,
    last_disks: Option<(Instant, DiskTotals)>,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        Self {
            system,
            disks: disks::refresh(),
            networks: Networks::new_with_refreshed_list(),
            last_cpu: None,
            pressure: resources::Pressure::default(),
            last_network: None,
            last_disks: None,
        }
    }

    pub fn static_info(&self) -> StaticInfo {
        StaticInfo {
            os: Some(std::env::consts::OS.into()),
            libc: if cfg!(target_os = "linux") {
                Some(
                    if cfg!(target_env = "musl") {
                        "musl"
                    } else {
                        "gnu"
                    }
                    .into(),
                )
            } else {
                None
            },
            runtime_libc: crate::runtime_platform::libc().map(str::to_owned),
            system: System::long_os_version().or_else(System::name),
            kernel: System::kernel_version(),
            arch: Some(std::env::consts::ARCH.into()),
            cpu_model: self
                .system
                .cpus()
                .first()
                .map(|cpu| cpu.brand().to_string())
                .filter(|value| !value.is_empty()),
            cpu_cores: u32::try_from(self.system.cpus().len())
                .ok()
                .filter(|count| *count > 0),
            memory_total: positive(self.system.total_memory()),
            disk_total: disks::totals(&self.disks).map(|(total, _)| total),
            virtualization: virtualization(),
            hostname: System::host_name(),
            agent_version: None,
            interface_addresses: self
                .networks
                .iter()
                .map(|(name, network)| {
                    (
                        name.clone(),
                        normalized_addresses(
                            network.ip_networks().iter().map(|address| address.addr),
                        ),
                    )
                })
                .collect(),
            ip_addresses: normalized_addresses(
                self.networks
                    .values()
                    .flat_map(|network| network.ip_networks().iter().map(|address| address.addr)),
            ),
            ..StaticInfo::default()
        }
    }

    pub fn metrics(&mut self) -> Metrics {
        let now = Instant::now();
        self.system.refresh_cpu_all();
        self.system.refresh_memory();
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage(),
        );
        // Fresh inventories do not retain measurements after a failed refresh.
        self.disks = disks::refresh();
        self.networks = Networks::new_with_refreshed_list();
        let cpu = self
            .last_cpu
            .filter(|previous| {
                now.duration_since(*previous) >= sysinfo::MINIMUM_CPU_UPDATE_INTERVAL
            })
            .filter(|_| !self.system.cpus().is_empty())
            .map(|_| f64::from(self.system.global_cpu_usage()))
            .filter(|value| value.is_finite());
        let process_elapsed = self
            .last_cpu
            .map(|previous| now.duration_since(previous).as_secs_f64())
            .filter(|seconds| *seconds > 0.0);
        self.last_cpu = Some(now);
        let totals: BTreeMap<_, _> = self
            .networks
            .iter()
            .map(|(name, data)| {
                (
                    name.clone(),
                    (data.total_received(), data.total_transmitted()),
                )
            })
            .collect();
        let interfaces = totals
            .iter()
            .map(|(name, &(received, transmitted))| {
                let previous = self
                    .last_network
                    .as_ref()
                    .and_then(|(time, previous)| previous.get(name).map(|values| (*time, *values)));
                let (receive_rate, transmit_rate) =
                    previous.map_or((None, None), |(time, (rx, tx))| {
                        let elapsed = now.duration_since(time).as_secs_f64();
                        if elapsed <= 0.0 {
                            return (None, None);
                        }
                        (
                            received.checked_sub(rx).map(|value| value as f64 / elapsed),
                            transmitted
                                .checked_sub(tx)
                                .map(|value| value as f64 / elapsed),
                        )
                    });
                (
                    name.clone(),
                    NetworkMetrics {
                        received_bytes: Some(received),
                        transmitted_bytes: Some(transmitted),
                        receive_bytes_per_sec: receive_rate,
                        transmit_bytes_per_sec: transmit_rate,
                    },
                )
            })
            .collect();
        self.last_network = Some((now, totals));
        let mut disk_counts = BTreeMap::new();
        let disks = self
            .disks
            .iter()
            .map(|disk| {
                let name = disk.name().to_string_lossy().into_owned();
                let usage = disk.usage();
                let current = (usage.total_read_bytes, usage.total_written_bytes);
                let mount_point = disk.mount_point().to_string_lossy().into_owned();
                let key = (name.clone(), mount_point.clone());
                let previous = self
                    .last_disks
                    .as_ref()
                    .and_then(|(time, values)| values.get(&key).map(|counts| (*time, *counts)));
                let rates = previous.and_then(|(time, (read, written))| {
                    let elapsed = now.duration_since(time).as_secs_f64();
                    (elapsed > 0.0).then(|| {
                        (
                            current.0.checked_sub(read).map(|v| v as f64 / elapsed),
                            current.1.checked_sub(written).map(|v| v as f64 / elapsed),
                        )
                    })
                });
                disk_counts.insert(key, current);
                DiskMetrics {
                    name,
                    mount_point,
                    total_bytes: positive(disk.total_space()),
                    used_bytes: disk.total_space().checked_sub(disk.available_space()),
                    read_bytes_per_sec: rates.and_then(|v| v.0),
                    write_bytes_per_sec: rates.and_then(|v| v.1),
                    ..DiskMetrics::default()
                }
            })
            .collect();
        self.last_disks = Some((now, disk_counts));
        let load = load_average();
        let mut metrics = Metrics {
            swap_total: Some(self.system.total_swap()),
            swap_used: Some(self.system.used_swap()),
            processes: u64::try_from(self.system.processes().len()).ok(),
            disks,
            cpu_percent: cpu,
            memory_used: positive(self.system.total_memory()).map(|_| self.system.used_memory()),
            load_1: load.map(|value| value.0),
            load_5: load.map(|value| value.1),
            load_15: load.map(|value| value.2),
            disk_used: disks::totals(&self.disks).map(|(_, used)| used),
            network_interfaces: interfaces,
            tcp_connections: connection_count("tcp"),
            udp_connections: connection_count("udp"),
            uptime_secs: positive(System::uptime()),
            ..Metrics::default()
        };
        // Snapshot capacities with each measurement; using present-day host
        // metadata to normalize old samples would rewrite historical usage.
        if let Some(total) = positive(self.system.total_memory()) {
            metrics.extra.insert("memory_total".into(), total.into());
        }
        if let Some((total, _)) = disks::totals(&self.disks) {
            metrics.extra.insert("disk_total".into(), total.into());
        }
        metrics.extra.insert(
            "process_resources".into(),
            resources::processes(&self.system, cpu.is_some(), process_elapsed),
        );
        metrics
            .extra
            .insert("system_pressure".into(), self.pressure.sample());
        let mounts: BTreeMap<String, bool> = std::fs::read_to_string("/proc/mounts")
            .ok()
            .into_iter()
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        (fields.len() >= 4 && fields[0].starts_with("/dev/")).then(|| {
                            (
                                fields[1].to_owned(),
                                fields[3].split(',').any(|option| option == "ro"),
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        metrics
            .extra
            .insert("disk_mount_read_only".into(), serde_json::json!(mounts));
        let inventory: Vec<_> = self.networks.keys().map(|name| serde_json::json!({"name":name,"physical":std::path::Path::new(&format!("/sys/class/net/{name}/device")).exists(),"loopback":name=="lo","duplicate_risk":name!="lo"&&!std::path::Path::new(&format!("/sys/class/net/{name}/device")).exists()})).collect();
        metrics
            .extra
            .insert("network_inventory".into(), inventory.into());
        metrics
    }
}

pub(crate) fn normalized_addresses(addresses: impl IntoIterator<Item = IpAddr>) -> Vec<String> {
    addresses
        .into_iter()
        .map(|address| match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        })
        .filter(|address| {
            !address.is_unspecified() && !address.is_multicast() && !address.is_loopback()
        })
        .filter(|address| match address {
            IpAddr::V4(address) => !address.is_link_local() && !address.is_broadcast(),
            IpAddr::V6(address) => !address.is_unicast_link_local(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

fn positive(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

fn load_average() -> Option<(f64, f64, f64)> {
    #[cfg(target_os = "linux")]
    {
        let value = std::fs::read_to_string("/proc/loadavg").ok()?;
        let mut fields = value.split_whitespace();
        Some((
            fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?,
            fields.next()?.parse().ok()?,
        ))
    }
    #[cfg(target_os = "windows")]
    {
        None
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let load = System::load_average();
        (load.one.is_finite() && load.five.is_finite() && load.fifteen.is_finite()).then_some((
            load.one,
            load.five,
            load.fifteen,
        ))
    }
}

fn connection_count(protocol: &str) -> Option<u64> {
    let ipv4 = std::fs::read_to_string(format!("/proc/net/{protocol}")).ok()?;
    let ipv6 = std::fs::read_to_string(format!("/proc/net/{protocol}6")).ok()?;
    u64::try_from(
        ipv4.lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .count()
            + ipv6
                .lines()
                .skip(1)
                .filter(|line| !line.trim().is_empty())
                .count(),
    )
    .ok()
}

fn virtualization() -> Option<String> {
    let cgroups = std::fs::read_to_string("/proc/1/cgroup").unwrap_or_default();
    for name in ["docker", "kubepods", "lxc"] {
        if cgroups.contains(name) {
            return Some(name.into());
        }
    }
    let product = std::fs::read_to_string("/sys/class/dmi/id/product_name")
        .ok()?
        .to_lowercase();
    for (pattern, name) in [
        ("kvm", "KVM"),
        ("qemu", "QEMU"),
        ("vmware", "VMware"),
        ("virtualbox", "VirtualBox"),
        ("virtual machine", "Virtual machine"),
    ] {
        if product.contains(pattern) {
            return Some(name.into());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_omits_unavailable_deltas() {
        let mut collector = Collector::new();
        let metrics = collector.metrics();
        assert!(metrics.cpu_percent.is_none());
        assert!(
            metrics
                .network_interfaces
                .values()
                .all(|value| value.receive_bytes_per_sec.is_none()
                    && value.transmit_bytes_per_sec.is_none())
        );
        let encoded = serde_json::to_value(metrics).unwrap();
        assert!(encoded.get("cpu_percent").is_none());
    }

    #[test]
    fn reported_addresses_are_canonical_deduplicated_and_exclude_local_noise() {
        let addresses = normalized_addresses(
            [
                "::1",
                "127.0.0.1",
                "0.0.0.0",
                "224.0.0.1",
                "fe80::1",
                "169.254.0.1",
                "192.0.2.1",
                "192.0.2.1",
                "2001:0db8:0:0:0:0:0:1",
                "10.0.0.2",
            ]
            .map(|value| value.parse().unwrap()),
        );
        assert_eq!(addresses, vec!["10.0.0.2", "192.0.2.1", "2001:db8::1"]);
    }
}
