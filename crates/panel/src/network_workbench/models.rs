use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Ipv4,
    Ipv6,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Panel,
    Server { server_id: i64 },
    Group { server_ids: Vec<i64> },
}
impl Source {
    pub fn servers(&self) -> Vec<i64> {
        match self {
            Self::Panel => vec![],
            Self::Server { server_id } => vec![*server_id],
            Self::Group { server_ids } => server_ids.clone(),
        }
    }
    pub fn valid(&self) -> bool {
        let ids = self.servers();
        ids.len() <= 16
            && ids.iter().all(|v| *v > 0)
            && {
                let mut copy = ids.clone();
                copy.sort();
                copy.dedup();
                copy.len() == ids.len()
            }
            && !matches!(self,Self::Group { server_ids } if server_ids.is_empty())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub duration_secs: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub traffic_bytes: u64,
    pub rate_bps: u64,
    pub concurrency: u8,
    pub cpu_percent: u8,
    #[serde(default = "default_cpu_weight")]
    pub cpu_weight: u16,
    pub pause_on_service_error: bool,
}
fn default_cpu_weight() -> u16 {
    20
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            duration_secs: 60,
            memory_bytes: 64 * 1024 * 1024,
            disk_bytes: 128 * 1024 * 1024,
            traffic_bytes: 256 * 1024 * 1024,
            rate_bps: 20_000_000,
            concurrency: 1,
            cpu_percent: 20,
            cpu_weight: default_cpu_weight(),
            pause_on_service_error: true,
        }
    }
}
impl Budget {
    pub fn validate(&self) -> ApiResult<()> {
        if !(1..=3600).contains(&self.duration_secs)
            || !(16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&self.memory_bytes)
            || self.disk_bytes > 8 * 1024 * 1024 * 1024
            || self.traffic_bytes > 16 * 1024 * 1024 * 1024
            || self.rate_bps > 1_000_000_000
            || !(1..=4).contains(&self.concurrency)
            || !(1..=80).contains(&self.cpu_percent)
            || !(1..=100).contains(&self.cpu_weight)
        {
            return Err(ApiError::BadRequest("预算超出允许范围".into()));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub region: String,
    pub carrier: String,
    pub purpose: String,
    pub authorization: String,
    pub authorized_until: Option<i64>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    Tcp {
        target_id: Uuid,
        port: u16,
        family: Family,
        samples: u8,
    },
    Icmp {
        target_id: Uuid,
        family: Family,
        samples: u8,
        packet_bytes: u16,
    },
    Http {
        target_id: Uuid,
        url: String,
        family: Family,
        expected_status: u16,
        expected_content: Option<String>,
        follow_redirects: bool,
    },
    Dns {
        target_id: Uuid,
        resolvers: Vec<String>,
        record_type: String,
        expected: Vec<String>,
        family: Family,
    },
    Tls {
        target_id: Uuid,
        port: u16,
        server_name: String,
        family: Family,
    },
    Udp {
        target_id: Uuid,
        port: u16,
        family: Family,
        request_hex: String,
        expected_hex: String,
        protocol: String,
    },
    Quic {
        target_id: Uuid,
        url: String,
        family: Family,
        tool_version: String,
        expected_status: u16,
    },
    GeekbenchImport {
        tool_version: String,
        major_version: u16,
        platform: String,
    },
    HardwareInfo {
        tool_version: String,
        device: String,
    },
    WebSocket {
        target_id: Uuid,
        url: String,
        family: Family,
        hold_secs: u16,
    },
    Route {
        target_id: Uuid,
        family: Family,
        protocol: String,
        port: u16,
        tool: String,
        tool_version: String,
        max_hops: u8,
        reverse_server: Option<i64>,
    },
    Mtr {
        target_id: Uuid,
        family: Family,
        protocol: String,
        port: u16,
        tool_version: String,
        samples: u8,
    },
    Throughput {
        client_mode: String,
        receiver_server: i64,
        receiver_host: String,
        port: u16,
        family: Family,
        direction: String,
        protocol: String,
        streams: u8,
        duration_secs: u16,
        rate_bps: u64,
        tool_version: String,
        latency_target: Option<String>,
    },
    Cpu {
        tool_version: String,
        threads: u16,
        duration_secs: u16,
    },
    Memory {
        tool_version: String,
        block_bytes: u64,
        total_bytes: u64,
        operation: String,
    },
    Disk {
        tool_version: String,
        directory: String,
        file_bytes: u64,
        block_bytes: u32,
        queue_depth: u16,
        mode: String,
        read_percent: u8,
        duration_secs: u16,
    },
    Stability {
        tool_version: String,
        cpu_workers: u8,
        memory_bytes: u64,
        io_workers: u8,
        duration_secs: u16,
    },
    Exit {
        discovery_url: String,
        family: Family,
        route_kind: String,
        proxy_url: Option<String>,
    },
    IpInfo {
        address: String,
        family: Family,
        provider_ids: Vec<Uuid>,
    },
    Mail {
        target_id: Uuid,
        domain: String,
        selector: String,
        resolvers: Vec<String>,
        ports: Vec<u16>,
        family: Family,
    },
    Speedtest {
        tool_version: String,
        server_id: Option<u64>,
        license_acknowledged: bool,
    },
    NodeQualityFull,
}
impl Check {
    pub fn target(&self) -> Option<Uuid> {
        match self {
            Self::Tcp { target_id, .. }
            | Self::Icmp { target_id, .. }
            | Self::Http { target_id, .. }
            | Self::Dns { target_id, .. }
            | Self::Tls { target_id, .. }
            | Self::Udp { target_id, .. }
            | Self::WebSocket { target_id, .. }
            | Self::Quic { target_id, .. }
            | Self::Route { target_id, .. }
            | Self::Mtr { target_id, .. }
            | Self::Mail { target_id, .. } => Some(*target_id),
            _ => None,
        }
    }
    pub fn tool(&self) -> Option<(&str, &str)> {
        match self {
            Self::Quic { tool_version, .. } => Some(("curl", tool_version)),
            Self::HardwareInfo { tool_version, .. } => Some(("smartctl", tool_version)),
            Self::Route {
                tool, tool_version, ..
            } => Some((tool, tool_version)),
            Self::Mtr { tool_version, .. } => Some(("mtr", tool_version)),
            Self::Throughput { tool_version, .. } => Some(("iperf3", tool_version)),
            Self::Cpu { tool_version, .. } | Self::Memory { tool_version, .. } => {
                Some(("sysbench", tool_version))
            }
            Self::Disk { tool_version, .. } => Some(("fio", tool_version)),
            Self::Stability { tool_version, .. } => Some(("stress-ng", tool_version)),
            Self::Speedtest { tool_version, .. } => Some(("speedtest", tool_version)),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::GeekbenchImport { .. } => "Geekbench获准导入",
            Self::Quic { .. } => "QUIC有效请求",
            Self::HardwareInfo { .. } => "硬件健康",
            Self::Tcp { .. } => "TCP连接",
            Self::Icmp { .. } => "ICMP延迟",
            Self::Http { .. } => "HTTP可用性",
            Self::Dns { .. } => "DNS解析",
            Self::Tls { .. } => "TLS证书",
            Self::Udp { .. } => "UDP有效请求",
            Self::WebSocket { .. } => "WebSocket长连接",
            Self::Route { .. } => "路由路径",
            Self::Mtr { .. } => "MTR采样",
            Self::Throughput { .. } => "双端吞吐",
            Self::Cpu { .. } => "CPU验机",
            Self::Memory { .. } => "内存验机",
            Self::Disk { .. } => "磁盘验机",
            Self::Stability { .. } => "持续负载",
            Self::Exit { .. } => "出口发现",
            Self::IpInfo { .. } => "多来源IP资料",
            Self::Mail { .. } => "邮件配置",
            Self::Speedtest { .. } => "Speedtest",
            Self::NodeQualityFull => "NodeQuality完整验机",
        }
    }
    pub fn validate(&self, budget: &Budget) -> ApiResult<()> {
        let valid = match self {
            Self::GeekbenchImport {
                tool_version,
                major_version,
                platform,
            } => {
                *major_version > 0
                    && *major_version <= 32
                    && !platform.is_empty()
                    && tool_version
                        .split('.')
                        .next()
                        .and_then(|v| v.parse::<u16>().ok())
                        == Some(*major_version)
            }
            Self::Quic {
                url,
                expected_status,
                ..
            } => valid_url(url, &["https"]) && (100..=599).contains(expected_status),
            Self::HardwareInfo { device, .. } => {
                device.starts_with("/dev/") && !device.contains("..") && device.len() < 128
            }
            Self::Tcp { port, samples, .. } => *port > 0 && (1..=32).contains(samples),
            Self::Icmp {
                samples,
                packet_bytes,
                ..
            } => (1..=32).contains(samples) && (16..=1400).contains(packet_bytes),
            Self::Http {
                url,
                expected_status,
                expected_content,
                ..
            } => {
                valid_url(url, &["http", "https"])
                    && (100..=599).contains(expected_status)
                    && expected_content.as_ref().is_none_or(|v| v.len() <= 4096)
            }
            Self::Dns {
                resolvers,
                record_type,
                expected,
                ..
            } => {
                valid_resolvers(resolvers)
                    && ["A", "AAAA", "TXT", "MX", "NS", "PTR", "CNAME", "SOA"]
                        .contains(&record_type.as_str())
                    && expected.len() <= 16
            }
            Self::Tls {
                port, server_name, ..
            } => *port > 0 && valid_host(server_name),
            Self::Udp {
                port,
                request_hex,
                expected_hex,
                protocol,
                ..
            } => {
                *port > 0
                    && valid_hex(request_hex)
                    && valid_hex(expected_hex)
                    && ["dns", "echo", "custom_authorized"].contains(&protocol.as_str())
                    && (protocol != "dns" || request_hex.len() >= 24)
            }
            Self::WebSocket { url, hold_secs, .. } => {
                valid_url(url, &["ws", "wss"])
                    && *hold_secs > 0
                    && u32::from(*hold_secs) <= budget.duration_secs
            }
            Self::Route {
                protocol,
                tool,
                max_hops,
                port,
                reverse_server,
                ..
            } => {
                ["icmp", "tcp", "udp"].contains(&protocol.as_str())
                    && ["nexttrace", "traceroute"].contains(&tool.as_str())
                    && (1..=64).contains(max_hops)
                    && *port > 0
                    && reverse_server.is_none_or(|v| v > 0)
            }
            Self::Mtr {
                protocol,
                port,
                samples,
                ..
            } => {
                ["icmp", "tcp", "udp"].contains(&protocol.as_str())
                    && *port > 0
                    && (1..=100).contains(samples)
                    && u32::from(*samples) <= budget.duration_secs
            }
            Self::Throughput {
                client_mode,
                receiver_server,
                receiver_host,
                port,
                direction,
                protocol,
                streams,
                duration_secs,
                rate_bps,
                ..
            } => {
                ["managed", "local"].contains(&client_mode.as_str())
                    && *receiver_server > 0
                    && valid_host(receiver_host)
                    && *port >= 1024
                    && ["forward", "reverse", "bidirectional"].contains(&direction.as_str())
                    && ["tcp", "udp"].contains(&protocol.as_str())
                    && (1..=8).contains(streams)
                    && *duration_secs > 0
                    && u32::from(*duration_secs) <= budget.duration_secs
                    && *rate_bps > 0
                    && *rate_bps <= budget.rate_bps
                    && rate_bps
                        .saturating_mul(u64::from(*duration_secs))
                        .saturating_mul(u64::from(*streams))
                        .saturating_mul(if direction == "bidirectional" { 2 } else { 1 })
                        / 8
                        <= budget.traffic_bytes
            }
            Self::Cpu {
                threads,
                duration_secs,
                ..
            } => {
                (1..=32).contains(threads)
                    && *duration_secs > 0
                    && u32::from(*duration_secs) <= budget.duration_secs
            }
            Self::Memory {
                block_bytes,
                total_bytes,
                operation,
                ..
            } => {
                *block_bytes >= 1024
                    && *block_bytes <= budget.memory_bytes
                    && *total_bytes > 0
                    && *total_bytes <= 16 * 1024 * 1024 * 1024
                    && ["read", "write"].contains(&operation.as_str())
            }
            Self::Disk {
                directory,
                file_bytes,
                block_bytes,
                queue_depth,
                mode,
                read_percent,
                duration_secs,
                ..
            } => {
                directory.starts_with('/')
                    && !directory.split('/').any(|v| v == "..")
                    && !directory.starts_with("/dev")
                    && *file_bytes > 0
                    && *file_bytes <= budget.disk_bytes
                    && (512..=1024 * 1024).contains(block_bytes)
                    && block_bytes.is_power_of_two()
                    && (1..=64).contains(queue_depth)
                    && ["read", "write", "randread", "randwrite", "randrw"].contains(&mode.as_str())
                    && *read_percent <= 100
                    && *duration_secs > 0
                    && u32::from(*duration_secs) <= budget.duration_secs
            }
            Self::Stability {
                cpu_workers,
                memory_bytes,
                io_workers,
                duration_secs,
                ..
            } => {
                *cpu_workers <= 8
                    && *memory_bytes <= budget.memory_bytes / 2
                    && *io_workers <= 2
                    && (*cpu_workers > 0 || *memory_bytes > 0 || *io_workers > 0)
                    && *duration_secs > 0
                    && u32::from(*duration_secs) <= budget.duration_secs
            }
            Self::Exit {
                discovery_url,
                route_kind,
                proxy_url,
                ..
            } => {
                valid_url(discovery_url, &["https"])
                    && ((route_kind == "nat_public" && proxy_url.is_none())
                        || (route_kind == "proxy_chain"
                            && proxy_url.as_ref().is_some_and(|value| {
                                reqwest::Url::parse(value).is_ok_and(|url| {
                                    url.scheme() == "http"
                                        && url.host_str().is_some_and(|host| {
                                            host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
                                        })
                                        && url.username().is_empty()
                                        && url.password().is_none()
                                        && url.port().is_some()
                                })
                            })))
            }
            Self::IpInfo {
                address,
                family,
                provider_ids,
            } => {
                address.parse::<IpAddr>().is_ok_and(|ip| {
                    matches!(
                        (ip, family),
                        (IpAddr::V4(_), Family::Ipv4) | (IpAddr::V6(_), Family::Ipv6)
                    )
                }) && !provider_ids.is_empty()
                    && provider_ids.len() <= 8
            }
            Self::Mail {
                domain,
                selector,
                resolvers,
                ports,
                ..
            } => {
                valid_host(domain)
                    && valid_host(selector)
                    && valid_resolvers(resolvers)
                    && !ports.is_empty()
                    && ports.len() <= 8
                    && ports.iter().all(|v| [25, 465, 587, 993, 995].contains(v))
            }
            Self::Speedtest {
                license_acknowledged,
                ..
            } => *license_acknowledged,
            Self::NodeQualityFull => {
                return Err(ApiError::Conflict(
                    crate::diagnostic_plugins::nodequality::FULL_START_DENIAL.into(),
                ));
            }
        };
        if !valid {
            return Err(ApiError::BadRequest(format!(
                "{}参数不合法或超过预算",
                self.name()
            )));
        }
        if let Some((_, version)) = self.tool()
            && (version.is_empty() || version.len() > 128 || version.chars().any(char::is_control))
        {
            return Err(ApiError::BadRequest("必须选择明确的工具版本".into()));
        }
        Ok(())
    }
}
fn valid_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2400
        && value.len().is_multiple_of(2)
        && value.bytes().all(|v| v.is_ascii_hexdigit())
}
fn valid_resolvers(value: &[String]) -> bool {
    !value.is_empty() && value.len() <= 8 && value.iter().all(|v| v.parse::<IpAddr>().is_ok())
}
pub fn valid_host(value: &str) -> bool {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return !ip.is_unspecified() && !ip.is_multicast();
    }
    !value.is_empty()
        && value.len() <= 253
        && value.trim_end_matches('.').split('.').all(|v| {
            !v.is_empty()
                && v.len() <= 63
                && !v.starts_with('-')
                && !v.ends_with('-')
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub fn valid_url(value: &str, schemes: &[&str]) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        schemes.contains(&url.scheme())
            && url.host_str().is_some_and(valid_host)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub name: String,
    pub source: Source,
    pub check: Check,
    pub stop_on_failure: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub name: String,
    pub budget: Budget,
    pub steps: Vec<Step>,
    pub schedule: Option<Schedule>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub interval_secs: u32,
    pub first_run_at: i64,
    pub timezone: String,
    pub missed_window: String,
}
impl Plan {
    pub fn validate(&self) -> ApiResult<()> {
        self.budget.validate()?;
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || self.steps.is_empty()
            || self.steps.len() > 16
        {
            return Err(ApiError::BadRequest("测试方案必须包含1–16个步骤".into()));
        }
        let mut throughput_total = 0u64;
        for step in &self.steps {
            if step.name.is_empty() || step.name.len() > 128 || !step.source.valid() {
                return Err(ApiError::BadRequest("步骤名称或探测来源无效".into()));
            }
            step.check.validate(&self.budget)?;
            if matches!(step.check, Check::IpInfo { .. }) && !matches!(step.source, Source::Panel) {
                return Err(ApiError::BadRequest(
                    "IP资料查询在面板执行，出口实际发现请另选Agent步骤".into(),
                ));
            }
            if let Check::Throughput {
                rate_bps,
                duration_secs,
                streams,
                direction,
                ..
            } = &step.check
            {
                throughput_total = throughput_total.saturating_add(
                    rate_bps
                        .saturating_mul(u64::from(*duration_secs))
                        .saturating_mul(u64::from(*streams))
                        .saturating_mul(if direction == "bidirectional" { 2 } else { 1 })
                        / 8,
                );
            }
            if matches!(step.source, Source::Panel)
                && !matches!(
                    step.check,
                    Check::Tcp { .. } | Check::Http { .. } | Check::IpInfo { .. }
                )
                && !matches!(&step.check,Check::Throughput{client_mode,..} if client_mode=="local")
            {
                return Err(ApiError::Conflict(
                    "此项目需由具备能力的Agent执行，不能将面板来源冒充Agent结果".into(),
                ));
            }
            if let Check::Throughput {
                client_mode,
                receiver_server,
                ..
            } = &step.check
                && ((client_mode == "managed"
                    && (step.source.servers().len() != 1
                        || step.source.servers().contains(receiver_server)))
                    || (client_mode == "local" && !matches!(step.source, Source::Panel)))
            {
                return Err(ApiError::BadRequest(
                    "吞吐测试必须选择两台不同受管服务器".into(),
                ));
            }
        }
        if throughput_total > self.budget.traffic_bytes {
            return Err(ApiError::BadRequest(
                "方案所有吞吐步骤累计发送量超过总流量预算".into(),
            ));
        }
        if let Some(schedule) = &self.schedule
            && (!(300..=31_536_000).contains(&schedule.interval_secs)
                || schedule.first_run_at <= 0
                || schedule.timezone.is_empty()
                || !["skip", "run_once"].contains(&schedule.missed_window.as_str()))
        {
            return Err(ApiError::BadRequest("计划时间与错过窗口策略无效".into()));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub schema: u32,
    pub source_server: Option<i64>,
    pub target: Option<Target>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_target: Option<Target>,
    pub check: Check,
    pub budget: Budget,
    pub role: String,
    pub source_label: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: u32,
    pub source: String,
    pub target: String,
    pub method: String,
    pub tool: String,
    pub tool_version: String,
    pub parameters: serde_json::Value,
    pub collected_at: i64,
    pub status: String,
    pub data: serde_json::Value,
    pub raw_output: String,
    pub error: Option<String>,
    pub cleanup: Cleanup,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
    pub process_stopped: bool,
    pub files_removed: bool,
    pub listeners_closed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_hard_cap_and_contention_weight_are_independent_and_legacy_weight_defaults() {
        let mut encoded = serde_json::to_value(Budget::default()).unwrap();
        encoded.as_object_mut().unwrap().remove("cpu_weight");
        encoded["cpu_percent"] = serde_json::json!(25);
        let mut budget: Budget = serde_json::from_value(encoded).unwrap();
        assert_eq!(budget.cpu_weight, 20);
        assert_eq!(budget.cpu_percent, 25);
        budget.cpu_weight = 100;
        assert!(budget.validate().is_ok());
        budget.cpu_weight = 101;
        assert!(budget.validate().is_err());
        budget.cpu_weight = 20;
        budget.cpu_percent = 81;
        assert!(budget.validate().is_err());
    }
    #[test]
    fn multistream_bidirectional_budget_accounts_for_both_senders() {
        let budget = Budget::default();
        let check = Check::Throughput {
            client_mode: "managed".into(),
            receiver_server: 2,
            receiver_host: "192.0.2.2".into(),
            port: 5201,
            family: Family::Ipv4,
            direction: "bidirectional".into(),
            protocol: "udp".into(),
            streams: 8,
            duration_secs: 60,
            rate_bps: 20_000_000,
            tool_version: "3.16".into(),
            latency_target: None,
        };
        assert!(check.validate(&budget).is_err());
    }
    #[test]
    fn disk_device_writes_and_identity_cloning_are_not_valid_steps() {
        let check = Check::Disk {
            tool_version: "3.38".into(),
            directory: "/dev/sda".into(),
            file_bytes: 1024,
            block_bytes: 4096,
            queue_depth: 1,
            mode: "write".into(),
            read_percent: 0,
            duration_secs: 1,
        };
        assert!(check.validate(&Budget::default()).is_err());
        assert!(
            !Source::Group {
                server_ids: vec![1, 1]
            }
            .valid()
        );
    }
    #[test]
    fn udp_requires_valid_request_and_response_expectation() {
        let check = Check::Udp {
            target_id: Uuid::new_v4(),
            port: 53,
            family: Family::Ipv4,
            request_hex: "abcd".into(),
            expected_hex: String::new(),
            protocol: "dns".into(),
        };
        assert!(check.validate(&Budget::default()).is_err());
    }
    #[test]
    fn full_start_gate_is_not_replaced_by_a_composite_plan() {
        assert!(Check::NodeQualityFull.validate(&Budget::default()).is_err());
    }
}
