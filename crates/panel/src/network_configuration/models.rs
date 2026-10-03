use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use std::{collections::BTreeMap, net::IpAddr};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Configuration {
    Domain {
        name: String,
        server_ids: Vec<i64>,
        ddns_rule_ids: Vec<Uuid>,
        applications: Vec<String>,
        maintainer: String,
        notes: String,
    },
    Certificate {
        name: String,
        domain_ids: Vec<Uuid>,
        maintainer: String,
        issuer: String,
        targets: Vec<CertificateTarget>,
        renewal: RenewalPolicy,
    },
    Endpoint {
        name: String,
        server_id: Option<i64>,
        listen_address: String,
        public_address: Option<String>,
        port: u16,
        protocol: String,
        owner: String,
        notes: String,
    },
    Forwarding {
        name: String,
        server_id: i64,
        listen_address: String,
        listen_port: u16,
        target_address: String,
        target_port: u16,
        protocol: String,
        owner: String,
        enabled: bool,
        dependency_ids: Vec<Uuid>,
    },
    Tuning {
        name: String,
        server_id: i64,
        parameters: BTreeMap<String, String>,
        restore_after_secs: u32,
        purpose: String,
    },
    Tunnel {
        name: String,
        server_id: i64,
        relay_address: String,
        relay_port: u16,
        relay_account: String,
        relay_host_key: String,
        listen_address: String,
        listen_port: u16,
        target_address: String,
        target_port: u16,
        enabled: bool,
    },
    Mesh {
        name: String,
        server_id: i64,
        address: String,
        listen_port: u16,
        peers: Vec<MeshPeer>,
    },
    Firewall {
        name: String,
        server_id: i64,
        rules: Vec<FirewallRule>,
        management_ports: Vec<u16>,
        restore_after_secs: u32,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MeshPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: u16,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FirewallRule {
    pub source: String,
    pub protocol: String,
    pub port: u16,
    pub action: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CertificateTarget {
    pub server_id: i64,
    pub service: String,
    pub domain: String,
    pub port: u16,
    #[serde(default)]
    pub certificate_path: Option<String>,
    #[serde(default)]
    pub private_key_path: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RenewalPolicy {
    External {
        responsibility: String,
    },
    Dns01 {
        ddns_rule_id: Uuid,
        responsibility: String,
    },
}

impl Configuration {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Domain { .. } => "domain",
            Self::Certificate { .. } => "certificate",
            Self::Endpoint { .. } => "endpoint",
            Self::Forwarding { .. } => "forwarding",
            Self::Tuning { .. } => "tuning",
            Self::Tunnel { .. } => "tunnel",
            Self::Mesh { .. } => "mesh",
            Self::Firewall { .. } => "firewall",
        }
    }

    pub fn servers(&self) -> Vec<i64> {
        match self {
            Self::Domain { server_ids, .. } => server_ids.clone(),
            Self::Certificate { targets, .. } => {
                targets.iter().map(|target| target.server_id).collect()
            }
            Self::Endpoint { server_id, .. } => server_id.iter().copied().collect(),
            Self::Forwarding { server_id, .. }
            | Self::Tuning { server_id, .. }
            | Self::Tunnel { server_id, .. }
            | Self::Mesh { server_id, .. }
            | Self::Firewall { server_id, .. } => vec![*server_id],
        }
    }

    pub fn validate(&mut self) -> ApiResult<()> {
        match self {
            Self::Domain {
                name,
                server_ids,
                ddns_rule_ids,
                applications,
                maintainer,
                notes,
            } => {
                *name = hostname(name, true)?;
                text(maintainer, 128, true)?;
                text(notes, 4096, false)?;
                if server_ids.len() > 64 || ddns_rule_ids.len() > 64 || applications.len() > 64 {
                    return invalid("关联项不能超过64个");
                }
                for application in applications {
                    text(application, 128, true)?;
                }
            }
            Self::Certificate {
                name,
                domain_ids,
                maintainer,
                issuer,
                targets,
                renewal,
            } => {
                text(name, 128, true)?;
                text(maintainer, 128, true)?;
                text(issuer, 256, true)?;
                if domain_ids.is_empty() || domain_ids.len() > 100 || targets.len() > 100 {
                    return invalid("请选择1–100个覆盖域名，部署目标最多100个");
                }
                for target in targets {
                    target.domain = hostname(&target.domain, false)?;
                    text(&mut target.service, 128, true)?;
                    if target.server_id <= 0 || target.port == 0 {
                        return invalid("证书部署目标无效");
                    }
                    match (&target.certificate_path, &target.private_key_path) {
                        (Some(public), Some(private))
                            if public != private
                                && [public, private].iter().all(|path| {
                                    path.starts_with('/')
                                        && !path.contains(['\0', '\n', '\r'])
                                        && !std::path::Path::new(path).components().any(|part| {
                                            matches!(
                                                part,
                                                std::path::Component::ParentDir
                                                    | std::path::Component::CurDir
                                            )
                                        })
                                }) => {}
                        (None, None) => {}
                        _ => {
                            return invalid(
                                "受管部署须填写不同的证书与私钥绝对路径；手工维护可同时留空",
                            );
                        }
                    }
                }
                match renewal {
                    RenewalPolicy::External { responsibility }
                    | RenewalPolicy::Dns01 { responsibility, .. } => {
                        text(responsibility, 128, true)?
                    }
                }
            }
            Self::Endpoint {
                name,
                listen_address,
                public_address,
                port,
                protocol,
                owner,
                notes,
                ..
            } => {
                text(name, 128, true)?;
                address(listen_address)?;
                if let Some(value) = public_address {
                    *value = value.trim().into();
                    if value.parse::<IpAddr>().is_err() {
                        *value = hostname(value, false)?;
                    }
                }
                network(*port, protocol, owner)?;
                text(notes, 4096, false)?;
            }
            Self::Forwarding {
                name,
                listen_address,
                listen_port,
                target_address,
                target_port,
                protocol,
                owner,
                dependency_ids,
                ..
            } => {
                text(name, 128, true)?;
                address(listen_address)?;
                address(target_address)?;
                network(*listen_port, protocol, owner)?;
                if *target_port == 0 || dependency_ids.len() > 64 {
                    return invalid("转发目标或依赖无效");
                }
            }
            Self::Tuning {
                name,
                parameters,
                restore_after_secs,
                purpose,
                ..
            } => {
                text(name, 128, true)?;
                text(purpose, 4096, true)?;
                if !(60..=900).contains(restore_after_secs)
                    || parameters.is_empty()
                    || parameters.len() > 10
                {
                    return invalid("恢复等待必须60–900秒，最多10个参数");
                }
                for (key, value) in parameters.iter() {
                    if !matches!(
                        key.as_str(),
                        "net.ipv4.tcp_congestion_control"
                            | "net.core.default_qdisc"
                            | "net.core.rmem_max"
                            | "net.core.wmem_max"
                            | "net.ipv4.tcp_rmem"
                            | "net.ipv4.tcp_wmem"
                            | "net.core.somaxconn"
                            | "net.core.netdev_max_backlog"
                            | "net.netfilter.nf_conntrack_max"
                            | "net.ipv4.ip_local_port_range"
                    ) || value.is_empty()
                        || value.len() > 256
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_ ".contains(&byte))
                    {
                        return invalid("网络参数不在受管范围或值无效");
                    }
                }
            }
            Self::Tunnel {
                name,
                relay_address,
                relay_port,
                relay_account,
                relay_host_key,
                listen_address,
                listen_port,
                target_address,
                target_port,
                ..
            } => {
                text(name, 128, true)?;
                address(relay_address)?;
                address(listen_address)?;
                address(target_address)?;
                text(relay_account, 32, true)?;
                text(relay_host_key, 512, true)?;
                if *relay_port == 0
                    || *listen_port == 0
                    || *target_port == 0
                    || !relay_host_key.starts_with("ssh-ed25519 ")
                {
                    return invalid("反向隧道端口或明确中转主机公钥无效");
                }
            }
            Self::Mesh {
                name,
                address,
                listen_port,
                peers,
                ..
            } => {
                text(name, 128, true)?;
                if !address.contains('/') || *listen_port == 0 || peers.len() > 64 {
                    return invalid("私有组网地址、端口或成员数量无效");
                }
                for peer in peers {
                    if peer.public_key.len() != 44
                        || peer.allowed_ips.is_empty()
                        || peer.allowed_ips.len() > 16
                        || peer.persistent_keepalive > 120
                    {
                        return invalid("组网成员的公钥、允许网段或保活无效");
                    }
                }
            }
            Self::Firewall {
                name,
                rules,
                management_ports,
                restore_after_secs,
                ..
            } => {
                text(name, 128, true)?;
                if rules.len() > 128
                    || management_ports.is_empty()
                    || management_ports.len() > 16
                    || management_ports.contains(&0)
                    || !(60..=900).contains(restore_after_secs)
                {
                    return invalid("防火墙管理端口、规则或本机恢复时间无效");
                }
                for rule in rules {
                    if !rule.source.contains('/')
                        || rule.port == 0
                        || !matches!(rule.protocol.as_str(), "tcp" | "udp")
                        || !matches!(rule.action.as_str(), "accept" | "drop")
                    {
                        return invalid("受管防火墙规则无效");
                    }
                }
            }
        }
        if self.servers().iter().any(|id| *id <= 0) {
            return invalid("服务器关联无效");
        }
        Ok(())
    }
}

pub(super) fn hostname(value: &str, wildcard: bool) -> ApiResult<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = if wildcard {
        value.strip_prefix("*.").unwrap_or(&value)
    } else {
        &value
    };
    if host.len() > 253
        || !host.contains('.')
        || host.parse::<IpAddr>().is_ok()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return invalid("请输入完整ASCII域名；国际域名请使用punycode");
    }
    Ok(value)
}

fn text(value: &mut String, max: usize, required: bool) -> ApiResult<()> {
    *value = value.trim().into();
    if value.len() > max || value.chars().any(char::is_control) || (required && value.is_empty()) {
        return invalid("文本字段为空、过长或包含控制字符");
    }
    Ok(())
}
fn address(value: &mut String) -> ApiResult<()> {
    *value = value.trim().into();
    if value.parse::<IpAddr>().is_err() {
        return invalid("地址必须是明确的IPv4或IPv6地址");
    }
    Ok(())
}
fn network(port: u16, protocol: &str, owner: &str) -> ApiResult<()> {
    if port == 0 || !matches!(protocol, "tcp" | "udp") || !matches!(owner, "sinan" | "external") {
        return invalid("端口、协议或维护方无效");
    }
    Ok(())
}
fn invalid<T>(message: &str) -> ApiResult<T> {
    Err(ApiError::BadRequest(message.into()))
}

#[derive(FromRow, Serialize)]
pub(super) struct Document {
    pub id: Uuid,
    pub kind: String,
    pub revision: i64,
    pub config: Value,
    pub active_version: Option<Uuid>,
    pub created_at: i64,
    pub updated_at: i64,
}
