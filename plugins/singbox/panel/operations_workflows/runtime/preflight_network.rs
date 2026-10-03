use super::preflight::check;
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use futures_util::{StreamExt, TryStreamExt, stream};
use serde_json::{Value, json};
use sinan_compiler::{Node, TlsConfig};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};

mod acme;
use acme::preparation;
pub(super) use acme::resolve_dependencies;
const MAX_DNS_ADDRESSES: usize = 32;

fn addresses(info: &Value) -> BTreeSet<IpAddr> {
    ["ip_addresses", "discovered_public_ips"]
        .into_iter()
        .flat_map(|key| info[key].as_array().into_iter().flatten())
        .filter_map(|value| value.as_str()?.parse().ok())
        .collect()
}

fn covers(names: &Value, host: &str) -> bool {
    names
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|name| {
            name == host
                || name.strip_prefix("*.").is_some_and(|suffix| {
                    host.strip_suffix(&format!(".{suffix}"))
                        .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
                })
        })
}

fn dns_evidence(
    observed: BTreeSet<IpAddr>,
    expected: &BTreeSet<IpAddr>,
    truncated: bool,
    public_challenge: bool,
) -> (&'static str, Value) {
    let mut families = BTreeMap::new();
    let mut unmatched = false;
    let mut unverifiable = false;
    for (name, ipv4) in [("A", true), ("AAAA", false)] {
        let actual: BTreeSet<_> = observed
            .iter()
            .copied()
            .filter(|ip| ip.is_ipv4() == ipv4)
            .collect();
        let declared: BTreeSet<_> = expected
            .iter()
            .copied()
            .filter(|ip| ip.is_ipv4() == ipv4)
            .collect();
        let unexpected: BTreeSet<_> = actual.difference(&declared).copied().collect();
        let status = if actual.is_empty() {
            "no_answer"
        } else if declared.is_empty() {
            unverifiable = true;
            "unknown"
        } else if !unexpected.is_empty() {
            unmatched = true;
            "failed"
        } else {
            "passed"
        };
        families.insert(name, json!({"state":status,"addresses":actual,"expected_addresses":declared,"unexpected_addresses":unexpected}));
    }
    let non_public: Vec<_> = observed
        .iter()
        .copied()
        .filter(|ip| !crate::ip_quality::public_ip(*ip))
        .collect();
    let status = if observed.is_empty() || unmatched || public_challenge && !non_public.is_empty() {
        "failed"
    } else if truncated || unverifiable {
        "unknown"
    } else {
        "passed"
    };
    (
        status,
        json!({
            "addresses":observed,"expected_addresses":expected,"families":families,
            "all_addresses_match":!observed.is_empty() && observed.is_subset(expected),
            "truncated":truncated,"address_limit":MAX_DNS_ADDRESSES,
            "public_acme_challenge":public_challenge,"non_public_addresses":non_public,
            "coverage":"panel_system_resolver_answers","authoritative_dns_verified":false,
        }),
    )
}

async fn dns(node: Node, expected: BTreeSet<IpAddr>, public_challenge: bool) -> Value {
    let now = now_timestamp();
    let key = format!("dns:{}", node.id);
    if let Ok(address) = node.public_host.parse::<IpAddr>() {
        return check(
            &key,
            "公开入口 DNS",
            "not_applicable",
            Some(now),
            "panel_configuration",
            json!({"node_id":node.id,"host":node.public_host,"address":address,"reason":"literal_ip_no_dns"}),
            "入口为明确 IP，不需要域名解析；这不证明公网可达。",
        );
    }
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((node.public_host.clone(), node.public_port())),
    )
    .await;
    let observed_at = now_timestamp();
    match result {
        Ok(Ok(values)) => {
            let sampled: Vec<_> = values.take(MAX_DNS_ADDRESSES + 1).collect();
            let truncated = sampled.len() > MAX_DNS_ADDRESSES;
            let observed = sampled.into_iter().map(|address| address.ip()).collect();
            let (status, mut evidence) =
                dns_evidence(observed, &expected, truncated, public_challenge);
            evidence["node_id"] = json!(node.id);
            evidence["from"] = json!("panel");
            evidence["to"] = json!(node.public_host);
            evidence["resolver"] = json!("panel_system_resolver");
            check(
                &key,
                "公开入口 DNS",
                status,
                Some(observed_at),
                "panel_system_resolver",
                evidence,
                match status {
                    "passed" => {
                        "面板解析返回的每个 A／AAAA 地址均与该服务器观测或明确登记入口匹配；只代表本来源本次结果，不证明所有解析器或 CA 挑战可达。"
                    }
                    "failed" => {
                        "存在错误的同族地址、无解析结果或 ACME 非公网地址；单个正确地址不能掩盖其他错误结果。"
                    }
                    _ => {
                        "解析超过地址预算，或某一返回地址族尚无已观测／登记的同族地址可核对；未知继续阻塞。"
                    }
                },
            )
        }
        Ok(Err(_)) => check(
            &key,
            "公开入口 DNS",
            "failed",
            Some(observed_at),
            "panel_system_resolver",
            json!({"node_id":node.id,"from":"panel","to":node.public_host,"error_code":"dns_resolution_failed"}),
            "面板实际解析失败，未将错误转换为可用。",
        ),
        Err(_) => check(
            &key,
            "公开入口 DNS",
            "unknown",
            Some(observed_at),
            "panel_system_resolver",
            json!({"node_id":node.id,"from":"panel","to":node.public_host,"error_code":"dns_timeout"}),
            "解析超过三秒预算，结果未知且阻塞确认。",
        ),
    }
}

pub(super) fn refresh(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    server: i64,
    nodes: &[Node],
    info: &Value,
) -> impl std::future::Future<Output = ApiResult<Vec<Value>>> + Send + use<> {
    let state = state.clone();
    let headers = headers.clone();
    let nodes = nodes.to_vec();
    let info = info.clone();
    async move {
        let active: Vec<Node> = nodes
            .iter()
            .filter(|node| node.enabled && !node.users.is_empty())
            .cloned()
            .collect();
        if active.len() > 64 {
            return Err(ApiError::BadRequest(
                "一次完整预检最多 64 个当前有效普通节点，请先拆分服务器业务配置".into(),
            ));
        }
        let _permit = state
            .quality_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::Busy)?;
        let mut expected = addresses(&info);
        match crate::control_center::require_server(&state, &headers, server, "network:read").await
        {
            Ok(_) => {
                let declared:Vec<Value>=sqlx::query_scalar("SELECT config FROM network_documents WHERE kind='endpoint' AND (config->>'server_id')::bigint=$1").bind(server).fetch_all(&state.pool).await?;
                for endpoint in declared {
                    if let Some(address) = endpoint["public_address"]
                        .as_str()
                        .and_then(|value| value.parse::<IpAddr>().ok())
                    {
                        expected.insert(address);
                    }
                }
            }
            Err(ApiError::Forbidden(_)) => {}
            Err(error) => return Err(error),
        }
        let dns_expected = expected.clone();
        let mut checks: Vec<Value> = stream::iter(active.clone())
            .map(move |node| {
                let expected = dns_expected.clone();
                async move {
                    let challenge =
                        matches!(node.protocol_config.tls(), Some(TlsConfig::Acme { .. }))
                            && node.sni == node.public_host;
                    Ok::<_, ApiError>(dns(node, expected, challenge).await)
                }
            })
            .buffer_unordered(8)
            .try_collect()
            .await?;
        let challenge_nodes: Vec<Node> = active
            .iter()
            .filter(|node| {
                matches!(node.protocol_config.tls(), Some(TlsConfig::Acme { .. }))
                    && node.sni != node.public_host
            })
            .cloned()
            .collect();
        for node in challenge_nodes {
            let mut challenge_node = node.clone();
            challenge_node.public_host = node.sni.clone();
            let mut observed = dns(challenge_node, expected.clone(), true).await;
            observed["key"] = json!(format!("acme_dns:{}", node.id));
            observed["name"] = json!("自动证书验证域名 DNS");
            checks.push(observed);
        }
        let compiled = sinan_compiler::compile_server(&nodes)
            .ok()
            .and_then(|value| serde_json::from_str::<Value>(&value).ok());
        for node in active {
            let key = format!("certificate:{}", node.id);
            let now = now_timestamp();
            match node.protocol_config.tls() {
                None => checks.push(check(
                    &key,
                    "证书材料",
                    "not_applicable",
                    Some(now),
                    "compiled_protocol",
                    json!({"node_id":node.id,"protocol":node.protocol_config.kind()}),
                    "此协议不使用普通本机 TLS 证书；Reality 的伪装握手不能被当成本机证书。",
                )),
                Some(TlsConfig::Manual {
                    certificate,
                    key: private_key,
                }) => {
                    let metadata = crate::network_configuration::certificate_metadata(certificate);
                    let pair =
                        super::super::super::node_protocol::validate_pem(certificate, private_key)
                            .is_ok();
                    let (status, evidence) = match metadata {
                        Ok(metadata) => {
                            let valid = pair
                                && metadata["not_before"].as_i64().is_some_and(|at| at <= now)
                                && metadata["not_after"].as_i64().is_some_and(|at| at > now)
                                && covers(&metadata["names"], &node.sni);
                            (
                                if valid { "passed" } else { "failed" },
                                json!({"node_id":node.id,"server_name":node.sni,"key_pair_matches":pair,"metadata":metadata,"trust_mode":"configured_public_certificate_pin","private_key_returned":false}),
                            )
                        }
                        Err(_) => (
                            "failed",
                            json!({"node_id":node.id,"error_code":"invalid_public_certificate_metadata","private_key_returned":false}),
                        ),
                    };
                    checks.push(check(&key,"证书材料",status,Some(now),"current_managed_certificate",evidence,"核对当前配置中的证书域名、有效期与私钥匹配；这里只证明可部署材料，不冒充已经部署或实际握手。"));
                }
                Some(TlsConfig::Acme { .. }) => {
                    checks.push(preparation(&node, compiled.as_ref(), now));
                    let evidence =
                        recent_handshake(state.clone(), headers.clone(), server, node.clone())
                            .await?;
                    let mut issued = if let Some((observed_at, mut evidence)) = evidence {
                        evidence["current_endpoint_certificate_observed"] = json!(true);
                        evidence["certificate_issued"] = Value::Null;
                        evidence["issuance_owner_confirmation"] = json!("unknown");
                        check(
                            &format!("certificate_issued:{}", node.id),
                            "自动证书入口的当前证书观测",
                            "passed",
                            Some(observed_at),
                            "panel_tls_handshake",
                            evidence,
                            "近期真实握手已验证当前入口的证书；可能仍是先前或人工签发的证书，不能证明本次目标运行时的 ACME 签发已完成，也不确认签发责任方。",
                        )
                    } else {
                        check(
                            &format!("certificate_issued:{}", node.id),
                            "自动证书入口的当前证书观测",
                            "unknown",
                            None,
                            "runtime_issuance_not_observed",
                            json!({"node_id":node.id,"server_name":node.sni,"current_endpoint_certificate_observed":null,"certificate_issued":null,"issuance_owner":"target_runtime","issuance_owner_confirmation":"unknown","local_trusted_handshake_on_apply":true,"health_budget_seconds":240}),
                            "首次自动签发在实际部署后由目标运行时执行；目前没有已签发证据。TCP TLS 或 QUIC 真实信任链与域名握手属于部署健康检查，失败使部署失败，不以准备条件代替签发成功。",
                        )
                    };
                    issued["blocking"] = json!(false);
                    checks.push(issued);
                }
            }
            if node.protocol_config.tls().is_none() {
                continue;
            }
            let observed =
                recent_handshake(state.clone(), headers.clone(), server, node.clone()).await?;
            let mut handshake = if let Some((at, evidence)) = observed {
                check(
                    &format!("tls_handshake:{}", node.id),
                    "已部署 TLS 握手",
                    "passed",
                    Some(at),
                    "panel_tls_handshake",
                    evidence,
                    "实际观测域名和信任链；只代表该来源核对时的结果。",
                )
            } else {
                check(
                    &format!("tls_handshake:{}", node.id),
                    "已部署 TLS 握手",
                    "unknown",
                    None,
                    "not_observed",
                    json!({"node_id":node.id,"from":"panel","to":format!("{}:{}",node.public_host,node.public_port()),"transport":if node.protocol_config.uses_tcp(){"tcp"}else{"udp"}}),
                    "初次部署前服务可能尚未监听；握手是部署后独立验收。UDP/QUIC 节点不采用 TCP 握手认定服务成功。",
                )
            };
            handshake["blocking"] = json!(false);
            checks.push(handshake);
        }
        Ok(checks)
    }
}

async fn recent_handshake(
    state: AppState,
    headers: axum::http::HeaderMap,
    server: i64,
    node: Node,
) -> ApiResult<Option<(i64, Value)>> {
    if node.protocol_config.tls().is_none()
        || !node.protocol_config.uses_tcp()
        || node.public_host != node.sni
    {
        return Ok(None);
    }
    let expected_fingerprint = match node.protocol_config.tls() {
        Some(TlsConfig::Manual { certificate, .. }) => {
            let Ok(metadata) = crate::network_configuration::certificate_metadata(certificate)
            else {
                return Ok(None);
            };
            let Some(fingerprint) = metadata["fingerprint"].as_str() else {
                return Ok(None);
            };
            Some(fingerprint.to_owned())
        }
        _ => None,
    };
    match crate::control_center::require_server(&state, &headers, server, "network:read").await {
        Ok(_) => {}
        Err(ApiError::Forbidden(_)) => return Ok(None),
        Err(error) => return Err(error),
    }
    let row=sqlx::query("SELECT o.id,o.observed_at,o.result,d.active_version,v.fingerprint,v.not_after FROM network_observations o JOIN network_documents d ON d.id=o.document_id JOIN network_certificate_versions v ON v.id=d.active_version WHERE o.server_id=$1 AND o.source='panel_tls_handshake' AND o.result->>'to'=$2 AND o.observed_at BETWEEN $3-300 AND $3 AND o.result->>'status'='verified' AND o.result->>'version_id'=d.active_version::text AND v.not_after>$3 AND ($4::text IS NULL OR v.fingerprint=$4) ORDER BY o.observed_at DESC LIMIT 1")
        .bind(server).bind(format!("{}:{}",node.public_host,node.public_port())).bind(now_timestamp()).bind(expected_fingerprint).fetch_optional(&state.pool).await?;
    Ok(row.map(|row|(row.get("observed_at"),json!({"observation_id":row.get::<uuid::Uuid,_>("id"),"from":"panel","to":format!("{}:{}",node.public_host,node.public_port()),"server_name":node.sni,"version_id":row.get::<uuid::Uuid,_>("active_version"),"fingerprint":row.get::<String,_>("fingerprint"),"not_after":row.get::<i64,_>("not_after"),"trust_chain":"validated","hostname":"validated"}))))
}

#[cfg(test)]
mod tests;
