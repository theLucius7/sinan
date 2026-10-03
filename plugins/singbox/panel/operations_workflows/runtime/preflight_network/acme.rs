use super::{Node, TlsConfig, Value, check, json};
use std::collections::BTreeMap;

pub(super) fn preparation(node: &Node, compiled: Option<&Value>, now: i64) -> Value {
    let Some(TlsConfig::Acme { email, challenge }) = node.protocol_config.tls() else {
        return check(
            &format!("certificate:{}", node.id),
            "自动签发准备条件",
            "failed",
            Some(now),
            "compiled_runtime_acme_provider",
            json!({"node_id":node.id,"configuration_verified":false}),
            "当前节点没有受支持的运行时自动签发配置。",
        );
    };
    let providers = compiled.and_then(|value| value["certificate_providers"].as_array());
    let provider = providers
        .filter(|values| values.len() == 1)
        .and_then(|values| values.first());
    let inbound = compiled
        .and_then(|value| value["inbounds"].as_array())
        .and_then(|values| {
            values
                .iter()
                .find(|value| value["tag"] == format!("node-{}", node.id))
        });
    let domain = node.sni.to_ascii_lowercase();
    let valid = provider.is_some_and(|provider| {
        provider["type"] == "acme"
            && provider["tag"] == "managed-tls"
            && provider["provider"] == "letsencrypt"
            && provider["data_directory"] == "certificates"
            && provider["email"].as_str() == Some(email.as_str())
            && provider["disable_http_challenge"].as_bool() == Some(challenge.port() != 80)
            && provider["disable_tls_alpn_challenge"].as_bool() == Some(challenge.port() != 443)
            && provider["domain"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == &domain))
    }) && inbound.is_some_and(|inbound| {
        inbound["tls"]["enabled"] == true
            && inbound["tls"]["certificate_provider"] == "managed-tls"
            && inbound["tls"]["server_name"] == node.sni
    });
    let mut required = vec![
        "online".to_owned(),
        "lifecycle".to_owned(),
        "policy".to_owned(),
        "configuration".to_owned(),
        "artifact".to_owned(),
        "snapshot".to_owned(),
        "ports".to_owned(),
        "directories".to_owned(),
        "acme_storage".to_owned(),
        "service_manager".to_owned(),
        "capability:singbox".to_owned(),
        format!(
            "capability:{}",
            sinan_protocol::fleet::OPERATIONS_CAPABILITY
        ),
        format!(
            "capability:{}",
            sinan_protocol::fleet::RUNTIME_PREFLIGHT_CAPABILITY
        ),
        format!(
            "capability:{}",
            sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY
        ),
        format!("dns:{}", node.id),
    ];
    if node.sni != node.public_host {
        required.push(format!("acme_dns:{}", node.id));
    }
    check(
        &format!("certificate:{}", node.id),
        "自动签发准备条件",
        if valid { "passed" } else { "failed" },
        Some(now),
        "compiled_runtime_acme_provider",
        json!({
            "node_id":node.id,"server_name":node.sni,"configuration_verified":valid,
            "runtime_version":"1.14.2","provider":"letsencrypt","provider_tag":"managed-tls",
            "challenge":challenge,"challenge_protocol":"tcp","challenge_port":challenge.port(),
            "runtime_data_directory":"data","certificate_directory":"data/certificates",
            "domain_in_compiled_provider":valid,"inbound_uses_compiled_provider":valid,
            "requires":required,"prerequisites_ready":null,
            "external_challenge_reachability":"not_observed","certificate_issued":null,
            "actual_issuance_on_apply":true,"issuance_and_local_handshake_budget_seconds":240,
            "target_handshake_transport":if node.protocol_config.uses_tcp(){"tls_tcp"}else{"quic"},
            "secret_values_returned":false,
        }),
        if valid {
            "固定编译器确实生成目标运行时可用的 ACME 提供方与节点引用；还须同时满足 DNS、签名制品、挑战端口、持久证书目录和系统服务权限。外部 CA 对挑战端口的可达性未实测，签发与部署后握手分别保留状态。"
        } else {
            "当前配置不能生成受支持的自动签发提供方、域名或节点引用；不会以已有握手绕过当前材料错误。"
        },
    )
}

pub(in super::super) fn resolve_dependencies(checks: &mut [Value]) {
    let states: BTreeMap<_, _> = checks
        .iter()
        .filter_map(|item| {
            Some((
                item["key"].as_str()?.to_owned(),
                item["state"].as_str()?.to_owned(),
            ))
        })
        .collect();
    for item in checks
        .iter_mut()
        .filter(|item| item["source"] == "compiled_runtime_acme_provider")
    {
        let required: Vec<_> = item["evidence"]["requires"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let dependencies: Vec<_> = required
            .iter()
            .map(|key| {
                let state = states.get(key).map_or("unknown", String::as_str);
                json!({"key":key,"state":state})
            })
            .collect();
        let failed = item["evidence"]["configuration_verified"] != true
            || dependencies
                .iter()
                .any(|dependency| dependency["state"] == "failed");
        let ready = !failed
            && item["state"] == "passed"
            && !required.is_empty()
            && dependencies.iter().all(|dependency| {
                dependency["state"] == "passed"
                    || dependency["state"] == "not_applicable"
                        && dependency["key"]
                            .as_str()
                            .is_some_and(|key| key.starts_with("dns:"))
            });
        item["evidence"]["dependencies"] = json!(dependencies);
        item["evidence"]["prerequisites_ready"] = json!(ready);
        item["state"] = json!(if failed {
            "failed"
        } else if ready {
            "passed"
        } else {
            "unknown"
        });
        item["blocking"] = json!(!ready);
        item["detail"] = json!(if ready {
            "固定运行时提供方、当前有效域名解析、签名制品及目标 Agent 的挑战端口／持久证书目录／服务权限证据均满足首次签发准备条件。外部 CA 挑战可达性与签发结果未确认；实际部署必须通过独立 TCP TLS 或 QUIC 信任链及域名握手健康检查。"
        } else {
            "首次签发准备条件尚有缺失、失败或过期证据；当前材料、DNS、签名制品、挑战端口、持久证书目录和服务权限必须同时满足，不依靠人工声明或既有握手替代。"
        });
    }
}
