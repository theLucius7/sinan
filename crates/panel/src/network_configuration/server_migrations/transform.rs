use super::super::models::Configuration;
use crate::error::{ApiError, ApiResult};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) fn replace(
    config: &Configuration,
    source: i64,
    target: i64,
) -> ApiResult<Configuration> {
    if !config.servers().contains(&source) {
        return Err(ApiError::BadRequest("所选网络业务不属于原服务器".into()));
    }
    let mut result = config.clone();
    match &mut result {
        Configuration::Domain { server_ids, .. } => {
            for server in server_ids.iter_mut() {
                if *server == source {
                    *server = target;
                }
            }
            let mut seen = BTreeSet::new();
            server_ids.retain(|server| seen.insert(*server));
        }
        Configuration::Certificate { targets, .. } => {
            for destination in targets {
                if destination.server_id == source {
                    destination.server_id = target;
                }
            }
        }
        Configuration::Endpoint { server_id, .. } => *server_id = Some(target),
        Configuration::Forwarding { server_id, .. }
        | Configuration::Tuning { server_id, .. }
        | Configuration::Tunnel { server_id, .. }
        | Configuration::Mesh { server_id, .. }
        | Configuration::Firewall { server_id, .. } => *server_id = target,
    }
    Ok(result)
}

pub(super) fn selected(
    config: &Configuration,
    replacement: Option<&Configuration>,
    source: i64,
    target: i64,
    identity_map: &BTreeMap<Uuid, Uuid>,
) -> ApiResult<Configuration> {
    let expected = replace(config, source, target)?;
    let mut result = replacement.cloned().unwrap_or_else(|| expected.clone());
    if config.kind() != result.kind() || result.servers().contains(&source) {
        return Err(ApiError::BadRequest(
            "迁移只能替换所选业务的原服务器引用，不能改变业务类型".into(),
        ));
    }
    let expected_servers: BTreeSet<_> = expected.servers().into_iter().collect();
    let actual_servers: BTreeSet<_> = result.servers().into_iter().collect();
    if expected_servers != actual_servers {
        return Err(ApiError::BadRequest(
            "迁移不能增加其他服务器或移除未选择的关联".into(),
        ));
    }
    let old = serde_json::to_value(config).map_err(anyhow::Error::from)?;
    let new = serde_json::to_value(&result).map_err(anyhow::Error::from)?;
    let allowed: &[&str] = match config {
        Configuration::Domain { .. } => &["server_ids"],
        Configuration::Certificate { .. } => &["targets"],
        Configuration::Endpoint { .. } => &[
            "server_id",
            "listen_address",
            "public_address",
            "port",
            "protocol",
        ],
        Configuration::Forwarding { .. } => &[
            "server_id",
            "listen_address",
            "listen_port",
            "target_address",
            "target_port",
            "protocol",
        ],
        Configuration::Tunnel { .. } => &[
            "server_id",
            "relay_address",
            "relay_port",
            "relay_account",
            "relay_host_key",
            "listen_address",
            "listen_port",
            "target_address",
            "target_port",
            "enabled",
        ],
        Configuration::Mesh { .. } => &["server_id", "address", "listen_port", "peers"],
        Configuration::Tuning { .. } | Configuration::Firewall { .. } => &["server_id"],
    };
    for (key, value) in old.as_object().ok_or(ApiError::NotFound)? {
        if !allowed.contains(&key.as_str()) && new.get(key) != Some(value) {
            return Err(ApiError::BadRequest(
                "迁移不能同时修改名称、维护责任、凭据、覆盖域名或其他业务参数".into(),
            ));
        }
    }
    if let (
        Configuration::Certificate {
            targets: before, ..
        },
        Configuration::Certificate { targets: after, .. },
    ) = (config, &result)
    {
        if before.len() != after.len() {
            return Err(ApiError::BadRequest(
                "迁移不能隐式新增或删除证书部署目标".into(),
            ));
        }
        for (left, right) in before.iter().zip(after) {
            if left.server_id == source {
                if right.server_id != target {
                    return Err(ApiError::BadRequest(
                        "证书目标只能替换为已选新服务器".into(),
                    ));
                }
            } else if serde_json::to_value(left).map_err(anyhow::Error::from)?
                != serde_json::to_value(right).map_err(anyhow::Error::from)?
            {
                return Err(ApiError::BadRequest(
                    "未选择的证书目标不能随迁移改变".into(),
                ));
            }
        }
    }
    if let Configuration::Forwarding { dependency_ids, .. } = &mut result {
        for id in dependency_ids {
            if let Some(replacement) = identity_map.get(id) {
                *id = *replacement;
            }
        }
    }
    if let Configuration::Tunnel { enabled, .. } = &mut result {
        *enabled = false;
    }
    result.validate()?;
    Ok(result)
}

pub(super) fn relation_ids(config: &Configuration) -> Vec<Uuid> {
    match config {
        Configuration::Certificate { domain_ids, .. } => domain_ids.clone(),
        Configuration::Forwarding { dependency_ids, .. } => dependency_ids.clone(),
        _ => Vec::new(),
    }
}

pub(super) fn rules(config: &Configuration) -> Vec<Uuid> {
    match config {
        Configuration::Domain { ddns_rule_ids, .. } => ddns_rule_ids.clone(),
        Configuration::Certificate {
            renewal: super::super::models::RenewalPolicy::Dns01 { ddns_rule_id, .. },
            ..
        } => vec![*ddns_rule_id],
        _ => Vec::new(),
    }
}

pub(super) fn values_differ(before: &Configuration, after: &Configuration) -> ApiResult<Value> {
    let before = serde_json::to_value(before).map_err(anyhow::Error::from)?;
    let after = serde_json::to_value(after).map_err(anyhow::Error::from)?;
    let mut changes = Vec::new();
    for (key, value) in before.as_object().ok_or(ApiError::NotFound)? {
        if after.get(key) != Some(value) {
            changes.push(serde_json::json!({"field":key,"before":value,"after":after.get(key)}));
        }
    }
    Ok(Value::Array(changes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn configuration(value: Value) -> Configuration {
        serde_json::from_value(value).unwrap()
    }
    #[test]
    fn server_replacement_preserves_business_references_and_deduplicates_membership() {
        let id = Uuid::new_v4();
        let config = configuration(
            json!({"kind":"domain","name":"example.com","server_ids":[1,2,3],"ddns_rule_ids":[id],"applications":["application"],"maintainer":"owner","notes":"keep"}),
        );
        let moved = selected(&config, None, 1, 2, &BTreeMap::new()).unwrap();
        let moved = serde_json::to_value(moved).unwrap();
        assert_eq!(moved["server_ids"], json!([2, 3]));
        assert_eq!(moved["ddns_rule_ids"], json!([id]));
        assert_eq!(moved["applications"], json!(["application"]));
        let mut unrelated = moved.clone();
        unrelated["server_ids"] = json!([2, 4]);
        assert!(
            selected(
                &config,
                Some(&configuration(unrelated)),
                1,
                2,
                &BTreeMap::new()
            )
            .is_err()
        );
    }
    #[test]
    fn certificate_replacement_cannot_change_other_server_targets() {
        let config = configuration(
            json!({"kind":"certificate","name":"test","domain_ids":[Uuid::new_v4()],"maintainer":"owner","issuer":"external","renewal":{"mode":"external","responsibility":"owner"},"targets":[{"server_id":1,"service":"web","domain":"example.com","port":443},{"server_id":3,"service":"other","domain":"example.com","port":443}]}),
        );
        let mut moved = serde_json::to_value(replace(&config, 1, 2).unwrap()).unwrap();
        moved["targets"][1]["port"] = 8443.into();
        assert!(selected(&config, Some(&configuration(moved)), 1, 2, &BTreeMap::new()).is_err());
    }
    #[test]
    fn tunnel_candidate_never_inherits_start_authorization() {
        let config = configuration(
            json!({"kind":"tunnel","name":"tunnel","server_id":1,"relay_address":"192.0.2.1","relay_port":22,"relay_account":"relay","relay_host_key":"ssh-ed25519 TEST_ONLY","listen_address":"127.0.0.1","listen_port":8080,"target_address":"127.0.0.1","target_port":80,"enabled":true}),
        );
        let moved =
            serde_json::to_value(selected(&config, None, 1, 2, &BTreeMap::new()).unwrap()).unwrap();
        assert_eq!(moved["enabled"], false);
        assert!(moved.get("private_key").is_none());
    }
}
