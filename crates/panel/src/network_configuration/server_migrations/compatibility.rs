use super::super::models::Configuration;
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, path::Path};

pub(super) fn checks(config: &Configuration, target: &Value) -> Vec<Value> {
    let mut blockers = Vec::new();
    let policy = &target["policy"];
    match config {
        Configuration::Forwarding { owner, .. } if owner == "sinan" => require(
            &mut blockers,
            target,
            "port_forward",
            "system:forwarding:v1",
        ),
        Configuration::Tunnel { .. } => require(
            &mut blockers,
            target,
            "reverse_tunnel",
            "system:reverse-tunnel:v1",
        ),
        Configuration::Mesh { .. } => require(
            &mut blockers,
            target,
            "private_mesh",
            "system:private-mesh:v1",
        ),
        Configuration::Tuning { .. } => require(
            &mut blockers,
            target,
            "system_network",
            "system:network:apply:v1",
        ),
        Configuration::Firewall { .. } => {
            require(&mut blockers, target, "firewall", "system:firewall:v1")
        }
        Configuration::Certificate { targets, .. } => {
            for destination in targets
                .iter()
                .filter(|destination| Some(destination.server_id) == target["id"].as_i64())
            {
                if let (Some(public), Some(private)) =
                    (&destination.certificate_path, &destination.private_key_path)
                {
                    require(
                        &mut blockers,
                        target,
                        "certificate_deploy",
                        "system:certificate-deploy:v1",
                    );
                    if !policy["services"].as_array().is_some_and(|values| {
                        values
                            .iter()
                            .any(|value| value.as_str() == Some(destination.service.as_str()))
                    }) {
                        blockers.push(json!({"code":"target_service_not_authorized","service":destination.service}));
                    }
                    for path in [public, private] {
                        if !policy["write_directories"]
                            .as_array()
                            .is_some_and(|directories| {
                                directories
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .any(|directory| {
                                        directory != "/"
                                            && Path::new(directory).is_absolute()
                                            && Path::new(path).starts_with(directory)
                                    })
                            })
                        {
                            blockers.push(json!({"code":"target_certificate_directory_not_authorized","path":path}));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if !matches!(target["lifecycle"].as_str(), Some("active")) {
        blockers.push(json!({"code":"target_not_active","lifecycle":target["lifecycle"]}));
    }
    let listen = match config {
        Configuration::Endpoint { listen_address, .. }
        | Configuration::Forwarding { listen_address, .. } => Some(listen_address.as_str()),
        _ => None,
    };
    if let Some(address) = listen.and_then(|value| value.parse::<IpAddr>().ok())
        && !address.is_loopback()
        && !address.is_unspecified()
        && !target["addresses"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .any(|value| value == address.to_string())
        })
    {
        blockers.push(json!({"code":"listener_address_not_observed_on_target","address":address.to_string(),"action":"specify_target_address"}));
    }
    if let Configuration::Certificate { targets, .. } = config {
        let mut destinations = BTreeSet::new();
        for destination in targets {
            let public = destination.certificate_path.as_deref().unwrap_or("");
            if !destinations.insert((destination.server_id, destination.service.as_str(), public)) {
                blockers.push(json!({"code":"duplicate_certificate_service_target","server_id":destination.server_id,"service":destination.service}));
            }
        }
    }
    blockers
}

fn require(blockers: &mut Vec<Value>, target: &Value, flag: &str, capability: &str) {
    let capabilities = &target["capabilities"];
    if target["policy"][flag] != true
        || !capabilities
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(capability)))
    {
        blockers.push(json!({"code":"target_capability_missing","permission":flag,"capability":capability,"server_id":target["id"]}));
    }
    if !capabilities.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.as_str() == Some(sinan_protocol::fleet::OPERATIONS_CAPABILITY))
    }) {
        blockers.push(json!({"code":"target_fleet_operations_missing","server_id":target["id"]}));
    }
}

pub(super) fn listener_conflict(left: &Configuration, right: &Configuration) -> bool {
    let listener = |config: &Configuration| match config {
        Configuration::Forwarding {
            server_id,
            listen_address,
            listen_port,
            protocol,
            owner,
            enabled: true,
            ..
        } if owner == "sinan" => Some((
            *server_id,
            listen_address.clone(),
            *listen_port,
            protocol.clone(),
        )),
        Configuration::Mesh {
            server_id,
            listen_port,
            ..
        } => Some((*server_id, "0.0.0.0".into(), *listen_port, "udp".into())),
        Configuration::Endpoint {
            server_id: Some(server),
            listen_address,
            port,
            protocol,
            owner,
            ..
        } if owner == "sinan" => Some((*server, listen_address.clone(), *port, protocol.clone())),
        _ => None,
    };
    match (listener(left), listener(right)) {
        (
            Some((left_server, left_address, left_port, left_protocol)),
            Some((right_server, right_address, right_port, right_protocol)),
        ) => {
            left_server == right_server
                && left_port == right_port
                && left_protocol == right_protocol
                && (left_address == right_address
                    || matches!(left_address.as_str(), "0.0.0.0" | "::")
                    || matches!(right_address.as_str(), "0.0.0.0" | "::"))
        }
        _ => false,
    }
}

pub(super) fn represented_by(
    id: uuid::Uuid,
    left: &Configuration,
    other_id: uuid::Uuid,
    right: &Configuration,
) -> bool {
    matches!((left,right),(Configuration::Forwarding{dependency_ids,..},Configuration::Endpoint{..}) if dependency_ids.contains(&other_id))
        || matches!((left,right),(Configuration::Endpoint{..},Configuration::Forwarding{dependency_ids,..}) if dependency_ids.contains(&id))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_bound_address_requires_explicit_replacement_but_wildcard_does_not() {
        let target = json!({"id":2,"lifecycle":"active","addresses":["192.0.2.2"],"capabilities":[],"policy":{}});
        let configuration = |address: &str| {
            serde_json::from_value(json!({"kind":"endpoint","name":"test","server_id":2,"listen_address":address,"public_address":null,"port":443,"protocol":"tcp","owner":"external","notes":""})).unwrap()
        };
        assert!(
            checks(&configuration("192.0.2.1"), &target)
                .iter()
                .any(|issue| issue["code"] == "listener_address_not_observed_on_target")
        );
        assert!(checks(&configuration("0.0.0.0"), &target).is_empty());
    }
}
