use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use sinan_compiler::{Access, AcmeChallenge, ProtocolConfig};
use uuid::Uuid;

fn ip_set(values: &[&str]) -> BTreeSet<IpAddr> {
    values
        .iter()
        .map(|value| value.parse().expect("fixture address"))
        .collect()
}

fn automatic_node(udp: bool) -> Node {
    let tls = TlsConfig::Acme {
        email: "admin@example.com".into(),
        challenge: AcmeChallenge::Http01,
    };
    Node {
        id: 1,
        name: "First automatic certificate".into(),
        enabled: true,
        port: 2443,
        public_host: "proxy.example.com".into(),
        sni: "proxy.example.com".into(),
        private_key: String::new(),
        public_key: String::new(),
        short_id: String::new(),
        settings: Default::default(),
        users: vec![Access {
            user_id: 1,
            uuid: Uuid::new_v4(),
            credential: STANDARD.encode([1; 32]),
        }],
        protocol_config: if udp {
            ProtocolConfig::Hysteria2 { tls }
        } else {
            ProtocolConfig::Anytls { tls }
        },
    }
}

fn compiled(node: &Node) -> Value {
    serde_json::from_str(
        &sinan_compiler::compile_server(std::slice::from_ref(node)).expect("fixture compile"),
    )
    .expect("compiled configuration")
}

fn complete_preparation(node: &Node, compiled: &Value) -> Vec<Value> {
    let preparation = preparation(node, Some(compiled), 100);
    let mut checks: Vec<_> = preparation["evidence"]["requires"]
        .as_array()
        .expect("required checks")
        .iter()
        .map(|key| {
            check(
                key.as_str().expect("dependency key"),
                "Fixture observation",
                "passed",
                Some(100),
                "fixture",
                json!({}),
                "Fixture",
            )
        })
        .collect();
    checks.push(preparation);
    checks.push(check(
        "certificate_issued:1",
        "Certificate issued",
        "unknown",
        None,
        "not_observed",
        json!({}),
        "Fixture",
    ));
    checks.last_mut().expect("issued observation")["blocking"] = json!(false);
    checks
}

#[test]
fn wildcard_certificate_only_covers_one_label() {
    let names = json!(["*.example.com"]);
    assert!(covers(&names, "proxy.example.com"));
    assert!(!covers(&names, "example.com"));
    assert!(!covers(&names, "deep.proxy.example.com"));
}

#[test]
fn one_matching_address_does_not_hide_another_wrong_address() {
    let (state, evidence) = dns_evidence(
        ip_set(&["192.0.2.1", "192.0.2.2"]),
        &ip_set(&["192.0.2.1"]),
        false,
        false,
    );
    assert_eq!(state, "failed");
    assert_eq!(
        evidence["families"]["A"]["unexpected_addresses"],
        json!(["192.0.2.2"])
    );
    assert_eq!(evidence["all_addresses_match"], false);
}

#[test]
fn address_families_are_independently_matched_or_unknown() {
    let observed = ip_set(&["192.0.2.1", "2001:db8::1"]);
    let (state, evidence) = dns_evidence(observed.clone(), &ip_set(&["192.0.2.1"]), false, false);
    assert_eq!(state, "unknown");
    assert_eq!(evidence["families"]["A"]["state"], "passed");
    assert_eq!(evidence["families"]["AAAA"]["state"], "unknown");
    assert_eq!(
        dns_evidence(
            observed.clone(),
            &ip_set(&["192.0.2.1", "2001:db8::2"]),
            false,
            false
        )
        .0,
        "failed"
    );
    assert_eq!(
        dns_evidence(observed.clone(), &observed, false, false).0,
        "passed"
    );
}

#[test]
fn truncated_or_empty_dns_answers_never_pass() {
    let observed = ip_set(&["192.0.2.1"]);
    let (state, evidence) = dns_evidence(observed.clone(), &observed, true, false);
    assert_eq!(state, "unknown");
    assert_eq!(evidence["truncated"], true);
    assert_eq!(
        dns_evidence(BTreeSet::new(), &observed, false, false).0,
        "failed"
    );
}

#[test]
fn acme_requires_public_challenge_addresses() {
    let private = ip_set(&["127.0.0.1"]);
    let (state, evidence) = dns_evidence(private.clone(), &private, false, true);
    assert_eq!(state, "failed");
    assert_eq!(evidence["non_public_addresses"], json!(["127.0.0.1"]));
}

#[test]
fn first_tcp_and_quic_issuance_requires_real_preparation_without_prior_certificate() {
    for udp in [false, true] {
        for challenge in [AcmeChallenge::Http01, AcmeChallenge::TlsAlpn01] {
            let mut node = automatic_node(udp);
            let tls = TlsConfig::Acme {
                email: "admin@example.com".into(),
                challenge,
            };
            node.protocol_config = if udp {
                ProtocolConfig::Hysteria2 { tls }
            } else {
                ProtocolConfig::Anytls { tls }
            };
            let compiled = compiled(&node);
            let mut checks = complete_preparation(&node, &compiled);
            resolve_dependencies(&mut checks);
            let preparation = checks
                .iter()
                .find(|item| item["key"] == "certificate:1")
                .expect("preparation check");
            assert_eq!(preparation["state"], "passed");
            assert_eq!(preparation["evidence"]["prerequisites_ready"], true);
            assert_eq!(preparation["evidence"]["challenge_protocol"], "tcp");
            assert_eq!(
                preparation["evidence"]["challenge_port"],
                json!(challenge.port())
            );
            assert_eq!(
                preparation["evidence"]["target_handshake_transport"],
                if udp { "quic" } else { "tls_tcp" }
            );
            assert!(preparation["evidence"]["certificate_issued"].is_null());
            assert_eq!(
                preparation["evidence"]["external_challenge_reachability"],
                "not_observed"
            );
            assert_eq!(
                checks.last().expect("issued observation")["state"],
                "unknown"
            );
            assert_eq!(
                checks.last().expect("issued observation")["blocking"],
                false
            );
        }
    }
}

#[test]
fn missing_storage_or_wrong_dns_still_blocks_first_issuance() {
    let node = automatic_node(true);
    let compiled = compiled(&node);
    for (missing, expected) in [(true, "unknown"), (false, "failed")] {
        let mut checks = complete_preparation(&node, &compiled);
        if missing {
            checks.retain(|item| item["key"] != "acme_storage");
        } else {
            checks
                .iter_mut()
                .find(|item| item["key"] == "dns:1")
                .expect("DNS check")["state"] = json!("failed");
        }
        resolve_dependencies(&mut checks);
        let preparation = checks
            .iter()
            .find(|item| item["key"] == "certificate:1")
            .expect("preparation");
        assert_eq!(preparation["state"], expected);
        assert_eq!(preparation["blocking"], true);
    }
}

#[test]
fn actual_provider_and_inbound_binding_cannot_be_replaced_by_prior_handshake() {
    let node = automatic_node(false);
    for missing_domain in [false, true] {
        let mut compiled = compiled(&node);
        if missing_domain {
            compiled["certificate_providers"][0]["domain"] = json!([]);
        } else {
            compiled["inbounds"][0]["tls"]["certificate_provider"] = json!("unmanaged");
        }
        let mut checks = complete_preparation(&node, &compiled);
        checks.last_mut().expect("issued observation")["state"] = json!("passed");
        resolve_dependencies(&mut checks);
        let preparation = checks
            .iter()
            .find(|item| item["key"] == "certificate:1")
            .expect("preparation");
        assert_eq!(preparation["state"], "failed");
        assert_eq!(preparation["blocking"], true);
    }
}

#[test]
fn separate_acme_domain_and_stale_snapshot_remain_mandatory() {
    let mut node = automatic_node(false);
    node.public_host = "192.0.2.1".into();
    let compiled = compiled(&node);
    let mut checks = complete_preparation(&node, &compiled);
    checks.retain(|item| item["key"] != "acme_dns:1");
    resolve_dependencies(&mut checks);
    assert_eq!(
        checks
            .iter()
            .find(|item| item["key"] == "certificate:1")
            .expect("preparation")["state"],
        "unknown"
    );
    let mut checks = complete_preparation(&node, &compiled);
    checks
        .iter_mut()
        .find(|item| item["key"] == "snapshot")
        .expect("snapshot")["state"] = json!("unknown");
    resolve_dependencies(&mut checks);
    assert_eq!(
        checks
            .iter()
            .find(|item| item["key"] == "certificate:1")
            .expect("preparation")["blocking"],
        true
    );
    let mut checks = complete_preparation(&node, &compiled);
    checks
        .iter_mut()
        .find(|item| item["key"] == "certificate:1")
        .expect("preparation")["state"] = json!("unknown");
    resolve_dependencies(&mut checks);
    assert_eq!(
        checks
            .iter()
            .find(|item| item["key"] == "certificate:1")
            .expect("preparation")["state"],
        "unknown"
    );
}
