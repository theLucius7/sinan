use super::{
    model::{self, Config, Observation, Rule},
    providers::Providers,
};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

mod lifecycle;
mod multicloud;
mod provider;
mod scheduling;

const ZONE: &str = "00000000000000000000000000000001";
const RECORD: &str = "00000000000000000000000000000002";
const TOKEN: &str = "TEST_ONLY_CLOUDFLARE_TOKEN";

fn config() -> Config {
    Config {
        address_source: model::AddressSource::Agent,
        manual_ip: None,
        credential_id: None,
        interface_name: None,
        account_id: None,
        provider: model::Provider::Cloudflare,
        line: String::new(),
        name: "测试规则".into(),
        server_id: 1,
        zone_id: ZONE.into(),
        record_name: "node.example.com".into(),
        record_type: "A".into(),
        ttl: 300,
        proxied: false,
        interval_secs: 300,
        enabled: true,
        adopt_existing: false,
    }
}

fn rule() -> Rule {
    Rule {
        id: Uuid::new_v4(),
        config: config(),
        api_token: TOKEN.into(),
        access_key_id: String::new(),
        access_key_secret: String::new(),
        revision: 1,
        record_id: None,
        last_ip: None,
        last_success_at: None,
        attempted_at: None,
        next_run_at: 0,
        failures: 0,
        status: "pending".into(),
        error_code: None,
        lease_until: 0,
    }
}

// Synthetic numeric addresses are only payloads to the loopback provider;
// they are never contacted or resolved by these tests.
fn public_ip(last: u8) -> IpAddr {
    Ipv4Addr::new(1, 2, 3, last).into()
}

#[test]
fn domains_tokens_and_ttl_are_validated_before_storage() {
    assert_eq!(
        model::domain(" *.EXAMPLE.com. ").as_deref(),
        Some("*.example.com")
    );
    let idn = model::domain("节点.example.com").unwrap();
    assert!(idn.starts_with("xn--") && idn.ends_with(".example.com"));
    for name in [
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "a..example.com",
        "example.com@evil.test",
        "127.0.0.1",
        "*foo.example.com",
        "_srv.example.com",
        "example.com%2fevil",
        "example.com?x",
    ] {
        assert!(model::domain(name).is_none(), "{name}");
    }
    let mut spec = config();
    for ttl in [0, 2, 30, 59, 86401] {
        spec.ttl = ttl;
        assert!(spec.normalize().is_err());
    }
    spec.proxied = true;
    spec.normalize().unwrap();
    assert_eq!(spec.ttl, 1);
    assert!(model::token("invalid\nheader-value").is_err());
    assert!(model::token(TOKEN).is_ok());
    let serialized = serde_json::to_string(&rule()).unwrap();
    assert!(!serialized.contains(TOKEN));
    assert!(!serialized.contains("api_token"));
}

#[test]
fn selection_keeps_a_still_reported_address_and_requires_recent_authenticated_reports() {
    let now = 10000;
    let mut info = Observation {
        name: "测试".into(),
        static_info: json!({"ip_addresses":[public_ip(8),public_ip(3),"127.0.0.1","192.0.2.1","2001:db8::1"]}),
        static_info_received_at: Some(now),
        last_seen: Some(now),
        deleted_at: None,
        retiring: false,
        plugin_enabled: true,
    };
    let spec = config();
    assert_eq!(info.select(&spec, None, now).unwrap(), public_ip(3));
    assert_eq!(
        info.select(&spec, Some(&public_ip(8).to_string()), now)
            .unwrap(),
        public_ip(8)
    );
    let mut v6 = config();
    v6.record_type = "AAAA".into();
    assert_eq!(info.select(&v6, None, now), Err("no_public_ip"));
    info.static_info_received_at = None;
    assert_eq!(info.select(&spec, None, now), Err("ip_stale"));
    info.static_info_received_at = Some(now - 601);
    assert_eq!(info.select(&spec, None, now), Err("ip_stale"));
    info.static_info_received_at = Some(now);
    info.last_seen = Some(now - 61);
    assert_eq!(info.select(&spec, None, now), Err("server_offline"));
    info.retiring = true;
    assert_eq!(info.select(&spec, None, now), Err("server_retired"));
}

#[test]
fn ddns_rejects_new_documentation_benchmark_and_deprecated_ipv4_ranges() {
    let now = 10000;
    let mut info = Observation {
        name: "TEST_ONLY public filter".into(),
        static_info: Value::Null,
        static_info_received_at: Some(now),
        last_seen: Some(now),
        deleted_at: None,
        retiring: false,
        plugin_enabled: true,
    };
    for address in [
        "3fff::1",
        "3fff:0fff:ffff::1",
        "2001:2::1",
        "2001:2:0:ffff::1",
        "192.88.99.1",
    ] {
        info.static_info = json!({"ip_addresses":[address]});
        let mut spec = config();
        spec.record_type = if address.contains(':') { "AAAA" } else { "A" }.into();
        assert_eq!(
            info.select(&spec, None, now),
            Err("no_public_ip"),
            "{address}"
        );
    }
    info.static_info = json!({"ip_addresses":["2001:200::1","3fff:1000::1"]});
    let mut spec = config();
    spec.record_type = "AAAA".into();
    assert!(info.select(&spec, None, now).is_ok());
}
