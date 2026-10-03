use super::*;
use serde_json::json;

fn input() -> Request {
    Request {
        operation: "create".into(),
        zone_id: "00000000000000000000000000000001".into(),
        record_id: None,
        record: json!({"name":"_acme-challenge.EXAMPLE.com.","type":"TXT","content":"TEST_ONLY challenge","ttl":300}),
    }
}

#[test]
fn record_names_support_dns_service_labels_and_fields_are_never_silently_removed() {
    let mut request = input();
    normalize(&mut request, "example.com").unwrap();
    assert_eq!(request.record["name"], "_acme-challenge.example.com");
    for field in ["unknown_setting", "password", "zone_id"] {
        let mut request = input();
        request.record[field] = true.into();
        assert!(normalize(&mut request, "example.com").is_err());
    }
    let mut request = input();
    request.record["name"] = "unowned.example.net".into();
    assert!(normalize(&mut request, "example.com").is_err());
    for bad in [
        "node.example.com/path",
        "node..example.com",
        "node.example.com:443",
        "@example.com",
    ] {
        assert!(name(bad).is_none());
    }
}

#[test]
fn create_update_delete_and_family_bounds_are_explicit() {
    let mut request = input();
    request.operation = "update".into();
    assert!(normalize(&mut request, "example.com").is_err());
    request.record_id = Some("00000000000000000000000000000002".into());
    normalize(&mut request, "example.com").unwrap();
    request.operation = "delete".into();
    normalize(&mut request, "example.com").unwrap();
    assert!(request.record.is_null());
    let mut request = input();
    request.record["type"] = "AAAA".into();
    request.record["content"] = "192.0.2.1".into();
    assert!(normalize(&mut request, "example.com").is_err());
    request.record["content"] = "2001:db8::1".into();
    normalize(&mut request, "example.com").unwrap();
    request.record["ttl"] = 59.into();
    assert!(normalize(&mut request, "example.com").is_err());
    let snapshot = snapshot(
        &json!({"id":"record","content":"value","ttl":300,"tags":["retain"],"modified_on":"provider metadata"}),
    );
    assert!(snapshot.get("tags").is_none());
    assert_eq!(snapshot["content"], "value");
}
