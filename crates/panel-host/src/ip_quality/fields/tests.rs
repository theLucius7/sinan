use super::*;
use serde_json::json;

fn response(path: &str, value: Value) -> Value {
    let mut root = value;
    for key in path.rsplit('/').filter(|key| !key.is_empty()) {
        let mut object = serde_json::Map::new();
        object.insert(key.into(), root);
        root = Value::Object(object);
    }
    root
}

#[test]
fn every_known_field_requires_its_declared_type_and_valid_value() {
    for (database, _) in super::super::DATABASES
        .into_iter()
        .chain([("abuseipdb-v2", "正式接口")])
    {
        for (path, label, kind) in definitions(database) {
            let known = match kind {
                QualityFieldKind::Boolean => json!(false),
                QualityFieldKind::Score
                | QualityFieldKind::Latitude
                | QualityFieldKind::Longitude => json!(0),
                QualityFieldKind::Asn => json!(64500),
                QualityFieldKind::CountryCode => json!("ZZ"),
                QualityFieldKind::Text => json!("fixture"),
            };
            assert_eq!(
                parse_fields(database, &response(path, known.clone()))[0].value,
                known,
                "{database}/{label}"
            );
            for unknown in [
                Value::Null,
                json!({}),
                json!([]),
                json!(""),
                json!("   "),
                json!("null"),
                json!("unknown"),
            ] {
                assert!(
                    parse_fields(database, &response(path, unknown)).is_empty(),
                    "{database}/{label}"
                );
            }
            let invalid = match kind {
                QualityFieldKind::Boolean => json!(0),
                _ => json!(false),
            };
            assert!(
                parse_fields(database, &response(path, invalid)).is_empty(),
                "{database}/{label}"
            );
        }
    }
}

#[test]
fn uncertain_response_status_cannot_confirm_default_values() {
    for status in [
        json!({"success":false}),
        json!({"success":null}),
        json!({"success":"true"}),
        json!({"status":"failed"}),
        json!({"status":"pending"}),
        json!({"error":"unavailable"}),
    ] {
        let mut body = json!({"fraud_score":0,"proxy":false});
        body.as_object_mut()
            .unwrap()
            .extend(status.as_object().unwrap().clone());
        assert!(parse_fields("ipqualityscore", &body).is_empty());
    }
    for status in [
        json!({}),
        json!({"success":true}),
        json!({"status":"OK","error":null}),
    ] {
        let mut body = json!({"fraud_score":0,"proxy":false});
        body.as_object_mut()
            .unwrap()
            .extend(status.as_object().unwrap().clone());
        let fields = parse_fields("ipqualityscore", &body);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].value, json!(0));
        assert_eq!(fields[1].value, json!(false));
    }
}

#[test]
fn valid_raw_scores_remain_raw_and_missing_flags_are_not_false() {
    for score in [json!(0), json!("0"), json!("0.0047 (Very Low)")] {
        let fields = parse_fields(
            "ipapi",
            &json!({"company":{"abuser_score":score},"is_proxy":null}),
        );
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, score);
    }
    for score in [
        json!(-1),
        json!("NaN"),
        json!("inf"),
        json!("clean"),
        json!("0 ()"),
    ] {
        assert!(parse_fields("ipqualityscore", &json!({"fraud_score":score})).is_empty());
    }
    for invalid in [
        json!({"ASN":{"AutonomousSystemNumber":0}}),
        json!({"ASN":{"AutonomousSystemNumber":1.5}}),
        json!({"City":{"Latitude":91}}),
        json!({"City":{"Longitude":181}}),
        json!({"Country":{"IsoCode":"unknown"}}),
    ] {
        assert!(parse_fields("maxmind", &invalid).is_empty());
    }
    assert!(
        parse_fields(
            "unlicensed-fixture",
            &json!({"fraud_score":0,"proxy":false})
        )
        .is_empty()
    );
}

#[test]
fn explicit_errors_and_failed_abuseipdb_envelopes_cannot_confirm_default_scores() {
    for database in ["abuseipdb", "abuseipdb-v2"] {
        for body in [
            json!({"errors":[{"detail":"fixture denied"}],"data":{"abuseConfidenceScore":0}}),
            json!({"errors":{"detail":"fixture denied"},"data":{"abuseConfidenceScore":0}}),
            json!({"errors":"false","data":{"abuseConfidenceScore":0}}),
            json!({"data":{"success":false,"abuseConfidenceScore":0}}),
            json!({"data":{"success":null,"abuseConfidenceScore":0}}),
            json!({"data":{"success":"false","abuseConfidenceScore":0}}),
            json!({"data":{"success":"true","abuseConfidenceScore":0}}),
            json!({"data":{"status":"failed","abuseConfidenceScore":0}}),
            json!({"data":{"error":"fixture unavailable","abuseConfidenceScore":0}}),
            json!({"data":{"errors":[{"detail":"fixture unavailable"}],"abuseConfidenceScore":0}}),
        ] {
            assert!(
                parse_fields(database, &body).is_empty(),
                "{database}: {body}"
            );
        }
    }
}

#[test]
fn absent_or_empty_errors_and_confirmed_zero_remain_compatible() {
    for body in [
        json!({"data":{"abuseConfidenceScore":0}}),
        json!({"errors":null,"data":{"success":true,"abuseConfidenceScore":0}}),
        json!({"errors":[],"data":{"status":"OK","errors":[],"abuseConfidenceScore":0}}),
        json!({"errors":{},"data":{"status":"OK","errors":{},"abuseConfidenceScore":0}}),
    ] {
        let fields = parse_fields("abuseipdb", &body);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, json!(0));
    }
    let fields = parse_fields(
        "ipqualityscore",
        &json!({"errors":[],"fraud_score":0,"proxy":false}),
    );
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].value, json!(0));
    assert_eq!(fields[1].value, json!(false));
}

#[test]
fn unrelated_metadata_is_not_recursively_treated_as_query_failure() {
    let fields = parse_fields(
        "ipapi",
        &json!({"company":{"abuser_score":0,"status":"registered","error":"metadata note"},"is_proxy":false}),
    );
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].value, json!(0));
    assert_eq!(fields[1].value, json!(false));
    let fields = parse_fields(
        "maxmind",
        &json!({"ASN":{"AutonomousSystemNumber":64500,"status":"registered","errors":["metadata note"]}}),
    );
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].value, json!(64500));
}
