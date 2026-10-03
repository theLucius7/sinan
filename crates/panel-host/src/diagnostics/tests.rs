use super::{ReportRequest, safe_report_url};
use serde_json::json;

#[test]
fn report_upload_requires_an_explicit_boolean_opt_in() {
    for request in [json!({}), json!({"upload_report":false})] {
        let request: ReportRequest = serde_json::from_value(request).unwrap();
        assert!(!request.upload_report);
    }
    let request: ReportRequest = serde_json::from_value(json!({"upload_report":true})).unwrap();
    assert!(request.upload_report);
    for value in [json!("true"), json!(1), json!(null)] {
        assert!(serde_json::from_value::<ReportRequest>(json!({"upload_report":value})).is_err());
    }
}
#[test]
fn report_links_are_restricted_to_the_official_https_origin() {
    assert!(safe_report_url("https://nodequality.com/r/example"));
    for url in [
        "http://nodequality.com/r/example",
        "https://nodequality.com.evil.invalid/r/x",
        "https://user:secret@nodequality.com/r/x",
        "https://nodequality.com:8443/r/x",
        "javascript:alert(1)",
        "https://nodequality.com/r/x#fragment",
    ] {
        assert!(!safe_report_url(url), "{url}");
    }
}
