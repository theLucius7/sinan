use super::*;
use crate::plugins::{
    cloud_api::test_support::{Mock, Reply},
    ddns::{
        dns_record_actions::confirmed_status, dns_record_reconcile::desired_matches,
        dns_record_spec::normalize_for,
    },
};

const ZONE: &str = "00000000000000000000000000000001";
const RECORD: &str = "00000000000000000000000000000002";
fn request(provider: Provider) -> Request {
    let mut request = Request {
        operation: "create".into(),
        zone_id: if provider == Provider::Huawei {
            ZONE
        } else {
            "example.com"
        }
        .into(),
        record_id: None,
        record: json!({"name":"_service.example.com","type":"TXT","content":"TEST_ONLY value","ttl":300}),
    };
    normalize_for(&mut request, "example.com", provider).unwrap();
    request
}
fn ali() -> Value {
    json!({"RecordId":"2","DomainName":"example.com","RR":"_service","Type":"TXT","Value":"TEST_ONLY value","TTL":300,"Line":"default","Status":"Enable","Locked":false,"RequestId":"TEST_ONLY_read"})
}
fn tc() -> Value {
    json!({"Id":2,"SubDomain":"_service","RecordType":"TXT","Value":"TEST_ONLY value","TTL":300,"RecordLineId":"0","Enabled":1})
}
fn hw(status: &str) -> Value {
    json!({"id":RECORD,"zone_id":ZONE,"name":"_service.example.com.","type":"TXT","records":["TEST_ONLY value"],"ttl":300,"status":status})
}

#[tokio::test]
async fn aliyun_record_create_update_delete_are_signed_and_read_back_exactly() {
    let mock = Mock::start(vec![
        Reply::ok(
            "AddDomainRecord",
            json!({"RequestId":"TEST_ONLY_create","RecordId":"2"}),
        ),
        Reply::ok("DescribeDomainRecordInfo", ali()),
        Reply::ok(
            "UpdateDomainRecord",
            json!({"RequestId":"TEST_ONLY_update","RecordId":"2"}),
        ),
        Reply::ok("DescribeDomainRecordInfo", ali()),
        Reply::ok(
            "DeleteDomainRecord",
            json!({"RequestId":"TEST_ONLY_delete","RecordId":"2"}),
        ),
    ])
    .await;
    let client = RecordClient::local(Provider::Aliyun, &mock.endpoint);
    let mut request = request(Provider::Aliyun);
    let created = client.write(&request, "example.com").await.unwrap();
    assert!(desired_matches(&request, &created));
    request.operation = "update".into();
    request.record_id = Some("2".into());
    assert_eq!(
        client.write(&request, "example.com").await.unwrap(),
        created
    );
    request.operation = "delete".into();
    request.record = Value::Null;
    assert!(
        client
            .write(&request, "example.com")
            .await
            .unwrap()
            .is_null()
    );
    let requests = mock.requests();
    assert_eq!(requests[0].params["RR"], "_service");
    assert_eq!(requests[0].params["Line"], "default");
    assert!(requests[0].params.contains_key("Signature"));
    assert_eq!(requests[2].params["RecordId"], "2");
    mock.exhausted();
}

#[tokio::test]
async fn tencent_record_create_update_delete_keep_record_id_numeric_and_line_explicit() {
    let mock = Mock::start(vec![
        Reply::ok(
            "CreateRecord",
            json!({"Response":{"RequestId":"TEST_ONLY_create","RecordId":2}}),
        ),
        Reply::ok(
            "DescribeRecord",
            json!({"Response":{"RequestId":"TEST_ONLY_read","RecordInfo":tc()}}),
        ),
        Reply::ok(
            "ModifyRecord",
            json!({"Response":{"RequestId":"TEST_ONLY_update","RecordId":2}}),
        ),
        Reply::ok(
            "DescribeRecord",
            json!({"Response":{"RequestId":"TEST_ONLY_read","RecordInfo":tc()}}),
        ),
        Reply::ok(
            "DeleteRecord",
            json!({"Response":{"RequestId":"TEST_ONLY_delete"}}),
        ),
    ])
    .await;
    let client = RecordClient::local(Provider::Tencent, &mock.endpoint);
    let mut request = request(Provider::Tencent);
    let created = client.write(&request, "example.com").await.unwrap();
    assert!(desired_matches(&request, &created));
    request.operation = "update".into();
    request.record_id = Some("2".into());
    assert_eq!(
        client.write(&request, "example.com").await.unwrap(),
        created
    );
    request.operation = "delete".into();
    request.record = Value::Null;
    assert!(
        client
            .write(&request, "example.com")
            .await
            .unwrap()
            .is_null()
    );
    let requests = mock.requests();
    assert_eq!(requests[0].body["SubDomain"], "_service");
    assert_eq!(requests[0].body["RecordLineId"], "0");
    assert_eq!(requests[2].body["RecordId"], 2);
    assert!(
        requests[0].headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("TC3-HMAC-SHA256 Credential=TEST_ONLY_ACCESS_ID/")
    );
    mock.exhausted();
}

#[tokio::test]
async fn huawei_pending_create_update_delete_are_submitted_until_a_later_read() {
    let mut deleted = hw("PENDING_DELETE");
    deleted["records"] = json!([]);
    let mock = Mock::start(vec![
        Reply::ok(
            &format!("POST /v2/zones/{ZONE}/recordsets"),
            hw("PENDING_CREATE"),
        ),
        Reply::ok(
            &format!("PUT /v2/zones/{ZONE}/recordsets/{RECORD}"),
            hw("PENDING_UPDATE"),
        ),
        Reply::ok(
            &format!("DELETE /v2/zones/{ZONE}/recordsets/{RECORD}"),
            deleted,
        ),
    ])
    .await;
    let client = RecordClient::local(Provider::Huawei, &mock.endpoint);
    let mut request = request(Provider::Huawei);
    let created = client.write(&request, "example.com").await.unwrap();
    assert!(desired_matches(&request, &created));
    assert_eq!(confirmed_status(&created), "submitted");
    request.operation = "update".into();
    request.record_id = Some(RECORD.into());
    assert_eq!(
        confirmed_status(&client.write(&request, "example.com").await.unwrap()),
        "submitted"
    );
    request.operation = "delete".into();
    request.record = Value::Null;
    assert_eq!(
        confirmed_status(&client.write(&request, "example.com").await.unwrap()),
        "submitted"
    );
    let requests = mock.requests();
    assert_eq!(requests[0].body["name"], "_service.example.com.");
    assert!(
        requests[0].headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("SDK-HMAC-SHA256 Access=TEST_ONLY_ACCESS_ID")
    );
    mock.exhausted();
}

#[tokio::test]
async fn detail_response_cannot_escape_authorized_zone() {
    let mut record = ali();
    record["DomainName"] = "other.example.com".into();
    let mock = Mock::start(vec![Reply::ok("DescribeDomainRecordInfo", record)]).await;
    assert_eq!(
        RecordClient::local(Provider::Aliyun, &mock.endpoint)
            .get("example.com", "2", "example.com")
            .await
            .unwrap_err()
            .code,
        "zone_mismatch"
    );
    mock.exhausted();
}

#[test]
fn provider_shapes_and_recordset_reordering_are_explicit() {
    let mut input = request(Provider::Tencent);
    input.record["proxied"] = true.into();
    assert!(normalize_for(&mut input, "example.com", Provider::Tencent).is_err());
    let mut input = request(Provider::Aliyun);
    input.record["data"] = json!({"priority":1});
    assert!(normalize_for(&mut input, "example.com", Provider::Aliyun).is_err());
    let mut input = request(Provider::Huawei);
    input.record.as_object_mut().unwrap().remove("content");
    input.record["data"] = json!({"records":["TEST_ONLY a","TEST_ONLY b"]});
    normalize_for(&mut input, "example.com", Provider::Huawei).unwrap();
    let observed = json!({"name":"_service.example.com","type":"TXT","ttl":300,"data":{"records":["TEST_ONLY b","TEST_ONLY a"]}});
    assert!(desired_matches(&input, &observed));
}
