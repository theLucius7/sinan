use super::*;
use crate::cloud_api::{
    Failure,
    test_support::{Mock, Reply},
};
use crate::{cloudflare::Outcome, model::Provider, worker};

#[path = "multicloud_boundaries.rs"]
mod boundaries;

fn configured(provider: Provider) -> Rule {
    let mut rule = rule();
    rule.config.provider = provider;
    rule.config.line = match provider {
        Provider::Tencent => "0",
        Provider::Aliyun => "default",
        _ => "",
    }
    .into();
    if matches!(provider, Provider::Tencent | Provider::Aliyun) {
        rule.config.zone_id = "example.com".into();
    }
    rule.api_token = String::new();
    rule.access_key_id = "TEST_ONLY_ID".into();
    rule.access_key_secret = "TEST_ONLY_SECRET".into();
    rule
}
fn ali_record(ip: IpAddr) -> Value {
    json!({"RecordId":"record2","DomainName":"example.com","RR":"node","Type":"A","Line":"default","Value":ip.to_string(),"TTL":300,"Status":"Enable","Locked":false,"RequestId":"read"})
}
fn ali_read(records: Vec<Value>) -> Vec<Reply> {
    vec![
        Reply::ok(
            "DescribeDomainInfo",
            json!({"RequestId":"zone","DomainName":"example.com","MinTtl":60}),
        ),
        Reply::ok(
            "DescribeSubDomainRecords",
            json!({"RequestId":"list","PageNumber":1,"TotalCount":records.len(),"DomainRecords":{"Record":records}}),
        ),
    ]
}
fn tencent_record(ip: IpAddr, detail: bool) -> Value {
    if detail {
        json!({"Id":2,"SubDomain":"node","RecordType":"A","RecordLineId":"0","Value":ip.to_string(),"TTL":300,"Enabled":1})
    } else {
        json!({"RecordId":2,"Name":"node","Type":"A","LineId":"0","Value":ip.to_string(),"TTL":300,"Status":"ENABLE","Weight":null})
    }
}
fn tencent_read(records: Vec<Value>) -> Vec<Reply> {
    vec![
        Reply::ok(
            "DescribeDomain",
            json!({"Response":{"RequestId":"zone","DomainInfo":{"Domain":"example.com","Status":"ENABLE"}}}),
        ),
        Reply::ok(
            "DescribeRecordList",
            json!({"Response":{"RequestId":"list","RecordCountInfo":{"TotalCount":records.len()},"RecordList":records}}),
        ),
    ]
}
fn hw_record(rule: &Rule, status: &str) -> Value {
    json!({"id":RECORD,"zone_id":ZONE,"name":"node.example.com.","type":"A","ttl":300,"records":[public_ip(9)],"status":status,"description":format!("sinan-ddns:{}",rule.id)})
}
fn hw_read(records: Vec<Value>) -> Vec<Reply> {
    vec![
        Reply::ok(
            &format!("GET /v2/zones/{ZONE}"),
            json!({"id":ZONE,"name":"example.com.","status":"ACTIVE","zone_type":"public"}),
        ),
        Reply::ok(
            &format!("GET /v2/zones/{ZONE}/recordsets"),
            json!({"recordsets":records,"metadata":{"total_count":records.len()},"links":{}}),
        ),
    ]
}

#[tokio::test]
async fn aliyun_create_then_readback_preserves_exact_record_and_line() {
    let rule = configured(Provider::Aliyun);
    let mut replies = ali_read(vec![]);
    replies.extend([
        Reply::ok(
            "AddDomainRecord",
            json!({"RequestId":"write","RecordId":"record2"}),
        ),
        Reply::ok("DescribeDomainRecordInfo", ali_record(public_ip(9))),
    ]);
    let mock = Mock::start(replies).await;
    let client = Providers::local(&mock.endpoint);
    let outcome = client.reconcile(&rule, public_ip(9)).await.unwrap();
    assert_eq!(outcome.record_id, "record2");
    assert_eq!(outcome.status, "updated");
    let requests = mock.requests();
    assert_eq!(requests[2].params["RR"], "node");
    assert_eq!(requests[2].params["Line"], "default");
    assert!(requests[2].params.contains_key("Signature"));
    assert!(!requests[2].headers.contains_key("authorization"));
    mock.exhausted();
}
#[tokio::test]
async fn tencent_detail_shape_differs_from_list_and_must_confirm_enabled() {
    let mut rule = configured(Provider::Tencent);
    rule.config.adopt_existing = true;
    rule.config.line = "10=1".into();
    rule.config.normalize().unwrap();
    let mut listed = tencent_record(public_ip(1), false);
    listed["LineId"] = "10=1".into();
    let mut detail = tencent_record(public_ip(9), true);
    detail["RecordLineId"] = "10=1".into();
    let mut replies = tencent_read(vec![listed]);
    replies.extend([
        Reply::ok(
            "ModifyRecord",
            json!({"Response":{"RequestId":"write","RecordId":2}}),
        ),
        Reply::ok(
            "DescribeRecord",
            json!({"Response":{"RequestId":"read","RecordInfo":detail}}),
        ),
    ]);
    let mock = Mock::start(replies).await;
    let outcome = Providers::local(&mock.endpoint)
        .reconcile(&rule, public_ip(9))
        .await
        .unwrap();
    assert_eq!(outcome.record_id, "2");
    let requests = mock.requests();
    assert_eq!(requests[2].body["RecordId"], 2);
    assert_eq!(requests[2].body["RecordLineId"], "10=1");
    assert!(
        requests[2].headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("TC3-HMAC-SHA256 Credential=TEST_ONLY_ID/")
    );
    mock.exhausted();
}
#[tokio::test]
async fn huawei_async_receipt_is_not_confirmation_and_pending_is_not_rewritten() {
    let rule = configured(Provider::Huawei);
    let pending = hw_record(&rule, "PENDING_CREATE");
    let mut replies = hw_read(vec![]);
    replies.push(Reply::ok(
        &format!("POST /v2/zones/{ZONE}/recordsets"),
        pending.clone(),
    ));
    let mock = Mock::start(replies).await;
    let client = Providers::local(&mock.endpoint);
    assert_eq!(
        client.reconcile(&rule, public_ip(9)).await.unwrap().status,
        "submitted"
    );
    mock.exhausted();
    let mock = Mock::start(hw_read(vec![pending])).await;
    assert_eq!(
        Providers::local(&mock.endpoint)
            .reconcile(&rule, public_ip(9))
            .await
            .unwrap_err()
            .code,
        "provider_pending"
    );
    mock.exhausted();
    let mock = Mock::start(hw_read(vec![hw_record(&rule, "ACTIVE")])).await;
    assert_eq!(
        Providers::local(&mock.endpoint)
            .reconcile(&rule, public_ip(9))
            .await
            .unwrap()
            .status,
        "unchanged"
    );
    mock.exhausted();
}
#[tokio::test]
async fn all_new_providers_check_the_write_guard_after_reading_and_before_creating() {
    for (provider, replies) in [
        (Provider::Aliyun, ali_read(vec![])),
        (Provider::Tencent, tencent_read(vec![])),
        (Provider::Huawei, hw_read(vec![])),
    ] {
        let rule = configured(provider);
        let mock = Mock::start(replies).await;
        let result = Providers::local(&mock.endpoint)
            .reconcile_guarded(&rule, public_ip(9), || async {
                Err::<(), _>(Failure::from("lease_lost"))
            })
            .await;
        assert_eq!(result.unwrap_err().code, "lease_lost");
        assert_eq!(mock.requests().len(), 2);
        mock.exhausted();
    }
}
#[tokio::test]
async fn foreign_records_duplicates_wrong_names_and_multi_value_sets_are_never_overwritten() {
    for (provider, replies, expected) in [
        (
            Provider::Aliyun,
            ali_read(vec![ali_record(public_ip(9))]),
            "record_not_owned",
        ),
        (
            Provider::Tencent,
            tencent_read(vec![
                tencent_record(public_ip(9), false),
                tencent_record(public_ip(9), false),
            ]),
            "record_conflict",
        ),
        (
            Provider::Aliyun,
            ali_read(vec![{
                let mut v = ali_record(public_ip(9));
                v["RR"] = "wrong".into();
                v
            }]),
            "invalid_response",
        ),
    ] {
        let mock = Mock::start(replies).await;
        assert_eq!(
            Providers::local(&mock.endpoint)
                .reconcile(&configured(provider), public_ip(9))
                .await
                .unwrap_err()
                .code,
            expected
        );
        mock.exhausted();
    }
    let mut rule = configured(Provider::Huawei);
    rule.config.adopt_existing = true;
    let mut record = hw_record(&rule, "ACTIVE");
    record["records"] = json!([public_ip(9), public_ip(8)]);
    let mock = Mock::start(hw_read(vec![record])).await;
    assert_eq!(
        Providers::local(&mock.endpoint)
            .reconcile(&rule, public_ip(9))
            .await
            .unwrap_err()
            .code,
        "record_conflict"
    );
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn submitted_dns_update_keeps_previous_confirmed_address_and_timestamp(pool: sqlx::PgPool) {
    let server: i64 =
        sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY DDNS') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut rule = configured(Provider::Huawei);
    rule.config.server_id = server;
    let lease = Uuid::new_v4();
    sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token,last_ip,last_success_at,lease_id) VALUES($1,$2,$3,'',$4,123,$5)")
        .bind(rule.id).bind(server).bind(json!(rule.config)).bind(public_ip(1).to_string()).bind(lease).execute(&pool).await.unwrap();
    worker::complete(
        &pool,
        &rule,
        lease,
        Ok((
            public_ip(9),
            Outcome {
                record_id: RECORD.into(),
                status: "submitted",
            },
        )),
    )
    .await
    .unwrap();
    let stored = super::super::load(&pool, rule.id).await.unwrap();
    assert_eq!(
        stored.last_ip.as_deref(),
        Some(public_ip(1).to_string().as_str())
    );
    assert_eq!(stored.last_success_at, Some(123));
    assert_eq!(stored.status, "submitted");
    assert_eq!(stored.record_id.as_deref(), Some(RECORD));
}
