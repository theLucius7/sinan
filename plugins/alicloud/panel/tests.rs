use super::{
    billing,
    client::Cloud,
    model::{Account, Target},
    operations, worker,
};
use crate::cloud_api::test_support::{Mock, Reply};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

mod billing_cases;

const KEY: &str = "TEST_ONLY_CLOUD_ID";
const SECRET: &str = "TEST_ONLY_CLOUD_SECRET";
async fn seed(pool: &PgPool, kind: &str) -> (Uuid, Uuid) {
    let account = Uuid::new_v4();
    let resource = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret) VALUES($1,'测试账号',$2,$3)")
        .bind(account).bind(KEY).bind(SECRET).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'测试资源',$3,'cn-hangzhou',$4)")
        .bind(resource).bind(account).bind(kind).bind(if kind=="ecs"{"i-testonly"}else{"eip-testonly"}).execute(pool).await.unwrap();
    (account, resource)
}
async fn account(pool: &PgPool, id: Uuid) -> Account {
    sqlx::query_as("SELECT * FROM alicloud_accounts WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}
fn target() -> Target {
    Target {
        bandwidth_mbps: 1,
        charge_type: "PayByTraffic".into(),
    }
}
fn snapshot(kind: &str, bandwidth: i64) -> Reply {
    let (action, value) = if kind == "ecs" {
        (
            "DescribeInstances",
            json!({"Instances":{"Instance":[{"InstanceId":"i-testonly","RegionId":"cn-hangzhou","PublicIpAddress":{"IpAddress":["192.0.2.1"]},"InternetMaxBandwidthOut":bandwidth,"InternetChargeType":"PayByTraffic","InstanceChargeType":"PostPaid","Status":"Running"}]}}),
        )
    } else {
        (
            "DescribeEipAddresses",
            json!({"EipAddresses":{"EipAddress":[{"AllocationId":"eip-testonly","RegionId":"cn-hangzhou","IpAddress":"192.0.2.1","Bandwidth":bandwidth.to_string(),"InternetChargeType":"PayByTraffic","ChargeType":"PostPaid","Status":"InUse","Netmode":"public","BandwidthPackageId":""}]}}),
        )
    };
    let mut value = value;
    value["RequestId"] = "read-request".into();
    value["TotalCount"] = 1.into();
    Reply::ok(action, value)
}
async fn due(pool: &PgPool, id: Uuid) {
    sqlx::query("UPDATE alicloud_operations SET next_check_at=0 WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn ecs_preview_is_read_only_confirmation_is_idempotent_and_change_is_verified(pool: PgPool) {
    let (_, id) = seed(&pool, "ecs").await;
    let mock = Mock::start(vec![
        snapshot("ecs", 10),
        snapshot("ecs", 10),
        Reply::ok(
            "ModifyInstanceNetworkSpec",
            json!({"RequestId":"write-request"}),
        ),
        snapshot("ecs", 1),
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    let preview = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    assert_eq!(preview.status, "preview");
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(
        operations::confirm(&pool, preview.id).await.unwrap().status,
        "queued"
    );
    operations::confirm(&pool, preview.id).await.unwrap();
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    assert_eq!(
        operations::load(&pool, preview.id).await.unwrap().status,
        "succeeded"
    );
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, preview.id).await.unwrap();
    let requests = mock.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.action.starts_with("Modify"))
            .count(),
        1
    );
    let params = &requests[2].params;
    assert_eq!(params["ClientToken"], preview.id.to_string());
    assert_eq!(params["AllocatePublicIp"], "false");
    assert_eq!(params["AutoPay"], "true");
    assert!(!params.contains_key("NetworkChargeType"));
    assert_eq!(requests.len(), 4);
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn eip_adjusts_bandwidth_only_and_refuses_charge_conversion_and_shared_packages(
    pool: PgPool,
) {
    let (account_id, id) = seed(&pool, "eip").await;
    let a = account(&pool, account_id).await;
    let r = super::resource(&pool, id).await.unwrap();
    let mut shared = snapshot("eip", 10);
    shared.value["EipAddresses"]["EipAddress"][0]["BandwidthPackageId"] = "cbwp-testonly".into();
    let mock = Mock::start(vec![shared]).await;
    assert_eq!(
        Cloud::local(&mock.endpoint)
            .snapshot(&a, &r)
            .await
            .unwrap_err()
            .code,
        "unsupported_resource"
    );
    mock.exhausted();
    let mock = Mock::start(vec![snapshot("eip", 10)]).await;
    let invalid = Target {
        bandwidth_mbps: 1,
        charge_type: "PayByBandwidth".into(),
    };
    assert!(
        operations::preview(&pool, id, invalid, 1, &Cloud::local(&mock.endpoint))
            .await
            .is_err()
    );
    mock.exhausted();
    let mock = Mock::start(vec![
        snapshot("eip", 10),
        snapshot("eip", 10),
        Reply::ok(
            "ModifyEipAddressAttribute",
            json!({"RequestId":"write-eip"}),
        ),
        snapshot("eip", 1),
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    let preview = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, preview.id).await.unwrap();
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    let params = &mock.requests()[2].params;
    assert_eq!(params["AllocationId"], "eip-testonly");
    assert_eq!(params["Bandwidth"], "1");
    assert!(!params.contains_key("InternetChargeType"));
    assert!(!params.contains_key("ClientToken"));
    assert_eq!(
        operations::load(&pool, preview.id).await.unwrap().status,
        "succeeded"
    );
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn uncertain_write_survives_restart_and_never_replays_eip_mutation(pool: PgPool) {
    let (_, id) = seed(&pool, "eip").await;
    let mock = Mock::start(vec![
        snapshot("eip", 10),
        snapshot("eip", 10),
        Reply {
            action: "ModifyEipAddressAttribute".into(),
            status: 503,
            value: json!({"secret":SECRET}),
        },
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    let preview = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, preview.id).await.unwrap();
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    mock.exhausted();
    let operation = operations::load(&pool, preview.id).await.unwrap();
    assert_eq!(operation.status, "uncertain");
    assert!(!serde_json::to_string(&operation).unwrap().contains(SECRET));
    assert!(
        operations::preview(&pool, id, target(), 1, &cloud)
            .await
            .is_err()
    );
    // A fresh client represents a restarted panel. It only issues a read.
    let restored = Mock::start(vec![snapshot("eip", 1)]).await;
    due(&pool, preview.id).await;
    operations::process(&pool, preview.id, &Cloud::local(&restored.endpoint))
        .await
        .unwrap();
    assert_eq!(
        operations::load(&pool, preview.id).await.unwrap().status,
        "succeeded"
    );
    restored.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn committed_intent_and_external_drift_are_never_blindly_reapplied(pool: PgPool) {
    let (_, id) = seed(&pool, "ecs").await;
    let mock = Mock::start(vec![snapshot("ecs", 10), snapshot("ecs", 20)]).await;
    let cloud = Cloud::local(&mock.endpoint);
    let preview = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, preview.id).await.unwrap();
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    assert_eq!(
        operations::load(&pool, preview.id)
            .await
            .unwrap()
            .error_code
            .as_deref(),
        Some("state_changed")
    );
    mock.exhausted();
    let mock = Mock::start(vec![snapshot("ecs", 10), snapshot("ecs", 10)]).await;
    let cloud = Cloud::local(&mock.endpoint);
    let preview = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, preview.id).await.unwrap();
    sqlx::query("UPDATE alicloud_operations SET status='running' WHERE id=$1")
        .bind(preview.id)
        .execute(&pool)
        .await
        .unwrap();
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    assert_eq!(
        operations::load(&pool, preview.id).await.unwrap().status,
        "uncertain"
    );
    mock.exhausted();
    sqlx::query("UPDATE alicloud_resources SET auto_enabled=true WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    operations::cancel(&pool, preview.id, true).await.unwrap();
    assert!(!super::resource(&pool, id).await.unwrap().auto_enabled);
    assert_eq!(
        operations::load(&pool, preview.id).await.unwrap().status,
        "dismissed"
    );
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn cancelled_or_revised_policy_does_not_reach_the_cloud(pool: PgPool) {
    let (account_id, id) = seed(&pool, "ecs").await;
    let mock = Mock::start(vec![snapshot("ecs", 10), snapshot("ecs", 10)]).await;
    let cloud = Cloud::local(&mock.endpoint);
    let preview = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, preview.id).await.unwrap();
    operations::cancel(&pool, preview.id, false).await.unwrap();
    operations::process(&pool, preview.id, &cloud)
        .await
        .unwrap();
    let second = operations::preview(&pool, id, target(), 1, &cloud)
        .await
        .unwrap();
    operations::confirm(&pool, second.id).await.unwrap();
    let mut tx = super::lock(&pool, account_id).await.unwrap();
    sqlx::query("UPDATE alicloud_accounts SET enabled=false,revision=revision+1 WHERE id=$1")
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    operations::process(&pool, second.id, &cloud).await.unwrap();
    assert_eq!(
        operations::load(&pool, second.id).await.unwrap().status,
        "cancelled"
    );
    mock.exhausted();
}
