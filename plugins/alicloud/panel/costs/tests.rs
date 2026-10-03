use super::*;
use crate::cloud_api::test_support::{Mock, Reply};
use serde_json::json;

async fn seed(pool: &PgPool) -> (Uuid, Uuid) {
    let a = Uuid::new_v4();
    let r = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret,site) VALUES($1,'测试账号','TEST_ONLY_KEY','TEST_ONLY_SECRET','international')").bind(a).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'测试实例','ecs','cn-hangzhou','i-testonly')").bind(r).bind(a).execute(pool).await.unwrap();
    (a, r)
}
fn balance(value: Value) -> Reply {
    Reply::ok(
        "QueryAccountBalance",
        json!({"RequestId":"test-balance","Success":true,"Data":value}),
    )
}
fn bill(month: &str, token: &str, rows: Value, total: u64) -> Reply {
    Reply::ok(
        "DescribeInstanceBill",
        json!({"RequestId":"test-bill","Success":true,"Data":{"BillingCycle":month,"NextToken":token,"TotalCount":total,"Items":rows}}),
    )
}
fn row(amount: &str, currency: &str) -> Value {
    json!({"InstanceID":"i-testonly","Item":"PayAsYouGoBill","PretaxAmount":amount,"Currency":currency})
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn balance_cache_avoids_repeat_calls_and_retains_stale_value_on_error(pool: PgPool) {
    let (a, _) = seed(&pool).await;
    let now = sinan_protocol::now_timestamp();
    let mock = Mock::start(vec![
        balance(json!({"AvailableAmount":"1,234.5600","Currency":"USD"})),
        balance(json!({"AvailableAmount":"0"})),
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    refresh_balance(&pool, a, &cloud, now).await.unwrap();
    refresh_balance(&pool, a, &cloud, now + 21599)
        .await
        .unwrap();
    assert_eq!(mock.requests().len(), 1);
    refresh_balance(&pool, a, &cloud, now + 21600)
        .await
        .unwrap();
    refresh_balance(&pool, a, &cloud, now + 21601)
        .await
        .unwrap();
    let mut tx = lock(&pool, a).await.unwrap();
    let stored = account_on(&mut tx, a).await.unwrap();
    let value = stored.balance.unwrap();
    assert_eq!(value.currency, "USD");
    assert_eq!(value.available, "1234.5600");
    assert_eq!(value.queried_at, now);
    assert_eq!(stored.balance_error.as_deref(), Some("invalid_response"));
    assert_eq!(stored.balance_next_at, now + 21900);
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn instance_cache_collects_pages_keeps_currencies_and_refreshes_on_month_rollover(
    pool: PgPool,
) {
    let (_, r) = seed(&pool).await;
    let now = 1790783940; // 2026-09-30 23:59 in UTC+8.
    let month = billing::month(now);
    let next = billing::month(now + 120);
    assert_ne!(month, next);
    let mock = Mock::start(vec![
        bill(&month, "page-2", json!([row("12.3456", "CNY")]), 2),
        bill(&month, "", json!([row("-1.25", "USD")]), 2),
        bill(&next, "", json!([]), 0),
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    refresh_bill(&pool, r, &cloud, now).await.unwrap();
    refresh_bill(&pool, r, &cloud, now + 1).await.unwrap();
    assert_eq!(mock.requests().len(), 2);
    let stored = super::super::resource(&pool, r)
        .await
        .unwrap()
        .instance_bill
        .unwrap();
    assert_eq!(stored.rows[0].amount, "12.3456");
    assert_eq!(stored.rows[1].currency, "USD");
    refresh_bill(&pool, r, &cloud, now + 120).await.unwrap();
    assert_eq!(
        super::super::resource(&pool, r)
            .await
            .unwrap()
            .instance_bill
            .unwrap()
            .month,
        next
    );
    let requests = mock.requests();
    assert_eq!(requests[1].params["NextToken"], "page-2");
    assert_eq!(requests[0].params["InstanceID"], "i-testonly");
    assert!(!requests[0].params.contains_key("PageNum"));
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn incomplete_bills_wrong_resource_and_repeated_pages_never_replace_valid_cache(
    pool: PgPool,
) {
    let (_, r) = seed(&pool).await;
    let now = sinan_protocol::now_timestamp();
    let month = billing::month(now);
    let mut wrong = row("1.00", "CNY");
    wrong["InstanceID"] = "i-other-test".into();
    let mock = Mock::start(vec![
        bill(&month, "", json!([row("1.00", "CNY")]), 1),
        bill(&month, "", json!([wrong]), 1),
        bill(&month, "loop", json!([row("2.00", "CNY")]), 2),
        bill(&month, "loop", json!([row("2.00", "CNY")]), 2),
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    refresh_bill(&pool, r, &cloud, now).await.unwrap();
    refresh_bill(&pool, r, &cloud, now + 21600).await.unwrap();
    refresh_bill(&pool, r, &cloud, now + 21900).await.unwrap();
    let stored = super::super::resource(&pool, r).await.unwrap();
    assert_eq!(stored.bill_error.as_deref(), Some("billing_incomplete"));
    assert_eq!(stored.instance_bill.unwrap().queried_at, now);
    mock.exhausted();
}
