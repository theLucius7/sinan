use super::super::super::notices;
use super::*;

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn active_power_job_does_not_roll_back_fresh_billing_or_queue_bandwidth_changes(
    pool: PgPool,
) {
    let (a, r) = seed(&pool).await;
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE alicloud_accounts SET auto_enabled=true WHERE id=$1")
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE alicloud_resources SET auto_enabled=true WHERE id=$1")
        .bind(r)
        .execute(&pool)
        .await
        .unwrap();
    let initial = state("Running", "KeepCharging");
    let job = prepare(&pool, r, &initial, "stop", "KeepCharging").await;
    api::confirm_on(&pool, job).await.unwrap();
    let mut snapshot = response(&initial);
    snapshot.value["Instances"]["Instance"][0]["InternetMaxBandwidthOut"] = 10.into();
    snapshot.value["Instances"]["Instance"][0]["InternetChargeType"] = "PayByTraffic".into();
    let mock=Mock::start(vec![Reply::ok("QueryInstanceBill",json!({"RequestId":"test-bill","Data":{"BillingCycle":billing::month(now),"PageNum":1,"TotalCount":1,"Items":{"Item":[{"Item":"PayAsYouGoBill","ProductCode":"cdt","InstanceID":"test-instance","Usage":"100","UsageUnit":"GB","Currency":"CNY","PretaxAmount":"1.00"}]}}})),Reply::ok("ListCdtInternetTraffic",json!({"RequestId":"test-traffic","TrafficDetails":[{"BusinessRegionId":"cn-hangzhou","Traffic":100}]})),snapshot]).await;
    super::super::super::worker::refresh(&pool, a, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    let mut tx = lock(&pool, a).await.unwrap();
    let account = account_on(&mut tx, a).await.unwrap();
    assert_eq!(account.bill.unwrap().usage_micro_gb, Some(100_000_000));
    assert!(account.next_run_at > now);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_operations")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count, 0);
    mock.exhausted();
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn delayed_scheduled_stop_is_revoked_when_the_next_running_window_begins(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let day = 20000 * 86400 - 8 * 3600;
    let mut p = policy();
    p.threshold_action = "off".into();
    p.keepalive = false;
    p.stop_time = "08:00".into();
    p.start_time = "08:01".into();
    sqlx::query("UPDATE alicloud_resources SET power_policy=$2 WHERE id=$1")
        .bind(r)
        .bind(Json(&p))
        .execute(&pool)
        .await
        .unwrap();
    evaluate(
        &pool,
        a,
        r,
        &state("Running", "KeepCharging"),
        day + 8 * 3600,
    )
    .await;
    let mut tx = lock(&pool, a).await.unwrap();
    let account = account_on(&mut tx, a).await.unwrap();
    let resource = jobs::fresh(&mut tx, r).await.unwrap();
    let job: super::super::Job = sqlx::query_as("SELECT * FROM alicloud_power_jobs")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(jobs::allowed(
        &job,
        &account,
        &resource,
        day + 8 * 3600 + 30
    ));
    assert!(!jobs::allowed(
        &job,
        &account,
        &resource,
        day + 8 * 3600 + 61
    ));
}
use crate::settings::Settings;

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn new_threshold_cancels_queued_start_before_any_write(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let now = sinan_protocol::now_timestamp();
    let mut p = policy();
    p.schedule_enabled = false;
    sqlx::query("UPDATE alicloud_resources SET power_policy=$2 WHERE id=$1")
        .bind(r)
        .bind(Json(&p))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE alicloud_accounts SET bill=$2 WHERE id=$1").bind(a).bind(json!({"month":billing::month(now),"queried_at":now,"rows":[],"usage_micro_gb":94_000_000})).execute(&pool).await.unwrap();
    let id = prepare(
        &pool,
        r,
        &state("Stopped", "KeepCharging"),
        "start",
        "KeepCharging",
    )
    .await;
    api::confirm_on(&pool, id).await.unwrap();
    sqlx::query("UPDATE alicloud_accounts SET bill=jsonb_set(bill,'{usage_micro_gb}','95000000') WHERE id=$1").bind(a).execute(&pool).await.unwrap();
    evaluate(&pool, a, r, &state("Stopped", "KeepCharging"), now).await;
    let mock = Mock::start(vec![]).await;
    jobs::process(&pool, id, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    assert_eq!(jobs::load(&pool, id).await.unwrap().status, "cancelled");
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn schedule_restart_deduplicates_completed_events_and_does_not_replay_old_days(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let mut p = policy();
    p.threshold_action = "off".into();
    p.keepalive = false;
    p.start_time = "08:00".into();
    p.stop_time = "23:00".into();
    sqlx::query("UPDATE alicloud_resources SET power_policy=$2 WHERE id=$1")
        .bind(r)
        .bind(Json(&p))
        .execute(&pool)
        .await
        .unwrap();
    let day = 20000 * 86400 - 8 * 3600;
    let stopped = state("Stopped", "KeepCharging");
    evaluate(&pool, a, r, &stopped, day + 8 * 3600 + 60).await;
    sqlx::query("UPDATE alicloud_power_jobs SET status='succeeded'")
        .execute(&pool)
        .await
        .unwrap();
    evaluate(&pool, a, r, &stopped, day + 8 * 3600 + 120).await;
    evaluate(&pool, a, r, &stopped, day + 86400 + 8 * 3600 + 601).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    evaluate(
        &pool,
        a,
        r,
        &state("Running", "KeepCharging"),
        day + 2 * 86400 + 23 * 3600 + 60,
    )
    .await;
    let action: String =
        sqlx::query_scalar("SELECT action FROM alicloud_power_jobs WHERE status='queued'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(action, "stop");
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn cloud_identity_is_checked_and_prepaid_economical_stop_is_rejected(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let mut tx = lock(&pool, a).await.unwrap();
    let a = account_on(&mut tx, a).await.unwrap();
    let r = jobs::fresh(&mut tx, r).await.unwrap();
    tx.rollback().await.unwrap();
    let mut s = state("Running", "KeepCharging");
    s.cloud_id = "i-other-test".into();
    let mock = Mock::start(vec![response(&s)]).await;
    assert_eq!(
        Cloud::local(&mock.endpoint)
            .power_state(&a, &r)
            .await
            .unwrap_err()
            .code,
        "resource_not_found"
    );
    mock.exhausted();
    s = state("Running", "KeepCharging");
    s.charge_type = "PrePaid".into();
    assert_eq!(
        s.validate("stop", "StopCharging").unwrap_err().code,
        "stop_mode_unsupported"
    );
    s.validate("stop", "KeepCharging").unwrap();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn cloud_notices_deduplicate_and_retry_without_real_delivery(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let now = sinan_protocol::now_timestamp();
    let settings = Settings {
        telegram_enabled: true,
        telegram_chat_id: "-100000".into(),
        telegram_token: "123:TEST_ONLY_SECRET_00000000000".into(),
        ..Default::default()
    };
    sqlx::query("UPDATE panel_settings SET settings=$1")
        .bind(serde_json::to_value(settings).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = lock(&pool, a).await.unwrap();
    let r = jobs::fresh(&mut tx, r).await.unwrap();
    for _ in 0..2 {
        notices::record(&mut tx, &r, "test-event", "流量提醒", "测试事件", now)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_deliveries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    notices::dispatch_with(&pool, |_, channel, payload| async move {
        assert_eq!(channel, "telegram");
        assert!(payload.contains("测试事件"));
        assert!(!payload.contains("TEST_ONLY_SECRET"));
        Err(("测试限流".into(), Some(321)))
    })
    .await
    .unwrap();
    let (status, attempts, next): (String, i32, i64) =
        sqlx::query_as("SELECT status,attempts,next_attempt_at FROM alicloud_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "pending");
    assert_eq!(attempts, 1);
    assert!(next >= now + 321);
    notices::dispatch_with(&pool, |_, _, _| async {
        panic!("retry cooldown must be respected");
        #[allow(unreachable_code)]
        Ok(())
    })
    .await
    .unwrap();
    sqlx::query("UPDATE alicloud_deliveries SET next_attempt_at=0")
        .execute(&pool)
        .await
        .unwrap();
    notices::dispatch_with(&pool, |_, _, _| async { Ok(()) })
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM alicloud_deliveries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "sent");
}
