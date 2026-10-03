use super::super::{account_on, billing, client::Cloud, lock, model::Resource, operations};
use super::{State, api, jobs, policy::Policy, scheduler};
use crate::cloud_api::test_support::{Mock, Reply};
use serde_json::json;
use sqlx::{PgPool, types::Json};
use uuid::Uuid;
mod cases;
mod regressions;

async fn seed(pool: &PgPool) -> (Uuid, Uuid) {
    let a = Uuid::new_v4();
    let r = Uuid::new_v4();
    sqlx::query("INSERT INTO alicloud_accounts(id,name,access_key_id,access_key_secret) VALUES($1,'测试账号','TEST_ONLY_KEY','TEST_ONLY_SECRET')").bind(a).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id) VALUES($1,$2,'测试实例','ecs','cn-hangzhou','i-testonly')").bind(r).bind(a).execute(pool).await.unwrap();
    (a, r)
}
fn state(status: &str, mode: &str) -> State {
    State {
        cloud_id: "i-testonly".into(),
        region: "cn-hangzhou".into(),
        status: status.into(),
        stopped_mode: Some(mode.into()),
        charge_type: "PostPaid".into(),
        network_type: "vpc".into(),
        spot_strategy: "SpotAsPriceGo".into(),
        interruption_behavior: Some("Stop".into()),
        public_ips: vec!["192.0.2.1".into()],
        locked: false,
    }
}
fn response(s: &State) -> Reply {
    Reply::ok(
        "DescribeInstances",
        json!({"RequestId":"test-read","TotalCount":1,"Instances":{"Instance":[{"InstanceId":s.cloud_id,"RegionId":s.region,"Status":s.status,"StoppedMode":s.stopped_mode,"InstanceChargeType":s.charge_type,"InstanceNetworkType":s.network_type,"SpotStrategy":s.spot_strategy,"SpotInterruptionBehavior":s.interruption_behavior,"PublicIpAddress":{"IpAddress":s.public_ips},"OperationLocks":{"LockReason":[]}}]}}),
    )
}
async fn prepare(pool: &PgPool, id: Uuid, s: &State, action: &str, mode: &str) -> Uuid {
    let r = super::super::resource(pool, id).await.unwrap();
    let mut tx = lock(pool, r.account_id).await.unwrap();
    let a = account_on(&mut tx, r.account_id).await.unwrap();
    let now = sinan_protocol::now_timestamp();
    let id = jobs::prepare(
        &mut tx,
        &a,
        &r,
        s,
        jobs::Intent {
            action,
            mode,
            source: "manual",
            key: None,
            expires_at: now + 300,
        },
        now,
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    id
}
async fn force_due(pool: &PgPool, id: Uuid) {
    sqlx::query("UPDATE alicloud_power_jobs SET next_check_at=0 WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn stop_is_confirmed_once_and_recovers_without_duplicate_write(pool: PgPool) {
    let (_, r) = seed(&pool).await;
    let initial = state("Running", "KeepCharging");
    let id = prepare(&pool, r, &initial, "stop", "StopCharging").await;
    api::confirm_on(&pool, id).await.unwrap();
    api::confirm_on(&pool, id).await.unwrap();
    assert!(super::super::resource(&pool, r).await.unwrap().manual_hold);
    let mut stopped = state("Stopped", "StopCharging");
    stopped.public_ips.clear();
    let mock = Mock::start(vec![
        response(&initial),
        Reply::ok("StopInstance", json!({"RequestId":"test-stop"})),
        response(&state("Stopping", "KeepCharging")),
        response(&stopped),
    ])
    .await;
    let cloud = Cloud::local(&mock.endpoint);
    jobs::process(&pool, id, &cloud).await.unwrap();
    assert_eq!(jobs::load(&pool, id).await.unwrap().status, "uncertain");
    assert!(api::close(&pool, id, false).await.is_err());
    force_due(&pool, id).await;
    jobs::process(&pool, id, &cloud).await.unwrap();
    jobs::process(&pool, id, &cloud).await.unwrap();
    let job = jobs::load(&pool, id).await.unwrap();
    assert_eq!(job.status, "succeeded");
    assert_eq!(job.request_id.as_deref(), Some("test-stop"));
    let requests = mock.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.action == "StopInstance")
            .count(),
        1
    );
    assert_eq!(requests[1].params["ForceStop"], "false");
    assert_eq!(requests[1].params["StoppedMode"], "StopCharging");
    assert!(!requests[1].params.contains_key("ClientToken"));
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn crash_after_intent_only_reads_state_and_mode_mismatch_is_not_success(pool: PgPool) {
    let (_, r) = seed(&pool).await;
    let id = prepare(
        &pool,
        r,
        &state("Running", "KeepCharging"),
        "stop",
        "StopCharging",
    )
    .await;
    sqlx::query("UPDATE alicloud_power_jobs SET status='running' WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let mock = Mock::start(vec![response(&state("Stopped", "KeepCharging"))]).await;
    jobs::process(&pool, id, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    let job = jobs::load(&pool, id).await.unwrap();
    assert_eq!(job.status, "failed");
    assert_eq!(job.error_code.as_deref(), Some("stop_mode_mismatch"));
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn cancellation_revision_changes_and_bandwidth_interlock_block_writes(pool: PgPool) {
    let (_, r) = seed(&pool).await;
    let id = prepare(
        &pool,
        r,
        &state("Stopped", "KeepCharging"),
        "start",
        "KeepCharging",
    )
    .await;
    api::confirm_on(&pool, id).await.unwrap();
    let initial = super::super::resource(&pool, r).await.unwrap();
    let mut tx = lock(&pool, initial.account_id).await.unwrap();
    assert!(operations::idle(&mut tx, r).await.is_err());
    tx.rollback().await.unwrap();
    api::close(&pool, id, false).await.unwrap();
    let mock = Mock::start(vec![]).await;
    jobs::process(&pool, id, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    let id = prepare(
        &pool,
        r,
        &state("Stopped", "KeepCharging"),
        "start",
        "KeepCharging",
    )
    .await;
    api::confirm_on(&pool, id).await.unwrap();
    sqlx::query("UPDATE alicloud_resources SET revision=revision+1 WHERE id=$1")
        .bind(r)
        .execute(&pool)
        .await
        .unwrap();
    jobs::process(&pool, id, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    assert_eq!(jobs::load(&pool, id).await.unwrap().status, "cancelled");
    mock.exhausted();
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn start_rejection_is_terminal_but_unknown_write_remains_uncertain(pool: PgPool) {
    let (_, r) = seed(&pool).await;
    let s = state("Stopped", "KeepCharging");
    let id = prepare(&pool, r, &s, "start", "KeepCharging").await;
    api::confirm_on(&pool, id).await.unwrap();
    let mut rejected = Reply::ok(
        "StartInstance",
        json!({"RequestId":"test-reject","Code":"OperationDenied.NoStock"}),
    );
    rejected.status = 403;
    let mock = Mock::start(vec![response(&s), rejected]).await;
    jobs::process(&pool, id, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    let job = jobs::load(&pool, id).await.unwrap();
    assert_eq!(job.status, "failed");
    assert_eq!(job.error_code.as_deref(), Some("capacity_unavailable"));
    assert_eq!(mock.requests()[1].params["InitLocalDisk"], "false");
    mock.exhausted();
    let id = prepare(&pool, r, &s, "start", "KeepCharging").await;
    api::confirm_on(&pool, id).await.unwrap();
    let mut unknown = Reply::ok("StartInstance", json!({"RequestId":"test-reject"}));
    unknown.status = 503;
    let mock = Mock::start(vec![response(&s), unknown, response(&s)]).await;
    let cloud = Cloud::local(&mock.endpoint);
    jobs::process(&pool, id, &cloud).await.unwrap();
    force_due(&pool, id).await;
    jobs::process(&pool, id, &cloud).await.unwrap();
    assert_eq!(jobs::load(&pool, id).await.unwrap().status, "uncertain");
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|r| r.action == "StartInstance")
            .count(),
        1
    );
    mock.exhausted();
}
fn policy() -> Policy {
    serde_json::from_value(json!({"enabled":true,"stop_mode":"KeepCharging","threshold_action":"stop","limit_gb":100,"threshold_percent":95,"schedule_enabled":true,"start_time":"23:58","stop_time":"08:00","utc_offset_minutes":480,"keepalive":true})).unwrap()
}
#[test]
fn schedule_handles_midnight_window_and_overlapping_due_events() {
    let mut p = policy();
    p.validate().unwrap();
    let day = 20000 * 86400 - 8 * 3600;
    assert!(p.in_window(day + 86400 + 60));
    assert_eq!(
        p.occurrence("start", day + 86400 + 60),
        Some(day + 23 * 3600 + 58 * 60)
    );
    assert!(p.occurrence("start", day + 86400 + 9 * 60).is_none());
    assert!(!p.in_window(day + 8 * 3600));
    p.start_time = "08:00".into();
    p.stop_time = "08:03".into();
    assert!(!p.in_window(day + 8 * 3600 + 4 * 60));
    assert!(p.occurrence("start", day + 8 * 3600 + 4 * 60).is_some());
    p.stop_time = "08:00".into();
    assert!(p.validate().is_err());
    p.stop_time = "24:00".into();
    assert!(p.validate().is_err());
}
async fn evaluate(pool: &PgPool, a: Uuid, r: Uuid, s: &State, now: i64) -> Resource {
    let mut tx = lock(pool, a).await.unwrap();
    let a = account_on(&mut tx, a).await.unwrap();
    let mut r = jobs::fresh(&mut tx, r).await.unwrap();
    scheduler::evaluate(&mut tx, &a, &mut r, s, now)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    r
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn threshold_is_sticky_and_preempts_start_notify_is_deduplicated(pool: PgPool) {
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
    let bill =
        json!({"month":billing::month(now),"queried_at":now,"rows":[],"usage_micro_gb":95_000_000});
    sqlx::query("UPDATE alicloud_accounts SET bill=$2 WHERE id=$1")
        .bind(a)
        .bind(bill)
        .execute(&pool)
        .await
        .unwrap();
    let running = state("Running", "KeepCharging");
    let result = evaluate(&pool, a, r, &running, now).await;
    assert!(result.threshold_hold);
    evaluate(&pool, a, r, &running, now).await;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs WHERE source='threshold'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    sqlx::query("UPDATE alicloud_accounts SET error_code='network_error' WHERE id=$1")
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        evaluate(&pool, a, r, &state("Stopped", "StopCharging"), now + 60)
            .await
            .threshold_hold
    );
    sqlx::query("UPDATE alicloud_accounts SET error_code=NULL,bill=jsonb_set(bill,'{usage_micro_gb}','null') WHERE id=$1").bind(a).execute(&pool).await.unwrap();
    assert!(
        evaluate(&pool, a, r, &state("Stopped", "StopCharging"), now + 60)
            .await
            .threshold_hold
    );
    sqlx::query("UPDATE alicloud_accounts SET error_code=NULL,bill=jsonb_set(bill,'{usage_micro_gb}','94000000') WHERE id=$1").bind(a).execute(&pool).await.unwrap();
    assert!(
        !evaluate(&pool, a, r, &state("Stopped", "StopCharging"), now + 60)
            .await
            .threshold_hold
    );
}
#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn manual_hold_and_non_spot_instances_disable_keepalive_and_schedule_deduplicates(
    pool: PgPool,
) {
    let (a, r) = seed(&pool).await;
    let mut p = policy();
    p.threshold_action = "off".into();
    p.schedule_enabled = false;
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE alicloud_resources SET power_policy=$2,manual_hold=true WHERE id=$1")
        .bind(r)
        .bind(Json(&p))
        .execute(&pool)
        .await
        .unwrap();
    evaluate(&pool, a, r, &state("Stopped", "KeepCharging"), now).await;
    sqlx::query("UPDATE alicloud_resources SET manual_hold=false WHERE id=$1")
        .bind(r)
        .execute(&pool)
        .await
        .unwrap();
    let mut regular = state("Stopped", "KeepCharging");
    regular.spot_strategy = "NoSpot".into();
    evaluate(&pool, a, r, &regular, now).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    evaluate(&pool, a, r, &state("Stopped", "KeepCharging"), now).await;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs WHERE source='keepalive'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    sqlx::query("UPDATE alicloud_power_jobs SET status='failed'")
        .execute(&pool)
        .await
        .unwrap();
    evaluate(&pool, a, r, &state("Stopped", "KeepCharging"), now + 899).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
