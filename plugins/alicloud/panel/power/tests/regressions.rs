use super::super::super::model::{Snapshot, Target};
use super::*;

fn snapshot() -> Snapshot {
    Snapshot {
        kind: "ecs".into(),
        cloud_id: "i-testonly".into(),
        region: "cn-hangzhou".into(),
        public_ip: "192.0.2.1".into(),
        bandwidth_mbps: 10,
        charge_type: "PayByTraffic".into(),
        resource_charge_type: "PostPaid".into(),
        status: "Running".into(),
    }
}

async fn bandwidth_preview(pool: &PgPool, a: Uuid, r: Uuid) -> Uuid {
    let mut tx = lock(pool, a).await.unwrap();
    let account = account_on(&mut tx, a).await.unwrap();
    let resource = jobs::fresh(&mut tx, r).await.unwrap();
    let target = Target {
        bandwidth_mbps: 1,
        charge_type: "PayByTraffic".into(),
    };
    let id = operations::prepare(&mut tx, &account, &resource, &snapshot(), &target, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn keepalive_rejection_cools_down_from_response_not_old_creation(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let mut p = policy();
    p.threshold_action = "off".into();
    p.schedule_enabled = false;
    sqlx::query("UPDATE alicloud_resources SET power_policy=$2 WHERE id=$1")
        .bind(r)
        .bind(Json(&p))
        .execute(&pool)
        .await
        .unwrap();
    let stopped = state("Stopped", "KeepCharging");
    let id = prepare(&pool, r, &stopped, "start", "KeepCharging").await;
    api::confirm_on(&pool, id).await.unwrap();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE alicloud_power_jobs SET source='keepalive',created_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now - 240)
        .execute(&pool)
        .await
        .unwrap();
    let mut rejection = Reply::ok(
        "StartInstance",
        json!({"RequestId":"test-reject","Code":"OperationDenied.NoStock"}),
    );
    rejection.status = 403;
    let mock = Mock::start(vec![response(&stopped), rejection]).await;
    jobs::process(&pool, id, &Cloud::local(&mock.endpoint))
        .await
        .unwrap();
    let job = jobs::load(&pool, id).await.unwrap();
    assert_eq!(job.status, "failed");
    assert_eq!(job.error_code.as_deref(), Some("capacity_unavailable"));
    let resource = super::super::super::resource(&pool, r).await.unwrap();
    assert!(resource.next_power_at >= job.updated_at + 900);
    evaluate(&pool, a, r, &stopped, job.updated_at + 899).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    evaluate(&pool, a, r, &stopped, job.updated_at + 900).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(mock.requests().len(), 2);
    mock.exhausted();
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn dismissing_unknown_bandwidth_pauses_both_automations_and_old_power_preview(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    let p = policy();
    sqlx::query("UPDATE alicloud_resources SET auto_enabled=true,power_policy=$2 WHERE id=$1")
        .bind(r)
        .bind(Json(&p))
        .execute(&pool)
        .await
        .unwrap();
    let power = prepare(
        &pool,
        r,
        &state("Running", "KeepCharging"),
        "stop",
        "KeepCharging",
    )
    .await;
    let bandwidth = bandwidth_preview(&pool, a, r).await;
    sqlx::query("UPDATE alicloud_operations SET status='uncertain' WHERE id=$1")
        .bind(bandwidth)
        .execute(&pool)
        .await
        .unwrap();
    operations::cancel(&pool, bandwidth, true).await.unwrap();
    let resource = super::super::super::resource(&pool, r).await.unwrap();
    assert!(!resource.auto_enabled);
    assert!(!resource.power_policy.enabled);
    assert!(resource.manual_hold);
    assert_eq!(resource.revision, 2);
    assert_eq!(
        operations::load(&pool, bandwidth).await.unwrap().status,
        "dismissed"
    );
    assert_eq!(jobs::load(&pool, power).await.unwrap().status, "cancelled");
    evaluate(
        &pool,
        a,
        r,
        &state("Stopped", "KeepCharging"),
        sinan_protocol::now_timestamp(),
    )
    .await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM alicloud_power_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "../../../crates/panel/migrations")]
async fn resume_requires_current_revision_and_revokes_prior_previews(pool: PgPool) {
    let (a, r) = seed(&pool).await;
    sqlx::query("UPDATE alicloud_resources SET manual_hold=true WHERE id=$1")
        .bind(r)
        .execute(&pool)
        .await
        .unwrap();
    let power = prepare(
        &pool,
        r,
        &state("Running", "KeepCharging"),
        "stop",
        "KeepCharging",
    )
    .await;
    let bandwidth = bandwidth_preview(&pool, a, r).await;
    assert!(api::resume_on(&pool, r, 0).await.is_err());
    assert!(
        super::super::super::resource(&pool, r)
            .await
            .unwrap()
            .manual_hold
    );
    api::resume_on(&pool, r, 1).await.unwrap();
    let resource = super::super::super::resource(&pool, r).await.unwrap();
    assert!(!resource.manual_hold);
    assert_eq!(resource.revision, 2);
    assert_eq!(jobs::load(&pool, power).await.unwrap().status, "cancelled");
    assert_eq!(
        operations::load(&pool, bandwidth).await.unwrap().status,
        "cancelled"
    );
    assert!(api::resume_on(&pool, r, 1).await.is_err());
}
