use super::{provider::Mock, *};
use crate::plugins::ddns::{editable, load, worker};
use sqlx::PgPool;

async fn seed(pool: &PgPool) -> anyhow::Result<Uuid> {
    let now = sinan_protocol::now_timestamp();
    let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,static_info,last_seen,static_info_received_at) VALUES('TEST_ONLY DDNS',$1,$2,$2) RETURNING id")
        .bind(json!({"ip_addresses":[public_ip(4)]})).bind(now).fetch_one(pool).await?;
    let mut rule = rule();
    rule.config.server_id = server;
    super::super::settings::set_enabled(pool, server, true).await?;
    sqlx::query("INSERT INTO ddns_rules(id,server_id,config,api_token) VALUES($1,$2,$3,$4)")
        .bind(rule.id)
        .bind(server)
        .bind(json!(rule.config))
        .bind(TOKEN)
        .execute(pool)
        .await?;
    Ok(rule.id)
}

async fn due(pool: &PgPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE ddns_rules SET attempted_at=NULL,next_run_at=0 WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[sqlx::test]
async fn plugin_disable_blocks_claims_preserves_rules_and_cannot_acknowledge_during_io(
    pool: PgPool,
) -> anyhow::Result<()> {
    let id = seed(&pool).await?;
    let rule = load(&pool, id).await?;
    let mock = Mock::start().await;
    sqlx::query("UPDATE ddns_rules SET lease_until=$1")
        .bind(sinan_protocol::now_timestamp() + 60)
        .execute(&pool)
        .await?;
    assert!(
        super::super::settings::set_enabled(&pool, rule.config.server_id, false)
            .await
            .is_err()
    );
    sqlx::query("UPDATE ddns_rules SET lease_until=0")
        .execute(&pool)
        .await?;
    super::super::settings::set_enabled(&pool, rule.config.server_id, false).await?;
    worker::sync_with(&pool, id, false, &mock.client).await?;
    assert!(
        worker::sync_with(&pool, id, true, &mock.client)
            .await
            .is_err()
    );
    assert!(mock.data.lock().unwrap().requests.is_empty());
    assert!(load(&pool, id).await?.config.enabled);
    let view = model::view(&pool, load(&pool, id).await?).await?;
    assert_eq!(view["plugin_enabled"], false);
    assert_eq!(view["ip_status"], "plugin_disabled");
    super::super::settings::set_enabled(&pool, rule.config.server_id, true).await?;
    worker::sync_with(&pool, id, false, &mock.client).await?;
    assert_eq!(mock.writes(), 1);
    Ok(())
}

#[sqlx::test]
async fn scheduler_persists_success_and_does_not_repeat_unchanged_writes(
    pool: PgPool,
) -> anyhow::Result<()> {
    let id = seed(&pool).await?;
    let mock = Mock::start().await;
    worker::sync_with(&pool, id, false, &mock.client).await?;
    let row = load(&pool, id).await?;
    assert_eq!(row.status, "updated");
    assert_eq!(
        row.last_ip.as_deref(),
        Some(public_ip(4).to_string().as_str())
    );
    assert!(row.last_success_at.is_some());
    assert_eq!(mock.writes(), 1);
    assert!(
        worker::sync_with(&pool, id, true, &mock.client)
            .await
            .is_err()
    );
    worker::sync_with(&pool, id, false, &mock.client).await?;
    assert_eq!(mock.data.lock().unwrap().requests.len(), 5);
    due(&pool, id).await?;
    worker::sync_with(&pool, id, false, &mock.client).await?;
    assert_eq!(load(&pool, id).await?.status, "unchanged");
    assert_eq!(mock.writes(), 1);
    Ok(())
}

#[sqlx::test]
async fn missing_stale_offline_and_retired_ips_preserve_dns_without_external_requests(
    pool: PgPool,
) -> anyhow::Result<()> {
    let id = seed(&pool).await?;
    let mock = Mock::start().await;
    worker::sync_with(&pool, id, false, &mock.client).await?;
    let original = load(&pool, id).await?;
    mock.data.lock().unwrap().requests.clear();
    for (statement, code) in [
        ("UPDATE servers SET static_info='{}'", "no_public_ip"),
        (
            "UPDATE servers SET static_info_received_at=NULL",
            "ip_stale",
        ),
        ("UPDATE servers SET last_seen=NULL", "server_offline"),
        ("UPDATE servers SET deleted_at=1", "server_retired"),
    ] {
        sqlx::query(statement).execute(&pool).await?;
        due(&pool, id).await?;
        worker::sync_with(&pool, id, false, &mock.client).await?;
        let current = load(&pool, id).await?;
        assert_eq!(current.error_code.as_deref(), Some(code));
        assert_eq!(current.status, "waiting");
        assert_eq!(current.last_ip, original.last_ip);
        assert_eq!(current.last_success_at, original.last_success_at);
    }
    assert!(mock.data.lock().unwrap().requests.is_empty());
    assert_eq!(mock.data.lock().unwrap().records.len(), 1);
    Ok(())
}

#[sqlx::test]
async fn leases_exclude_parallel_work_block_edits_and_recover_after_expiry(
    pool: PgPool,
) -> anyhow::Result<()> {
    let id = seed(&pool).await?;
    let mock = Mock::start().await;
    sqlx::query("UPDATE ddns_rules SET lease_id=$2,lease_until=$3,status='running' WHERE id=$1")
        .bind(id)
        .bind(Uuid::new_v4())
        .bind(sinan_protocol::now_timestamp() + 60)
        .execute(&pool)
        .await?;
    let mut tx = pool.begin().await?;
    assert!(editable(&mut tx, id).await.is_err());
    tx.rollback().await?;
    assert!(
        worker::sync_with(&pool, id, true, &mock.client)
            .await
            .is_err()
    );
    assert!(mock.data.lock().unwrap().requests.is_empty());
    sqlx::query("UPDATE ddns_rules SET lease_until=0 WHERE id=$1")
        .bind(id)
        .execute(&pool)
        .await?;
    let (first, second) = tokio::join!(
        worker::sync_with(&pool, id, true, &mock.client),
        worker::sync_with(&pool, id, true, &mock.client)
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(mock.writes(), 1);
    assert_eq!(mock.data.lock().unwrap().requests.len(), 5);
    assert_eq!(load(&pool, id).await?.lease_until, 0);
    Ok(())
}

#[sqlx::test]
async fn rate_limit_backoff_survives_retries_without_exposing_response_or_losing_success(
    pool: PgPool,
) -> anyhow::Result<()> {
    let id = seed(&pool).await?;
    let mock = Mock::start().await;
    worker::sync_with(&pool, id, false, &mock.client).await?;
    let original = load(&pool, id).await?;
    due(&pool, id).await?;
    mock.data.lock().unwrap().reply = Some((429, TOKEN.into()));
    worker::sync_with(&pool, id, false, &mock.client).await?;
    let current = load(&pool, id).await?;
    assert_eq!(current.error_code.as_deref(), Some("rate_limited"));
    assert_eq!(current.last_success_at, original.last_success_at);
    assert!(current.next_run_at >= sinan_protocol::now_timestamp() + 899);
    sqlx::query("UPDATE ddns_rules SET attempted_at=NULL")
        .execute(&pool)
        .await?;
    assert!(
        worker::sync_with(&pool, id, true, &mock.client)
            .await
            .is_err()
    );
    worker::sync_with(&pool, id, false, &mock.client).await?;
    assert_eq!(mock.data.lock().unwrap().requests.len(), 6);
    assert!(
        !model::view(&pool, current)
            .await?
            .to_string()
            .contains(TOKEN)
    );
    Ok(())
}

#[sqlx::test]
async fn changes_during_provider_reads_stop_before_any_dns_write(
    pool: PgPool,
) -> anyhow::Result<()> {
    use std::sync::Arc;
    use tokio::sync::Notify;
    for (statement, expected) in [
        ("UPDATE servers SET deleted_at=1", "server_retired"),
        ("UPDATE servers SET last_seen=0", "server_offline"),
        ("UPDATE servers SET static_info_received_at=0", "ip_stale"),
        (
            "UPDATE servers SET static_info='{\"ip_addresses\":[\"1.2.3.9\"]}'",
            "address_changed",
        ),
        ("UPDATE ddns_rules SET lease_id=NULL", "lease_lost"),
    ] {
        let id = seed(&pool).await?;
        let mock = Arc::new(Mock::start().await);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        mock.data.lock().unwrap().list_pause = Some((entered.clone(), release.clone()));
        let task_pool = pool.clone();
        let task_mock = mock.clone();
        let task = tokio::spawn(async move {
            worker::sync_with(&task_pool, id, false, &task_mock.client).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified()).await?;
        sqlx::query(statement).execute(&pool).await?;
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), task).await???;
        assert_eq!(mock.writes(), 0, "{expected}");
        if expected != "lease_lost" {
            assert_eq!(load(&pool, id).await?.error_code.as_deref(), Some(expected));
        }
        sqlx::query("DELETE FROM ddns_rules").execute(&pool).await?;
        sqlx::query("DELETE FROM server_plugins WHERE plugin='ddns'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM servers").execute(&pool).await?;
    }
    Ok(())
}

#[sqlx::test]
async fn a_retirement_committing_while_the_write_guard_waits_is_observed(
    pool: PgPool,
) -> anyhow::Result<()> {
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Notify;
    let id = seed(&pool).await?;
    let rule = load(&pool, id).await?;
    let mock = Arc::new(Mock::start().await);
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    mock.data.lock().unwrap().list_pause = Some((entered.clone(), release.clone()));
    let task_pool = pool.clone();
    let task_mock = mock.clone();
    let task =
        tokio::spawn(
            async move { worker::sync_with(&task_pool, id, false, &task_mock.client).await },
        );
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    let mut retirement = pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 FOR UPDATE")
        .bind(rule.config.server_id)
        .execute(&mut *retirement)
        .await?;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(2),async {
        loop {
            let waiting: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT id FROM servers WHERE id=$1 FOR SHARE%')").fetch_one(&pool).await?;
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(),sqlx::Error>(())
    }).await??;
    sqlx::query("INSERT INTO server_retirements(server_id,request_id,status,requested_at) VALUES($1,$2,'pending',$3)")
        .bind(rule.config.server_id).bind(Uuid::new_v4()).bind(sinan_protocol::now_timestamp())
        .execute(&mut *retirement).await?;
    retirement.commit().await?;
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    assert_eq!(
        load(&pool, id).await?.error_code.as_deref(),
        Some("server_retired")
    );
    assert_eq!(mock.writes(), 0);
    Ok(())
}

#[sqlx::test]
async fn an_inflight_write_holds_the_rule_and_server_lifecycle_locks(
    pool: PgPool,
) -> anyhow::Result<()> {
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Notify;
    let id = seed(&pool).await?;
    let rule = load(&pool, id).await?;
    let mock = Arc::new(Mock::start().await);
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    mock.data.lock().unwrap().write_pause = Some((entered.clone(), release.clone()));
    let task_pool = pool.clone();
    let task_mock = mock.clone();
    let task =
        tokio::spawn(
            async move { worker::sync_with(&task_pool, id, false, &task_mock.client).await },
        );
    tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
    for table in ["servers", "ddns_rules"] {
        let mut blocked = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='100ms'")
            .execute(&mut *blocked)
            .await?;
        let result = if table == "servers" {
            sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
                .bind(rule.config.server_id)
                .execute(&mut *blocked)
                .await
        } else {
            sqlx::query("UPDATE ddns_rules SET lease_until=0 WHERE id=$1")
                .bind(id)
                .execute(&mut *blocked)
                .await
        };
        let error = result.unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("55P03")
        );
        blocked.rollback().await?;
    }
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    assert_eq!(mock.writes(), 1);
    assert_eq!(load(&pool, id).await?.status, "updated");
    sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
        .bind(rule.config.server_id)
        .execute(&pool)
        .await?;
    Ok(())
}

#[sqlx::test]
async fn special_range_reported_ips_never_contact_cloudflare(pool: PgPool) -> anyhow::Result<()> {
    let id = seed(&pool).await?;
    let rule = load(&pool, id).await?;
    let mock = Mock::start().await;
    for address in [
        "3fff::1",
        "3fff:0fff:ffff::1",
        "2001:2::1",
        "2001:2:0:ffff::1",
    ] {
        let mut config = rule.config.clone();
        config.record_type = "AAAA".into();
        sqlx::query("UPDATE ddns_rules SET config=$2,attempted_at=NULL,next_run_at=0 WHERE id=$1")
            .bind(id)
            .bind(json!(config))
            .execute(&pool)
            .await?;
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(rule.config.server_id)
            .bind(json!({"ip_addresses":[address]}))
            .execute(&pool)
            .await?;
        worker::sync_with(&pool, id, false, &mock.client).await?;
        assert_eq!(
            load(&pool, id).await?.error_code.as_deref(),
            Some("no_public_ip")
        );
    }
    assert!(mock.data.lock().unwrap().requests.is_empty());
    Ok(())
}

#[sqlx::test]
async fn old_completion_never_overwrites_a_new_revision_after_an_expired_lease(
    pool: PgPool,
) -> anyhow::Result<()> {
    use crate::plugins::ddns::cloudflare::{Failure, Outcome};
    for success in [true, false] {
        let id = seed(&pool).await?;
        let old = load(&pool, id).await?;
        let lease = Uuid::new_v4();
        let next = sinan_protocol::now_timestamp() + 600;
        // A wall-clock jump can make the old lease editable while its request
        // has just released its shared locks. Keep UUID to prove revision is
        // an independent guard, rather than relying only on edit invalidation.
        sqlx::query("UPDATE ddns_rules SET lease_id=$2,lease_until=0,revision=revision+1,status='pending',next_run_at=$3 WHERE id=$1")
            .bind(id).bind(lease).bind(next).execute(&pool).await?;
        let result = if success {
            Ok((
                public_ip(4),
                Outcome {
                    record_id: RECORD.into(),
                    status: "updated",
                },
            ))
        } else {
            Err(Failure {
                code: "network_error",
                retry_after: 0,
            })
        };
        worker::complete(&pool, &old, lease, result).await?;
        let current = load(&pool, id).await?;
        assert_eq!(current.revision, 2);
        assert_eq!(current.status, "pending");
        assert_eq!(current.next_run_at, next);
        assert!(current.last_success_at.is_none() && current.last_ip.is_none());
        assert!(current.error_code.is_none());
        assert_eq!(current.failures, 0);
        sqlx::query("DELETE FROM ddns_rules WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await?;
    }
    Ok(())
}
