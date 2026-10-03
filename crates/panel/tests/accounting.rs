#![forbid(unsafe_code)]

mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::{TestPanel, id, receive_envelope, send_envelope};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use sinan_panel::usage;
use sinan_protocol::{Envelope, UsageAck, UsageBatch, UsageRecord};
use sqlx::PgPool;
use uuid::Uuid;

fn batch(user: i64, node: i64, up: u64, down: u64) -> UsageBatch {
    UsageBatch {
        epoch: Uuid::new_v4(),
        seq: 1,
        period_start: 100,
        period_end: 130,
        records: vec![UsageRecord {
            stat_name: format!("u{user}_n{node}"),
            uplink: up,
            downlink: down,
        }],
    }
}

async fn totals(panel: &TestPanel, cookie: &str, suffix: &str) -> Result<Value> {
    Ok(panel
        .admin(
            Method::GET,
            &format!("/api/plugins/sing-box/usage{suffix}"),
            cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[sqlx::test]
async fn websocket_acknowledges_committed_and_repeated_batches_once(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, mut socket, _) = panel.authenticated_device(&cookie, "traffic").await?;
    let node = id(&panel.create_node(&cookie, server, "node").await?)?;
    let user = id(&panel.create_user(&cookie, "member").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.publish_now().await?;
    let value = batch(user, node, 100, 200);
    for _ in 0..2 {
        send_envelope(&mut socket, Envelope::new("usage.batch", &value)?).await?;
        loop {
            let response = receive_envelope(&mut socket).await?;
            if response.message_type == "usage.ack" {
                let ack: UsageAck = response.to_payload()?;
                assert_eq!((ack.epoch, ack.seq), (value.epoch, value.seq));
                break;
            }
            assert_eq!(response.message_type, "manifest.changed");
        }
    }
    let summary = totals(&panel, &cookie, "").await?;
    assert_eq!(summary["uplink"], "100");
    assert_eq!(summary["downlink"], "200");
    assert_eq!(summary["total"], "300");
    assert_eq!(summary["by_user"][0]["user_id"], user);
    assert_eq!(summary["by_node"][0]["node_id"], node);
    assert_eq!(
        totals(&panel, &cookie, &format!("?user_id={user}&node_id={node}")).await?["total"],
        "300"
    );
    assert_eq!(
        totals(&panel, &cookie, "?user_id=999999").await?["total"],
        "0"
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/plugins/sing-box/usage", panel.base))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_records")
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[sqlx::test]
async fn rejected_batch_keeps_the_device_channel_and_acknowledges_later_batches(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, mut socket, _) = panel.authenticated_device(&cookie, "traffic").await?;
    let node = id(&panel.create_node(&cookie, server, "node").await?)?;
    let user = id(&panel.create_user(&cookie, "member").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.publish_now().await?;
    // A durable outbox can retain an identity never published to this device,
    // for example after a reinstall onto a new server record.
    let stale = batch(user, node + 1000, 5, 5);
    let valid = batch(user, node, 100, 200);
    send_envelope(&mut socket, Envelope::new("usage.batch", &stale)?).await?;
    send_envelope(&mut socket, Envelope::new("usage.batch", &valid)?).await?;
    loop {
        let response = receive_envelope(&mut socket).await?;
        if response.message_type == "usage.ack" {
            let ack: UsageAck = response.to_payload()?;
            assert_eq!(
                (ack.epoch, ack.seq),
                (valid.epoch, valid.seq),
                "only the valid batch may be acknowledged"
            );
            break;
        }
        assert_eq!(response.message_type, "manifest.changed");
    }
    let batches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_batches WHERE server_id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(batches, 1, "the rejected batch must be rolled back");
    assert_eq!(totals(&panel, &cookie, "").await?["total"], "300");
    Ok(())
}

#[sqlx::test]
async fn invalid_records_roll_back_whole_batches_and_full_width_values_survive(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "one").await?;
    let other = panel.create_server(&cookie, "two").await?;
    let node = id(&panel.create_node(&cookie, server, "one").await?)?;
    let foreign = id(&panel.create_node(&cookie, other, "two").await?)?;
    let user = id(&panel.create_user(&cookie, "member").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.grant(&cookie, user, foreign).await?;
    panel.publish_now().await?;
    let mut invalid = batch(user, node, 1, 2);
    invalid.records.push(UsageRecord {
        stat_name: format!("u{user}_n{foreign}"),
        uplink: 5,
        downlink: 6,
    });
    assert!(usage::ingest(&panel.state, server, invalid).await.is_err());
    for table in ["usage_batches", "usage_records"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&panel.state.pool)
            .await?;
        assert_eq!(count, 0);
    }
    let mut value = batch(user, node, u64::MAX, u64::MAX);
    value.seq = u64::MAX;
    usage::ingest(&panel.state, server, value.clone()).await?;
    usage::ingest(&panel.state, server, value.clone()).await?;
    let summary = totals(&panel, &cookie, "").await?;
    assert_eq!(summary["uplink"], u64::MAX.to_string());
    assert_eq!(summary["total"], (u128::from(u64::MAX) * 2).to_string());
    value.records[0].uplink = 0;
    assert!(usage::ingest(&panel.state, server, value).await.is_err());
    assert_eq!(
        totals(&panel, &cookie, "").await?["uplink"],
        u64::MAX.to_string()
    );
    Ok(())
}

#[sqlx::test]
async fn terminal_batches_remain_valid_after_revocation_and_deleted_users_keep_history(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "history").await?;
    let node = id(&panel.create_node(&cookie, server, "node").await?)?;
    let user = id(&panel.create_user(&cookie, "member").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.publish_now().await?;
    panel
        .admin(
            Method::DELETE,
            &format!("/api/plugins/sing-box/users/{user}/accesses/{node}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    panel.publish_now().await?;
    usage::ingest(&panel.state, server, batch(user, node, 7, 9)).await?;
    panel
        .admin(
            Method::DELETE,
            &format!("/api/plugins/sing-box/users/{user}"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?;
    usage::ingest(&panel.state, server, batch(user, node, 3, 1)).await?;
    let summary = totals(&panel, &cookie, "").await?;
    assert_eq!(summary["total"], "20");
    assert_eq!(summary["by_user"][0]["deleted"], true);
    assert_eq!(summary["by_user"][0]["name"], "member");
    Ok(())
}

#[sqlx::test]
async fn empty_batches_and_canonical_order_are_immutable_and_bad_names_rejected(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "canonical").await?;
    let node = id(&panel.create_node(&cookie, server, "node").await?)?;
    let a = id(&panel.create_user(&cookie, "one").await?)?;
    let b = id(&panel.create_user(&cookie, "two").await?)?;
    panel.grant(&cookie, a, node).await?;
    panel.grant(&cookie, b, node).await?;
    panel.publish_now().await?;
    let mut value = batch(a, node, 1, 2);
    value.records.push(batch(b, node, 3, 4).records.remove(0));
    usage::ingest(&panel.state, server, value.clone()).await?;
    value.records.reverse();
    usage::ingest(&panel.state, server, value).await?;
    let mut empty = batch(a, node, 0, 0);
    empty.records.clear();
    usage::ingest(&panel.state, server, empty.clone()).await?;
    usage::ingest(&panel.state, server, empty.clone()).await?;
    empty.records.push(batch(a, node, 1, 1).records.remove(0));
    assert!(usage::ingest(&panel.state, server, empty).await.is_err());
    for name in ["u0_n1", "u01_n1", "u1_n-1", "u1_n2_extra", ""] {
        let mut invalid = batch(a, node, 1, 1);
        invalid.records[0].stat_name = name.into();
        assert!(usage::ingest(&panel.state, server, invalid).await.is_err());
    }
    let mut invalid = batch(a, node, 1, 1);
    invalid.period_end = 99;
    assert!(usage::ingest(&panel.state, server, invalid).await.is_err());
    assert_eq!(totals(&panel, &cookie, "").await?["total"], "10");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM usage_batches")
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(count, 2);
    Ok(())
}
