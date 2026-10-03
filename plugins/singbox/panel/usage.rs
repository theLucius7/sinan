use crate::{
    AppState, agent_api, auth,
    error::{ApiError, ApiResult},
};
use anyhow::{Context, ensure};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::{Envelope, UsageAck, UsageBatch};
use sqlx::Row;

/// Commits an immutable batch before sending its acknowledgement.
pub async fn ingest(state: &AppState, server_id: i64, mut batch: UsageBatch) -> anyhow::Result<()> {
    ensure!(
        batch.period_start >= 0 && batch.period_end >= batch.period_start,
        "invalid usage period"
    );
    ensure!(batch.records.len() <= 10_000, "too many usage records");
    batch.records.sort_by(|a, b| a.stat_name.cmp(&b.stat_name));
    ensure!(
        batch
            .records
            .windows(2)
            .all(|pair| pair[0].stat_name != pair[1].stat_name),
        "duplicate usage record"
    );
    let identities = batch
        .records
        .iter()
        .map(|record| parse_name(&record.stat_name))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&batch)?));
    let seq = batch.seq.to_string();
    let mut tx = state.pool.begin().await?;
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(server_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(active, "unknown usage server");
    let inserted = sqlx::query("INSERT INTO usage_batches(server_id,epoch,seq,payload_hash,received_at) VALUES($1,$2,$3::text::numeric,$4,$5) ON CONFLICT DO NOTHING")
        .bind(server_id).bind(batch.epoch).bind(&seq).bind(&hash).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?.rows_affected() != 0;
    if inserted {
        for (record, (user_id, node_id)) in batch.records.iter().zip(identities) {
            // Revoked identities remain valid for terminal samples and offline outbox replay.
            // Deployment history is retained, so search newest first: current identities match the
            // latest revision without decoding every historical snapshot. EXISTS would discard the
            // ordering, hence the scalar subquery with LIMIT.
            let authorized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND server_id=$2) AND COALESCE((SELECT TRUE FROM deployments d WHERE d.server_id=$2 AND d.module='singbox' AND (d.source_json @> $3 OR d.source_json @> $4) ORDER BY d.rev DESC LIMIT 1),FALSE)")
                .bind(node_id).bind(server_id).bind(json!([{"id":node_id,"users":[{"user_id":user_id}]}])).bind(json!({"schema_version":1,"accounting_users":[{"user_id":user_id,"node_id":node_id,"stat_name":record.stat_name}]}))
                .fetch_one(&mut *tx).await?;
            ensure!(
                authorized,
                "usage identity was never published for this server"
            );
            sqlx::query("INSERT INTO usage_records(server_id,epoch,seq,stat_name,user_id,node_id,uplink,downlink,period_start,period_end) VALUES($1,$2,$3::text::numeric,$4,$5,$6,$7::text::numeric,$8::text::numeric,$9,$10) ON CONFLICT DO NOTHING")
                .bind(server_id).bind(batch.epoch).bind(&seq).bind(&record.stat_name).bind(user_id).bind(node_id)
                .bind(record.uplink.to_string()).bind(record.downlink.to_string()).bind(batch.period_start).bind(batch.period_end)
                .execute(&mut *tx).await?;
        }
    } else {
        let previous: String = sqlx::query_scalar("SELECT payload_hash FROM usage_batches WHERE server_id=$1 AND epoch=$2 AND seq=$3::text::numeric")
            .bind(server_id).bind(batch.epoch).bind(&seq).fetch_one(&mut *tx).await?;
        ensure!(previous == hash, "usage batch identity changed payload");
        sqlx::query("UPDATE usage_batches SET last_replayed_at=$4,replay_count=LEAST(replay_count,9223372036854775806)+1 WHERE server_id=$1 AND epoch=$2 AND seq=$3::text::numeric")
            .bind(server_id).bind(batch.epoch).bind(&seq).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    agent_api::notify(
        state,
        server_id,
        Envelope::new(
            "usage.ack",
            UsageAck {
                epoch: batch.epoch,
                seq: batch.seq,
            },
        )?,
    )
    .await;
    Ok(())
}

fn parse_name(name: &str) -> anyhow::Result<(i64, i64)> {
    let (user, node) = name
        .strip_prefix('u')
        .and_then(|name| name.split_once("_n"))
        .context("invalid usage identity")?;
    let user: i64 = user.parse().context("invalid usage user")?;
    let node: i64 = node.parse().context("invalid usage node")?;
    ensure!(
        user > 0 && node > 0 && name == format!("u{user}_n{node}"),
        "invalid usage identity"
    );
    Ok((user, node))
}

#[derive(Default, Deserialize)]
pub struct UsageQuery {
    pub user_id: Option<i64>,
    pub node_id: Option<i64>,
}

pub async fn summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    if query.user_id.is_some_and(|id| id <= 0) || query.node_id.is_some_and(|id| id <= 0) {
        return Err(ApiError::BadRequest("用户和节点编号必须为正整数".into()));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let totals = sqlx::query("SELECT COALESCE(SUM(uplink),0)::text AS uplink,COALESCE(SUM(downlink),0)::text AS downlink,(COALESCE(SUM(uplink),0)+COALESCE(SUM(downlink),0))::text AS total FROM usage_records WHERE ($1::bigint IS NULL OR user_id=$1) AND ($2::bigint IS NULL OR node_id=$2)")
        .bind(query.user_id).bind(query.node_id).fetch_one(&mut *tx).await?;
    let users = sqlx::query("SELECT u.id,u.name,u.deleted_at IS NOT NULL AS deleted,SUM(r.uplink)::text AS uplink,SUM(r.downlink)::text AS downlink FROM usage_records r JOIN users u ON u.id=r.user_id WHERE ($1::bigint IS NULL OR r.user_id=$1) AND ($2::bigint IS NULL OR r.node_id=$2) GROUP BY u.id ORDER BY u.id")
        .bind(query.user_id).bind(query.node_id).fetch_all(&mut *tx).await?;
    let nodes = sqlx::query("SELECT n.id,n.name,(n.deleted_at IS NOT NULL OR s.deleted_at IS NOT NULL) AS deleted,SUM(r.uplink)::text AS uplink,SUM(r.downlink)::text AS downlink FROM usage_records r JOIN nodes n ON n.id=r.node_id JOIN servers s ON s.id=n.server_id WHERE ($1::bigint IS NULL OR r.user_id=$1) AND ($2::bigint IS NULL OR r.node_id=$2) GROUP BY n.id,s.deleted_at ORDER BY n.id")
        .bind(query.user_id).bind(query.node_id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    let by_user: Vec<_> = users.iter().map(|row| json!({"user_id":row.get::<i64,_>("id"),"name":row.get::<String,_>("name"),"deleted":row.get::<bool,_>("deleted"),"uplink":row.get::<String,_>("uplink"),"downlink":row.get::<String,_>("downlink")})).collect();
    let by_node: Vec<_> = nodes.iter().map(|row| json!({"node_id":row.get::<i64,_>("id"),"name":row.get::<String,_>("name"),"deleted":row.get::<bool,_>("deleted"),"uplink":row.get::<String,_>("uplink"),"downlink":row.get::<String,_>("downlink")})).collect();
    Ok(Json(
        json!({"uplink":totals.get::<String,_>("uplink"),"downlink":totals.get::<String,_>("downlink"),"total":totals.get::<String,_>("total"),"by_user":by_user,"by_node":by_node}),
    ))
}
