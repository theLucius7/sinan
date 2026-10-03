use super::{
    cloudflare::Outcome,
    lifecycle::{Snapshot, target_snapshot},
    model::{Provider, Rule},
};
use crate::error::ApiResult;
use serde::Serialize;
use sqlx::{FromRow, PgConnection, PgPool};
use uuid::Uuid;

#[derive(FromRow, Serialize)]
pub(super) struct Entry {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub server_id: i64,
    pub revision: i64,
    pub operation: String,
    pub desired_ip: Option<String>,
    #[sqlx(json(nullable))]
    pub previous: Option<Snapshot>,
    #[sqlx(json(nullable))]
    pub observed: Option<Snapshot>,
    pub status: String,
    pub error_code: Option<String>,
    pub occurred_at: i64,
}

pub(super) fn observed(
    rule: &Rule,
    ip: std::net::IpAddr,
    outcome: &Outcome,
    previous: Option<&Snapshot>,
) -> Snapshot {
    if outcome.status == "unchanged"
        && let Some(previous) = previous
    {
        return previous.clone();
    }
    let mut value = target_snapshot(rule, ip, outcome.record_id.clone());
    value.active = outcome.status != "submitted";
    value.marker = if let Some(previous) = previous {
        previous.marker.clone()
    } else {
        matches!(
            rule.config.provider,
            Provider::Cloudflare | Provider::Huawei
        )
        .then(|| format!("sinan-ddns:{}", rule.id))
    };
    value
}

pub(super) async fn append(connection: &mut PgConnection, entry: Entry) -> ApiResult<()> {
    sqlx::query("INSERT INTO ddns_history(id,rule_id,server_id,revision,operation,desired_ip,previous,observed,status,error_code,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(entry.id).bind(entry.rule_id).bind(entry.server_id).bind(entry.revision).bind(entry.operation)
        .bind(entry.desired_ip).bind(entry.previous.map(sqlx::types::Json))
        .bind(entry.observed.map(sqlx::types::Json)).bind(entry.status).bind(entry.error_code)
        .bind(entry.occurred_at).execute(&mut *connection).await?;
    // Keep a bounded, useful history without storing credentials or raw API bodies.
    sqlx::query("DELETE FROM ddns_history WHERE rule_id=$1 AND id IN (SELECT id FROM ddns_history WHERE rule_id=$1 ORDER BY occurred_at DESC,id DESC OFFSET 256)")
        .bind(entry.rule_id).execute(connection).await?;
    Ok(())
}

pub(super) async fn list(pool: &PgPool, id: Uuid) -> ApiResult<Vec<Entry>> {
    Ok(sqlx::query_as(
        "SELECT * FROM ddns_history WHERE rule_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 256",
    )
    .bind(id)
    .fetch_all(pool)
    .await?)
}
