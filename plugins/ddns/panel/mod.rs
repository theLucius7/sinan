mod api;
mod cloudflare;
mod credentials;
pub(crate) mod dns01;
mod dns_accounts;
mod dns_record_actions;
mod dns_record_reconcile;
mod dns_record_rollback;
mod dns_record_spec;
mod dns_records;
mod dns_resolvers;
mod dns_wire;
mod history;
mod lifecycle;
mod migration;
mod model;
mod observation;
mod providers;
mod rollback;
mod settings;
#[cfg(test)]
mod tests;
mod worker;

pub use api::routes;
pub use worker::run;

use crate::error::{ApiError, ApiResult};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use model::Rule;

const MAX_RULES: i64 = 32;
const LEASE_SECS: i64 = 60;
const REQUEST_BUDGET: u64 = 20;

async fn load(pool: &PgPool, id: Uuid) -> ApiResult<Rule> {
    sqlx::query_as("SELECT * FROM ddns_rules WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn editable(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<Rule> {
    let row: Rule = sqlx::query_as("SELECT * FROM ddns_rules WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.lease_until > sinan_protocol::now_timestamp() {
        return Err(ApiError::Conflict("规则正在同步，请稍后操作".into()));
    }
    Ok(row)
}
