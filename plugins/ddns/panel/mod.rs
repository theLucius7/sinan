#![forbid(unsafe_code)]
//! DDNS plugin: reconciles DNS records with addresses reported by devices.

mod api;
mod cloudflare;
mod model;
mod providers;
mod settings;
#[cfg(test)]
mod tests;
mod worker;

pub use api::routes;
pub use worker::run;

pub(crate) use sinan_cloud_api as cloud_api;
pub(crate) use sinan_panel_host::{AppState, auth, error, ip_quality};

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
