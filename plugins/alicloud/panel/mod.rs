#![forbid(unsafe_code)]
//! Alibaba Cloud plugin: CDT traffic, ECS power, billing and cost tracking.

mod api;
mod billing;
mod client;
mod costs;
mod model;
mod notices;
mod operations;
mod power;
#[cfg(test)]
mod tests;
mod worker;

pub use api::routes;
pub use worker::run;

pub(crate) use sinan_cloud_api as cloud_api;
pub(crate) use sinan_panel_host::{AppState, auth, error, notifications, settings};

use crate::error::{ApiError, ApiResult};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

async fn lock(pool: &PgPool, account_id: Uuid) -> ApiResult<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,739104830))")
        .bind(account_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn account_on(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<model::Account> {
    sqlx::query_as("SELECT * FROM alicloud_accounts WHERE id=$1 AND NOT archived")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn resource(pool: &PgPool, id: Uuid) -> ApiResult<model::Resource> {
    sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

fn failure(error: crate::cloud_api::Failure) -> ApiError {
    ApiError::Conflict(format!("云接口未完成操作：{}", model::message(error.code)))
}
