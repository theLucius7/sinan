mod fetch;
#[cfg(test)]
mod tests;

use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, future::Future, time::Duration};
use uuid::Uuid;

const DAY: i64 = 86_400;
const RETRY_INTERVAL: i64 = 3600;

#[derive(Debug, Serialize)]
pub struct ExchangeView {
    base: &'static str,
    rates: BTreeMap<String, f64>,
    rate_dates: BTreeMap<String, String>,
    rate_date: Option<String>,
    source: Option<String>,
    source_url: Option<&'static str>,
    fetched_at: Option<i64>,
    attempted_at: Option<i64>,
    next_refresh_at: i64,
    stale: bool,
    status: &'static str,
    error_code: Option<String>,
}

pub async fn current(pool: &PgPool) -> ApiResult<ExchangeView> {
    current_at(pool, sinan_protocol::now_timestamp()).await
}

async fn current_at(pool: &PgPool, now: i64) -> ApiResult<ExchangeView> {
    let row = sqlx::query("SELECT * FROM exchange_rates WHERE singleton")
        .fetch_one(pool)
        .await?;
    let fetched_at: Option<i64> = row.get("fetched_at");
    let source: Option<String> = row.get("source");
    let error_code: Option<String> = row.get("last_error");
    let rate_date: Option<String> = row.get("rate_date");
    let stale = fetched_at.is_none_or(|at| at > now || now.saturating_sub(at) >= DAY)
        || error_code.is_some()
        || rate_date
            .as_deref()
            .and_then(fetch::date_day)
            .is_none_or(|day| {
                day > now.div_euclid(DAY) || now.div_euclid(DAY).saturating_sub(day) > 7
            });
    Ok(ExchangeView {
        base: "CNY",
        rates: serde_json::from_value(row.get("rates")).map_err(anyhow::Error::from)?,
        rate_dates: serde_json::from_value(row.get("rate_dates")).map_err(anyhow::Error::from)?,
        source_url: source.as_ref().map(|_| "https://frankfurter.dev/"),
        source,
        rate_date,
        fetched_at,
        attempted_at: row.get("attempted_at"),
        next_refresh_at: row.get("next_refresh_at"),
        stale,
        status: if fetched_at.is_none() {
            "unavailable"
        } else if stale {
            "stale"
        } else {
            "fresh"
        },
        error_code,
    })
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ExchangeView>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(current(&state.pool).await?))
}

pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ExchangeView>> {
    auth::require_admin(&state, &headers).await?;
    refresh_with(&state.pool, true, fetch::latest).await?;
    Ok(Json(current(&state.pool).await?))
}

async fn claim(pool: &PgPool, now: i64, force: bool) -> ApiResult<Option<Uuid>> {
    // Persist the lease and retry time before I/O. No database lock is held
    // during a request, and a process restart cannot create a request storm.
    Ok(sqlx::query_scalar("UPDATE exchange_rates SET lease_id=$1,lease_until=$2,attempted_at=$3,next_refresh_at=$4 WHERE singleton AND lease_until<=$3 AND (($5 AND COALESCE(attempted_at,0)<=$3-30) OR (NOT $5 AND next_refresh_at<=$3)) RETURNING lease_id")
        .bind(Uuid::new_v4()).bind(now+30).bind(now).bind(now+RETRY_INTERVAL).bind(force)
        .fetch_optional(pool).await?)
}

async fn complete(
    pool: &PgPool,
    id: Uuid,
    now: i64,
    result: Result<fetch::FetchedRates, &'static str>,
) -> ApiResult<()> {
    match result {
        Ok(value) => {
            // Replace one coherent provider snapshot; never fill missing rates
            // using constants or a different day's successful response.
            let date = value.dates.values().min().cloned();
            sqlx::query("UPDATE exchange_rates SET rates=$2,rate_dates=$3,source=$4,rate_date=$5,fetched_at=$6,next_refresh_at=$7,last_error=NULL,lease_id=NULL,lease_until=0 WHERE singleton AND lease_id=$1")
                .bind(id).bind(serde_json::json!(value.rates)).bind(serde_json::json!(value.dates))
                .bind(value.source).bind(date).bind(now).bind(now+DAY).execute(pool).await?;
        }
        Err(code) => {
            sqlx::query("UPDATE exchange_rates SET last_error=$2,next_refresh_at=$3,lease_id=NULL,lease_until=0 WHERE singleton AND lease_id=$1")
                .bind(id).bind(code).bind(now+RETRY_INTERVAL).execute(pool).await?;
        }
    }
    Ok(())
}

async fn refresh_with<F, Fut>(pool: &PgPool, force: bool, fetch: F) -> ApiResult<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<fetch::FetchedRates, &'static str>>,
{
    let Some(id) = claim(pool, sinan_protocol::now_timestamp(), force).await? else {
        return if force { Err(ApiError::Busy) } else { Ok(()) };
    };
    let result = tokio::time::timeout(Duration::from_secs(20), fetch())
        .await
        .unwrap_or(Err("download_timeout"));
    complete(pool, id, sinan_protocol::now_timestamp(), result).await
}

pub async fn run(pool: PgPool) {
    let mut timer = tokio::time::interval(Duration::from_secs(60));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if let Err(error) = refresh_with(&pool, false, fetch::latest).await {
            tracing::warn!(%error, "exchange-rate maintenance failed; retained previous snapshot");
        }
    }
}
