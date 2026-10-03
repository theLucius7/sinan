use crate::{AppState, auth, error::ApiResult};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::Serialize;
use serde_json::{Value, json};
use sinan_panel_host::statistics::StatisticsQuery;
use sqlx::{FromRow, Row};

// Whole days before today read the per-day rollup (ADR 0077); today stays exact
// up to now from the ledger, so later-dated records remain excluded.
const WINDOW_USAGE: &str = "WITH usage AS (
    SELECT user_id,node_id,day,uplink,downlink,last_period_end FROM singbox_usage_daily
    WHERE day >= $1 AND day < $3
    UNION ALL
    SELECT user_id,node_id,period_end/86400*86400,uplink,downlink,period_end FROM usage_records
    WHERE period_end >= $3 AND period_end <= $2)";

#[derive(Serialize, FromRow)]
struct UsageBucket {
    day: Option<i64>,
    uploaded: Option<String>,
    downloaded: Option<String>,
    total: Option<String>,
    recorded_users: i64,
    recorded_nodes: i64,
    last_record_at: Option<i64>,
}

pub async fn summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StatisticsQuery>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let window = query.window()?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    let counts = sqlx::query(
        "SELECT (SELECT COUNT(*) FROM nodes n JOIN servers s ON n.server_id=s.id WHERE n.deleted_at IS NULL AND s.deleted_at IS NULL) AS nodes,
         (SELECT COUNT(*) FROM users WHERE deleted_at IS NULL) AS users",
    )
    .fetch_one(&mut *tx)
    .await?;
    let today = window.now / 86_400 * 86_400;
    let buckets: Vec<UsageBucket> = sqlx::query_as(&format!(
        "{WINDOW_USAGE} SELECT day,SUM(uplink)::text AS uploaded,
         SUM(downlink)::text AS downloaded,SUM(uplink+downlink)::text AS total,
         COUNT(DISTINCT user_id) AS recorded_users,COUNT(DISTINCT node_id) AS recorded_nodes,
         MAX(last_period_end) AS last_record_at FROM usage
         GROUP BY GROUPING SETS ((day),()) ORDER BY day NULLS FIRST"
    ))
    .bind(window.from)
    .bind(window.now)
    .bind(today)
    .fetch_all(&mut *tx)
    .await?;
    let users = sqlx::query(&format!(
        "{WINDOW_USAGE} SELECT u.id,u.name,u.deleted_at IS NOT NULL AS deleted,SUM(r.uplink)::text AS uploaded,
         SUM(r.downlink)::text AS downloaded,SUM(r.uplink+r.downlink)::text AS total
         FROM usage r JOIN users u ON u.id=r.user_id
         GROUP BY u.id ORDER BY SUM(r.uplink+r.downlink) DESC,u.id LIMIT 8"
    ))
    .bind(window.from)
    .bind(window.now)
    .bind(today)
    .fetch_all(&mut *tx)
    .await?;
    let nodes = sqlx::query(&format!(
        "{WINDOW_USAGE} SELECT n.id,n.name,(n.deleted_at IS NOT NULL OR s.deleted_at IS NOT NULL) AS deleted,
         SUM(r.uplink)::text AS uploaded,SUM(r.downlink)::text AS downloaded,SUM(r.uplink+r.downlink)::text AS total
         FROM usage r JOIN nodes n ON n.id=r.node_id JOIN servers s ON s.id=n.server_id
         GROUP BY n.id,s.deleted_at ORDER BY SUM(r.uplink+r.downlink) DESC,n.id LIMIT 8"
    ))
    .bind(window.from)
    .bind(window.now)
    .bind(today)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let points: Vec<_> = (0..window.days)
        .map(|index| {
            let day = window.from + i64::from(index) * 86_400;
            buckets.iter().find(|row| row.day == Some(day)).map_or_else(
                || json!({"day":day,"uploaded":null,"downloaded":null,"total":null,"recorded_users":0,"recorded_nodes":0,"last_record_at":null}),
                |row| json!(row),
            )
        })
        .collect();
    let ranking = |rows: Vec<sqlx::postgres::PgRow>| -> Vec<Value> {
        rows.into_iter().map(|row| json!({
            "id":row.get::<i64,_>("id"),"name":row.get::<String,_>("name"),"deleted":row.get::<bool,_>("deleted"),
            "uploaded":row.get::<String,_>("uploaded"),"downloaded":row.get::<String,_>("downloaded"),"total":row.get::<String,_>("total"),
        })).collect()
    };
    Ok(Json(json!({
        "generated_at":window.now,"from":window.from,"days":window.days,
        "nodes":counts.get::<i64,_>("nodes"),"users":counts.get::<i64,_>("users"),
        "traffic":buckets.iter().find(|row| row.day.is_none()),"points":points,
        "by_user":ranking(users),"by_node":ranking(nodes),
    })))
}
