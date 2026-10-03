use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Row};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatisticsQuery {
    pub days: Option<u8>,
}

pub struct Window {
    pub days: u8,
    pub from: i64,
    pub now: i64,
}

impl StatisticsQuery {
    pub fn window(&self) -> ApiResult<Window> {
        let days = self.days.unwrap_or(7);
        if !matches!(days, 7 | 30) {
            return Err(ApiError::BadRequest(
                "统计范围仅支持最近 7 天或 30 天".into(),
            ));
        }
        let now = sinan_protocol::now_timestamp();
        Ok(Window {
            days,
            from: now / 86_400 * 86_400 - (i64::from(days) - 1) * 86_400,
            now,
        })
    }
}

#[derive(Serialize, FromRow)]
struct TrafficBucket {
    day: Option<i64>,
    uploaded: Option<String>,
    downloaded: Option<String>,
    total: Option<String>,
    sampled_servers: i64,
    incomplete: bool,
    last_sample_at: Option<i64>,
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
        "SELECT COUNT(*) AS total,
         COUNT(*) FILTER (WHERE last_seen >= $1) AS online,
         COUNT(*) FILTER (WHERE NOT COALESCE(last_seen >= $1,FALSE) AND device_public_key IS NOT NULL) AS offline,
         COUNT(*) FILTER (WHERE NOT COALESCE(last_seen >= $1,FALSE) AND device_public_key IS NULL) AS pending,
         COUNT(*) FILTER (WHERE asset_settings->>'hidden'='true') AS hidden
         FROM servers WHERE deleted_at IS NULL",
    )
    .bind(window.now - 60)
    .fetch_one(&mut *tx)
    .await?;
    let buckets: Vec<TrafficBucket> = sqlx::query_as(
        "SELECT d.day,SUM(d.uploaded)::text AS uploaded,SUM(d.downloaded)::text AS downloaded,
         SUM(d.uploaded+d.downloaded)::text AS total,COUNT(DISTINCT d.server_id) AS sampled_servers,
         COALESCE(BOOL_OR(d.incomplete),FALSE) AS incomplete,MAX(d.last_sample_at) AS last_sample_at
         FROM server_network_daily d JOIN servers s ON s.id=d.server_id
         WHERE s.deleted_at IS NULL AND d.day >= $1 AND d.day <= $2
           AND (COALESCE(s.asset_settings->>'network_interface','')='' OR s.asset_settings->>'network_interface'=d.interface)
         GROUP BY GROUPING SETS ((d.day),()) ORDER BY d.day NULLS FIRST",
    )
    .bind(window.from)
    .bind(window.now / 86_400 * 86_400)
    .fetch_all(&mut *tx)
    .await?;
    let ranking = sqlx::query(
        "SELECT s.id,s.name,SUM(d.uploaded)::text AS uploaded,SUM(d.downloaded)::text AS downloaded,
         SUM(d.uploaded+d.downloaded)::text AS total,BOOL_OR(d.incomplete) AS incomplete
         FROM server_network_daily d JOIN servers s ON s.id=d.server_id
         WHERE s.deleted_at IS NULL AND d.day >= $1 AND d.day <= $2
           AND (COALESCE(s.asset_settings->>'network_interface','')='' OR s.asset_settings->>'network_interface'=d.interface)
         GROUP BY s.id ORDER BY SUM(d.uploaded+d.downloaded) DESC,s.id LIMIT 8",
    )
    .bind(window.from)
    .bind(window.now / 86_400 * 86_400)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let points: Vec<_> = (0..window.days)
        .map(|index| {
            let day = window.from + i64::from(index) * 86_400;
            buckets.iter().find(|row| row.day == Some(day)).map_or_else(
                || json!({"day":day,"uploaded":null,"downloaded":null,"total":null,"sampled_servers":0,"incomplete":false,"last_sample_at":null}),
                |row| json!(row),
            )
        })
        .collect();
    let by_server: Vec<_> = ranking.iter().map(|row| json!({
        "id":row.get::<i64,_>("id"),"name":row.get::<String,_>("name"),
        "uploaded":row.get::<String,_>("uploaded"),"downloaded":row.get::<String,_>("downloaded"),
        "total":row.get::<String,_>("total"),"incomplete":row.get::<bool,_>("incomplete"),
    })).collect();
    Ok(Json(json!({
        "generated_at":window.now,"from":window.from,"days":window.days,
        "servers":{
            "total":counts.get::<i64,_>("total"),"online":counts.get::<i64,_>("online"),
            "offline":counts.get::<i64,_>("offline"),"pending":counts.get::<i64,_>("pending"),"hidden":counts.get::<i64,_>("hidden"),
        },
        "traffic":buckets.iter().find(|row| row.day.is_none()),"points":points,"by_server":by_server,
    })))
}
