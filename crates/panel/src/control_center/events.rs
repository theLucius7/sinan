use super::{authenticate, require_capability};
use crate::{AppState, error::ApiResult};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::stream;
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::{collections::VecDeque, convert::Infallible, time::Duration};

#[derive(Deserialize)]
pub struct Cursor {
    #[serde(default)]
    after: i64,
}
struct Feed {
    state: AppState,
    headers: HeaderMap,
    actor: i64,
    cursor: i64,
    pending: VecDeque<Value>,
    timer: tokio::time::Interval,
    ended: bool,
}

pub async fn subscribe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<Cursor>,
) -> ApiResult<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>> {
    let actor = authenticate(&state, &headers).await?;
    require_capability(&state, &headers, "operations:read").await?;
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let feed = Feed {
        state,
        headers,
        actor: actor.admin_id,
        cursor: input.after.max(0),
        pending: VecDeque::new(),
        timer,
        ended: false,
    };
    let output = stream::unfold(feed, |mut feed| async move {
        if feed.ended {
            return None;
        }
        loop {
            if let Some(value) = feed.pending.pop_front() {
                let id = value["id"].as_i64().unwrap_or(feed.cursor);
                feed.cursor = id;
                return Some((
                    Ok(Event::default()
                        .event("management-operation")
                        .id(id.to_string())
                        .data(value.to_string())),
                    feed,
                ));
            }
            feed.timer.tick().await;
            if authenticate(&feed.state, &feed.headers).await.is_err()
                || require_capability(&feed.state, &feed.headers, "operations:read")
                    .await
                    .is_err()
            {
                feed.ended = true;
                return Some((
                    Ok(Event::default().event("authorization-ended").data("{}")),
                    feed,
                ));
            }
            let rows=match sqlx::query("SELECT id,action,object_path,result,occurred_at FROM management_audit WHERE admin_id=$1 AND id>$2 ORDER BY id LIMIT 100").bind(feed.actor).bind(feed.cursor).fetch_all(&feed.state.pool).await {Ok(rows)=>rows,Err(_)=>{feed.ended=true;return Some((Ok(Event::default().event("source-unavailable").data("{}")),feed));}};
            for row in rows {
                let value = (|| -> Result<Value, sqlx::Error> {
                    Ok(
                        json!({"id":row.try_get::<i64,_>("id")?,"action":row.try_get::<String,_>("action")?,"object":row.try_get::<String,_>("object_path")?,"result":row.try_get::<Value,_>("result")?,"occurred_at":row.try_get::<i64,_>("occurred_at")?}),
                    )
                })();
                if let Ok(value) = value {
                    feed.pending.push_back(value);
                }
            }
        }
    });
    Ok(Sse::new(output).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("连接保持"),
    ))
}
pub async fn export_servers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let actor = authenticate(&state, &headers).await?;
    require_capability(&state, &headers, "servers:read").await?;
    let rows=sqlx::query("SELECT id,name,last_seen,manifest_rev,static_info,latest_metrics FROM servers WHERE deleted_at IS NULL ORDER BY id LIMIT 10000").fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    for row in rows {
        let id: i64 = row.try_get("id")?;
        if actor.allows_server(id) {
            values.push(json!({"id":id,"name":row.try_get::<String,_>("name")?,"last_seen":row.try_get::<Option<i64>,_>("last_seen")?,"manifest_rev":row.try_get::<i64,_>("manifest_rev")?,"static_info":row.try_get::<Value,_>("static_info")?,"metrics":row.try_get::<Value,_>("latest_metrics")?}));
        }
    }
    Ok(Json(
        json!({"schema_version":1,"exported_at":now_timestamp(),"scope":"authorized-servers","servers":values,"credentials_included":false}),
    ))
}
