use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
    server_traffic,
    servers::{SERVER_COLUMNS, Server},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    cycle_start: i64,
    reset_day: u8,
    network_interface: String,
    correction_id: Option<i64>,
    baseline_uploaded: String,
    baseline_downloaded: String,
    uploaded: String,
    downloaded: String,
    reason: String,
}

fn bytes(value: &str) -> ApiResult<i128> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiError::BadRequest(
            "流量需为非负整数字节，且不超过 2^64−1".into(),
        ));
    }
    value
        .parse::<u64>()
        .map(i128::from)
        .map_err(|_| ApiError::BadRequest("流量字节数超出范围".into()))
}

pub async fn correct(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<Correction>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let (up, down) = (bytes(&request.uploaded)?, bytes(&request.downloaded)?);
    let (before_up, before_down) = (
        bytes(&request.baseline_uploaded)?,
        bytes(&request.baseline_downloaded)?,
    );
    let reason = request.reason.trim();
    if reason.is_empty() || reason.chars().count() > 200 || reason.chars().any(char::is_control) {
        return Err(ApiError::BadRequest("请填写 1–200 字的矫正原因".into()));
    }
    let mut tx = state.pool.begin().await?;
    let query = format!(
        "SELECT {SERVER_COLUMNS} FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
    );
    let mut server = sqlx::query_as::<_, Server>(&query)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    // Telemetry and asset edits use this same server row lock. Preserve every raw counter.
    server_traffic::attach(
        &state.pool,
        std::slice::from_mut(&mut server),
        now_timestamp(),
    )
    .await?;
    let traffic = server
        .traffic
        .as_ref()
        .ok_or_else(|| ApiError::Conflict("暂时无法读取流量".into()))?;
    if traffic.cycle_start != request.cycle_start
        || server.asset_settings.reset_day != request.reset_day
        || server.asset_settings.network_interface != request.network_interface
        || traffic.correction_id != request.correction_id
    {
        return Err(ApiError::Conflict(
            "账单周期、网卡选择或矫正记录已变化，请刷新后重新调整".into(),
        ));
    }
    let previous: Option<(String,String)> = sqlx::query_as("SELECT uploaded_offset::text,downloaded_offset::text FROM server_traffic_corrections WHERE id=$1 AND server_id=$2")
        .bind(traffic.correction_id).bind(id).fetch_optional(&mut *tx).await?;
    let (old_up, old_down) = previous.unwrap_or_else(|| ("0".into(), "0".into()));
    let offset_up = old_up.parse::<i128>().map_err(anyhow::Error::from)? + up - before_up;
    let offset_down = old_down.parse::<i128>().map_err(anyhow::Error::from)? + down - before_down;
    let correction_id: i64 = sqlx::query_scalar("INSERT INTO server_traffic_corrections(server_id,cycle_start,reset_day,network_interface,uploaded_offset,downloaded_offset,reason,created_at) VALUES($1,$2,$3,$4,$5::text::numeric,$6::text::numeric,$7,$8) RETURNING id")
        .bind(id).bind(request.cycle_start).bind(i32::from(request.reset_day)).bind(request.network_interface)
        .bind(offset_up.to_string()).bind(offset_down.to_string()).bind(reason).bind(now_timestamp()).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"correction_id":correction_id})))
}

#[derive(sqlx::FromRow)]
pub(crate) struct SavedCorrection {
    pub id: i64,
    pub server_id: i64,
    pub uploaded_offset: String,
    pub downloaded_offset: String,
}

pub(crate) async fn current(
    pool: &sqlx::PgPool,
    servers: &[Server],
    now: i64,
) -> anyhow::Result<Vec<SavedCorrection>> {
    let ids: Vec<_> = servers.iter().map(|s| s.id).collect();
    let days: Vec<_> = servers
        .iter()
        .map(|s| i32::from(s.asset_settings.reset_day))
        .collect();
    let interfaces: Vec<_> = servers
        .iter()
        .map(|s| s.asset_settings.network_interface.clone())
        .collect();
    Ok(sqlx::query_as("SELECT correction.id,selected.id AS server_id,correction.uploaded_offset::text,correction.downloaded_offset::text
        FROM unnest($1::bigint[],$2::integer[],$3::text[]) AS selected(id,reset_day,network_interface)
        CROSS JOIN LATERAL (SELECT id,uploaded_offset,downloaded_offset FROM server_traffic_corrections
          WHERE server_id=selected.id AND cycle_start=sinan_traffic_cycle_start($4,selected.reset_day)
            AND reset_day=selected.reset_day AND network_interface=selected.network_interface AND invalidated_at IS NULL ORDER BY id DESC LIMIT 1) correction")
        .bind(ids).bind(days).bind(interfaces).bind(now).fetch_all(pool).await?)
}
