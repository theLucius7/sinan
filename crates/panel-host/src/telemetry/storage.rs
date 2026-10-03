use super::*;
use serde::{Deserialize, Serialize};
use sinan_protocol::telemetry::TelemetrySettings;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPolicy {
    pub history_retention_days: i32,
}

pub(super) async fn read_policy(pool: &sqlx::PgPool) -> ApiResult<HistoryPolicy> {
    Ok(HistoryPolicy {
        history_retention_days: sqlx::query_scalar(
            "SELECT history_retention_days FROM telemetry_policy WHERE singleton",
        )
        .fetch_one(pool)
        .await?,
    })
}

pub async fn policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<HistoryPolicy>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(read_policy(&state.pool).await?))
}

pub async fn update_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(policy): Json<HistoryPolicy>,
) -> ApiResult<Json<HistoryPolicy>> {
    auth::require_admin(&state, &headers).await?;
    if !(1..=3650).contains(&policy.history_retention_days) {
        return Err(ApiError::BadRequest("历史保存期限须为 1–3650 天".into()));
    }
    sqlx::query("UPDATE telemetry_policy SET history_retention_days=$1 WHERE singleton")
        .bind(policy.history_retention_days)
        .execute(&state.pool)
        .await?;
    Ok(Json(policy))
}

pub(super) async fn read_storage_settings(
    state: &AppState,
    server: i64,
) -> ApiResult<Json<TelemetrySettings>> {
    let value: serde_json::Value = sqlx::query_scalar(
        "SELECT telemetry_settings FROM servers WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(server)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(
        serde_json::from_value(value).map_err(anyhow::Error::from)?,
    ))
}

pub async fn storage_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<TelemetrySettings>> {
    auth::require_admin(&state, &headers).await?;
    read_storage_settings(&state, server).await
}

pub async fn agent_storage_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<TelemetrySettings>> {
    let server = auth::require_agent(&state, &headers).await?;
    read_storage_settings(&state, server).await
}

pub async fn update_storage_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(settings): Json<TelemetrySettings>,
) -> ApiResult<Json<TelemetrySettings>> {
    auth::require_admin(&state, &headers).await?;
    if !settings.valid() {
        return Err(ApiError::BadRequest("历史写入间隔须为 15–3600 秒".into()));
    }
    let changed =
        sqlx::query("UPDATE servers SET telemetry_settings=$2 WHERE id=$1 AND deleted_at IS NULL")
            .bind(server)
            .bind(serde_json::to_value(&settings).map_err(anyhow::Error::from)?)
            .execute(&state.pool)
            .await?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(settings))
}
