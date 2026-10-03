use crate::{error::ApiResult, plugin_api::ActivityEvidence};

pub async fn runtime_activity_on(
    connection: &mut sqlx::PgConnection,
    server_id: i64,
    checked_at: i64,
) -> ApiResult<ActivityEvidence> {
    let configured: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM deployments WHERE server_id=$1 AND module='singbox')",
    )
    .bind(server_id)
    .fetch_one(&mut *connection)
    .await?;
    let last_positive_at: Option<i64> = sqlx::query_scalar("SELECT MAX(period_end) FROM usage_records WHERE server_id=$1 AND (uplink>0 OR downlink>0) AND period_end<=$2")
        .bind(server_id).bind(checked_at.saturating_add(60)).fetch_one(&mut *connection).await?;
    Ok(ActivityEvidence {
        configured,
        last_positive_at,
    })
}
