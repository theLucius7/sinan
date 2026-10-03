mod api;
mod jobs;
mod policy;
mod scheduler;
mod state;
#[cfg(test)]
mod tests;

pub(super) use api::routes;
pub(super) use jobs::idle;
pub(super) use policy::Policy;
pub(super) use state::State;

use serde::Serialize;
use sqlx::{FromRow, types::Json};
use uuid::Uuid;

pub(super) async fn run(pool: sqlx::PgPool) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let result = match super::client::Cloud::new(&pool) {
            Ok(cloud) => jobs::tick(&pool, &cloud).await,
            Err(error) => Err(super::failure(error)),
        };
        let (status, details) = match result {
            Ok(()) => (
                "healthy",
                serde_json::json!({"scope":"power_scheduler_and_reconciliation_cycle","completed":true,"remote_resource_health_confirmed":false}),
            ),
            Err(error) => {
                tracing::warn!(%error,"Cloud power reconciliation failed");
                (
                    "failed",
                    serde_json::json!({"scope":"power_scheduler_and_reconciliation_cycle","completed":false,"error":error.to_string(),"remote_resource_health_confirmed":false}),
                )
            }
        };
        if let Err(error) =
            crate::control_center::system::heartbeat(&pool, "alicloud-power", status, details).await
        {
            tracing::warn!(%error,"Cloud power heartbeat storage failed");
        }
    }
}

#[derive(Serialize, FromRow)]
pub(super) struct Job {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub account_revision: i64,
    pub resource_revision: i64,
    pub action: String,
    pub stop_mode: String,
    pub source: String,
    pub dedup_key: Option<String>,
    pub before_state: Json<State>,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
    pub next_check_at: i64,
    pub request_id: Option<String>,
    pub error_code: Option<String>,
}
