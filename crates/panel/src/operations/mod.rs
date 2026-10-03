mod api;
mod backup_executor;
mod backups;
mod cancellation_reminders;
mod cloud;
mod hetzner;
mod incidents;
mod model;
mod panel_job_backup;
mod planning;
mod recovery;
mod remediation;
mod runtime_reconciliation;
mod suppliers;
mod typed_steps;
mod worker;

pub use worker::{run, tick};

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(hetzner::router())
        .merge(crate::plugins::alicloud::security_groups_routes())
        .route(
            "/api/operations/templates",
            get(api::templates).post(api::save_template),
        )
        .route("/api/operations/jobs", get(api::jobs))
        .route("/api/operations/preview", post(api::preview))
        .route("/api/operations/jobs/{id}", get(api::detail))
        .route("/api/operations/jobs/{id}/confirm", post(api::confirm))
        .route("/api/operations/jobs/{id}/cancel", post(api::cancel))
        .route("/api/operations/jobs/{id}/resume", post(api::resume))
        .route("/api/operations/jobs/{id}/reconcile", post(api::reconcile))
        .route(
            "/api/operations/jobs/{id}/panel-backup/reconcile",
            post(panel_job_backup::reconcile),
        )
        .route(
            "/api/operations/jobs/{id}/runtime-reconcile/checkpoint",
            post(runtime_reconciliation::checkpoint),
        )
        .route(
            "/api/operations/jobs/{id}/runtime-reconcile",
            post(runtime_reconciliation::reconcile),
        )
        .route(
            "/api/operations/schedules",
            get(api::schedules).post(api::save_schedule),
        )
        .route(
            "/api/operations/schedules/{id}/pause",
            post(api::pause_schedule),
        )
        .route(
            "/api/operations/remediation",
            get(remediation::list).post(remediation::create),
        )
        .route(
            "/api/operations/remediation/{id}/pause",
            post(remediation::pause),
        )
        .route(
            "/api/operations/maintenance",
            get(api::maintenance).post(api::save_maintenance),
        )
        .route("/api/operations/incidents", get(incidents::list))
        .route("/api/operations/incidents/{id}", get(incidents::detail))
        .route(
            "/api/operations/incidents/{id}/action",
            post(incidents::action),
        )
        .route(
            "/api/operations/incidents/{id}/assignees",
            get(incidents::assignees),
        )
        .route(
            "/api/operations/backups",
            get(recovery::backups).post(recovery::import_backup),
        )
        .route(
            "/api/operations/backups/{id}/drills",
            post(recovery::import_drill),
        )
        .route(
            "/api/operations/backups/{id}/retire",
            post(recovery::retire),
        )
        .route(
            "/api/operations/backup-schedules",
            get(backups::list).post(backups::create),
        )
        .route(
            "/api/operations/backup-schedules/{id}/pause",
            post(backups::pause),
        )
        .route("/api/operations/cloud", get(cloud::list))
        .route("/api/operations/cloud/{id}/link", post(cloud::link))
        .route("/api/operations/cloud/{id}/history", get(cloud::history))
        .route("/api/operations/suppliers", get(suppliers::comparison))
        .route(
            "/api/operations/cancellation-reminders",
            get(cancellation_reminders::list).post(cancellation_reminders::configure),
        )
}

pub(crate) async fn notifications_suppressed(
    pool: &sqlx::PgPool,
    server: i64,
    now: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND suppress_notifications AND starts_at<=$2 AND ends_at>$2) OR EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$2 AND (maintenance_until IS NULL OR maintenance_until>$2))")
        .bind(server).bind(now).fetch_one(pool).await
}

async fn require_global(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    capability: &str,
) -> crate::error::ApiResult<i64> {
    let actor = crate::control_center::authenticate(state, headers).await?;
    if !actor.allows(capability) || !actor.global_servers() {
        return Err(crate::error::ApiError::Forbidden(
            "此功能涉及面板全局恢复材料或未关联云资源，需要明确的全局授权".into(),
        ));
    }
    Ok(actor.admin_id)
}
