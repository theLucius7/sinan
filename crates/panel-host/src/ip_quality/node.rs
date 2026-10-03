use super::{IpQuality, cache};
use crate::{
    AppState,
    diagnostic_plugins::ipquality::{IpQualityPlugin, PLUGIN_VERSION, Projection},
    diagnostics::{
        ReportRecord,
        service::{self, SectionContext},
    },
    error::ApiResult,
};
use serde::Serialize;
use sinan_protocol::DiagnosticSectionUpdate;
use sqlx::Row;

pub const PROVIDER_PREFIX: &str = "ipquality-node/";

#[derive(Serialize)]
pub struct NodeQualityView {
    pub ready: bool,
    pub reason: Option<String>,
    pub version: &'static str,
    pub reports: Vec<ReportRecord>,
    pub observed_egress_ips: Vec<String>,
    pub current_egress_ips: Vec<String>,
    pub cancel_supported: bool,
    #[serde(skip)]
    pub(crate) source_ready: bool,
    #[serde(skip)]
    pub(crate) source_reason: Option<String>,
}

pub(crate) async fn view(state: &AppState, server_id: i64) -> ApiResult<NodeQualityView> {
    let row = sqlx::query(
        "SELECT static_info,last_seen,capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(server_id)
    .fetch_one(&state.pool)
    .await?;
    let mut readiness = service::readiness(state, &row, &IpQualityPlugin).await;
    let source_ready = readiness.ready;
    let source_reason = readiness.reason.clone();
    let reports = service::history(state, server_id, Some("ipquality")).await?;
    let active: bool = sqlx::query_scalar(crate::diagnostics::UNRESOLVED_QUERY)
        .bind(server_id)
        .bind(None::<uuid::Uuid>)
        .fetch_one(&state.pool)
        .await?;
    if active {
        readiness.ready = false;
        readiness.reason =
            Some("此服务器已有诊断任务或正在等待清理、取消确认，请等待设备完成".into());
    }
    Ok(NodeQualityView {
        ready: readiness.ready,
        reason: readiness.reason,
        version: PLUGIN_VERSION,
        reports,
        observed_egress_ips: Vec::new(),
        current_egress_ips: Vec::new(),
        cancel_supported: service::cancel_supported(&row.get("capabilities")),
        source_ready,
        source_reason,
    })
}

pub(crate) async fn cached(
    state: &AppState,
    server_id: i64,
    view: &mut NodeQualityView,
) -> ApiResult<Vec<IpQuality>> {
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let historical_ips: Vec<String> = sqlx::query_scalar("SELECT ip FROM server_ip_quality WHERE server_id=$1 AND provider LIKE 'ipquality-node/%' GROUP BY ip ORDER BY MAX(checked_at) DESC,ip LIMIT 8")
        .bind(server_id).fetch_all(&mut *tx).await?;
    let current_egress_ips: Vec<String> = sqlx::query_scalar("SELECT egress_ip FROM server_ip_quality_node_generations WHERE server_id=$1 AND egress_ip IS NOT NULL ORDER BY ip_version")
        .bind(server_id).fetch_all(&mut *tx).await?;
    let mut observed_egress_ips = current_egress_ips.clone();
    for ip in historical_ips {
        if !observed_egress_ips.contains(&ip) {
            observed_egress_ips.push(ip);
        }
    }
    observed_egress_ips.truncate(8);
    let mut quality = cache::read_on_connection(&mut tx, server_id, &observed_egress_ips).await?;
    tx.commit().await?;
    view.observed_egress_ips = observed_egress_ips;
    view.current_egress_ips = current_egress_ips;
    quality.retain(|entry| entry.provider.starts_with(PROVIDER_PREFIX));
    for entry in &mut quality {
        let source = entry
            .provider
            .strip_prefix(PROVIDER_PREFIX)
            .unwrap_or_default();
        let registered = crate::diagnostic_plugins::ipquality::SOURCES
            .iter()
            .any(|(provider, _)| *provider == source);
        let restricted = source.ends_with("-not-configured") || source.ends_with("-disabled");
        let available = view.source_ready && registered && !restricted;
        let reason = if restricted {
            Some("此来源未配置授权适配或主动探测已禁用，信息未知".into())
        } else if !registered {
            Some("此历史节点入口当前没有登记，字段仅作历史参考".into())
        } else {
            view.source_reason.clone()
        };
        for dataset in &mut entry.databases {
            dataset.available = Some(available);
            dataset.unavailable_reason = reason.clone();
            if !available || !view.current_egress_ips.contains(&entry.ip) {
                dataset.historical = !dataset.fields.is_empty();
            }
        }
    }
    Ok(quality)
}

/// The caller already holds server -> job locks and owns the chapter transaction.
pub(crate) async fn persist(
    connection: &mut sqlx::PgConnection,
    context: &SectionContext<'_>,
    update: &DiagnosticSectionUpdate,
    mut projection: Projection,
) -> ApiResult<()> {
    let previous = sqlx::query("SELECT job_generation,section_revision FROM server_ip_quality_node_generations WHERE server_id=$1 AND ip_version=$2")
        .bind(context.server_id).bind(&projection.ip_version).fetch_optional(&mut *connection).await?;
    if let Some(previous) = previous {
        let generation: i64 = previous.get("job_generation");
        if context.job_generation < generation
            || (context.job_generation == generation
                && update.revision <= previous.get::<i64, _>("section_revision") as u64)
        {
            // Keep the late chapter in history, but never restore an obsolete outlet.
            return Ok(());
        }
    }
    sqlx::query("INSERT INTO server_ip_quality_node_generations(server_id,ip_version,job_created_at,job_id,section_revision,egress_ip,job_generation) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(server_id,ip_version) DO UPDATE SET job_created_at=EXCLUDED.job_created_at,job_id=EXCLUDED.job_id,section_revision=EXCLUDED.section_revision,egress_ip=EXCLUDED.egress_ip,job_generation=EXCLUDED.job_generation")
        .bind(context.server_id).bind(&projection.ip_version).bind(context.created_at).bind(update.id)
        .bind(update.revision as i64).bind(&projection.egress_ip).bind(context.job_generation).execute(&mut *connection).await?;
    for entry in &mut projection.quality {
        // A partial snapshot has only completed datasets. Preserve siblings rather
        // than replacing the provider's visible inventory with a shorter array.
        let prior: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM server_ip_quality WHERE server_id=$1 AND ip=$2 AND provider=$3",
        )
        .bind(context.server_id)
        .bind(&entry.ip)
        .bind(&entry.provider)
        .fetch_optional(&mut *connection)
        .await?;
        if let Some(prior) = prior {
            let prior: IpQuality = serde_json::from_value(prior).map_err(anyhow::Error::from)?;
            for dataset in prior.databases {
                if !entry
                    .databases
                    .iter()
                    .any(|incoming| incoming.database == dataset.database)
                {
                    entry.databases.push(dataset);
                }
            }
            entry.databases.sort_by(|a, b| a.database.cmp(&b.database));
        }
        let succeeded = entry
            .databases
            .iter()
            .filter(|dataset| dataset.status == "succeeded")
            .count();
        entry.status = if succeeded == entry.databases.len() {
            "succeeded"
        } else if succeeded == 0 {
            "failed"
        } else {
            "partial"
        }
        .into();
        cache::persist_on_connection(
            connection,
            context.server_id,
            std::slice::from_ref(entry),
            true,
        )
        .await?;
        sqlx::query("UPDATE server_ip_quality SET source_job_created_at=$4,source_job_id=$5,source_section_revision=$6 WHERE server_id=$1 AND ip=$2 AND provider=$3")
            .bind(context.server_id).bind(&entry.ip).bind(&entry.provider).bind(context.created_at)
            .bind(update.id).bind(update.revision as i64).execute(&mut *connection).await?;
    }
    Ok(())
}
