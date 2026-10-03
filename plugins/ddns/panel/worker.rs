use super::{
    LEASE_SECS, REQUEST_BUDGET,
    cloudflare::{Failure, Outcome},
    history::{self, Entry},
    lifecycle::Snapshot,
    load,
    model::{self, Rule},
    providers::Providers,
};
use crate::error::{ApiError, ApiResult};
use futures_util::{StreamExt, stream};
use sqlx::PgPool;
use std::{net::IpAddr, time::Duration};
use uuid::Uuid;

async fn claim(pool: &PgPool, id: Uuid, force: bool) -> ApiResult<Option<(Uuid, Rule)>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await?;
    let now = sinan_protocol::now_timestamp();
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM ddns_rules WHERE lease_until>$1")
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
    if active >= 2 {
        return if force { Err(ApiError::Busy) } else { Ok(None) };
    }
    let Some(rule) =
        sqlx::query_as::<_, Rule>("SELECT * FROM ddns_rules WHERE id=$1 FOR UPDATE SKIP LOCKED")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return if force {
            load(pool, id).await?;
            Err(ApiError::Busy)
        } else {
            Ok(None)
        };
    };
    if !rule.config.enabled {
        return if force {
            Err(ApiError::Conflict("请先启用规则".into()))
        } else {
            Ok(None)
        };
    }
    let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_plugins WHERE server_id=$1 AND plugin='ddns' AND enabled)")
        .bind(rule.config.server_id).fetch_one(&mut *tx).await?;
    if !enabled {
        return if force {
            Err(ApiError::Conflict("请先为该服务器启用 DDNS 插件".into()))
        } else {
            Ok(None)
        };
    }
    if rule.lease_until > now
        || (force && rule.attempted_at.is_some_and(|at| at + 60 > now))
        || (rule.next_run_at > now && (!force || rule.failures > 0))
    {
        return if force { Err(ApiError::Busy) } else { Ok(None) };
    }
    let lease = Uuid::new_v4();
    sqlx::query("UPDATE ddns_rules SET lease_id=$2,lease_until=$3,attempted_at=$4,next_run_at=$5,status='running' WHERE id=$1")
        .bind(id).bind(lease).bind(now+LEASE_SECS).bind(now).bind(now+i64::from(rule.config.interval_secs)).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some((lease, rule)))
}

#[cfg(test)]
pub(super) async fn complete(
    pool: &PgPool,
    rule: &Rule,
    lease: Uuid,
    result: Result<(IpAddr, Outcome), Failure>,
) -> ApiResult<()> {
    let desired = result.as_ref().ok().map(|(ip, _)| *ip);
    complete_with_history(pool, rule, lease, result, None, desired).await
}

async fn complete_with_history(
    pool: &PgPool,
    rule: &Rule,
    lease: Uuid,
    result: Result<(IpAddr, Outcome), Failure>,
    previous: Option<Snapshot>,
    desired: Option<IpAddr>,
) -> ApiResult<()> {
    let now = sinan_protocol::now_timestamp();
    let mut tx = pool.begin().await?;
    let (status, error, observed) = match &result {
        Ok((ip, outcome)) => (
            outcome.status,
            None,
            Some(history::observed(rule, *ip, outcome, previous.as_ref())),
        ),
        Err(error) => ("error", Some(error.code.to_owned()), None),
    };
    let updated = match result {
        Ok((_, outcome)) if outcome.status == "submitted" => {
            sqlx::query("UPDATE ddns_rules SET record_id=$3,status='submitted',error_code=NULL,failures=0,lease_id=NULL,lease_until=0,next_run_at=$4 WHERE id=$1 AND lease_id=$2 AND revision=$5")
                .bind(rule.id).bind(lease).bind(outcome.record_id).bind(now+60).bind(rule.revision).execute(&mut *tx).await?
        }
        Ok((ip, outcome)) => {
            sqlx::query("UPDATE ddns_rules SET record_id=$3,last_ip=$4,last_success_at=$5,status=$6,error_code=NULL,failures=0,lease_id=NULL,lease_until=0,next_run_at=$7 WHERE id=$1 AND lease_id=$2 AND revision=$8")
                .bind(rule.id).bind(lease).bind(outcome.record_id).bind(ip.to_string()).bind(now).bind(outcome.status).bind(now+i64::from(rule.config.interval_secs)).bind(rule.revision).execute(&mut *tx).await?
        }
        Err(error) => {
            let waiting = matches!(
                error.code,
                "server_retired"
                    | "server_offline"
                    | "ip_stale"
                    | "no_public_ip"
                    | "source_unavailable"
                    | "address_changed"
                    | "plugin_disabled"
                    | "provider_pending"
            );
            let failures = if waiting {
                0
            } else {
                rule.failures.saturating_add(1).min(16)
            };
            let delay = if waiting {
                60
            } else {
                (60_i64 << failures.saturating_sub(1).min(6))
                    .min(3600)
                    .max(error.retry_after)
            };
            sqlx::query("UPDATE ddns_rules SET status=$3,error_code=$4,failures=$5,lease_id=NULL,lease_until=0,next_run_at=$6 WHERE id=$1 AND lease_id=$2 AND revision=$7")
                .bind(rule.id).bind(lease).bind(if waiting { "waiting" } else { "error" }).bind(error.code).bind(failures).bind(now+delay).bind(rule.revision).execute(&mut *tx).await?
        }
    };
    if updated.rows_affected() == 1 {
        history::append(
            &mut tx,
            Entry {
                id: Uuid::new_v4(),
                rule_id: rule.id,
                server_id: rule.config.server_id,
                revision: rule.revision,
                operation: "sync".into(),
                desired_ip: desired.map(|ip| ip.to_string()),
                previous,
                observed,
                status: status.into(),
                error_code: error,
                occurred_at: now,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn write_guard(
    pool: &PgPool,
    rule: &Rule,
    lease: Uuid,
    ip: IpAddr,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, Failure> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| Failure::from("storage_error"))?;
    // Claims and plugin disable use this same order. Holding the lock through
    // the write prevents an expired wall-clock lease being reclaimed mid-request.
    sqlx::query("SELECT pg_advisory_xact_lock(739104824)")
        .execute(&mut *tx)
        .await
        .map_err(|_| Failure::from("storage_error"))?;
    let now = sinan_protocol::now_timestamp();
    let current: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ddns_rules WHERE id=$1 AND lease_id=$2 AND revision=$3 AND lease_until>$4 AND config->>'enabled'='true' FOR SHARE")
        .bind(rule.id).bind(lease).bind(rule.revision).bind(now)
        .fetch_optional(&mut *tx).await.map_err(|_| Failure::from("storage_error"))?;
    if current.is_none() {
        return Err("lease_lost".into());
    }
    super::credentials::guard_reference(&mut tx, rule).await?;
    // Retirement and deletion both lock this server row for update. The shared
    // lock therefore keeps their acknowledgement after any already-started write.
    let info = model::locked_observation(&mut tx, rule.config.server_id)
        .await
        .map_err(|_| Failure::from("storage_error"))?;
    let preferred = ip.to_string();
    let selected = info
        .select(
            &rule.config,
            Some(&preferred),
            sinan_protocol::now_timestamp(),
        )
        .map_err(Failure::from)?;
    if selected != ip {
        return Err("address_changed".into());
    }
    Ok(tx)
}

pub(super) async fn sync_with(
    pool: &PgPool,
    id: Uuid,
    force: bool,
    provider: &Providers,
) -> ApiResult<()> {
    let Some((lease, mut rule)) = claim(pool, id, force).await? else {
        return Ok(());
    };
    let mut previous = None;
    let mut desired = None;
    let result = tokio::time::timeout(Duration::from_secs(REQUEST_BUDGET), async {
        super::credentials::hydrate(pool, &mut rule)
            .await
            .map_err(|_| Failure::from("credential_unavailable"))?;
        let info = model::observation(pool, rule.config.server_id)
            .await
            .map_err(|_| Failure::from("storage_error"))?;
        let ip = info
            .select(
                &rule.config,
                rule.last_ip.as_deref(),
                sinan_protocol::now_timestamp(),
            )
            .map_err(Failure::from)?;
        desired = Some(ip);
        previous = provider.inspect(&rule).await?;
        provider
            .reconcile_expected_guarded(&rule, ip, previous.as_ref(), || {
                write_guard(pool, &rule, lease, ip)
            })
            .await
            .map(|outcome| (ip, outcome))
    })
    .await
    .unwrap_or(Err("request_timeout".into()));
    complete_with_history(pool, &rule, lease, result, previous, desired).await
}

pub(super) async fn sync(pool: &PgPool, id: Uuid, force: bool) -> ApiResult<()> {
    let provider = Providers::new()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("DDNS client initialization failed")))?;
    sync_with(pool, id, force, &provider).await
}

pub async fn run(pool: PgPool) {
    let mut timer = tokio::time::interval(Duration::from_secs(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let result = tick(&pool).await;
        let (status, details) = match result {
            Ok(details) => ("healthy", details),
            Err(error) => {
                tracing::warn!(%error,"DDNS maintenance failed");
                (
                    "failed",
                    serde_json::json!({"source":"ddns_dispatcher_tick","scope":"dispatcher","rule_results_source":"ddns_rules_and_history","error_code":"dispatcher_failed"}),
                )
            }
        };
        if let Err(error) =
            crate::control_center::system::heartbeat(&pool, "ddns", status, details).await
        {
            tracing::warn!(%error,"DDNS heartbeat persistence failed");
        }
    }
}

async fn tick(pool: &PgPool) -> ApiResult<serde_json::Value> {
    let now = sinan_protocol::now_timestamp();
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM ddns_rules d WHERE config->>'enabled'='true' AND next_run_at<=$1 AND lease_until<=$1 AND EXISTS(SELECT 1 FROM server_plugins p WHERE p.server_id=d.server_id AND p.plugin='ddns' AND p.enabled) ORDER BY next_run_at,id LIMIT 8")
        .bind(now).fetch_all(pool).await?;
    let dispatched = ids.len();
    let results = stream::iter(
        ids.into_iter()
            .map(|id| async move { sync(pool, id, false).await }),
    )
    .buffer_unordered(2)
    .collect::<Vec<_>>()
    .await;
    for result in results {
        result?;
    }
    Ok(
        serde_json::json!({"source":"ddns_dispatcher_tick","scope":"dispatcher","dispatched_rules":dispatched,"rule_results_source":"ddns_rules_and_history","dns_success":null,"sampled_at":sinan_protocol::now_timestamp()}),
    )
}
