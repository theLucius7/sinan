use crate::{
    AppState, agent_api,
    business::{NODE_COLUMNS, NodeRow},
};
use sinan_compiler::{Access, Node};
use sinan_protocol::{Bundle, Envelope, ManifestChanged, now_timestamp};
use sqlx::{Postgres, Row, Transaction};
use std::{collections::BTreeMap, time::Duration};

const MODULE: &str = "singbox";
const DUE: &str = "dirty_at <= FLOOR(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint - 5000";

pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = super::entitlements::refresh(&state.pool, now_timestamp()).await {
            tracing::error!(%error, "package eligibility refresh failed; will retry");
        }
        if let Err(_error) = super::ordered_paths::lifecycle::tick(&state).await {
            tracing::error!("ordered path transition failed; durable work retained");
        }
        if let Err(error) = super::sources::refresh_due(&state).await {
            tracing::error!(%error, "subscription source refresh failed; will retry");
        }
        if let Err(error) = super::mixed_paths::follow_updates(&state).await {
            tracing::error!(%error, "path source update failed; current versions retained");
        }
        if let Err(error) = super::mixed_paths::advance(&state).await {
            tracing::error!(%error, "path publication transition failed; will retry");
        }
        if let Err(error) = publish_due(&state).await {
            tracing::error!(%error, "configuration publication failed; pending work retained");
        }
    }
}

pub async fn publish_due(state: &AppState) -> anyhow::Result<()> {
    let query = format!(
        "SELECT s.id FROM servers s LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' WHERE s.deleted_at IS NULL AND {DUE} AND ({}) IS NOT NULL ORDER BY s.id",
        super::settings::SOURCE_SQL
    );
    let ids: Vec<i64> = sqlx::query_scalar(&query).fetch_all(&state.pool).await?;
    let mut first_error = None;
    for server_id in ids {
        if let Err(error) = publish_server(state, server_id).await {
            tracing::error!(server_id, %error, "server publication failed");
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    server_id: i64,
    at: i64,
) -> anyhow::Result<Vec<Node>> {
    let query = format!(
        "SELECT {NODE_COLUMNS} FROM nodes n WHERE n.server_id=$1 AND n.deleted_at IS NULL ORDER BY n.id"
    );
    let nodes = sqlx::query_as::<_, NodeRow>(&query)
        .bind(server_id)
        .fetch_all(&mut **tx)
        .await?;
    let rows = sqlx::query("SELECT a.node_id,a.user_id,a.uuid,a.credential FROM singbox_eligible_accesses($2) a JOIN nodes n ON n.id=a.node_id WHERE n.server_id=$1 ORDER BY a.node_id,a.user_id")
        .bind(server_id).bind(at).fetch_all(&mut **tx).await?;
    let mut accesses: BTreeMap<i64, Vec<Access>> = BTreeMap::new();
    for row in rows {
        accesses
            .entry(row.get("node_id"))
            .or_default()
            .push(Access {
                user_id: row.get("user_id"),
                uuid: row.get("uuid"),
                credential: row.get("credential"),
            });
    }
    nodes
        .iter()
        .map(|node| node.model(accesses.remove(&node.id).unwrap_or_default()))
        .collect()
}

async fn publish_server(state: &AppState, server_id: i64) -> anyhow::Result<()> {
    let mut retries = 0;
    let revision = loop {
        match publish_server_transaction(state, server_id).await {
            Ok(revision) => break revision,
            Err(error)
                if retries < 2
                    && error
                        .chain()
                        .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
                        .any(|error| {
                            error
                                .as_database_error()
                                .is_some_and(|database| database.code().as_deref() == Some("40001"))
                        }) =>
            {
                // Waiting on the authorization lock can outlive the RR snapshot.
                // Retry the complete uncommitted ledger/configuration transaction;
                // a fresh snapshot may simply find that another publisher finished it.
                retries += 1;
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error),
        }
    };
    if let Some(rev) = revision {
        agent_api::notify(
            state,
            server_id,
            Envelope::new("manifest.changed", ManifestChanged { rev })?,
        )
        .await;
    }
    Ok(())
}

async fn publish_server_transaction(
    state: &AppState,
    server_id: i64,
) -> anyhow::Result<Option<u64>> {
    let mut tx = state.pool.begin().await?;
    // Authorization and relay selection must see the same ledger and clock.
    // Otherwise a reset/expiry between queries could leave an entry with direct routing.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    super::entitlements::lock(&mut tx).await?;
    let at = now_timestamp();
    let query = format!(
        "SELECT s.manifest_rev FROM servers s LEFT JOIN server_plugins p ON p.server_id=s.id AND p.plugin='sing-box' WHERE s.id=$1 AND s.deleted_at IS NULL AND {DUE} AND ({}) IS NOT NULL FOR UPDATE OF s SKIP LOCKED",
        super::settings::SOURCE_SQL
    );
    let Some(manifest_rev) = sqlx::query_scalar::<_, i64>(&query)
        .bind(server_id)
        .fetch_optional(&mut *tx)
        .await?
    else {
        return Ok(None);
    };
    // Device declarations may have changed since the due-work scan. Recheck
    // under the server lock before creating legacy deployment evidence.
    if !super::settings::is_enabled(&mut tx, server_id).await? {
        tx.commit().await?;
        return Ok(None);
    }
    let nodes = snapshot(&mut tx, server_id, at).await?;
    let relays = super::chains::load(&mut tx, server_id, at).await?;
    let plan =
        super::ordered_paths::publication::plan(state, &mut tx, server_id, at, nodes, relays)
            .await?;
    // Shared local controller credentials belong to this new desired bundle only.
    // Existing deployments and in-flight receipts retain their immutable old bytes.
    if let Some(control) = &plan.probe_control {
        synchronize_path_secret_on(&mut tx, server_id, &control.secret).await?;
    }
    let source = super::ordered_paths::publication::source(&plan)?;
    let prepared =
        super::mixed_paths::compile_on(&mut tx, server_id, &plan.nodes, &plan.legacy).await?;
    let native = sinan_compiler::compile_server_with_paths_on_config(
        &plan.nodes,
        &plan.legacy,
        &plan.paths,
        &plan.accepts,
        plan.probe_control.as_ref(),
        &prepared.compiled,
    )?;
    let mut files = BTreeMap::from([("config.json".into(), native)]);
    if let Some(probes) = &plan.probe_plan {
        files.insert("runtime-probes.json".into(), serde_json::to_string(probes)?);
    }
    if !prepared.evidence.is_empty() {
        files.insert(
            "runtime-constraints.json".into(),
            serde_json::to_string(&prepared.compiled.constraints)?,
        );
        files.insert(
            "path-checks.json".into(),
            serde_json::to_string(&prepared.compiled.checks)?,
        );
        files.insert(
            "path-features.json".into(),
            serde_json::to_string(&prepared.compiled.features)?,
        );
    }
    let bundle = serde_json::to_string(&Bundle { files })?;
    let hash = crate::auth::hash_token(&bundle);
    let previous = sqlx::query("SELECT rev,bundle_sha256 FROM deployments WHERE server_id=$1 AND module=$2 ORDER BY rev DESC LIMIT 1")
        .bind(server_id).bind(MODULE).fetch_optional(&mut *tx).await?;
    if let Some(previous) = previous.filter(|row| row.get::<String, _>("bundle_sha256") == hash) {
        // Public display metadata is separate from immutable accounting/path evidence.
        super::ordered_paths::publication::record(
            &mut tx,
            server_id,
            previous.get::<i64, _>("rev"),
            &hash,
            &plan,
        )
        .await?;
        // Subscription-only metadata may change without changing native bytes.
        sqlx::query(
            "INSERT INTO singbox_deployment_projections(server_id,rev,source_json) VALUES($1,$2,$3) ON CONFLICT(server_id,rev) DO UPDATE SET source_json=EXCLUDED.source_json",
        )
        .bind(server_id)
        .bind(previous.get::<i64, _>("rev"))
        .bind(&source)
        .execute(&mut *tx)
        .await?;
        super::mixed_paths::record_deployment_on(
            &mut tx,
            server_id,
            previous.get("rev"),
            &hash,
            &prepared.evidence,
        )
        .await?;
        sqlx::query("UPDATE servers SET dirty_at=NULL WHERE id=$1")
            .bind(server_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let rev = manifest_rev
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("revision overflow"))?;
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,source_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(server_id).bind(MODULE).bind(rev).bind(bundle).bind(&hash).bind(source).bind(now_timestamp()).execute(&mut *tx).await?;
    super::ordered_paths::publication::record(&mut tx, server_id, rev, &hash, &plan).await?;
    super::mixed_paths::record_deployment_on(&mut tx, server_id, rev, &hash, &prepared.evidence)
        .await?;
    sqlx::query("INSERT INTO server_module_status(server_id,module,target_rev,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(server_id,module) DO UPDATE SET target_rev=EXCLUDED.target_rev,updated_at=EXCLUDED.updated_at")
        .bind(server_id).bind(MODULE).bind(rev).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE servers SET manifest_rev=$2,dirty_at=NULL WHERE id=$1")
        .bind(server_id)
        .bind(rev)
        .execute(&mut *tx)
        .await?;
    let revision = rev.try_into()?;
    tx.commit().await?;
    Ok(Some(revision))
}

async fn synchronize_path_secret_on(
    tx: &mut Transaction<'_, Postgres>,
    server_id: i64,
    secret: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        secret.len() == 64 && secret.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "ordered private controller secret is invalid"
    );
    sqlx::query("UPDATE singbox_path_controls SET secret=$2 WHERE server_id=$1 AND secret<>$2")
        .bind(server_id)
        .bind(secret)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
