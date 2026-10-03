use serde_json::Value;
use sinan_protocol::{RuntimeBinding, runtime_module_valid};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(crate) async fn lock_server(
    connection: &mut PgConnection,
    server_id: i64,
) -> anyhow::Result<Value> {
    let capabilities: Option<Value> = sqlx::query_scalar(
        "SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(server_id)
    .fetch_optional(connection)
    .await?;
    capabilities.ok_or_else(|| anyhow::anyhow!("unknown or retired device"))
}

pub(super) async fn current_binding(
    connection: &mut PgConnection,
    server_id: i64,
    module: &str,
) -> anyhow::Result<RuntimeBinding> {
    anyhow::ensure!(runtime_module_valid(module), "invalid runtime module");
    let row = sqlx::query("SELECT d.rev,d.bundle_sha256 FROM server_module_status s JOIN deployments d ON d.server_id=s.server_id AND d.module=s.module AND d.rev=s.target_rev WHERE s.server_id=$1 AND s.module=$2 FOR UPDATE OF s")
        .bind(server_id).bind(module).fetch_optional(&mut *connection).await?
        .ok_or_else(|| anyhow::anyhow!("no published target for module"))?;
    let revision: i64 = row.get("rev");
    let bundle_sha256: String = row.get("bundle_sha256");
    let proposed = RuntimeBinding::new(
        Uuid::new_v4(),
        module.into(),
        revision as u64,
        bundle_sha256.clone(),
    );
    anyhow::ensure!(proposed.valid(), "invalid deployment identity");
    sqlx::query("INSERT INTO runtime_deployment_bindings(deployment_id,server_id,module,rev,bundle_sha256,binding_digest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(server_id,module,rev) DO NOTHING")
        .bind(proposed.deployment_id).bind(server_id).bind(module).bind(revision)
        .bind(&proposed.bundle_sha256).bind(&proposed.binding_digest).execute(&mut *connection).await?;
    let row = sqlx::query("SELECT deployment_id,bundle_sha256,binding_digest FROM runtime_deployment_bindings WHERE server_id=$1 AND module=$2 AND rev=$3")
        .bind(server_id).bind(module).bind(revision).fetch_one(&mut *connection).await?;
    let binding = RuntimeBinding {
        deployment_id: row.get("deployment_id"),
        module: module.into(),
        revision: revision as u64,
        bundle_sha256: row.get("bundle_sha256"),
        binding_digest: row.get("binding_digest"),
    };
    anyhow::ensure!(
        binding.valid() && binding.bundle_sha256 == bundle_sha256,
        "deployment identity changed"
    );
    Ok(binding)
}

pub(super) struct PendingRequest<'a> {
    pub module: &'a str,
    pub kind: &'a str,
    pub digest: String,
    pub payload: Value,
    pub request_id: Uuid,
    pub now: i64,
    pub expires_at: i64,
}

pub(super) async fn enqueue(
    connection: &mut PgConnection,
    server_id: i64,
    request: PendingRequest<'_>,
) -> anyhow::Result<Value> {
    let PendingRequest {
        module,
        kind,
        digest,
        payload,
        request_id,
        now,
        expires_at,
    } = request;
    sqlx::query("UPDATE runtime_control_requests SET state='expired' WHERE server_id=$1 AND state='pending' AND expires_at<=$2")
        .bind(server_id).bind(now).execute(&mut *connection).await?;
    if let Some(row) = sqlx::query("SELECT request_json FROM runtime_control_requests WHERE server_id=$1 AND module=$2 AND kind=$3 AND state='pending'")
        .bind(server_id).bind(module).bind(kind).fetch_optional(&mut *connection).await?
    {
        let existing: Value = row.get("request_json");
        // Reconnects repeat the exact request and deadline, rather than renewing it.
        if existing.get("expected") == payload.get("expected") && existing.get("minimum_revision") == payload.get("minimum_revision") {
            return Ok(existing);
        }
        sqlx::query("UPDATE runtime_control_requests SET state='expired' WHERE server_id=$1 AND module=$2 AND kind=$3 AND state='pending'")
            .bind(server_id).bind(module).bind(kind).execute(&mut *connection).await?;
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_control_requests WHERE server_id=$1 AND state='pending'",
    )
    .bind(server_id)
    .fetch_one(&mut *connection)
    .await?;
    anyhow::ensure!(count < 64, "too many pending runtime control requests");
    sqlx::query("INSERT INTO runtime_control_requests(request_id,server_id,module,kind,request_digest,request_json,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(request_id).bind(server_id).bind(module).bind(kind).bind(digest).bind(&payload)
        .bind(now).bind(expires_at).execute(connection).await?;
    Ok(payload)
}

pub(crate) async fn target_is_current(
    connection: &mut PgConnection,
    server_id: i64,
    binding: &RuntimeBinding,
) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_module_status s JOIN deployments d ON d.server_id=s.server_id AND d.module=s.module AND d.rev=s.target_rev JOIN runtime_deployment_bindings b ON b.server_id=d.server_id AND b.module=d.module AND b.rev=d.rev JOIN servers v ON v.id=s.server_id WHERE s.server_id=$1 AND s.module=$2 AND s.target_rev=$3 AND d.bundle_sha256=$4 AND b.deployment_id=$5 AND b.binding_digest=$6 AND v.deleted_at IS NULL AND v.dirty_at IS NULL AND v.capabilities @> '[\"runtime:checkpoint-v1\"]'::jsonb)")
        .bind(server_id).bind(&binding.module).bind(binding.revision as i64).bind(&binding.bundle_sha256)
        .bind(binding.deployment_id).bind(&binding.binding_digest).fetch_one(connection).await?)
}

pub(crate) async fn confirmed_is_current(
    connection: &mut PgConnection,
    server_id: i64,
    binding: &RuntimeBinding,
) -> anyhow::Result<bool> {
    if !target_is_current(connection, server_id, binding).await? {
        return Ok(false);
    }
    Ok(sqlx::query_scalar("SELECT healthy AND applied_rev>=target_rev FROM server_module_status WHERE server_id=$1 AND module=$2")
        .bind(server_id).bind(&binding.module).fetch_one(connection).await?)
}
