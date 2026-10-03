use super::receipts::{preliminary_outcome, request_for_result, save_receipt};
use super::storage::{PendingRequest, current_binding, enqueue};
use super::{confirmed_is_current, lock_server, supports, target_is_current};
use crate::{AppState, agent_api};
use sinan_protocol::{
    Bundle, Envelope, RUNTIME_PATH_PROBE_CAPABILITY, RuntimeCheckpoint, RuntimeControlAck,
    RuntimePathProbeRequest, RuntimePathProbeResult, now_timestamp,
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub async fn checked_target_checkpoint(
    connection: &mut PgConnection,
    server_id: i64,
    module: &str,
) -> anyhow::Result<RuntimeCheckpoint> {
    // Match apply/receipt handlers: server identity precedes module and checkpoint locks.
    lock_server(connection, server_id).await?;
    let binding = current_binding(connection, server_id, module).await?;
    let raw = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT checkpoint_json FROM runtime_module_checkpoints WHERE server_id=$1 AND module=$2 FOR UPDATE")
        .bind(server_id).bind(module).fetch_optional(&mut *connection).await?
        .ok_or_else(|| anyhow::anyhow!("no verified runtime checkpoint"))?;
    let checkpoint: RuntimeCheckpoint = serde_json::from_value(raw)?;
    anyhow::ensure!(
        checkpoint.valid()
            && checkpoint.healthy
            && checkpoint.binding == binding
            && confirmed_is_current(connection, server_id, &binding).await?,
        "verified runtime checkpoint is no longer current"
    );
    Ok(checkpoint)
}

pub async fn enqueue_path_probe(
    connection: &mut PgConnection,
    server_id: i64,
    module: &str,
    probe_id: Uuid,
    reserved_request_id: Option<Uuid>,
) -> anyhow::Result<RuntimePathProbeRequest> {
    anyhow::ensure!(!probe_id.is_nil(), "invalid path verification identifier");
    anyhow::ensure!(
        reserved_request_id.is_none_or(|id| !id.is_nil()),
        "invalid reserved verification request identifier"
    );
    let capabilities = lock_server(connection, server_id).await?;
    anyhow::ensure!(
        supports(&capabilities, RUNTIME_PATH_PROBE_CAPABILITY),
        "device does not support signed runtime path verification"
    );
    let expected = checked_target_checkpoint(connection, server_id, module).await?;
    let raw: String = sqlx::query_scalar(
        "SELECT bundle FROM deployments WHERE server_id=$1 AND module=$2 AND rev=$3",
    )
    .bind(server_id)
    .bind(module)
    .bind(expected.binding.revision as i64)
    .fetch_one(&mut *connection)
    .await?;
    let bundle: Bundle = serde_json::from_str(&raw)?;
    let plan = bundle
        .files
        .get("runtime-probes.json")
        .ok_or_else(|| anyhow::anyhow!("applied deployment has no path verification plan"))?;
    anyhow::ensure!(
        plan.len() <= 64 * 1024,
        "path verification plan exceeds its budget"
    );
    let plan: serde_json::Value = serde_json::from_str(plan)?;
    let bindings = plan["bindings"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid path verification bindings"))?;
    let id = probe_id.to_string();
    anyhow::ensure!(
        plan["schema"] == 1
            && plan["runtime_version"] == "1.14.2"
            && bindings.len() <= 256
            && bindings
                .iter()
                .filter(|binding| binding["id"].as_str() == Some(&id))
                .count()
                == 1,
        "verification identifier is not uniquely bound by the published snapshot"
    );
    let now = now_timestamp();
    if let Some(request_id) = reserved_request_id
        && let Some((saved_server, saved_module, payload)) =
            sqlx::query_as::<_, (i64, String, serde_json::Value)>(
                "SELECT server_id,module,request_json FROM runtime_control_requests WHERE request_id=$1 AND kind='probe'",
            )
            .bind(request_id)
            .fetch_optional(&mut *connection)
            .await?
    {
        let saved: RuntimePathProbeRequest = serde_json::from_value(payload)?;
        anyhow::ensure!(
            saved_server == server_id && saved_module == module && saved.expected == expected
                && saved.probe_id == probe_id && saved.request_id == request_id && saved.valid(),
            "reserved verification request belongs to a different runtime activation"
        );
        return Ok(saved);
    }
    if let Some(existing) = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT request_json FROM runtime_control_requests WHERE server_id=$1 AND module=$2 AND kind='probe' AND state='pending' AND expires_at>$3")
        .bind(server_id).bind(module).bind(now).fetch_optional(&mut *connection).await? {
        let existing: RuntimePathProbeRequest = serde_json::from_value(existing)?;
        // Strict callers associate an opaque request UUID with their own guarded
        // state in this transaction. A different queued request has unknown ownership
        // and must never be adopted merely because its runtime/probe identifiers match.
        anyhow::ensure!(reserved_request_id.is_none_or(|id| id == existing.request_id),
            "another verification request is pending and cannot be reassociated");
        anyhow::ensure!(existing.expected != expected || existing.probe_id == probe_id,
            "another path verification is pending for this runtime activation");
    }
    let request = RuntimePathProbeRequest {
        request_id: reserved_request_id.unwrap_or_else(Uuid::new_v4),
        expected,
        probe_id,
        expires_at: now + 60,
    };
    let payload = enqueue(
        connection,
        server_id,
        PendingRequest {
            module,
            kind: "probe",
            digest: request.digest()?,
            payload: serde_json::to_value(&request)?,
            request_id: request.request_id,
            now,
            expires_at: request.expires_at,
        },
    )
    .await?;
    let request: RuntimePathProbeRequest = serde_json::from_value(payload)?;
    anyhow::ensure!(
        request.probe_id == probe_id
            && reserved_request_id.is_none_or(|id| id == request.request_id),
        "path verification replay identifier mismatch"
    );
    Ok(request)
}

pub async fn notify_path_probe(
    state: &AppState,
    server_id: i64,
    request: &RuntimePathProbeRequest,
) -> anyhow::Result<()> {
    agent_api::notify(
        state,
        server_id,
        Envelope::new("runtime.path_probe.request", request)?,
    )
    .await;
    Ok(())
}

pub async fn request_path_probe(
    state: &AppState,
    server_id: i64,
    module: &str,
    probe_id: Uuid,
) -> anyhow::Result<RuntimePathProbeRequest> {
    let mut tx = state.pool.begin().await?;
    let request = enqueue_path_probe(&mut tx, server_id, module, probe_id, None).await?;
    tx.commit().await?;
    notify_path_probe(state, server_id, &request).await?;
    Ok(request)
}

pub async fn record_path_probe_result(
    state: &AppState,
    server_id: i64,
    result: RuntimePathProbeResult,
) -> anyhow::Result<RuntimeControlAck> {
    anyhow::ensure!(result.valid(), "invalid runtime path verification receipt");
    let mut tx = state.pool.begin().await?;
    let capabilities = lock_server(&mut tx, server_id).await?;
    let payload = serde_json::to_value(&result)?;
    let saved = request_for_result(
        &mut tx,
        server_id,
        result.request_id,
        &result.request_digest,
        "probe",
        &payload,
    )
    .await?;
    let request: RuntimePathProbeRequest = serde_json::from_value(saved.payload.clone())?;
    anyhow::ensure!(
        request.valid() && request.digest()? == result.request_digest,
        "invalid stored path verification request"
    );
    if !saved.duplicate {
        let now = now_timestamp();
        let matches = result.observed.as_ref() == Some(&request.expected)
            && result.probe_id == request.probe_id;
        let outcome = if let Some(outcome) =
            preliminary_outcome(&saved, result.success, matches, now)
        {
            outcome
        } else if !supports(&capabilities, RUNTIME_PATH_PROBE_CAPABILITY)
            || !target_is_current(&mut tx, server_id, &request.expected.binding).await?
            || !confirmed_is_current(&mut tx, server_id, &request.expected.binding).await?
        {
            "superseded"
        } else {
            let current: Option<serde_json::Value> = sqlx::query_scalar(
                "SELECT checkpoint_json FROM runtime_module_checkpoints WHERE server_id=$1 AND module=$2")
                .bind(server_id).bind(&request.expected.binding.module)
                .fetch_optional(&mut *tx).await?;
            if current == Some(serde_json::to_value(&request.expected)?) {
                "verified"
            } else {
                "mismatch"
            }
        };
        save_receipt(&mut tx, result.request_id, &payload, outcome, now).await?;
    }
    tx.commit().await?;
    Ok(RuntimeControlAck {
        request_id: result.request_id,
        request_digest: result.request_digest,
    })
}

pub async fn path_probe_fact(
    state: &AppState,
    server_id: i64,
    request_id: Uuid,
) -> anyhow::Result<Option<(String, RuntimePathProbeResult)>> {
    let row = sqlx::query("SELECT r.outcome,r.result_json FROM runtime_control_receipts r JOIN runtime_control_requests q ON q.request_id=r.request_id WHERE q.request_id=$1 AND q.server_id=$2 AND q.kind='probe'")
        .bind(request_id).bind(server_id).fetch_optional(&state.pool).await?;
    row.map(|row| {
        Ok((
            row.get("outcome"),
            serde_json::from_value(row.get("result_json"))?,
        ))
    })
    .transpose()
}
