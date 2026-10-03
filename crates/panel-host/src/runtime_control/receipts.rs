use super::{lock_server, target_is_current};
use crate::AppState;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sinan_protocol::{
    RuntimeCheckpoint, RuntimeCheckpointRequest, RuntimeCheckpointResult, RuntimeControlAck,
    RuntimeRecoveryBarrierRequest, RuntimeRecoveryBarrierResult, now_timestamp,
};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

pub(super) struct StoredRequest {
    pub(super) payload: Value,
    pub(super) expires_at: i64,
    pub(super) state: String,
    pub(super) duplicate: bool,
}

pub(super) async fn request_for_result(
    connection: &mut PgConnection,
    server_id: i64,
    request_id: Uuid,
    digest: &str,
    kind: &str,
    payload: &Value,
) -> anyhow::Result<StoredRequest> {
    let row = sqlx::query("SELECT request_digest,request_json,expires_at,state FROM runtime_control_requests WHERE request_id=$1 AND server_id=$2 AND kind=$3 FOR UPDATE")
        .bind(request_id).bind(server_id).bind(kind).fetch_optional(&mut *connection).await?
        .ok_or_else(|| anyhow::anyhow!("unknown runtime control request"))?;
    anyhow::ensure!(
        row.get::<String, _>("request_digest") == digest,
        "runtime request digest mismatch"
    );
    let duplicate = if let Some(existing) = sqlx::query_scalar::<_, Value>(
        "SELECT result_json FROM runtime_control_receipts WHERE request_id=$1",
    )
    .bind(request_id)
    .fetch_optional(&mut *connection)
    .await?
    {
        anyhow::ensure!(existing == *payload, "conflicting runtime control receipt");
        true
    } else {
        false
    };
    Ok(StoredRequest {
        payload: row.get("request_json"),
        expires_at: row.get("expires_at"),
        state: row.get("state"),
        duplicate,
    })
}

pub(super) async fn save_receipt(
    connection: &mut PgConnection,
    request_id: Uuid,
    payload: &Value,
    outcome: &str,
    now: i64,
) -> anyhow::Result<()> {
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(payload)?));
    sqlx::query("INSERT INTO runtime_control_receipts(request_id,result_json,result_sha256,received_at,outcome) VALUES($1,$2,$3,$4,$5)")
        .bind(request_id).bind(payload).bind(digest).bind(now).bind(outcome).execute(&mut *connection).await?;
    sqlx::query("UPDATE runtime_control_requests SET state='received' WHERE request_id=$1")
        .bind(request_id)
        .execute(connection)
        .await?;
    Ok(())
}

pub(super) fn preliminary_outcome(
    request: &StoredRequest,
    success: bool,
    matches: bool,
    now: i64,
) -> Option<&'static str> {
    if request.expires_at <= now {
        Some("late")
    } else if request.state != "pending" {
        Some("superseded")
    } else if !success {
        Some("failed")
    } else if !matches {
        Some("mismatch")
    } else {
        None
    }
}

/// ACK is returned only after the exact immutable result has committed.
pub async fn record_checkpoint_result(
    state: &AppState,
    server_id: i64,
    result: RuntimeCheckpointResult,
) -> anyhow::Result<RuntimeControlAck> {
    anyhow::ensure!(result.valid(), "invalid runtime checkpoint result");
    let payload = serde_json::to_value(&result)?;
    let mut tx = state.pool.begin().await?;
    lock_server(&mut tx, server_id).await?;
    let stored = request_for_result(
        &mut tx,
        server_id,
        result.request_id,
        &result.request_digest,
        "checkpoint",
        &payload,
    )
    .await?;
    let request: RuntimeCheckpointRequest = serde_json::from_value(stored.payload.clone())?;
    anyhow::ensure!(
        request.valid() && request.digest()? == result.request_digest,
        "invalid stored checkpoint request"
    );
    if !stored.duplicate {
        let now = now_timestamp();
        let matches = result
            .observed
            .as_ref()
            .is_some_and(|observed| observed.binding == request.expected && observed.healthy);
        let current = target_is_current(&mut tx, server_id, &request.expected).await?;
        let outcome = preliminary_outcome(&stored, result.success, matches, now)
            .unwrap_or(if current { "verified" } else { "superseded" });
        save_receipt(&mut tx, result.request_id, &payload, outcome, now).await?;
        if outcome == "verified" {
            let observed = result
                .observed
                .as_ref()
                .expect("validated successful checkpoint");
            sqlx::query("INSERT INTO runtime_module_checkpoints(server_id,module,checkpoint_json,checkpoint_request_id,verified_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(server_id,module) DO UPDATE SET checkpoint_json=EXCLUDED.checkpoint_json,checkpoint_request_id=EXCLUDED.checkpoint_request_id,verified_at=EXCLUDED.verified_at")
                .bind(server_id).bind(&request.expected.module).bind(serde_json::to_value(observed)?)
                .bind(result.request_id).bind(now).execute(&mut *tx).await?;
            sqlx::query("UPDATE server_module_status SET applied_rev=GREATEST(applied_rev,$3),last_result_rev=GREATEST(last_result_rev,$3),healthy=true,last_error=NULL,updated_at=$4 WHERE server_id=$1 AND module=$2 AND target_rev=$3")
                .bind(server_id).bind(&request.expected.module).bind(request.expected.revision as i64).bind(now).execute(&mut *tx).await?;
        } else if current && matches!(outcome, "failed" | "mismatch") {
            // A failed current observation invalidates the previous observation.
            sqlx::query("UPDATE server_module_status SET healthy=false,last_error=$3,updated_at=$4 WHERE server_id=$1 AND module=$2")
                .bind(server_id).bind(&request.expected.module)
                .bind(result.error.as_deref().unwrap_or("runtime checkpoint did not match the expected deployment"))
                .bind(now).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(RuntimeControlAck {
        request_id: result.request_id,
        request_digest: result.request_digest,
    })
}

pub async fn record_barrier_result(
    state: &AppState,
    server_id: i64,
    result: RuntimeRecoveryBarrierResult,
) -> anyhow::Result<RuntimeControlAck> {
    anyhow::ensure!(result.valid(), "invalid runtime recovery barrier result");
    let payload = serde_json::to_value(&result)?;
    let mut tx = state.pool.begin().await?;
    let capabilities = lock_server(&mut tx, server_id).await?;
    let stored = request_for_result(
        &mut tx,
        server_id,
        result.request_id,
        &result.request_digest,
        "barrier",
        &payload,
    )
    .await?;
    let request: RuntimeRecoveryBarrierRequest = serde_json::from_value(stored.payload.clone())?;
    anyhow::ensure!(
        request.valid() && request.digest()? == result.request_digest,
        "invalid stored barrier request"
    );
    if !stored.duplicate {
        let now = now_timestamp();
        let matches = result.observed.as_ref() == Some(&request.expected)
            && result.pending_intents_clear
            && result.minimum_revision.is_some_and(|floor| {
                floor >= request.minimum_revision && floor <= request.expected.binding.revision
            });
        let stored_checkpoint: Option<Value> = sqlx::query_scalar("SELECT checkpoint_json FROM runtime_module_checkpoints WHERE server_id=$1 AND module=$2 FOR UPDATE")
            .bind(server_id).bind(&request.expected.binding.module).fetch_optional(&mut *tx).await?;
        let current_checkpoint = stored_checkpoint
            .map(serde_json::from_value::<RuntimeCheckpoint>)
            .transpose()?;
        let current =
            super::supports(
                &capabilities,
                sinan_protocol::RUNTIME_RECOVERY_BARRIER_CAPABILITY,
            ) && super::confirmed_is_current(&mut tx, server_id, &request.expected.binding).await?
                && current_checkpoint.as_ref() == Some(&request.expected);
        let outcome = preliminary_outcome(&stored, result.success, matches, now)
            .unwrap_or(if current { "verified" } else { "superseded" });
        save_receipt(&mut tx, result.request_id, &payload, outcome, now).await?;
        if outcome == "verified" {
            sqlx::query("UPDATE runtime_module_checkpoints SET minimum_revision=GREATEST(minimum_revision,$3),barrier_request_id=$4 WHERE server_id=$1 AND module=$2")
                .bind(server_id).bind(&request.expected.binding.module)
                .bind(result.minimum_revision.expect("validated successful barrier") as i64)
                .bind(result.request_id).execute(&mut *tx).await?;
        } else if current && matches!(outcome, "failed" | "mismatch") {
            sqlx::query("UPDATE server_module_status SET healthy=false,last_error=$3,updated_at=$4 WHERE server_id=$1 AND module=$2")
                .bind(server_id).bind(&request.expected.binding.module)
                .bind(result.error.as_deref().unwrap_or("runtime recovery barrier did not match the expected checkpoint"))
                .bind(now).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(RuntimeControlAck {
        request_id: result.request_id,
        request_digest: result.request_digest,
    })
}
