use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use sinan_protocol::{
    Envelope, RETIREMENT_CAPABILITY, RetirementReceipt, RetirementRequest, RetirementResult,
    now_timestamp, retirement_receipt_message,
};
use sqlx::{Postgres, Row, Transaction};
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout};
use uuid::Uuid;

async fn delete_record(tx: &mut Transaction<'_, Postgres>, id: i64) -> Result<(), sqlx::Error> {
    let now = now_timestamp();
    sqlx::query("UPDATE servers SET deleted_at=COALESCE(deleted_at,$2) WHERE id=$1")
        .bind(id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE server_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM enrollment_tokens WHERE server_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE diagnostic_jobs SET status='failed',error='服务器已删除，任务已取消',updated_at=$2 WHERE server_id=$1 AND status IN ('queued','running')")
        .bind(id).bind(now).execute(&mut **tx).await?;
    Ok(())
}

pub async fn remove(state: &AppState, id: i64) -> ApiResult<StatusCode> {
    // Registration, deletion and connection cleanup share this lock order.
    let lifecycle = state.device_lifecycle.lock().await;
    let mut tx = state.pool.begin().await?;
    let server = sqlx::query(
        "SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let connection = state.connections.read().await.get(&id).cloned();
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT request_id FROM server_retirements WHERE server_id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(connection) = connection else {
        delete_record(&mut tx, id).await?;
        sqlx::query("UPDATE server_retirements SET status='offline_unconfirmed',error='设备离线，仅删除面板记录，未确认本机退役' WHERE server_id=$1 AND status<>'confirmed'")
            .bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT);
    };
    let capabilities: serde_json::Value = server.get("capabilities");
    if !capabilities.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|value| value.as_str() == Some(RETIREMENT_CAPABILITY))
    }) {
        return Err(ApiError::Conflict(
            "在线 Agent 不支持退役，请先升级后再删除".into(),
        ));
    }
    let request_id = existing.unwrap_or_else(Uuid::new_v4);
    sqlx::query("INSERT INTO server_retirements(server_id,request_id,status,requested_at) VALUES($1,$2,'pending',$3) ON CONFLICT(server_id) DO UPDATE SET status='pending',error=NULL")
        .bind(id).bind(request_id).bind(now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    drop(lifecycle);
    let envelope = Envelope::new("retirement.request", RetirementRequest { request_id })
        .map_err(anyhow::Error::from)?;
    if !matches!(
        timeout(Duration::from_secs(1), connection.sender.send(envelope)).await,
        Ok(Ok(()))
    ) {
        return Err(ApiError::Conflict(
            "退役请求已保存，设备连接暂不可用；请稍后重试".into(),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let row = sqlx::query(
            "SELECT status,error FROM server_retirements WHERE server_id=$1 AND request_id=$2",
        )
        .bind(id)
        .bind(request_id)
        .fetch_one(&state.pool)
        .await?;
        let status: String = row.get("status");
        if status == "confirmed" {
            return Ok(StatusCode::NO_CONTENT);
        }
        if status == "failed" {
            let error: Option<String> = row.get("error");
            return Err(ApiError::Conflict(format!(
                "设备退役未完成：{}",
                error.as_deref().unwrap_or("请检查设备日志后重试")
            )));
        }
        if Instant::now() >= deadline {
            return Err(ApiError::Conflict(
                "退役仍在进行，尚未收到清理确认；请稍后重试，面板记录已保留".into(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

pub async fn receipt(
    State(state): State<AppState>,
    Json(receipt): Json<RetirementReceipt>,
) -> ApiResult<StatusCode> {
    accept_receipt(&state, receipt).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn accept_receipt(state: &AppState, receipt: RetirementReceipt) -> ApiResult<()> {
    let _lifecycle = state.device_lifecycle.lock().await;
    let mut tx = state.pool.begin().await?;
    let public_key: Option<String> =
        sqlx::query_scalar("SELECT device_public_key FROM servers WHERE id=$1 FOR UPDATE")
            .bind(receipt.server_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let request_id: Option<Uuid> =
        sqlx::query_scalar("SELECT request_id FROM server_retirements WHERE server_id=$1")
            .bind(receipt.server_id)
            .fetch_optional(&mut *tx)
            .await?;
    if request_id != Some(receipt.request_id) {
        return Err(ApiError::Unauthorized);
    }
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_key.ok_or(ApiError::Unauthorized)?)
        .map_err(|_| ApiError::Unauthorized)?
        .try_into()
        .map_err(|_| ApiError::Unauthorized)?;
    if receipt.signature.len() > 128 {
        return Err(ApiError::Unauthorized);
    }
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(&receipt.signature)
            .map_err(|_| ApiError::Unauthorized)?,
    )
    .map_err(|_| ApiError::Unauthorized)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| ApiError::Unauthorized)?
        .verify_strict(
            &retirement_receipt_message(receipt.server_id, receipt.request_id),
            &signature,
        )
        .map_err(|_| ApiError::Unauthorized)?;
    delete_record(&mut tx, receipt.server_id).await?;
    sqlx::query("UPDATE fleet_terminal_sessions SET status='closed',close_requested=TRUE WHERE server_id=$1 AND status IN ('queued','running')").bind(receipt.server_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE server_retirements SET status='confirmed',error=NULL,completed_at=COALESCE(completed_at,$2) WHERE server_id=$1")
        .bind(receipt.server_id).bind(now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    state.connections.write().await.remove(&receipt.server_id);
    Ok(())
}

pub async fn record_result(
    state: &AppState,
    server_id: i64,
    result: RetirementResult,
) -> anyhow::Result<()> {
    if result.success {
        let receipt = result
            .receipt
            .ok_or_else(|| anyhow::anyhow!("successful retirement requires a receipt"))?;
        anyhow::ensure!(
            receipt.server_id == server_id && receipt.request_id == result.request_id,
            "retirement result identity mismatch"
        );
        accept_receipt(state, receipt).await?;
    } else {
        anyhow::ensure!(
            result.receipt.is_none(),
            "failed retirement must not contain a receipt"
        );
        let error: String = result
            .error
            .unwrap_or_else(|| "设备未完成停机与清理".into())
            .chars()
            .take(1024)
            .collect();
        let changed = sqlx::query("UPDATE server_retirements SET status='failed',error=$3 WHERE server_id=$1 AND request_id=$2 AND status IN ('pending','failed')")
            .bind(server_id).bind(result.request_id).bind(error).execute(&state.pool).await?;
        anyhow::ensure!(
            changed.rows_affected() == 1,
            "unknown or completed retirement request"
        );
    }
    Ok(())
}
