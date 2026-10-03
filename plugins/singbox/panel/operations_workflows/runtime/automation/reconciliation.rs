use super::*;

struct UnknownDeployment {
    server: i64,
    job: Uuid,
    binding: RuntimeBinding,
    artifact_sha256: String,
    cutoff: i64,
    original_result: Option<Value>,
}

async fn unknown_binding(
    tx: &mut Transaction<'_, Postgres>,
    original: Uuid,
) -> ApiResult<UnknownDeployment> {
    let server: i64 = sqlx::query_scalar("SELECT server_id FROM runtime_operations WHERE id=$1")
        .bind(original)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::plugins::singbox::business::lock_server(tx, server).await?;
    let row = sqlx::query("SELECT automation_job_id,spec,result,dispatched_at,reconciled_at FROM runtime_operations WHERE id=$1 FOR UPDATE").bind(original).fetch_one(&mut **tx).await?;
    let job: Uuid = row
        .get::<Option<Uuid>, _>("automation_job_id")
        .ok_or_else(|| conflict("此请求不属于自动化部署"))?;
    if row.get::<Option<i64>, _>("reconciled_at").is_some() {
        return Err(conflict("此未知部署已记录人工核对，请刷新结果"));
    }
    let dispatched: i64 = row
        .get::<Option<i64>, _>("dispatched_at")
        .ok_or_else(|| conflict("未派发部署应直接取消，无需未知结果核对"))?;
    let request: RuntimeOperationRequest =
        serde_json::from_value(row.get("spec")).map_err(anyhow::Error::from)?;
    let raw: Option<Value> = row.get("result");
    let result: Option<RuntimeOperationResult> = raw
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(anyhow::Error::from)?;
    let cutoff = if let Some(result) = result {
        if result.error != Some(RuntimeOperationError::Interrupted) {
            return Err(conflict(
                "此请求已有明确设备结果，请等待实际部署核对，不应人工改写结果",
            ));
        }
        dispatched.max(result.finished_at)
    } else {
        if request.expires_at > now_timestamp() {
            return Err(conflict("原请求尚在允许执行窗口内，先等待实际回执"));
        }
        dispatched.max(request.expires_at)
    };
    let saved: Value = sqlx::query_scalar("SELECT details->'candidate' FROM operations_history WHERE job_id=$1 AND action='runtime_deployment_bound' AND details->>'request_id'=$2 ORDER BY id LIMIT 1")
        .bind(job).bind(original.to_string()).fetch_optional(&mut **tx).await?.ok_or_else(|| conflict("原部署的固定候选事实缺失，不能宣称已核对"))?;
    let binding: RuntimeBinding =
        serde_json::from_value(saved["binding"].clone()).map_err(anyhow::Error::from)?;
    let sha = saved["artifact"]["sha256"]
        .as_str()
        .ok_or_else(|| conflict("原签名制品摘要缺失"))?
        .to_owned();
    if !binding.valid()
        || binding.module != MODULE
        || Some(binding.revision) != request.expected_revision
        || !crate::runtime_control::target_is_current(tx, server, &binding).await?
    {
        return Err(conflict(
            "当前目标已不匹配原固定部署，需要受控恢复，不能用其他版本证明原请求已恢复",
        ));
    }
    let same: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_runtime_manifest_facts WHERE server_id=$1 AND module='singbox' AND revision=$2 AND runtime_version='1.14.2' AND artifact_sha256=$3)").bind(server).bind(binding.revision as i64).bind(&sha).fetch_one(&mut **tx).await?;
    if !same {
        return Err(conflict("原固定签名制品身份已变化，不能核对解锁"));
    }
    Ok(UnknownDeployment {
        server,
        job,
        binding,
        artifact_sha256: sha,
        cutoff,
        original_result: raw,
    })
}

pub(crate) async fn request_automation_deployment_checkpoint_tx(
    tx: &mut Transaction<'_, Postgres>,
    original: Uuid,
) -> ApiResult<RuntimeCheckpointRequest> {
    let unknown = unknown_binding(tx, original).await?;
    let now = now_timestamp();
    if now < unknown.cutoff {
        return Err(conflict("原执行时间尚未进入核对窗口，请等待时钟差异消除"));
    }
    // A new read supersedes older reads, never the original deployment mutation.
    sqlx::query("UPDATE runtime_control_requests SET state='expired' WHERE server_id=$1 AND module='singbox' AND kind='checkpoint' AND state='pending'").bind(unknown.server).execute(&mut **tx).await?;
    let checkpoint = RuntimeCheckpointRequest {
        request_id: Uuid::new_v4(),
        expected: unknown.binding,
        expires_at: now + 120,
    };
    sqlx::query("INSERT INTO runtime_control_requests(request_id,server_id,module,kind,request_digest,request_json,created_at,expires_at) VALUES($1,$2,'singbox','checkpoint',$3,$4,$5,$6)")
        .bind(checkpoint.request_id).bind(unknown.server).bind(checkpoint.digest().map_err(anyhow::Error::from)?).bind(serde_json::to_value(&checkpoint).map_err(anyhow::Error::from)?).bind(now).bind(checkpoint.expires_at).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO operations_history(job_id,action,details,recorded_at) VALUES($1,'runtime_unknown_checkpoint',$2,$3)").bind(unknown.job).bind(json!({"request_id":original,"checkpoint_request_id":checkpoint.request_id,"read_only":true,"original_mutation_replayed":false})).bind(now).execute(&mut **tx).await?;
    sqlx::query("UPDATE server_module_status SET healthy=false,updated_at=$2 WHERE server_id=$1 AND module='singbox'").bind(unknown.server).bind(now).execute(&mut **tx).await?;
    Ok(checkpoint)
}

pub(crate) async fn reconcile_automation_deployment_tx(
    tx: &mut Transaction<'_, Postgres>,
    original: Uuid,
    checkpoint: Uuid,
    evidence: &str,
) -> ApiResult<Value> {
    if evidence.trim().is_empty()
        || evidence.len() > 4096
        || evidence
            .chars()
            .any(|value| value.is_control() && !matches!(value, '\n' | '\t'))
    {
        return Err(ApiError::BadRequest(
            "人工核对说明须为 1–4096 字节的普通文字".into(),
        ));
    }
    let unknown = unknown_binding(tx, original).await?;
    let now = now_timestamp();
    let verified: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_history h JOIN runtime_control_requests q ON q.request_id=$3 JOIN runtime_control_receipts r ON r.request_id=q.request_id JOIN runtime_module_checkpoints c ON c.checkpoint_request_id=r.request_id JOIN server_module_status m ON m.server_id=c.server_id AND m.module=c.module WHERE h.job_id=$1 AND h.action='runtime_unknown_checkpoint' AND h.details->>'request_id'=$2 AND h.details->>'checkpoint_request_id'=$3::text AND q.server_id=$4 AND q.module='singbox' AND q.kind='checkpoint' AND q.created_at>=$5 AND q.request_json->'expected'=$6 AND r.outcome='verified' AND r.received_at>$7-300 AND c.verified_at>$7-300 AND c.checkpoint_json->'binding'=$6 AND c.checkpoint_json->'healthy'='true'::jsonb AND m.healthy AND m.applied_rev=$8 AND m.target_rev=$8)")
        .bind(unknown.job).bind(original.to_string()).bind(checkpoint).bind(unknown.server).bind(unknown.cutoff).bind(serde_json::to_value(&unknown.binding).map_err(anyhow::Error::from)?).bind(now).bind(unknown.binding.revision as i64).fetch_one(&mut **tx).await?;
    if !verified {
        return Err(conflict(
            "尚无本次只读核对的新鲜 verified 回执，或原部署、当前实例和目标不匹配",
        ));
    }
    let reconciliation = json!({"checkpoint_request_id":checkpoint,"binding":unknown.binding,"artifact_sha256":unknown.artifact_sha256,"verified_at":now,"evidence":evidence,"original_state":"uncertain","original_result":unknown.original_result,"original_mutation_replayed":false,"original_result_rewritten":false,"checkpoint_scope":"Agent共同运行时门锁内核对签名实例和配置，且确认没有未完成运行时意图"});
    sqlx::query("UPDATE runtime_operations SET reconciled_at=$2,reconciliation=$3 WHERE id=$1 AND reconciled_at IS NULL").bind(original).bind(now).bind(&reconciliation).execute(&mut **tx).await?;
    Ok(reconciliation)
}
