use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use serde_json::{Value, json};
use sinan_protocol::{
    Artifact, RuntimeBinding, RuntimeCheckpointRequest, RuntimeOperation, RuntimeOperationError,
    RuntimeOperationRequest, RuntimeOperationResult, now_timestamp,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

const VERSION: &str = "1.14.2";
const MODULE: &str = "singbox";

fn conflict(message: &str) -> ApiError {
    ApiError::Conflict(message.into())
}

async fn fixed_binding(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    revision: i64,
    hash: &str,
) -> ApiResult<RuntimeBinding> {
    let proposed = RuntimeBinding::new(Uuid::new_v4(), MODULE.into(), revision as u64, hash.into());
    if !proposed.valid() {
        return Err(conflict("已发布部署身份或摘要无效"));
    }
    sqlx::query("INSERT INTO runtime_deployment_bindings(deployment_id,server_id,module,rev,bundle_sha256,binding_digest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(server_id,module,rev) DO NOTHING")
        .bind(proposed.deployment_id).bind(server).bind(MODULE).bind(revision).bind(hash).bind(&proposed.binding_digest).execute(&mut **tx).await?;
    let row = sqlx::query("SELECT deployment_id,bundle_sha256,binding_digest FROM runtime_deployment_bindings WHERE server_id=$1 AND module=$2 AND rev=$3")
        .bind(server).bind(MODULE).bind(revision).fetch_one(&mut **tx).await?;
    let binding = RuntimeBinding {
        deployment_id: row.get("deployment_id"),
        module: MODULE.into(),
        revision: revision as u64,
        bundle_sha256: row.get("bundle_sha256"),
        binding_digest: row.get("binding_digest"),
    };
    if !binding.valid() || binding.bundle_sha256 != hash {
        return Err(conflict("已发布部署的固定身份发生变化"));
    }
    Ok(binding)
}

fn artifact_identity(state: &AppState, artifact: &Artifact) -> ApiResult<Value> {
    let proof = artifact
        .proof
        .as_ref()
        .ok_or_else(|| conflict("运行时缺少独立签名证明"))?;
    let keys = state
        .release_keys
        .as_deref()
        .ok_or_else(|| conflict("面板缺少可信发布公钥"))?;
    let verified = sinan_protocol::release::verify_release(proof, keys)
        .map_err(|_| conflict("运行时签名证明校验失败"))?;
    let arch = artifact
        .url
        .rsplit('/')
        .next()
        .ok_or_else(|| conflict("签名制品平台无效"))?;
    let entry = verified
        .artifact("sing-box", VERSION, arch)
        .map_err(|_| conflict("签名运行时版本或平台不匹配"))?;
    if entry.sha256() != artifact.sha256 {
        return Err(conflict("运行时制品摘要与签名发布不匹配"));
    }
    Ok(
        json!({"sha256":artifact.sha256,"arch":arch,"bytes":entry.metadata().archive_size.to_string(),"version":VERSION,"signature_verified":true,"payload_verified":true,"source_repo":verified.metadata().source_repo,"release_tag":verified.metadata().tag}),
    )
}

pub(crate) async fn automation_candidate(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
) -> ApiResult<Value> {
    super::super::super::business::lock_server(tx, server).await?;
    super::super::super::settings::require_enabled(tx, server).await?;
    let row = sqlx::query("SELECT s.static_info,s.capabilities,s.last_seen,s.dirty_at,m.target_rev,m.last_result_rev,m.last_error,m.healthy,m.updated_at,d.bundle,d.bundle_sha256,(SELECT MAX(rev) FROM deployments WHERE server_id=$1 AND module='singbox') AS latest_rev FROM servers s JOIN server_module_status m ON m.server_id=s.id AND m.module='singbox' JOIN deployments d ON d.server_id=s.id AND d.module=m.module AND d.rev=m.target_rev WHERE s.id=$1 FOR UPDATE OF m")
        .bind(server).fetch_optional(&mut **tx).await?.ok_or_else(|| conflict("尚无已发布且失败的 sing-box 部署"))?;
    let now = now_timestamp();
    let caps: Value = row.get("capabilities");
    let required = [
        sinan_protocol::RUNTIME_OPERATIONS_CAPABILITY,
        sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY,
        sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY,
    ];
    if !caps.as_array().is_some_and(|values| {
        required
            .iter()
            .all(|required| values.iter().any(|value| value.as_str() == Some(*required)))
    }) || !row
        .get::<Option<i64>, _>("last_seen")
        .is_some_and(|seen| (0..=60).contains(&now.saturating_sub(seen)))
    {
        return Err(conflict(
            "此步骤需要在线 Agent、运行时运维、实际配置核对及制品验签能力",
        ));
    }
    let revision: i64 = row.get("target_rev");
    if revision <= 0
        || row.get::<Option<i64>, _>("dirty_at").is_some()
        || row.get::<Option<i64>, _>("latest_rev") != Some(revision)
        || row.get::<i64, _>("last_result_rev") != revision
        || row.get::<bool, _>("healthy")
        || row
            .get::<Option<String>, _>("last_error")
            .is_none_or(|error| error.is_empty())
    {
        return Err(conflict(
            "仅可重试稳定的、设备已明确回报失败的当前目标；新版本发布需使用代理业务发布流程",
        ));
    }
    let hash: String = row.get("bundle_sha256");
    if crate::auth::hash_token(&row.get::<String, _>("bundle")) != hash {
        return Err(conflict("已发布配置包完整性校验失败"));
    }
    let artifact =
        super::super::super::agent::runtime_artifact(state, &row.get::<Value, _>("static_info"))
            .await?;
    let identity = artifact_identity(state, &artifact)?;
    let pinned: Vec<Value> = sqlx::query_scalar("SELECT DISTINCT r.artifact FROM singbox_path_deployment_dependencies d JOIN singbox_chain_runtime_requirements r ON r.chain_id=d.chain_id AND r.generation=d.generation AND r.server_id=d.server_id WHERE d.server_id=$1 AND d.module='singbox' AND d.revision=$2")
        .bind(server).bind(revision).fetch_all(&mut **tx).await?;
    if pinned
        .iter()
        .any(|pin| pin["sha256"].as_str() != Some(artifact.sha256.as_str()))
    {
        return Err(conflict(
            "路径依赖与当前签名制品不一致，不能变更已有部署的运行时身份",
        ));
    }
    sqlx::query("INSERT INTO singbox_runtime_manifest_facts(server_id,module,revision,runtime_version,artifact_sha256,artifact) VALUES($1,'singbox',$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(server).bind(revision).bind(VERSION).bind(&artifact.sha256).bind(serde_json::to_value(&artifact).map_err(anyhow::Error::from)?).execute(&mut **tx).await?;
    let same: bool = sqlx::query_scalar("SELECT runtime_version=$3 AND artifact_sha256=$4 FROM singbox_runtime_manifest_facts WHERE server_id=$1 AND module='singbox' AND revision=$2")
        .bind(server).bind(revision).bind(VERSION).bind(&artifact.sha256).fetch_one(&mut **tx).await?;
    if !same {
        return Err(conflict("此部署已固定另一运行时制品，不能覆盖原始事实"));
    }
    let binding = fixed_binding(tx, server, revision, &hash).await?;
    Ok(
        json!({"kind":"singbox_retry_deployment","module":MODULE,"runtime_version":VERSION,"binding":binding,"artifact":identity,"expected_failure_revision":revision,"target_status_updated_at":row.get::<i64, _>("updated_at"),"changes_business_configuration":false,"retry_unknown_result":false}),
    )
}

pub(crate) async fn enqueue_automation_deployment_tx(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    job: Uuid,
    actor: i64,
    candidate: &Value,
    expires: i64,
) -> ApiResult<Uuid> {
    for capability in ["operations:write", "proxy:write"] {
        control_center::require_actor_server(state, actor, server, capability).await?;
    }
    super::super::super::business::lock_server(tx, server).await?;
    let now = now_timestamp();
    let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_server_locks l JOIN operations_jobs j ON j.id=l.job_id WHERE l.server_id=$1 AND l.job_id=$2 AND j.requested_by=$3 AND j.status IN ('queued','running') AND j.cancel_requested_at IS NULL AND j.expires_at>$4 AND $1=ANY(j.targets))")
        .bind(server).bind(job).bind(actor).bind(now).fetch_one(&mut **tx).await?;
    if !owned {
        return Err(conflict("自动化任务未持有此服务器的有效互斥锁"));
    }
    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) OR EXISTS(SELECT 1 FROM fleet_profiles WHERE server_id=$1 AND (lifecycle IN ('draining','retired') OR (lifecycle='maintenance' AND COALESCE(maintenance_from,0)<=$2 AND (maintenance_until IS NULL OR maintenance_until>$2)))) OR EXISTS(SELECT 1 FROM operations_maintenance WHERE $1=ANY(targets) AND block_new_tasks AND starts_at<=$2 AND ends_at>$2) OR EXISTS(SELECT 1 FROM remote_commands WHERE server_id=$1 AND state IN ('queued','claimed','running','cancel_requested')) OR EXISTS(SELECT 1 FROM fleet_operations WHERE server_id=$1 AND reconciled_at IS NULL AND status IN ('queued','dispatched','unknown')) OR EXISTS(SELECT 1 FROM diagnostic_jobs WHERE server_id=$1 AND (status IN ('queued','running','cleaning','cancel_requested') OR (NOT agent_completed AND job ? 'id'))) OR EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL)")
        .bind(server).bind(now).fetch_one(&mut **tx).await?;
    if blocked {
        return Err(conflict("服务器维护、退役或已有未核对操作，不能重试部署"));
    }
    let interrupted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_operations o WHERE o.server_id=$1 AND o.module='singbox' AND o.reconciled_at IS NULL AND o.result->>'error'='interrupted' AND NOT EXISTS(SELECT 1 FROM runtime_control_requests q JOIN runtime_control_receipts r ON r.request_id=q.request_id WHERE q.server_id=o.server_id AND q.module=o.module AND q.kind='checkpoint' AND q.created_at>=(o.result->>'finished_at')::bigint AND r.outcome='verified' AND r.result_json->'observed'->'healthy'='true'::jsonb))")
        .bind(server).fetch_one(&mut **tx).await?;
    if interrupted {
        return Err(conflict(
            "此前运行时操作曾中断且尚无之后的真实配置核对，不能自动重试未知动作",
        ));
    }
    let current = automation_candidate(state, tx, server).await?;
    if &current != candidate {
        return Err(conflict(
            "预览中的失败部署、固定身份或签名制品已变化，请重新预览",
        ));
    }
    let binding: RuntimeBinding =
        serde_json::from_value(candidate["binding"].clone()).map_err(anyhow::Error::from)?;
    let request = RuntimeOperationRequest {
        id: Uuid::new_v4(),
        module: MODULE.into(),
        operation: RuntimeOperation::RetryDeployment,
        expected_revision: Some(binding.revision),
        requested_at: now,
        expires_at: expires.min(now + 600),
    };
    if !request.valid() {
        return Err(ApiError::BadRequest(
            "运行时重试时限无效，最长为 600 秒".into(),
        ));
    }
    sqlx::query("INSERT INTO runtime_operations(id,server_id,module,requested_at,spec,automation_job_id) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(request.id).bind(server).bind(MODULE).bind(now).bind(serde_json::to_value(&request).map_err(anyhow::Error::from)?).bind(job).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO operations_history(job_id,actor,action,details,recorded_at) VALUES($1,$2,'runtime_deployment_bound',$3,$4)")
        .bind(job).bind(actor).bind(json!({"request_id":request.id,"server_id":server,"candidate":candidate,"replay":false})).bind(now).execute(&mut **tx).await?;
    Ok(request.id)
}

pub(crate) async fn cancel_automation_deployment_tx(
    tx: &mut Transaction<'_, Postgres>,
    request: Uuid,
) -> ApiResult<()> {
    sqlx::query("UPDATE runtime_operations SET cancelled_at=COALESCE(cancelled_at,$2) WHERE id=$1 AND automation_job_id IS NOT NULL AND result IS NULL AND dispatched_at IS NULL")
        .bind(request).bind(now_timestamp()).execute(&mut **tx).await?;
    Ok(())
}

pub(crate) async fn automation_dispatch_matches_tx(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    request: Uuid,
) -> ApiResult<bool> {
    if !super::super::super::settings::is_enabled(tx, server).await? {
        return Ok(false);
    }
    let caps: Value =
        sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL")
            .bind(server)
            .fetch_one(&mut **tx)
            .await?;
    let required = [
        sinan_protocol::RUNTIME_OPERATIONS_CAPABILITY,
        sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY,
        sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY,
    ];
    if !caps.as_array().is_some_and(|values| {
        required
            .iter()
            .all(|required| values.iter().any(|value| value.as_str() == Some(*required)))
    }) {
        return Ok(false);
    }
    let candidate: Option<Value> = sqlx::query_scalar("SELECT h.details->'candidate' FROM operations_history h JOIN runtime_operations r ON r.automation_job_id=h.job_id WHERE r.id=$1 AND r.server_id=$2 AND h.action='runtime_deployment_bound' AND h.details->>'request_id'=$1::text ORDER BY h.id LIMIT 1")
        .bind(request).bind(server).fetch_optional(&mut **tx).await?;
    let Some(candidate) = candidate else {
        return Ok(false);
    };
    let binding: RuntimeBinding =
        serde_json::from_value(candidate["binding"].clone()).map_err(anyhow::Error::from)?;
    if !binding.valid()
        || binding.module != MODULE
        || !crate::runtime_control::target_is_current(tx, server, &binding).await?
    {
        return Ok(false);
    }
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_runtime_manifest_facts WHERE server_id=$1 AND module='singbox' AND revision=$2 AND runtime_version='1.14.2' AND artifact_sha256=$3)")
        .bind(server).bind(binding.revision as i64).bind(candidate["artifact"]["sha256"].as_str().unwrap_or("")).fetch_one(&mut **tx).await?)
}

async fn checkpoint_once(
    tx: &mut Transaction<'_, Postgres>,
    job: Uuid,
    request: Uuid,
    server: i64,
    binding: &RuntimeBinding,
    now: i64,
    dispatched_at: i64,
) -> ApiResult<Option<Uuid>> {
    let existing: Option<Value> = sqlx::query_scalar("SELECT details FROM operations_history WHERE job_id=$1 AND action='runtime_deployment_checkpoint' AND details->>'request_id'=$2 ORDER BY id LIMIT 1")
        .bind(job).bind(request.to_string()).fetch_optional(&mut **tx).await?;
    if let Some(existing) = existing {
        return Ok(existing["checkpoint_request_id"]
            .as_str()
            .and_then(|id| id.parse().ok()));
    }
    sqlx::query("UPDATE runtime_control_requests SET state='expired' WHERE server_id=$1 AND module='singbox' AND kind='checkpoint' AND state='pending' AND expires_at<=$2")
        .bind(server).bind(now).execute(&mut **tx).await?;
    let pending = sqlx::query("SELECT request_id,request_json,created_at FROM runtime_control_requests WHERE server_id=$1 AND module='singbox' AND kind='checkpoint' AND state='pending'").bind(server).fetch_optional(&mut **tx).await?;
    let checkpoint = if let Some(pending) = pending {
        let saved: RuntimeCheckpointRequest =
            serde_json::from_value(pending.get("request_json")).map_err(anyhow::Error::from)?;
        if saved.expected != *binding || pending.get::<i64, _>("created_at") < dispatched_at {
            return Ok(None);
        }
        saved
    } else {
        let checkpoint = RuntimeCheckpointRequest {
            request_id: Uuid::new_v4(),
            expected: binding.clone(),
            expires_at: now + 120,
        };
        sqlx::query("INSERT INTO runtime_control_requests(request_id,server_id,module,kind,request_digest,request_json,created_at,expires_at) VALUES($1,$2,'singbox','checkpoint',$3,$4,$5,$6)")
            .bind(checkpoint.request_id).bind(server).bind(checkpoint.digest().map_err(anyhow::Error::from)?).bind(serde_json::to_value(&checkpoint).map_err(anyhow::Error::from)?).bind(now).bind(checkpoint.expires_at).execute(&mut **tx).await?;
        checkpoint
    };
    sqlx::query("INSERT INTO operations_history(job_id,action,details,recorded_at) VALUES($1,'runtime_deployment_checkpoint',$2,$3)")
        .bind(job).bind(json!({"request_id":request,"checkpoint_request_id":checkpoint.request_id,"binding":binding})).bind(now).execute(&mut **tx).await?;
    Ok(Some(checkpoint.request_id))
}

pub(crate) async fn automation_deployment_receipt(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> ApiResult<Value> {
    // Keep the server-before-operation order used by Agent dispatch and completion.
    let server: i64 = sqlx::query_scalar("SELECT server_id FROM runtime_operations WHERE id=$1")
        .bind(request_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    super::super::super::business::lock_server(tx, server).await?;
    let row = sqlx::query("SELECT spec,result,dispatched_at,cancelled_at,automation_job_id,reconciled_at,reconciliation FROM runtime_operations WHERE id=$1 FOR UPDATE").bind(request_id).fetch_one(&mut **tx).await?;
    let job: Uuid = row
        .get::<Option<Uuid>, _>("automation_job_id")
        .ok_or_else(|| conflict("此运行时请求不属于自动化任务"))?;
    let request: RuntimeOperationRequest =
        serde_json::from_value(row.get("spec")).map_err(anyhow::Error::from)?;
    let dispatched: Option<i64> = row.get("dispatched_at");
    let result: Option<RuntimeOperationResult> = row
        .get::<Option<Value>, _>("result")
        .map(serde_json::from_value)
        .transpose()
        .map_err(anyhow::Error::from)?;
    if let Some(reconciled_at) = row.get::<Option<i64>, _>("reconciled_at") {
        return Ok(
            json!({"state":"failed","original_state":"uncertain","result":result,"request_id":request_id,"dispatched_at":dispatched,"finished_at":reconciled_at,"reconciled_at":reconciled_at,"reconciliation":row.get::<Option<Value>, _>("reconciliation"),"running_cancel_supported":false,"retry_unknown_result":false,"original_mutation_replayed":false}),
        );
    }
    let now = now_timestamp();
    if dispatched.is_none() && result.is_none() && request.expires_at <= now {
        cancel_automation_deployment_tx(tx, request_id).await?;
    }
    let cancelled = row.get::<Option<i64>, _>("cancelled_at").is_some()
        || (dispatched.is_none() && result.is_none() && request.expires_at <= now);
    let mut state = if cancelled {
        "cancelled"
    } else if dispatched.is_some() {
        if request.expires_at <= now {
            "uncertain"
        } else {
            "running"
        }
    } else {
        "queued"
    };
    let mut confirmed = false;
    let mut checkpoint_request_id: Option<Uuid> = None;
    if let Some(result) = &result {
        if !result.valid()
            || result.id != request_id
            || result.module != request.module
            || result.operation != request.operation
            || result.finished_at < request.requested_at
            || dispatched.is_none()
            || result.error == Some(RuntimeOperationError::Interrupted)
        {
            state = "uncertain";
        } else if result.error.is_some()
            || !result.snapshot.as_ref().is_some_and(|snapshot| {
                snapshot.healthy == Some(true)
                    && snapshot.applied_revision == request.expected_revision
                    && dispatched.is_some_and(|sent| snapshot.observed_at >= sent)
            })
        {
            state = "failed";
        } else {
            let saved: Option<Value> = sqlx::query_scalar("SELECT details->'candidate' FROM operations_history WHERE job_id=$1 AND action='runtime_deployment_bound' AND details->>'request_id'=$2 ORDER BY id LIMIT 1")
                .bind(job).bind(request_id.to_string()).fetch_optional(&mut **tx).await?;
            if let Some(candidate) = saved {
                let binding: RuntimeBinding = serde_json::from_value(candidate["binding"].clone())
                    .map_err(anyhow::Error::from)?;
                let current =
                    crate::runtime_control::target_is_current(tx, server, &binding).await?;
                let facts: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_runtime_manifest_facts WHERE server_id=$1 AND module='singbox' AND revision=$2 AND runtime_version='1.14.2' AND artifact_sha256=$3)")
                    .bind(server).bind(binding.revision as i64).bind(candidate["artifact"]["sha256"].as_str().unwrap_or("")).fetch_one(&mut **tx).await?;
                let matching_request = binding.valid()
                    && binding.module == request.module
                    && Some(binding.revision) == request.expected_revision;
                if current && facts && matching_request {
                    confirmed = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_module_checkpoints c JOIN runtime_control_receipts r ON r.request_id=c.checkpoint_request_id JOIN server_module_status m ON m.server_id=c.server_id AND m.module=c.module WHERE c.server_id=$1 AND c.module='singbox' AND c.verified_at>=$2 AND c.verified_at>$3-300 AND r.outcome='verified' AND c.checkpoint_json->'healthy'='true'::jsonb AND c.checkpoint_json->'binding'=$4 AND m.target_rev=$5 AND m.applied_rev=$5 AND m.healthy)")
                        .bind(server).bind(dispatched.unwrap_or(i64::MAX)).bind(now).bind(serde_json::to_value(&binding).map_err(anyhow::Error::from)?).bind(binding.revision as i64).fetch_one(&mut **tx).await?;
                    if confirmed {
                        state = "succeeded";
                    } else {
                        checkpoint_request_id = checkpoint_once(
                            tx,
                            job,
                            request_id,
                            server,
                            &binding,
                            now,
                            dispatched.unwrap_or(i64::MAX),
                        )
                        .await?;
                        state = if request.expires_at <= now {
                            "uncertain"
                        } else {
                            "running"
                        };
                    }
                } else {
                    state = "uncertain";
                }
            } else {
                state = "uncertain";
            }
        }
    }
    Ok(
        json!({"state":state,"result":result,"request_id":request_id,"dispatched_at":dispatched,"finished_at":result.as_ref().map(|result|result.finished_at),"expires_at":request.expires_at,"checkpoint_confirmed":confirmed,"checkpoint_request_id":checkpoint_request_id,"running_cancel_supported":false,"local_cancelled_before_dispatch":cancelled,"retry_unknown_result":false}),
    )
}

#[path = "automation/reconciliation.rs"]
mod reconciliation;
pub(crate) use reconciliation::{
    reconcile_automation_deployment_tx, request_automation_deployment_checkpoint_tx,
};

#[cfg(test)]
#[path = "automation/tests.rs"]
mod tests;
