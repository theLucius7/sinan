use super::*;
use sinan_protocol::{
    RuntimeCheckpoint, RuntimeCheckpointResult, RuntimeServiceState, RuntimeSnapshot,
};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn interrupted_mutation_is_reconciled_only_with_its_new_verified_read_and_keeps_original_result(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (server, original, binding) = fixture(
        &pool,
        true,
        false,
        Some(RuntimeOperationError::Interrupted),
        false,
    )
    .await?;
    let mut tx = pool.begin().await?;
    let read = request_automation_deployment_checkpoint_tx(&mut tx, original).await?;
    assert_eq!(read.expected, binding);
    assert!(matches!(
        reconcile_automation_deployment_tx(
            &mut tx,
            original,
            read.request_id,
            "TEST_ONLY checked exact instance"
        )
        .await,
        Err(ApiError::Conflict(_))
    ));
    tx.commit().await?;
    let observed = RuntimeCheckpoint {
        binding,
        activation_id: Uuid::new_v4(),
        instance_id: "TEST_ONLY-verified-instance".into(),
        healthy: true,
    };
    let result = RuntimeCheckpointResult {
        request_id: read.request_id,
        request_digest: read.digest()?,
        observed: Some(observed.clone()),
        success: true,
        error: None,
    };
    let now = now_timestamp();
    sqlx::query("INSERT INTO runtime_control_receipts(request_id,result_json,result_sha256,received_at,outcome) VALUES($1,$2,$3,$4,'verified')").bind(read.request_id).bind(serde_json::to_value(result)?).bind("d".repeat(64)).bind(now).execute(&pool).await?;
    sqlx::query("UPDATE runtime_control_requests SET state='received' WHERE request_id=$1")
        .bind(read.request_id)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO runtime_module_checkpoints(server_id,module,checkpoint_json,checkpoint_request_id,verified_at) VALUES($1,'singbox',$2,$3,$4)").bind(server).bind(serde_json::to_value(observed)?).bind(read.request_id).bind(now).execute(&pool).await?;
    sqlx::query("UPDATE server_module_status SET applied_rev=1,healthy=true,last_error=NULL WHERE server_id=$1 AND module='singbox'").bind(server).execute(&pool).await?;
    let mut tx = pool.begin().await?;
    assert!(matches!(
        reconcile_automation_deployment_tx(
            &mut tx,
            original,
            Uuid::new_v4(),
            "TEST_ONLY unrelated read must fail"
        )
        .await,
        Err(ApiError::Conflict(_))
    ));
    let reconciliation = reconcile_automation_deployment_tx(
        &mut tx,
        original,
        read.request_id,
        "TEST_ONLY exact checkpoint checked; stop all later steps",
    )
    .await?;
    assert_eq!(reconciliation["original_result"]["error"], "interrupted");
    assert_eq!(reconciliation["original_mutation_replayed"], false);
    let receipt = automation_deployment_receipt(&mut tx, original).await?;
    assert_eq!(receipt["state"], "failed");
    assert_eq!(receipt["original_state"], "uncertain");
    assert_eq!(receipt["result"]["error"], "interrupted");
    assert!(receipt["reconciled_at"].as_i64().is_some());
    tx.commit().await?;
    Ok(())
}

async fn fixture(
    pool: &PgPool,
    dispatched: bool,
    expired: bool,
    error: Option<RuntimeOperationError>,
    success: bool,
) -> anyhow::Result<(i64, Uuid, RuntimeBinding)> {
    let now = now_timestamp();
    sqlx::query("INSERT INTO admins(id,password_hash) VALUES(1,'TEST_ONLY-not-a-login-password') ON CONFLICT DO NOTHING").execute(pool).await?;
    let server: i64 = sqlx::query_scalar("INSERT INTO servers(name,capabilities,last_seen) VALUES('TEST_ONLY automation deployment',$1,$2) RETURNING id")
        .bind(json!([sinan_protocol::RUNTIME_OPERATIONS_CAPABILITY,sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY,sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY])).bind(now).fetch_one(pool).await?;
    let hash = crate::auth::hash_token("{}");
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,source_json,created_at) VALUES($1,'singbox',1,'{}',$2,'[]',$3)").bind(server).bind(&hash).bind(now).execute(pool).await?;
    sqlx::query("INSERT INTO server_module_status(server_id,module,target_rev,applied_rev,last_result_rev,healthy,last_error,updated_at) VALUES($1,'singbox',1,0,1,false,'TEST_ONLY failed target',$2)").bind(server).bind(now).execute(pool).await?;
    let binding = RuntimeBinding::new(Uuid::new_v4(), MODULE.into(), 1, hash);
    sqlx::query("INSERT INTO runtime_deployment_bindings(deployment_id,server_id,module,rev,bundle_sha256,binding_digest) VALUES($1,$2,'singbox',1,$3,$4)").bind(binding.deployment_id).bind(server).bind(&binding.bundle_sha256).bind(&binding.binding_digest).execute(pool).await?;
    let artifact_sha = "a".repeat(64);
    sqlx::query("INSERT INTO singbox_runtime_manifest_facts(server_id,module,revision,runtime_version,artifact_sha256,artifact) VALUES($1,'singbox',1,'1.14.2',$2,$3)").bind(server).bind(&artifact_sha).bind(json!({"sha256":artifact_sha})).execute(pool).await?;
    let job = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_jobs(id,name,requested_by,spec,targets,status,created_at,updated_at,expires_at,preview_digest) VALUES($1,'TEST_ONLY runtime reapply',1,'{}',$2,'running',$3,$3,$4,'TEST_ONLY')").bind(job).bind(vec![server]).bind(now-10).bind(now+3600).execute(pool).await?;
    let request = RuntimeOperationRequest {
        id: Uuid::new_v4(),
        module: MODULE.into(),
        operation: RuntimeOperation::RetryDeployment,
        expected_revision: Some(1),
        requested_at: now - 10,
        expires_at: if expired { now - 1 } else { now + 300 },
    };
    let result = (error.is_some() || success).then(|| RuntimeOperationResult {
        id: request.id,
        module: MODULE.into(),
        operation: request.operation,
        finished_at: now,
        error,
        snapshot: success.then_some(RuntimeSnapshot {
            observed_at: now,
            applied_revision: Some(1),
            service: RuntimeServiceState::Active,
            healthy: Some(true),
            logs_available: false,
            logs_service_events: false,
            logs_truncated: false,
            logs: vec![],
        }),
    });
    sqlx::query("INSERT INTO runtime_operations(id,server_id,module,requested_at,spec,result,dispatched_at,automation_job_id) VALUES($1,$2,'singbox',$3,$4,$5,$6,$7)").bind(request.id).bind(server).bind(request.requested_at).bind(serde_json::to_value(&request)?).bind(result.map(serde_json::to_value).transpose()?).bind(dispatched.then_some(now-5)).bind(job).execute(pool).await?;
    sqlx::query("INSERT INTO operations_history(job_id,action,details,recorded_at) VALUES($1,'runtime_deployment_bound',$2,$3)").bind(job).bind(json!({"request_id":request.id,"candidate":{"binding":binding,"artifact":{"sha256":artifact_sha}}})).bind(now).execute(pool).await?;
    Ok((server, request.id, binding))
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_never_fabricates_a_device_result_or_cancels_dispatched_execution(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (_, queued, _) = fixture(&pool, false, false, None, false).await?;
    let mut tx = pool.begin().await?;
    cancel_automation_deployment_tx(&mut tx, queued).await?;
    let receipt = automation_deployment_receipt(&mut tx, queued).await?;
    assert_eq!(receipt["state"], "cancelled");
    assert!(receipt["result"].is_null());
    tx.commit().await?;
    let (_, dispatched, _) = fixture(&pool, true, false, None, false).await?;
    let mut tx = pool.begin().await?;
    cancel_automation_deployment_tx(&mut tx, dispatched).await?;
    let receipt = automation_deployment_receipt(&mut tx, dispatched).await?;
    assert_eq!(receipt["state"], "running");
    assert_eq!(receipt["local_cancelled_before_dispatch"], false);
    tx.commit().await?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn expiry_and_interruption_keep_unknown_result_distinct_from_definitive_failure(
    pool: PgPool,
) -> anyhow::Result<()> {
    for (dispatched, expired, error, expected) in [
        (false, true, None, "cancelled"),
        (true, true, None, "uncertain"),
        (
            true,
            false,
            Some(RuntimeOperationError::Interrupted),
            "uncertain",
        ),
        (
            true,
            false,
            Some(RuntimeOperationError::OperationFailed),
            "failed",
        ),
    ] {
        let (_, request, _) = fixture(&pool, dispatched, expired, error, false).await?;
        let mut tx = pool.begin().await?;
        let receipt = automation_deployment_receipt(&mut tx, request).await?;
        assert_eq!(receipt["state"], expected);
        assert_eq!(receipt["checkpoint_confirmed"], false);
        tx.commit().await?;
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn success_requires_a_fresh_exact_checkpoint_and_current_fixed_artifact(
    pool: PgPool,
) -> anyhow::Result<()> {
    let (server, request, binding) = fixture(&pool, true, false, None, true).await?;
    let mut tx = pool.begin().await?;
    let receipt = automation_deployment_receipt(&mut tx, request).await?;
    assert_eq!(receipt["state"], "running");
    assert_eq!(receipt["checkpoint_confirmed"], false);
    let checkpoint_id: Uuid = receipt["checkpoint_request_id"].as_str().unwrap().parse()?;
    let again = automation_deployment_receipt(&mut tx, request).await?;
    assert_eq!(
        again["checkpoint_request_id"],
        receipt["checkpoint_request_id"]
    );
    tx.commit().await?;
    let checkpoint: RuntimeCheckpointRequest = serde_json::from_value(
        sqlx::query_scalar::<_, Value>(
            "SELECT request_json FROM runtime_control_requests WHERE request_id=$1",
        )
        .bind(checkpoint_id)
        .fetch_one(&pool)
        .await?,
    )?;
    let observed = RuntimeCheckpoint {
        binding,
        activation_id: Uuid::new_v4(),
        instance_id: "TEST_ONLY-instance".into(),
        healthy: true,
    };
    let result = RuntimeCheckpointResult {
        request_id: checkpoint_id,
        request_digest: checkpoint.digest()?,
        observed: Some(observed.clone()),
        success: true,
        error: None,
    };
    let now = now_timestamp();
    sqlx::query("INSERT INTO runtime_control_receipts(request_id,result_json,result_sha256,received_at,outcome) VALUES($1,$2,$3,$4,'verified')").bind(checkpoint_id).bind(serde_json::to_value(&result)?).bind("b".repeat(64)).bind(now).execute(&pool).await?;
    sqlx::query("INSERT INTO runtime_module_checkpoints(server_id,module,checkpoint_json,checkpoint_request_id,verified_at) VALUES($1,'singbox',$2,$3,$4)").bind(server).bind(serde_json::to_value(observed)?).bind(checkpoint_id).bind(now).execute(&pool).await?;
    sqlx::query("UPDATE server_module_status SET applied_rev=1,healthy=true,last_error=NULL WHERE server_id=$1 AND module='singbox'").bind(server).execute(&pool).await?;
    let mut tx = pool.begin().await?;
    assert_eq!(
        automation_deployment_receipt(&mut tx, request).await?["state"],
        "succeeded"
    );
    sqlx::query("UPDATE singbox_runtime_manifest_facts SET artifact_sha256=$2 WHERE server_id=$1")
        .bind(server)
        .bind("c".repeat(64))
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        automation_deployment_receipt(&mut tx, request).await?["state"],
        "uncertain"
    );
    tx.rollback().await?;
    Ok(())
}
