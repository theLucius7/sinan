use super::super::{event, ids};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::{
    RuntimeOperation, RuntimeOperationRequest, RuntimeOperationResult, now_timestamp,
};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rollout {
    server_ids: Vec<i64>,
    canary_server_id: Option<i64>,
    runtime_version: String,
    batch_size: i32,
}

pub(crate) async fn create_rollout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Rollout>,
) -> ApiResult<Json<Value>> {
    let administrator =
        crate::control_center::require_capability(&state, &headers, "proxy:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    let mut targets = ids(&request.server_ids, false)?;
    if let Some(canary) = request.canary_server_id {
        let position = targets
            .iter()
            .position(|id| *id == canary)
            .ok_or_else(|| ApiError::BadRequest("首台验证服务器必须属于固定目标集合".into()))?;
        targets.remove(position);
        targets.insert(0, canary);
    }
    for server in &targets {
        crate::control_center::require_server(&state, &headers, *server, "proxy:write").await?;
    }
    if request.runtime_version != "1.14.2" || !(1..=20).contains(&request.batch_size) {
        return Err(ApiError::BadRequest(
            "当前仅支持固定可信版本 1.14.2，批次大小 1–20".into(),
        ));
    }
    super::inventory::require_version(&state, &request.runtime_version).await?;
    let mut tx = state.pool.begin().await?;
    super::super::super::entitlements::lock(&mut tx).await?;
    for server in &targets {
        super::super::super::business::lock_server(&mut tx, *server).await?;
        super::super::super::settings::require_enabled(&mut tx, *server).await?;
    }
    let earlier:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM singbox_runtime_rollouts WHERE targets&&$1::bigint[] AND completed_at IS NULL").bind(&targets).fetch_all(&mut *tx).await?;
    for previous in earlier {
        members(&mut tx, previous).await?;
    }
    let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_runtime_rollouts r WHERE r.targets&&$1::bigint[] AND r.completed_at IS NULL)").bind(&targets).fetch_one(&mut *tx).await?;
    if busy {
        return Err(ApiError::Conflict("所选服务器已有未完成发布计划".into()));
    }
    let mut artifacts = serde_json::Map::new();
    for server in &targets {
        let info: Value = sqlx::query_scalar("SELECT static_info FROM servers WHERE id=$1")
            .bind(server)
            .fetch_one(&mut *tx)
            .await?;
        let artifact = super::super::super::agent::runtime_artifact(&state, &info).await?;
        artifacts.insert(
            server.to_string(),
            serde_json::to_value(artifact).map_err(anyhow::Error::from)?,
        );
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO singbox_runtime_rollouts(id,administrator_id,runtime_version,targets,batch_size,created_at,updated_at,artifact_snapshot) VALUES($1,$2,$3,$4,$5,$6,$6,$7)").bind(id).bind(administrator).bind(request.runtime_version).bind(&targets).bind(request.batch_size).bind(now_timestamp()).bind(json!(artifacts)).execute(&mut *tx).await?;
    dispatch(&state, &headers, &mut tx, id).await?;
    event(&mut tx,Some(administrator),None,"runtime_rollout_create",json!({"id":id,"targets":targets,"batch_size":request.batch_size,"canary_size":1,"runtime_version":"1.14.2"})).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"state":"canary_dispatched","targets":targets}),
    ))
}

async fn members(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<Vec<Value>> {
    sqlx::query("UPDATE singbox_runtime_rollout_members r SET inspection_result=o.result FROM runtime_operations o WHERE r.rollout_id=$1 AND o.id=r.inspect_request_id AND o.result IS NOT NULL AND r.inspection_result IS NULL").bind(id).execute(&mut **tx).await?;
    let rows=sqlx::query("SELECT r.server_id,r.baseline_revision,r.artifact_sha256,r.dispatched_at,COALESCE(r.inspection_result,o.result) AS result,m.target_rev,m.applied_rev,m.healthy,s.dirty_at,f.runtime_version,f.artifact_sha256 AS observed_artifact_sha256 FROM singbox_runtime_rollout_members r JOIN servers s ON s.id=r.server_id LEFT JOIN runtime_operations o ON o.id=r.inspect_request_id LEFT JOIN server_module_status m ON m.server_id=r.server_id AND m.module='singbox' LEFT JOIN singbox_runtime_manifest_facts f ON f.server_id=r.server_id AND f.module='singbox' AND f.revision=m.applied_rev WHERE r.rollout_id=$1 ORDER BY r.dispatched_at,r.server_id").bind(id).fetch_all(&mut **tx).await?;
    let mut result = Vec::new();
    for row in rows {
        let receipt: Option<RuntimeOperationResult> = row
            .get::<Option<Value>, _>("result")
            .map(serde_json::from_value)
            .transpose()
            .map_err(anyhow::Error::from)?;
        let checkpoint_confirmed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_module_checkpoints c JOIN runtime_control_receipts f ON f.request_id=c.checkpoint_request_id JOIN runtime_deployment_bindings b ON b.server_id=c.server_id AND b.module=c.module AND b.rev=$2 WHERE c.server_id=$1 AND c.module='singbox' AND c.verified_at>=$3 AND c.verified_at>$4-300 AND f.outcome='verified' AND c.checkpoint_json->'healthy'='true' AND c.checkpoint_json->'binding'->>'binding_digest'=b.binding_digest AND c.checkpoint_json->'binding'->>'bundle_sha256'=b.bundle_sha256 AND c.checkpoint_json->'binding'->>'deployment_id'=b.deployment_id::text)").bind(row.get::<i64,_>("server_id")).bind(row.get::<Option<i64>,_>("applied_rev")).bind(row.get::<i64,_>("dispatched_at")).bind(now_timestamp()).fetch_one(&mut **tx).await?;
        let confirmed = checkpoint_confirmed
            && receipt.as_ref().is_some_and(|r| {
                r.error.is_none()
                    && r.snapshot.as_ref().is_some_and(|s| {
                        s.healthy == Some(true)
                            && s.observed_at >= row.get::<i64, _>("dispatched_at")
                            && s.applied_revision.map(|v| v as i64)
                                == row.get::<Option<i64>, _>("target_rev")
                    })
            })
            && row.get::<Option<bool>, _>("healthy") == Some(true)
            && row.get::<Option<i64>, _>("target_rev") == row.get::<Option<i64>, _>("applied_rev")
            && row.get::<Option<i64>, _>("dirty_at").is_none()
            && row.get::<Option<String>, _>("runtime_version").as_deref() == Some("1.14.2")
            && row
                .get::<Option<String>, _>("observed_artifact_sha256")
                .as_deref()
                == Some(row.get::<String, _>("artifact_sha256").as_str());
        result.push(json!({"server_id":row.get::<i64,_>("server_id"),"dispatched_at":row.get::<i64,_>("dispatched_at"),"confirmed":confirmed,"checkpoint_confirmed":checkpoint_confirmed,"candidate_artifact_sha256":row.get::<String,_>("artifact_sha256"),"state":if confirmed{"device_confirmed"}else if receipt.as_ref().is_some_and(|r|r.error.is_some()){"failed"}else{"awaiting_confirmation"},"target_revision":row.get::<Option<i64>,_>("target_rev"),"applied_revision":row.get::<Option<i64>,_>("applied_rev")}));
    }
    if !result.is_empty() && result.iter().all(|member| member["confirmed"] == true) {
        sqlx::query("UPDATE singbox_runtime_rollouts SET completed_at=$2,updated_at=$2 WHERE id=$1 AND completed_at IS NULL AND dispatched_count=cardinality(targets)").bind(id).bind(now_timestamp()).execute(&mut **tx).await?;
    }
    Ok(result)
}

async fn dispatch(
    state: &AppState,
    headers: &HeaderMap,
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> ApiResult<()> {
    let row=sqlx::query("SELECT targets,batch_size,dispatched_count,paused,artifact_snapshot FROM singbox_runtime_rollouts WHERE id=$1 FOR UPDATE").bind(id).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)?;
    if row.get::<bool, _>("paused") {
        return Err(ApiError::Conflict("发布计划已暂停".into()));
    }
    let previous = members(tx, id).await?;
    if previous.iter().any(|v| v["confirmed"] != true) {
        return Err(ApiError::Conflict(
            "上一批尚未取得目标版本健康与实时运维确认，不能继续".into(),
        ));
    }
    let targets: Vec<i64> = row.get("targets");
    let start = row.get::<i32, _>("dispatched_count") as usize;
    let count = if start == 0 {
        1
    } else {
        row.get::<i32, _>("batch_size") as usize
    };
    let end = (start + count).min(targets.len());
    if start == end {
        return Err(ApiError::Conflict("所有目标已分发，查看逐台结果".into()));
    }
    for server in &targets[start..end] {
        super::preflight::require_confirmed_tx(state, headers, *server, tx).await?;
        super::super::super::business::lock_server(tx, *server).await?;
        super::super::super::settings::require_enabled(tx, *server).await?;
        let status=sqlx::query("SELECT static_info,capabilities,last_seen,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) AS retiring FROM servers WHERE id=$1").bind(server).fetch_one(&mut **tx).await?;
        let caps: Value = status.get("capabilities");
        if status.get::<bool, _>("retiring")
            || !status
                .get::<Option<i64>, _>("last_seen")
                .is_some_and(|at| now_timestamp().saturating_sub(at) <= 60)
            || !caps.as_array().is_some_and(|v| {
                [
                    sinan_protocol::RUNTIME_OPERATIONS_CAPABILITY,
                    sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY,
                ]
                .iter()
                .all(|required| v.iter().any(|capability| capability == *required))
            })
        {
            return Err(ApiError::Conflict(format!(
                "服务器 #{server} 离线、退役或缺少运行时运维/实际配置核对能力"
            )));
        }
        let artifact = super::super::super::agent::runtime_artifact(
            state,
            &status.get::<Value, _>("static_info"),
        )
        .await?;
        let snapshot: Value = row.get("artifact_snapshot");
        let selected: sinan_protocol::Artifact =
            serde_json::from_value(snapshot[server.to_string()].clone())
                .map_err(anyhow::Error::from)?;
        if selected.sha256 != artifact.sha256 {
            return Err(ApiError::Conflict(format!(
                "服务器 #{server} 的运行时平台或已签名制品已变化，固定候选不会自动替换"
            )));
        }
        crate::fleet::ensure_accepts_tasks_tx(tx, *server).await?;
        let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND module='singbox' AND result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL)").bind(server).fetch_one(&mut **tx).await?;
        if busy {
            return Err(ApiError::Conflict(format!(
                "服务器 #{server} 仍有运行时操作"
            )));
        }
        let baseline:i64=sqlx::query_scalar("SELECT COALESCE(MAX(target_rev),0) FROM server_module_status WHERE server_id=$1 AND module='singbox'").bind(server).fetch_one(&mut **tx).await?;
        let inspect = RuntimeOperationRequest {
            id: Uuid::new_v4(),
            module: "singbox".into(),
            operation: RuntimeOperation::Inspect,
            expected_revision: None,
            requested_at: now_timestamp(),
            expires_at: now_timestamp() + 600,
        };
        sqlx::query("INSERT INTO runtime_operations(id,server_id,module,requested_at,spec) VALUES($1,$2,'singbox',$3,$4)").bind(inspect.id).bind(server).bind(inspect.requested_at).bind(serde_json::to_value(&inspect).map_err(anyhow::Error::from)?).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO singbox_runtime_rollout_members(rollout_id,server_id,baseline_revision,inspect_request_id,dispatched_at,artifact_sha256) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(server).bind(baseline).bind(inspect.id).bind(inspect.requested_at).bind(artifact.sha256).execute(&mut **tx).await?;
    }
    super::super::super::business::mark_dirty(tx, &targets[start..end]).await?;
    sqlx::query(
        "UPDATE singbox_runtime_rollouts SET dispatched_count=$2,updated_at=$3 WHERE id=$1",
    )
    .bind(id)
    .bind(end as i32)
    .bind(now_timestamp())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn rollouts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    crate::control_center::require_capability(&state, &headers, "proxy:read").await?;
    let mut tx = state.pool.begin().await?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(r) FROM singbox_runtime_rollouts r ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut result = Vec::new();
    for mut row in rows {
        let id: Uuid = serde_json::from_value(row["id"].clone()).map_err(anyhow::Error::from)?;
        row["members"] = json!(members(&mut tx, id).await?);
        result.push(row);
    }
    tx.commit().await?;
    Ok(Json(result))
}
pub(crate) async fn advance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let administrator =
        crate::control_center::require_capability(&state, &headers, "proxy:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    let targets: Vec<i64> =
        sqlx::query_scalar("SELECT targets FROM singbox_runtime_rollouts WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    for server in targets {
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    }
    let mut tx = state.pool.begin().await?;
    super::super::super::entitlements::lock(&mut tx).await?;
    dispatch(&state, &headers, &mut tx, id).await?;
    event(
        &mut tx,
        Some(administrator),
        None,
        "runtime_rollout_advance",
        json!({"id":id}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"state":"batch_dispatched"})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pause {
    paused: bool,
}
pub(crate) async fn pause(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Pause>,
) -> ApiResult<Json<Value>> {
    let administrator =
        crate::control_center::require_capability(&state, &headers, "proxy:write").await?;
    let targets: Vec<i64> =
        sqlx::query_scalar("SELECT targets FROM singbox_runtime_rollouts WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    for server in targets {
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    }
    let mut tx = state.pool.begin().await?;
    let changed =
        sqlx::query("UPDATE singbox_runtime_rollouts SET paused=$2,updated_at=$3 WHERE id=$1")
            .bind(id)
            .bind(request.paused)
            .bind(now_timestamp())
            .execute(&mut *tx)
            .await?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    event(
        &mut tx,
        Some(administrator),
        None,
        "runtime_rollout_pause",
        json!({"id":id,"paused":request.paused}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"paused":request.paused,"already_dispatched_operations_cancelled":false}),
    ))
}

pub(crate) async fn inspect_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, server)): Path<(Uuid, i64)>,
) -> ApiResult<Json<Value>> {
    let administrator =
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    let mut tx = state.pool.begin().await?;
    super::super::super::business::lock_server(&mut tx, server).await?;
    crate::fleet::ensure_accepts_tasks_tx(&mut tx, server).await?;
    let member:Option<i64>=sqlx::query_scalar("SELECT server_id FROM singbox_runtime_rollout_members WHERE rollout_id=$1 AND server_id=$2 FOR UPDATE").bind(id).bind(server).fetch_optional(&mut *tx).await?;
    member.ok_or(ApiError::NotFound)?;
    let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_operations WHERE server_id=$1 AND module='singbox' AND result IS NULL AND cancelled_at IS NULL AND reconciled_at IS NULL)").bind(server).fetch_one(&mut *tx).await?;
    if busy {
        return Err(ApiError::Conflict(
            "设备仍有运维操作，等待原请求确认后再读取".into(),
        ));
    }
    let row=sqlx::query("SELECT capabilities,last_seen,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1) AS retiring FROM servers WHERE id=$1").bind(server).fetch_one(&mut *tx).await?;
    let caps: Value = row.get("capabilities");
    if row.get::<bool, _>("retiring")
        || !row
            .get::<Option<i64>, _>("last_seen")
            .is_some_and(|at| now_timestamp().saturating_sub(at) <= 60)
        || !caps.as_array().is_some_and(|v| {
            v.iter()
                .any(|c| c == sinan_protocol::RUNTIME_OPERATIONS_CAPABILITY)
        })
    {
        return Err(ApiError::Conflict(
            "设备离线、退役或不支持运行时读取".into(),
        ));
    }
    let inspect = RuntimeOperationRequest {
        id: Uuid::new_v4(),
        module: "singbox".into(),
        operation: RuntimeOperation::Inspect,
        expected_revision: None,
        requested_at: now_timestamp(),
        expires_at: now_timestamp() + 600,
    };
    sqlx::query("INSERT INTO runtime_operations(id,server_id,module,requested_at,spec) VALUES($1,$2,'singbox',$3,$4)").bind(inspect.id).bind(server).bind(inspect.requested_at).bind(serde_json::to_value(&inspect).map_err(anyhow::Error::from)?).execute(&mut *tx).await?;
    sqlx::query("UPDATE singbox_runtime_rollout_members SET inspect_request_id=$3,inspection_result=NULL,dispatched_at=$4 WHERE rollout_id=$1 AND server_id=$2").bind(id).bind(server).bind(inspect.id).bind(inspect.requested_at).execute(&mut *tx).await?;
    event(
        &mut tx,
        Some(administrator),
        None,
        "runtime_rollout_inspect",
        json!({"id":id,"server_id":server,"request_id":inspect.id,"mutation_replayed":false}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"state":"inspection_queued","request_id":inspect.id}),
    ))
}
