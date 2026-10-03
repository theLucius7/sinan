use super::*;

async fn identity(state: &AppState, headers: &HeaderMap, operation: &Operation) -> ApiResult<()> {
    let actor = permission(
        state,
        headers,
        operation.resource_id,
        &operation.before.server_ids,
        true,
    )
    .await?;
    if actor != operation.requested_by {
        return Err(ApiError::Forbidden(
            "安全组预览只允许原发起管理员确认或核对".into(),
        ));
    }
    control_center::require_recent_proof(state, headers).await?;
    Ok(())
}
async fn unchanged(
    state: &AppState,
    headers: &HeaderMap,
    operation: &Operation,
) -> ApiResult<(Account, Resource)> {
    identity(state, headers, operation).await?;
    let (account, resource) = context(state, operation.resource_id).await?;
    let (scope, updated) = linked(&state.pool, resource.id).await?;
    if account.id != operation.before.account_id
        || account.revision != operation.before.account_revision
        || resource.revision != operation.before.resource_revision
        || resource.cloud_id != operation.before.instance_id
        || resource.region != operation.before.region
        || scope != operation.before.server_ids
        || updated != operation.before.link_updated_at
    {
        return Err(ApiError::Conflict(
            "账号、资源版本或服务器关联已变化；停止本次变更并重新核对".into(),
        ));
    }
    Ok((account, resource))
}
fn steps(operation: &Operation) -> Value {
    let additions = operation
        .target_groups
        .iter()
        .filter(|group| !operation.before.current_groups.contains(group))
        .map(|group| json!({"group_id":group,"action":"join","state":"pending"}));
    let removals = operation
        .before
        .current_groups
        .iter()
        .filter(|group| !operation.target_groups.contains(group))
        .map(|group| json!({"group_id":group,"action":"leave","state":"pending"}));
    json!(additions.chain(removals).collect::<Vec<_>>())
}
async fn stop(
    state: &AppState,
    id: Uuid,
    status: &str,
    error: &str,
    evidence: Value,
    actual: Option<Vec<String>>,
) -> ApiResult<()> {
    sqlx::query("UPDATE alicloud_security_group_operations SET status=$2,error_code=$3,steps=$4,actual_groups=$5,observed_at=CASE WHEN $5 IS NULL THEN observed_at ELSE $6 END,updated_at=$6,original_result=CASE WHEN $2='unknown' THEN 'unknown' ELSE original_result END WHERE id=$1 AND status='running'")
        .bind(id).bind(status).bind(error).bind(evidence).bind(actual).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(())
}
pub(super) async fn confirm(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    input: Confirm,
    cloud: &Cloud,
) -> ApiResult<Operation> {
    let initial = load(&state.pool, id).await?;
    identity(state, headers, &initial).await?;
    if !input.confirm || input.snapshot_digest != initial.snapshot_digest {
        return Err(ApiError::Conflict(
            "请明确确认原安全组差异与完整预览摘要".into(),
        ));
    }
    // A durable submitted intent is never submitted again, even after a timeout.
    if initial.status != "preview" {
        return load(&state.pool, id).await;
    }
    if initial.expires_at <= now_timestamp() {
        return Err(ApiError::Conflict(
            "安全组预览已过期，请重新读取并预览".into(),
        ));
    }
    let (account, resource) = unchanged(state, headers, &initial).await?;
    let (fresh, observed_at) =
        snapshot(state, cloud, &account, &resource, &initial.target_groups).await?;
    let impact = impact(&fresh, &initial.target_groups)?;
    if fresh != initial.before.0
        || digest(&json!({"before":fresh,"target":initial.target_groups,"impact":impact}))?
            != initial.snapshot_digest
    {
        return Err(ApiError::Conflict(
            "官方当前组、策略、版本或授权关联已变化，请重新预览".into(),
        ));
    }
    let mut tx = lock(&state.pool, account.id).await?;
    let operation = row_on(&mut tx, id).await?;
    if operation.status != "preview" {
        tx.commit().await?;
        return load(&state.pool, id).await;
    }
    super::super::operations::idle(&mut tx, resource.id).await?;
    let evidence = steps(&operation);
    sqlx::query("UPDATE alicloud_security_group_operations SET status='running',steps=$2,updated_at=$3,observed_at=$4,actual_groups=$5 WHERE id=$1 AND status='preview'")
        .bind(id).bind(&evidence).bind(now_timestamp()).bind(observed_at).bind(&fresh.current_groups).execute(&mut *tx).await?;
    tx.commit().await?;
    execute(state, headers, id, cloud).await?;
    load(&state.pool, id).await
}

async fn execute(state: &AppState, headers: &HeaderMap, id: Uuid, cloud: &Cloud) -> ApiResult<()> {
    let initial = load(&state.pool, id).await?;
    let mut expected = initial.before.current_groups.clone();
    let mut evidence = initial.steps.clone();
    let length = evidence.as_array().map_or(0, Vec::len);
    for position in 0..length {
        let (account, resource) = match unchanged(state, headers, &initial).await {
            Ok(value) => value,
            Err(
                ApiError::Forbidden(_)
                | ApiError::Unauthorized
                | ApiError::Conflict(_)
                | ApiError::NotFound,
            ) => {
                stop(
                    state,
                    id,
                    "failed",
                    "authorization_or_context_changed",
                    evidence,
                    None,
                )
                .await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let group = evidence[position]["group_id"]
            .as_str()
            .ok_or_else(|| ApiError::Conflict("固定安全组步骤缺失".into()))?
            .to_owned();
        let action = evidence[position]["action"]
            .as_str()
            .ok_or_else(|| ApiError::Conflict("固定安全组动作缺失".into()))?
            .to_owned();
        // The next action is committed before touching the remote API. A crash
        // after this point remains running/unknown and requires read-only reconciliation.
        evidence[position]["state"] = json!("submitting");
        sqlx::query("UPDATE alicloud_security_group_operations SET steps=$2,updated_at=$3 WHERE id=$1 AND status='running'")
            .bind(id).bind(&evidence).bind(now_timestamp()).execute(&state.pool).await?;
        let mut tx = lock(&state.pool, account.id).await?;
        let operation = row_on(&mut tx, id).await?;
        if operation.status != "running" {
            tx.commit().await?;
            return Ok(());
        }
        let resource_now: Resource =
            sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
                .bind(resource.id)
                .fetch_one(&mut *tx)
                .await?;
        let account_now = account_on(&mut tx, account.id).await?;
        let link=sqlx::query("SELECT server_id,updated_at FROM operations_cloud_links WHERE resource_id=$1 FOR UPDATE").bind(resource.id).fetch_optional(&mut *tx).await?;
        let current_link = link
            .map(|row| {
                (
                    row.get::<Option<i64>, _>("server_id")
                        .into_iter()
                        .collect::<Vec<_>>(),
                    Some(row.get::<i64, _>("updated_at")),
                )
            })
            .unwrap_or_default();
        if account_now.revision != initial.before.account_revision
            || resource_now.revision != initial.before.resource_revision
            || !account_now.enabled
            || current_link
                != (
                    initial.before.server_ids.clone(),
                    initial.before.link_updated_at,
                )
        {
            tx.commit().await?;
            stop(
                state,
                id,
                "failed",
                "context_changed_before_remote_action",
                evidence,
                None,
            )
            .await?;
            return Ok(());
        }
        if let Err(error) = identity(state, headers, &initial).await {
            tx.commit().await?;
            match error {
                ApiError::Forbidden(_)
                | ApiError::Unauthorized
                | ApiError::Conflict(_)
                | ApiError::NotFound => {
                    stop(
                        state,
                        id,
                        "failed",
                        "authorization_changed_before_remote_action",
                        evidence,
                        None,
                    )
                    .await?;
                    return Ok(());
                }
                error => return Err(error),
            }
        }
        let observed = client::instance(cloud, &account_now, &resource_now).await;
        let (vpc, current) = match observed {
            Ok(value) => value,
            Err(error) => {
                tx.commit().await?;
                stop(state, id, "failed", error.code, evidence, None).await?;
                return Ok(());
            }
        };
        if vpc != initial.before.vpc_id || current != expected {
            tx.commit().await?;
            stop(
                state,
                id,
                "failed",
                "remote_membership_changed",
                evidence,
                Some(current),
            )
            .await?;
            return Ok(());
        }
        evidence[position]["membership_observed_at"] = json!(now_timestamp());
        let frozen = initial
            .before
            .groups
            .iter()
            .find(|value| value.id == group)
            .ok_or_else(|| ApiError::Conflict("目标组固定策略缺失".into()))?;
        let fresh_group =
            match client::group(cloud, &account_now, &resource_now, &group, &vpc).await {
                Ok(value) => value,
                Err(error) => {
                    evidence[position]["state"] = json!("not_submitted");
                    evidence[position]["error_code"] = json!(error.code);
                    tx.commit().await?;
                    stop(state, id, "failed", error.code, evidence, Some(current)).await?;
                    return Ok(());
                }
            };
        let fresh_digest = digest(&fresh_group)?;
        evidence[position]["group_observed_at"] = json!(now_timestamp());
        evidence[position]["group_digest"] = json!(fresh_digest);
        let acceptable = fresh_group.kind == "normal"
            && fresh_group.inner_access_policy == "Accept"
            && fresh_group
                .permissions
                .as_array()
                .is_some_and(|rules| rules.iter().all(|rule| rule["Policy"] == "Accept"));
        let owned: bool = if action == "leave" {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM alicloud_managed_security_groups WHERE resource_id=$1 AND group_id=$2 AND group_digest=$3)")
                .bind(resource.id).bind(&group).bind(&fresh_digest).fetch_one(&mut *tx).await?
        } else {
            true
        };
        if &fresh_group != frozen || (action == "join" && !acceptable) || !owned {
            evidence[position]["state"] = json!("not_submitted");
            evidence[position]["error_code"] = json!("remote_group_policy_or_ownership_changed");
            tx.commit().await?;
            stop(
                state,
                id,
                "failed",
                "remote_group_policy_or_ownership_changed",
                evidence,
                Some(current),
            )
            .await?;
            return Ok(());
        }
        let response = client::change(cloud, &account_now, &resource_now, &action, &group).await;
        let request = match response {
            Ok(request) => request,
            Err(error) => {
                evidence[position]["state"] = json!("unknown");
                evidence[position]["error_code"] = json!(error.code);
                tx.commit().await?;
                stop(state, id, "unknown", error.code, evidence, None).await?;
                return Ok(());
            }
        };
        evidence[position]["request_id"] = json!(request);
        if action == "join" {
            expected.push(group.clone());
            expected.sort();
            expected.dedup();
        } else {
            expected.retain(|id| id != &group);
        }
        let observed = client::instance(cloud, &account_now, &resource_now).await;
        let current = match observed {
            Ok((vpc, current)) if vpc == initial.before.vpc_id && current == expected => current,
            Ok((_, current)) => {
                evidence[position]["state"] = json!("unknown");
                evidence[position]["observed_groups"] = json!(current);
                tx.commit().await?;
                stop(
                    state,
                    id,
                    "unknown",
                    "accepted_membership_not_verified",
                    evidence,
                    Some(current),
                )
                .await?;
                return Ok(());
            }
            Err(error) => {
                evidence[position]["state"] = json!("unknown");
                evidence[position]["error_code"] = json!(error.code);
                tx.commit().await?;
                stop(state, id, "unknown", error.code, evidence, None).await?;
                return Ok(());
            }
        };
        evidence[position]["state"] = json!("verified");
        evidence[position]["observed_groups"] = json!(current);
        if action == "join" {
            let data = initial
                .before
                .groups
                .iter()
                .find(|data| data.id == group)
                .ok_or_else(|| ApiError::Conflict("目标组固定策略缺失".into()))?;
            sqlx::query("INSERT INTO alicloud_managed_security_groups(resource_id,group_id,group_digest,operation_id,confirmed_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(resource_id,group_id) DO NOTHING")
                .bind(resource.id).bind(&group).bind(digest(data)?).bind(id).bind(now_timestamp()).execute(&mut *tx).await?;
        } else {
            sqlx::query(
                "DELETE FROM alicloud_managed_security_groups WHERE resource_id=$1 AND group_id=$2",
            )
            .bind(resource.id)
            .bind(&group)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE alicloud_security_group_operations SET steps=$2,actual_groups=$3,observed_at=$4,updated_at=$4 WHERE id=$1 AND status='running'")
            .bind(id).bind(&evidence).bind(&current).bind(now_timestamp()).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    sqlx::query("UPDATE alicloud_security_group_operations SET status='succeeded',updated_at=$2 WHERE id=$1 AND status='running'").bind(id).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(())
}

pub(super) async fn reconcile(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    input: Reconcile,
    cloud: &Cloud,
) -> ApiResult<Operation> {
    let operation = load(&state.pool, id).await?;
    identity(state, headers, &operation).await?;
    if !matches!(operation.status.as_str(), "running" | "unknown") {
        return Err(ApiError::Conflict("此安全组操作不需要未知结果核对".into()));
    }
    if !input.process_stopped || input.evidence.trim().len() < 32 || input.evidence.len() > 4096 {
        return Err(ApiError::BadRequest(
            "须实际确认原请求已结束，并记录检查方法与证据；不得自动重发".into(),
        ));
    }
    let (account, resource) = context(state, operation.resource_id).await?;
    let mut tx = lock(&state.pool, account.id).await?;
    let current = row_on(&mut tx, id).await?;
    if !matches!(current.status.as_str(), "running" | "unknown") {
        return Err(ApiError::Conflict("操作已经核对或结束".into()));
    }
    let (vpc, actual) = client::instance(cloud, &account, &resource)
        .await
        .map_err(super::super::failure)?;
    let observed = now_timestamp();
    // An unchanged observation cannot prove a timed-out mutation failed. Preserve
    // the original unknown result and close only through this explicit human assertion.
    let reconciliation = json!({"original_result":"unknown","process_stopped":true,"observed_at":observed,
        "official_source":"DescribeInstances","actual_groups":actual,"vpc_id":vpc,"target_matches":actual==operation.target_groups,
        "evidence":input.evidence,"remaining_steps":"stopped","automatic_retry":false,"cleanup":"no_temporary_listener_or_files"});
    sqlx::query("UPDATE alicloud_security_group_operations SET status='reconciled',original_result='unknown',actual_groups=$2,observed_at=$3,updated_at=$3,reconciliation=$4 WHERE id=$1")
        .bind(id).bind(actual).bind(observed).bind(reconciliation).execute(&mut *tx).await?;
    tx.commit().await?;
    load(&state.pool, id).await
}
