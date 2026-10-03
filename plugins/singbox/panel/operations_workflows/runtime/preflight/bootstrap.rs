use super::*;

async fn absent(tx: &mut Transaction<'_, Postgres>, server: i64) -> ApiResult<bool> {
    Ok(sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM deployments WHERE server_id=$1 AND module='singbox') AND NOT EXISTS(SELECT 1 FROM server_module_status WHERE server_id=$1 AND module='singbox' AND (COALESCE(target_rev,0)>0 OR COALESCE(applied_rev,0)>0))")
        .bind(server).fetch_one(&mut **tx).await?)
}

fn installation_directory(receipt: &Value, requested: i64, now: i64) -> Value {
    let result = &receipt["result"];
    let directory = &result["runtime_directory"];
    let at = result["sampled_at"].as_i64();
    let valid = receipt["succeeded"] == true
        && fresh(receipt, requested, now)
        && result["module"] == PERMISSIONS_MODULE
        && at.is_some_and(|at| at >= requested && (now - 300..=now).contains(&at));
    let states = [
        directory["readable"].as_bool(),
        directory["writable"].as_bool(),
        directory["executable"].as_bool(),
        directory["symlink_free"].as_bool(),
    ];
    let state = if !valid {
        "unknown"
    } else if result["privileged_effective_uid"] != 0
        || !directory["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("/sing-box@main"))
        || states.contains(&Some(false))
        || !directory["error"].is_null()
    {
        "failed"
    } else if states.iter().all(|value| *value == Some(true)) {
        "passed"
    } else {
        "unknown"
    };
    check(
        "bootstrap_directory",
        "首次安装特权目录",
        state,
        at,
        "agent_runtime_permissions",
        json!({"privileged_effective_uid":result["privileged_effective_uid"],"runtime_directory":directory,"runtime_account_required_for_business":true}),
        "这里只证明特权安装能访问无符号链接的目标/最近父目录；运行时账号的业务及证书权限必须在首次空安装后重新采集，不用 root 结果代替。",
    )
}

pub(super) struct Evidence<'a> {
    pub requested: i64,
    pub current: bool,
    pub permissions: &'a Value,
    pub ports: &'a Value,
}

pub(super) async fn status(
    state: &AppState,
    server: i64,
    tx: &mut Transaction<'_, Postgres>,
    context: &Context,
    evidence: Evidence<'_>,
) -> ApiResult<Value> {
    let Evidence {
        requested,
        current,
        permissions,
        ports,
    } = evidence;
    if !absent(tx, server).await? {
        return Ok(
            json!({"available":false,"ready":false,"reason":"已有部署记录；首次空安装不能覆盖当前配置或重放未知安装。"}),
        );
    }
    let mut checks = panel_checks(state, context).await?;
    checks.retain(|item| item["key"] != "configuration");
    let compiled = sinan_compiler::compile_server(&[]).is_ok();
    checks.push(check(
        "bootstrap_configuration",
        "无业务凭据的初始配置",
        if compiled { "passed" } else { "failed" },
        Some(now_timestamp()),
        "fixed_compiler_1.14.2",
        json!({"business_inbounds":0,"business_credentials":0}),
        "固定编译器只生成空业务监听与本机统计接口，不修改保存的普通节点目标。",
    ));
    let now = now_timestamp();
    checks.push(installation_directory(permissions, requested, now));
    checks.extend(
        permission_checks(permissions, requested, now)
            .into_iter()
            .filter(|item| item["key"] == "service_manager"),
    );
    checks.push(ports_check(
        ports,
        permissions,
        &listeners(&[]),
        requested,
        now,
        false,
    ));
    checks.push(check(
        "bootstrap_snapshot",
        "首次安装固定证据",
        if current { "passed" } else { "unknown" },
        Some(requested),
        "current_configuration_fingerprint",
        json!({"maximum_age_secs":300,"current":current}),
        "首次安装要求当前预检指纹及五分钟内的真实设备证据；业务发布仍须在空安装完成后重新预检。",
    ));
    let ready = checks.iter().all(|item| item["blocking"] != true);
    Ok(
        json!({"available":true,"ready":ready,"checks":checks,"reason":if ready{"首次空安装条件满足；再次验证后只创建空运行时目标，业务配置继续等待重新预检。"}else{"首次空安装仍缺少当前目录、系统服务安装权限、统计端口或签名制品证据。"}}),
    )
}

pub(in super::super::super) async fn install(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(request): Json<Confirm>,
) -> ApiResult<Json<Value>> {
    let actor =
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    for permission in ["operations:read", "monitoring:read", "diagnostics:write"] {
        crate::control_center::require_server(&state, &headers, server, permission).await?;
    }
    if !request.confirm {
        return Err(ApiError::BadRequest("请明确确认首次只安装空运行时".into()));
    }
    let mut tx = state.pool.begin().await?;
    super::super::super::super::entitlements::lock(&mut tx).await?;
    let context = context(&mut tx, server).await?;
    let latest=sqlx::query("SELECT * FROM singbox_deployment_preflights WHERE server_id=$1 ORDER BY sequence DESC LIMIT 1").bind(server).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::Conflict("请先采集首次安装的只读预检证据".into()))?;
    if latest.get::<Uuid, _>("id") != request.id
        || latest.get::<i64, _>("administrator_id") != actor
    {
        return Err(ApiError::Conflict(
            "首次安装必须使用本人最新采集的固定预检".into(),
        ));
    }
    let now = now_timestamp();
    let current = latest.get::<i64, _>("expires_at") > now
        && fingerprint(&state, &context).await? == latest.get::<String, _>("expected_digest");
    let mut receipts = Vec::new();
    for field in ["permissions_operation_id", "ports_operation_id"] {
        let receipt: Option<Value> =
            sqlx::query_scalar("SELECT result FROM fleet_operations WHERE id=$1 AND server_id=$2")
                .bind(latest.get::<Uuid, _>(field))
                .bind(server)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
        receipts.push(receipt.unwrap_or(Value::Null));
    }
    let status = status(
        &state,
        server,
        &mut tx,
        &context,
        Evidence {
            requested: latest.get("created_at"),
            current,
            permissions: &receipts[0],
            ports: &receipts[1],
        },
    )
    .await?;
    if status["available"] != true || status["ready"] != true {
        return Err(ApiError::Conflict(
            "首次空安装条件未满足或已有部署；未知、过期和冲突均不可确认".into(),
        ));
    }
    let artifact =
        super::super::super::super::agent::runtime_artifact(&state, &context.info).await?;
    let native = sinan_compiler::compile_server(&[]).map_err(anyhow::Error::from)?;
    let bundle = serde_json::to_string(&sinan_protocol::Bundle {
        files: std::collections::BTreeMap::from([("config.json".into(), native)]),
    })
    .map_err(anyhow::Error::from)?;
    let hash = crate::auth::hash_token(&bundle);
    let manifest: i64 = sqlx::query_scalar("SELECT manifest_rev FROM servers WHERE id=$1")
        .bind(server)
        .fetch_one(&mut *tx)
        .await?;
    let revision = manifest
        .checked_add(1)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("revision overflow")))?;
    sqlx::query("INSERT INTO deployments(server_id,module,rev,bundle,bundle_sha256,source_json,created_at) VALUES($1,'singbox',$2,$3,$4,'[]'::jsonb,$5)").bind(server).bind(revision).bind(bundle).bind(hash).bind(now).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO singbox_runtime_manifest_facts(server_id,module,revision,runtime_version,artifact_sha256,artifact) VALUES($1,'singbox',$2,'1.14.2',$3,$4)").bind(server).bind(revision).bind(&artifact.sha256).bind(serde_json::to_value(&artifact).map_err(anyhow::Error::from)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO server_module_status(server_id,module,target_rev,updated_at) VALUES($1,'singbox',$2,$3) ON CONFLICT(server_id,module) DO UPDATE SET target_rev=EXCLUDED.target_rev,updated_at=EXCLUDED.updated_at").bind(server).bind(revision).bind(now).execute(&mut *tx).await?;
    sqlx::query("UPDATE servers SET manifest_rev=$2 WHERE id=$1")
        .bind(server)
        .bind(revision)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE singbox_deployment_preflights SET expires_at=$2 WHERE id=$1")
        .bind(request.id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    event(&mut tx,Some(actor),None,"runtime_empty_bootstrap_requested",json!({"server_id":server,"revision":revision,"preflight_id":request.id,"artifact_sha256":artifact.sha256,"business_inbounds":0,"business_credentials":0,"business_preflight_invalidated":true})).await?;
    tx.commit().await?;
    crate::agent_api::notify(
        &state,
        server,
        sinan_protocol::Envelope::new(
            "manifest.changed",
            sinan_protocol::ManifestChanged {
                rev: revision.try_into().map_err(anyhow::Error::from)?,
            },
        )
        .map_err(anyhow::Error::from)?,
    )
    .await;
    Ok(Json(
        json!({"server_id":server,"revision":revision,"status":"waiting_agent","business_applied":false,"business_preflight_required":true,"retry_uses_existing_deployment":true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_install_access_does_not_claim_missing_runtime_account_can_run_business() {
        let mut receipt = json!({"succeeded":true,"completed_at":100,"result":{"module":"sing-box","sampled_at":100,"privileged_effective_uid":0,"runtime_account":{"known":false},"runtime_directory":{"path":"/TEST_ONLY/sing-box@main","readable":true,"writable":true,"executable":true,"symlink_free":true,"error":null,"runtime_readable":null,"runtime_executable":null,"runtime_error":"runtime_account_unknown"},"service_manager":{"available":true,"management_authorized":true,"privileged_effective_uid":0}}});
        assert_eq!(installation_directory(&receipt, 90, 101)["state"], "passed");
        assert_eq!(permission_checks(&receipt, 90, 101)[0]["state"], "unknown");
        receipt["result"]["runtime_directory"]["symlink_free"] = json!(false);
        assert_eq!(installation_directory(&receipt, 90, 101)["state"], "failed");
        assert_eq!(
            installation_directory(&receipt, 90, 500)["state"],
            "unknown"
        );
    }
}
