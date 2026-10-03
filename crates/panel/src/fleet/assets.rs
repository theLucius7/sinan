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
use sha2::{Digest, Sha256};
use sinan_protocol::{fleet::AccessPolicy, now_timestamp};
use sqlx::Row;
use uuid::Uuid;

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:read").await?;
    let row=sqlx::query("SELECT s.static_info,s.capabilities,s.agent_settings,s.asset_settings,s.metrics_sampled_at,s.latest_metrics,p.asset,p.policy,p.lifecycle,p.maintenance_from,p.maintenance_until,p.maintenance_reason FROM servers s LEFT JOIN fleet_profiles p ON p.server_id=s.id WHERE s.id=$1 AND s.deleted_at IS NULL")
        .bind(id).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let static_info: Value = row.get("static_info");
    let asset: Option<Value> = row.get("asset");
    let asset = asset.unwrap_or_else(|| json!({}));
    let purchased = asset.get("purchased").cloned().unwrap_or_else(|| json!({}));
    let policy: AccessPolicy = serde_json::from_value(
        row.get::<Option<Value>, _>("policy")
            .unwrap_or_else(|| json!({})),
    )
    .map_err(anyhow::Error::from)?;
    let digest = profile_digest(&asset, &policy)?;
    let observed = json!({"cpu_cores":static_info["cpu_cores"],"cpu_model":static_info["cpu_model"],"memory_bytes":static_info["memory_total"],"disk_bytes":static_info["disk_total"],"bandwidth_mbps":null});
    let related = references(&state.pool, id).await?;
    Ok(Json(
        json!({"server_id":id,"asset":asset,"policy":policy,"digest":digest,"lifecycle":row.get::<Option<String>,_>("lifecycle").unwrap_or_else(||"active".into()),"maintenance_from":row.get::<Option<i64>,_>("maintenance_from"),"maintenance_until":row.get::<Option<i64>,_>("maintenance_until"),"maintenance_reason":row.get::<Option<String>,_>("maintenance_reason"),"capabilities":row.get::<Value,_>("capabilities"),"purchased":purchased,"observed":observed,"asset_settings":row.get::<Value,_>("asset_settings"),"related":related,"sampled_at":row.get::<i64,_>("metrics_sampled_at"),"processes":row.get::<Value,_>("latest_metrics")["process_resources"],"pressure":row.get::<Value,_>("latest_metrics")["system_pressure"]}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileInput {
    asset: Value,
    policy: AccessPolicy,
    expected_digest: String,
}
fn profile_digest(asset: &Value, policy: &AccessPolicy) -> ApiResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&json!({"asset":asset,"policy":policy}))
                .map_err(anyhow::Error::from)?
        )
    ))
}
pub async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<ProfileInput>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    if !input.asset.is_object()
        || serde_json::to_vec(&input.asset)
            .map_err(anyhow::Error::from)?
            .len()
            > 16384
    {
        return Err(ApiError::BadRequest(
            "资产资料必须是小于 16 KiB 的对象".into(),
        ));
    }
    crate::control_center::require_capability(&state, &headers, "security:write").await?;
    let policy = normalize_policy(input.policy)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = sqlx::query("SELECT asset,policy FROM fleet_profiles WHERE server_id=$1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let (asset, original_policy) = if let Some(row) = current {
        (
            row.get::<Value, _>("asset"),
            serde_json::from_value::<AccessPolicy>(row.get("policy"))
                .map_err(anyhow::Error::from)?,
        )
    } else {
        (json!({}), AccessPolicy::default())
    };
    if input.expected_digest != profile_digest(&asset, &original_policy)? {
        return Err(ApiError::Conflict(
            "资产或授权已由其他窗口修改。当前表单保留，请保存草稿、读取最新资料后再确认差异".into(),
        ));
    }
    let digest = profile_digest(&input.asset, &policy)?;
    sqlx::query("INSERT INTO fleet_profiles(server_id,asset,policy,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(server_id) DO UPDATE SET asset=$2,policy=$3,updated_at=$4")
        .bind(id).bind(&input.asset).bind(json!(policy)).bind(now_timestamp()).execute(&mut *tx).await?;
    super::record(
        &mut tx,
        id,
        "profile_changed",
        json!({"asset":input.asset,"policy":policy}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"saved":true,"digest":digest})))
}

fn normalize_policy(mut policy: AccessPolicy) -> ApiResult<AccessPolicy> {
    if policy.terminal_accounts.len() > 16
        || policy.services.len() > 64
        || policy.read_directories.len() > 16
        || policy.write_directories.len() > 16
    {
        return Err(ApiError::BadRequest("授权范围数量超限".into()));
    }
    for name in policy.terminal_accounts.iter().chain(&policy.services) {
        if name.is_empty()
            || name.len() > 255
            || name.starts_with('-')
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'@'))
        {
            return Err(ApiError::BadRequest("账号或服务名称无效".into()));
        }
    }
    for path in policy
        .read_directories
        .iter()
        .chain(&policy.write_directories)
    {
        if !path.starts_with('/')
            || path == "/"
            || path.len() > 4096
            || path.contains(['\0', '\n', '\r'])
            || path.split('/').any(|p| p == ".." || p == ".")
        {
            return Err(ApiError::BadRequest(
                "允许目录必须为明确的绝对目录，不能授权根目录".into(),
            ));
        }
    }
    policy.maximum_file_bytes = policy.maximum_file_bytes.clamp(1, 256 * 1024);
    Ok(policy)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleInput {
    lifecycle: String,
    from: Option<i64>,
    until: Option<i64>,
    reason: String,
}
pub async fn lifecycle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<LifecycleInput>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:write").await?;
    if !["active", "maintenance", "draining", "retired"].contains(&input.lifecycle.as_str())
        || input
            .until
            .is_some_and(|until| until <= input.from.unwrap_or(now_timestamp()))
    {
        return Err(ApiError::BadRequest("生命周期或维护时间范围无效".into()));
    }
    if input.lifecycle == "retired" {
        return Err(ApiError::Conflict(
            "退役必须通过现有设备清理确认流程；先停止接收任务，再检查关联服务并删除设备".into(),
        ));
    }
    let reason = super::text(&input.reason, 512)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    sqlx::query("INSERT INTO fleet_profiles(server_id,lifecycle,maintenance_from,maintenance_until,maintenance_reason,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(server_id) DO UPDATE SET lifecycle=$2,maintenance_from=$3,maintenance_until=$4,maintenance_reason=$5,updated_at=$6")
        .bind(id).bind(&input.lifecycle).bind(input.from).bind(input.until).bind(reason).bind(now_timestamp()).execute(&mut *tx).await?;
    super::record(
        &mut tx,
        id,
        "lifecycle_changed",
        json!({"lifecycle":input.lifecycle,"from":input.from,"until":input.until}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"saved":true})))
}

async fn references(pool: &sqlx::PgPool, id: i64) -> ApiResult<Value> {
    let plugins: Vec<String> = sqlx::query_scalar(
        "SELECT plugin FROM server_plugins WHERE server_id=$1 AND enabled ORDER BY plugin",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    let deployments:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('module',module,'target_rev',target_rev,'applied_rev',applied_rev,'healthy',healthy) FROM server_module_status WHERE server_id=$1 ORDER BY module").bind(id).fetch_all(pool).await?;
    Ok(json!({"plugins":plugins,"applications":deployments}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInput {
    target_server_id: i64,
    confirmation: Option<String>,
}
async fn preview(state: &AppState, source: i64, target: i64) -> ApiResult<Value> {
    if source == target {
        return Err(ApiError::BadRequest("迁移来源与目标必须不同".into()));
    }
    let rows=sqlx::query("SELECT id,name,agent_settings,telemetry_settings,device_public_key FROM servers WHERE id=ANY($1) AND deleted_at IS NULL ORDER BY id").bind(vec![source,target]).fetch_all(&state.pool).await?;
    if rows.len() != 2 {
        return Err(ApiError::NotFound);
    }
    let probes: Vec<Value> =
        sqlx::query_scalar("SELECT spec FROM network_probes WHERE server_id=$1 ORDER BY id")
            .bind(source)
            .fetch_all(&state.pool)
            .await?;
    let snapshot = json!({"source":source,"target":target,"collection":rows.iter().map(|row|json!({"id":row.get::<i64,_>("id"),"name":row.get::<String,_>("name"),"agent_settings":row.get::<Value,_>("agent_settings"),"telemetry_settings":row.get::<Value,_>("telemetry_settings"),"enrolled":row.get::<Option<String>,_>("device_public_key").is_some()})).collect::<Vec<_>>(),"probes":probes,"related":references(&state.pool,source).await?,"scope":["agent_settings","telemetry_settings","network_probes"],"identity_copied":false,"business_requires_plugin_migration":true});
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&snapshot).map_err(anyhow::Error::from)?)
    );
    Ok(json!({"snapshot":snapshot,"confirmation":digest}))
}
pub async fn migration_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<MigrationInput>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:read").await?;
    crate::control_center::require_server(&state, &headers, input.target_server_id, "servers:read")
        .await?;
    Ok(Json(preview(&state, id, input.target_server_id).await?))
}
pub async fn migrate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<MigrationInput>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:write").await?;
    crate::control_center::require_server(
        &state,
        &headers,
        input.target_server_id,
        "servers:write",
    )
    .await?;
    let mut tx = state.pool.begin().await?;
    crate::latency_tasks::lock(&mut tx).await?;
    sqlx::query("SELECT id FROM servers WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(vec![id, input.target_server_id])
        .fetch_all(&mut *tx)
        .await?;
    super::ensure_accepts_tasks_tx(&mut tx, input.target_server_id).await?;
    let current = preview(&state, id, input.target_server_id).await?;
    if input.confirmation.as_deref() != current["confirmation"].as_str() {
        return Err(ApiError::Conflict("迁移影响已变化，请重新预览".into()));
    }
    let occupied: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_probes WHERE server_id=$1)")
            .bind(input.target_server_id)
            .fetch_one(&mut *tx)
            .await?;
    if occupied {
        return Err(ApiError::Conflict(
            "目标已有拨测，不能直接覆盖；请先处理目标配置".into(),
        ));
    }
    sqlx::query("UPDATE servers target SET agent_settings=source.agent_settings,telemetry_settings=source.telemetry_settings FROM servers source WHERE target.id=$2 AND source.id=$1")
        .bind(id).bind(input.target_server_id).execute(&mut *tx).await?;
    for spec in current["snapshot"]["probes"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let mut spec = spec.clone();
        let probe_id = Uuid::new_v4();
        spec["id"] = json!(probe_id);
        sqlx::query("INSERT INTO network_probes(id,server_id,spec) VALUES($1,$2,$3)")
            .bind(probe_id)
            .bind(input.target_server_id)
            .bind(spec)
            .execute(&mut *tx)
            .await?;
    }
    super::record(
        &mut tx,
        input.target_server_id,
        "collection_migrated",
        json!({"source":id,"identity_copied":false}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"migrated":true,"business_requires_plugin_migration":true}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostInput {
    kind: String,
    amount_minor: i64,
    currency: String,
    occurred_at: i64,
    valid_until: Option<i64>,
    reference: String,
}
pub async fn add_cost(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<CostInput>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:write").await?;
    let currency = input.currency.to_ascii_uppercase();
    if ![
        "purchase",
        "renewal",
        "price_change",
        "refund",
        "cancellation",
    ]
    .contains(&input.kind.as_str())
        || !(0..=100_000_000_000).contains(&input.amount_minor)
        || currency.len() != 3
        || !currency.bytes().all(|c| c.is_ascii_uppercase())
        || input.occurred_at < 0
        || input
            .valid_until
            .is_some_and(|until| until < input.occurred_at)
    {
        return Err(ApiError::BadRequest(
            "费用记录参数无效，金额以最小货币单位保存".into(),
        ));
    }
    let updates_expiry = matches!(input.kind.as_str(), "purchase" | "renewal");
    let record_id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO fleet_cost_records(id,server_id,kind,amount_minor,currency,occurred_at,valid_until,reference,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(record_id).bind(id).bind(input.kind).bind(input.amount_minor).bind(currency).bind(input.occurred_at).bind(input.valid_until).bind(super::text(&input.reference,512)?).bind(now_timestamp()).execute(&mut *tx).await?;
    if updates_expiry && let Some(until) = input.valid_until {
        sqlx::query("UPDATE servers SET asset_settings=jsonb_set(asset_settings,'{expires_at}',to_jsonb($2::bigint)) WHERE id=$1").bind(id).bind(until).execute(&mut *tx).await?;
    }
    super::record(&mut tx, id, "cost_recorded", json!({"record_id":record_id})).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":record_id})))
}
pub async fn costs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_server(&state, &headers, id, "servers:read").await?;
    let records:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(r)-'server_id' FROM fleet_cost_records r WHERE server_id=$1 ORDER BY occurred_at DESC,id LIMIT 1000").bind(id).fetch_all(&state.pool).await?;
    let annual:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('year',extract(year FROM to_timestamp(occurred_at))::integer,'currency',currency,'amount_minor',sum(CASE WHEN kind='refund' THEN -amount_minor WHEN kind IN ('purchase','renewal') THEN amount_minor ELSE 0 END)::text) FROM fleet_cost_records WHERE server_id=$1 GROUP BY extract(year FROM to_timestamp(occurred_at)),currency ORDER BY extract(year FROM to_timestamp(occurred_at)) DESC,currency").bind(id).fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"records":records,"annual":annual,"currency_conversion":false}),
    ))
}
