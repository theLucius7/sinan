use super::models::{Configuration, Document};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/documents",
            get(list).post(create),
        )
        .route(
            "/api/network-configuration/documents/preview",
            post(preview),
        )
        .route(
            "/api/network-configuration/documents/{id}",
            get(detail).put(update).delete(remove),
        )
        .route(
            "/api/network-configuration/documents/{id}/history",
            get(history),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    config: Configuration,
    revision: Option<i64>,
}

pub(super) async fn load(state: &AppState, id: Uuid) -> ApiResult<Document> {
    sqlx::query_as("SELECT * FROM network_documents WHERE id=$1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)
}

pub(super) async fn access(
    state: &AppState,
    headers: &HeaderMap,
    config: &Configuration,
    write: bool,
) -> ApiResult<()> {
    let capability = if write {
        "network:write"
    } else {
        "network:read"
    };
    crate::control_center::require_capability(state, headers, capability).await?;
    for server in config.servers() {
        crate::control_center::require_server(state, headers, server, capability).await?;
    }
    if let Configuration::Certificate { domain_ids, .. } = config {
        for id in domain_ids {
            let domain = load(state, *id).await?;
            let domain_config = configuration(&domain)?;
            if !matches!(domain_config, Configuration::Domain { .. }) {
                return Err(ApiError::Conflict("证书引用必须为域名台账".into()));
            }
            for server in domain_config.servers() {
                crate::control_center::require_server(state, headers, server, capability).await?;
            }
        }
    }
    Ok(())
}

pub(super) fn configuration(document: &Document) -> ApiResult<Configuration> {
    serde_json::from_value(document.config.clone())
        .map_err(|error| ApiError::Internal(error.into()))
}

async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Document>>> {
    auth::require_admin(&state, &headers).await?;
    let documents = sqlx::query_as::<_, Document>(
        "SELECT * FROM network_documents ORDER BY updated_at DESC,id LIMIT 1000",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut visible = Vec::new();
    for document in documents {
        if access(&state, &headers, &configuration(&document)?, false)
            .await
            .is_ok()
        {
            visible.push(document);
        }
    }
    Ok(Json(visible))
}

async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<Write>,
) -> ApiResult<Json<Value>> {
    input.config.validate()?;
    access(&state, &headers, &input.config, true).await?;
    reference_access(&state, &headers, &input.config).await?;
    let mut tx = state.pool.begin().await?;
    references(&mut tx, &input.config, None).await?;
    tx.rollback().await?;
    Ok(Json(
        json!({"config":input.config,"affected_servers":input.config.servers(),"scope":"configuration_only","execution":"requires_explicit_apply","notes":notes(&input.config)}),
    ))
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<Write>,
) -> ApiResult<(StatusCode, Json<Document>)> {
    input.config.validate()?;
    access(&state, &headers, &input.config, true).await?;
    reference_access(&state, &headers, &input.config).await?;
    let mut tx = state.pool.begin().await?;
    references(&mut tx, &input.config, None).await?;
    let id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO network_documents(id,kind,config,created_at,updated_at) VALUES($1,$2,$3,$4,$4)")
        .bind(id).bind(input.config.kind()).bind(json!(input.config)).bind(now).execute(&mut *tx).await.map_err(unique)?;
    archive(&mut tx, id, "created").await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(load(&state, id).await?)))
}

async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Document>> {
    let document = load(&state, id).await?;
    access(&state, &headers, &configuration(&document)?, false).await?;
    Ok(Json(document))
}

async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(mut input): Json<Write>,
) -> ApiResult<Json<Document>> {
    input.config.validate()?;
    access(&state, &headers, &input.config, true).await?;
    reference_access(&state, &headers, &input.config).await?;
    let mut tx = state.pool.begin().await?;
    let previous: Document =
        sqlx::query_as("SELECT * FROM network_documents WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    access(&state, &headers, &configuration(&previous)?, true).await?;
    if input.revision != Some(previous.revision) || input.config.kind() != previous.kind {
        return Err(ApiError::Conflict(
            "配置已修改或类型发生变化，请刷新后重试".into(),
        ));
    }
    references(&mut tx, &input.config, Some(id)).await?;
    sqlx::query(
        "UPDATE network_documents SET config=$2,revision=revision+1,updated_at=$3 WHERE id=$1",
    )
    .bind(id)
    .bind(json!(input.config))
    .bind(sinan_protocol::now_timestamp())
    .execute(&mut *tx)
    .await
    .map_err(unique)?;
    archive(&mut tx, id, "updated").await?;
    tx.commit().await?;
    Ok(Json(load(&state, id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delete {
    revision: i64,
    confirmed: bool,
}
async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Delete>,
) -> ApiResult<StatusCode> {
    let document = load(&state, id).await?;
    let config = configuration(&document)?;
    access(&state, &headers, &config, true).await?;
    if !input.confirmed {
        return Err(ApiError::BadRequest(
            "删除台账需要明确确认；实际服务不会因此停止".into(),
        ));
    }
    if matches!(config,Configuration::Forwarding{owner,enabled:true,..} if owner=="sinan") {
        return Err(ApiError::Conflict(
            "请先停止受管转发并核对进程结果，再删除台账".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM network_documents WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if revision != Some(input.revision) {
        return Err(ApiError::Conflict("配置版本已改变".into()));
    }
    let referenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_documents WHERE id<>$1 AND (config->'domain_ids' ? $2 OR config->'dependency_ids' ? $2)) OR EXISTS(SELECT 1 FROM network_certificate_versions WHERE certificate_id=$1) OR EXISTS(SELECT 1 FROM network_dns_challenges WHERE certificate_id=$1 AND status<>'cleaned') OR EXISTS(SELECT 1 FROM network_operation_links WHERE document_id=$1) OR EXISTS(SELECT 1 FROM network_observations WHERE document_id=$1) OR EXISTS(SELECT 1 FROM network_acme_plans WHERE certificate_id=$1) OR EXISTS(SELECT 1 FROM network_acme_jobs WHERE certificate_id=$1) OR EXISTS(SELECT 1 FROM network_certificate_deployment_previews WHERE certificate_id=$1) OR EXISTS(SELECT 1 FROM network_certificate_deployments WHERE certificate_id=$1)").bind(id).bind(id.to_string()).fetch_one(&mut *tx).await?;
    if referenced {
        return Err(ApiError::Conflict(
            "存在关联配置、执行观测或证书历史；请保留台账并解除关联，历史不会随删除丢失".into(),
        ));
    }
    archive(&mut tx, id, "deleted").await?;
    sqlx::query("DELETE FROM network_observations WHERE document_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM network_dns_challenges WHERE certificate_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM network_documents WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    let document = load(&state, id).await?;
    access(&state, &headers, &configuration(&document)?, false).await?;
    let entries:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'revision',revision,'config',config,'action',action,'occurred_at',occurred_at) FROM network_document_history WHERE document_id=$1 ORDER BY occurred_at DESC,id LIMIT 100").bind(id).fetch_all(&state.pool).await?;
    let mut visible = Vec::new();
    for entry in entries {
        if let Ok(config) = serde_json::from_value::<Configuration>(entry["config"].clone())
            && access(&state, &headers, &config, false).await.is_ok()
        {
            visible.push(entry);
        }
    }
    Ok(Json(visible))
}

pub(super) async fn references(
    tx: &mut Transaction<'_, Postgres>,
    config: &Configuration,
    own: Option<Uuid>,
) -> ApiResult<()> {
    for server in config.servers() {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL) AND NOT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1)").bind(server).fetch_one(&mut **tx).await?;
        if !valid {
            return Err(ApiError::Conflict("关联服务器不存在或正在退役".into()));
        }
    }
    if let Configuration::Forwarding {
        server_id,
        listen_address,
        listen_port,
        protocol,
        owner,
        enabled: true,
        ..
    } = config
        && owner == "sinan"
    {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "sinan-forward:{server_id}:{protocol}:{listen_port}"
            ))
            .execute(&mut **tx)
            .await?;
        let conflicts:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_documents WHERE kind='forwarding' AND ($1::UUID IS NULL OR id<>$1) AND (config->>'server_id')::bigint=$2 AND (config->>'listen_port')::integer=$3 AND config->>'protocol'=$4 AND config->>'owner'='sinan' AND config->>'enabled'='true' AND (config->>'listen_address'=$5 OR config->>'listen_address' IN ('0.0.0.0','::') OR $5 IN ('0.0.0.0','::')))").bind(own).bind(server_id).bind(i32::from(*listen_port)).bind(protocol).bind(listen_address).fetch_one(&mut **tx).await?;
        if conflicts {
            return Err(ApiError::Conflict(
                "受管监听与已有或待部署转发冲突；通配监听也计入冲突".into(),
            ));
        }
    }
    let (ids, kind) = match config {
        Configuration::Certificate { domain_ids, .. } => (domain_ids.as_slice(), Some("domain")),
        Configuration::Forwarding { dependency_ids, .. } => (dependency_ids.as_slice(), None),
        _ => ([].as_slice(), None),
    };
    for id in ids {
        if Some(*id) == own {
            return Err(ApiError::BadRequest("配置不能依赖自身".into()));
        }
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_documents WHERE id=$1 AND ($2::TEXT IS NULL OR kind=$2))").bind(id).bind(kind).fetch_one(&mut **tx).await?;
        if !exists {
            return Err(ApiError::Conflict("关联网络配置不存在或类型错误".into()));
        }
    }
    let dns = match config {
        Configuration::Domain { ddns_rule_ids, .. } => ddns_rule_ids.clone(),
        Configuration::Certificate {
            renewal: super::models::RenewalPolicy::Dns01 { ddns_rule_id, .. },
            ..
        } => vec![*ddns_rule_id],
        _ => vec![],
    };
    for id in dns {
        if !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM ddns_rules WHERE id=$1)")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?
        {
            return Err(ApiError::Conflict("DDNS凭据引用不存在".into()));
        }
    }
    Ok(())
}

pub(super) async fn reference_access(
    state: &AppState,
    headers: &HeaderMap,
    config: &Configuration,
) -> ApiResult<()> {
    let ids = match config {
        Configuration::Certificate { domain_ids, .. } => domain_ids.clone(),
        Configuration::Forwarding { dependency_ids, .. } => dependency_ids.clone(),
        _ => vec![],
    };
    for id in ids {
        let document = load(state, id).await?;
        access(state, headers, &configuration(&document)?, false).await?;
    }
    let rules = match config {
        Configuration::Domain { ddns_rule_ids, .. } => ddns_rule_ids.clone(),
        Configuration::Certificate {
            renewal: super::models::RenewalPolicy::Dns01 { ddns_rule_id, .. },
            ..
        } => vec![*ddns_rule_id],
        _ => vec![],
    };
    for id in rules {
        let server: i64 = sqlx::query_scalar("SELECT server_id FROM ddns_rules WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
        crate::control_center::require_server(state, headers, server, "dns:read").await?;
    }
    Ok(())
}

pub(super) async fn archive(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    action: &str,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO network_document_history(id,document_id,kind,revision,config,action,occurred_at) SELECT $2,id,kind,revision,config,$3,$4 FROM network_documents WHERE id=$1")
        .bind(id).bind(Uuid::new_v4()).bind(action).bind(sinan_protocol::now_timestamp()).execute(&mut **tx).await?;
    Ok(())
}

fn notes(config: &Configuration) -> Vec<&'static str> {
    match config {
        Configuration::Certificate { .. } => vec![
            "证书签发、保存、部署、握手验证分别记录",
            "受管部署引用加密凭据中心私钥，只交付到明确授权的目标Agent",
            "填写受管证书与私钥路径后才能生成批量部署预览",
        ],
        Configuration::Forwarding { .. } => vec![
            "配置关系不代表已连通",
            "Linux受管转发依赖systemd与socat；外部映射仅保存台账",
            "转发服务目前为临时服务，重启后需重新确认",
        ],
        Configuration::Tuning { .. } => vec![
            "临时应用前必须成功安排本机恢复计时器",
            "确认临时结果后单独持久化；不保证故障恢复覆盖所有情况",
        ],
        Configuration::Tunnel { .. } => vec![
            "独立本机SSH隧道密钥",
            "中转公钥须明确核对并授权",
            "服务状态不代表外部实际可达",
        ],
        Configuration::Mesh { .. } => vec![
            "本机私钥不回传",
            "禁止默认路由及公有网段",
            "握手与实际业务可达分别记录",
        ],
        Configuration::Firewall { .. } => vec![
            "只修改本配置独立的受管入站表",
            "保留管理端口和已建立连接，不改外部规则",
            "临时应用前安排本机恢复，持久化另行确认",
        ],
        _ => vec!["只保存台账；实际观测独立显示"],
    }
}
pub(super) fn unique(error: sqlx::Error) -> ApiError {
    if error
        .as_database_error()
        .is_some_and(|value| value.is_unique_violation())
    {
        ApiError::Conflict("域名或受管监听端点已被其他配置占用".into())
    } else {
        ApiError::Database(error)
    }
}
