use super::{
    documents,
    models::{CertificateTarget, Configuration},
    x509,
};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::fleet::Operation;
use sqlx::Row;
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/certificates/{id}/deployment-preview",
            post(preview),
        )
        .route(
            "/api/network-configuration/deployment-previews/{id}/apply",
            post(apply),
        )
        .route(
            "/api/network-configuration/certificates/{id}/deployments",
            get(list),
        )
        .route(
            "/api/agent/v1/network-certificates/{id}/material",
            get(material),
        )
        .route(
            "/api/agent/v1/network-certificates/{id}/inspection",
            get(inspection),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    version_id: Uuid,
    key_credential_id: Option<Uuid>,
    target_indexes: Vec<usize>,
    adopt_existing: bool,
}
async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Preview>,
) -> ApiResult<Json<Value>> {
    let document = documents::load(&state, id).await?;
    let config = documents::configuration(&document)?;
    documents::access(&state, &headers, &config, true).await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    let Configuration::Certificate { targets, .. } = config else {
        return Err(ApiError::BadRequest("请选择证书台账".into()));
    };
    if input.target_indexes.is_empty() || input.target_indexes.len() > 100 {
        return Err(ApiError::BadRequest("请选择1–100个明确部署目标".into()));
    }
    let version=sqlx::query("SELECT public_chain,fingerprint,not_after FROM network_certificate_versions WHERE id=$1 AND certificate_id=$2").bind(input.version_id).bind(id).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    if version.get::<i64, _>("not_after") <= sinan_protocol::now_timestamp() {
        return Err(ApiError::Conflict("目标证书已到期".into()));
    }
    let secret = if let Some(secret) = input.key_credential_id {
        secret
    } else {
        sqlx::query_scalar::<_,Uuid>("SELECT key_secret_ref FROM network_acme_jobs WHERE version_id=$1 AND key_secret_ref IS NOT NULL ORDER BY created_at DESC LIMIT 1").bind(input.version_id).fetch_optional(&state.pool).await?.ok_or_else(||ApiError::Conflict("手工证书需选择凭据中心的私钥引用".into()))?
    };
    let pem: String = version.get("public_chain");
    let certificate = x509::parse(&pem)?;
    validated_key(&state, secret, &pem).await?;
    let mut selected = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for index in input.target_indexes {
        if !seen.insert(index) {
            return Err(ApiError::BadRequest("部署目标不能重复".into()));
        }
        let target = targets
            .get(index)
            .ok_or_else(|| ApiError::BadRequest("部署目标不存在".into()))?;
        if target.certificate_path.is_none()
            || target.private_key_path.is_none()
            || !x509::covers(&certificate.names, &target.domain)
        {
            return Err(ApiError::BadRequest(
                "部署目标必须填写两条受管路径且被证书SAN覆盖".into(),
            ));
        }
        crate::control_center::require_server(&state, &headers, target.server_id, "network:write")
            .await?;
        selected.push(target.clone());
    }
    let preview = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("INSERT INTO network_certificate_deployment_previews(id,certificate_id,certificate_revision,version_id,key_secret_ref,snapshot,adopt_existing,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(preview).bind(id).bind(document.revision).bind(input.version_id).bind(secret).bind(json!(selected)).bind(input.adopt_existing).bind(now).bind(now+300).execute(&state.pool).await?;
    Ok(Json(
        json!({"id":preview,"certificate_id":id,"revision":document.revision,"version_id":input.version_id,"fingerprint":certificate.fingerprint,"targets":selected,"adopt_existing":input.adopt_existing,"expires_at":now+300,"impact":"write_certificate_and_protected_key_then_service_reload","handshake":"separate_verification"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    confirmed: bool,
}
async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Apply>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_recent_proof(&state, &headers).await?;
    if !input.confirmed {
        return Err(ApiError::BadRequest(
            "请确认每台服务器、服务、文件路径与重载影响".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    let row =
        sqlx::query("SELECT * FROM network_certificate_deployment_previews WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    if row.get::<Option<i64>, _>("applied_at").is_some()
        || row.get::<i64, _>("expires_at") <= sinan_protocol::now_timestamp()
    {
        return Err(ApiError::Conflict(
            "部署预览已使用或过期；未知结果不会自动重新分发".into(),
        ));
    }
    let certificate: Uuid = row.get("certificate_id");
    let document = documents::load(&state, certificate).await?;
    documents::access(
        &state,
        &headers,
        &documents::configuration(&document)?,
        true,
    )
    .await?;
    if document.revision != row.get::<i64, _>("certificate_revision") {
        return Err(ApiError::Conflict("证书目标台账已改变，请重新预览".into()));
    }
    let targets: Vec<CertificateTarget> =
        serde_json::from_value(row.get("snapshot")).map_err(anyhow::Error::from)?;
    let actor =
        crate::control_center::require_capability(&state, &headers, "network:write").await?;
    let mut deployments = Vec::new();
    for target in targets {
        crate::control_center::require_server(&state, &headers, target.server_id, "network:write")
            .await?;
        let deployment = Uuid::new_v4();
        sqlx::query("INSERT INTO network_certificate_deployments(id,certificate_id,certificate_revision,version_id,key_secret_ref,server_id,target,adopt_existing,requested_by,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'awaiting_queue',$10)").bind(deployment).bind(certificate).bind(document.revision).bind(row.get::<Uuid,_>("version_id")).bind(row.get::<Uuid,_>("key_secret_ref")).bind(target.server_id).bind(json!(target)).bind(row.get::<bool,_>("adopt_existing")).bind(actor).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
        deployments.push((deployment, target.server_id));
    }
    sqlx::query("UPDATE network_certificate_deployment_previews SET applied_at=$2 WHERE id=$1")
        .bind(id)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut results = Vec::new();
    for (deployment, server) in deployments {
        match crate::fleet::enqueue_for_actor(
            &state,
            server,
            actor,
            Operation::CertificateDeploy {
                deployment_id: deployment,
            },
        )
        .await
        {
            Ok(operation) => {
                sqlx::query("UPDATE network_certificate_deployments SET operation_id=$2,status='queued' WHERE id=$1").bind(deployment).bind(operation).execute(&state.pool).await?;
                results.push(json!({"id":deployment,"server_id":server,"operation_id":operation,"status":"queued"}));
            }
            Err(_) => {
                sqlx::query("UPDATE network_certificate_deployments SET status='queue_rejected' WHERE id=$1").bind(deployment).execute(&state.pool).await?;
                results.push(json!({"id":deployment,"server_id":server,"status":"queue_rejected","reason":"agent_capability_policy_or_lifecycle"}));
            }
        }
    }
    Ok(Json(
        json!({"targets":results,"deployed":false,"handshake_verified":false}),
    ))
}

async fn material(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let server = auth::require_agent(&state, &headers).await?;
    let row=sqlx::query("SELECT d.*,v.public_chain,v.fingerprint,v.not_after,o.status AS operation_status,o.expires_at AS operation_expires_at FROM network_certificate_deployments d JOIN network_certificate_versions v ON v.id=d.version_id JOIN fleet_operations o ON o.id=d.operation_id WHERE d.id=$1 AND d.server_id=$2").bind(id).bind(server).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    if row.get::<String, _>("operation_status") != "dispatched"
        || row.get::<i64, _>("operation_expires_at") <= sinan_protocol::now_timestamp()
        || row.get::<i64, _>("not_after") <= sinan_protocol::now_timestamp()
    {
        return Err(ApiError::Conflict(
            "部署未派发、派发已过期或证书已到期".into(),
        ));
    }
    crate::control_center::require_actor_server(
        &state,
        row.get("requested_by"),
        server,
        "network:write",
    )
    .await?;
    let certificate: Uuid = row.get("certificate_id");
    let document = documents::load(&state, certificate).await?;
    if document.revision != row.get::<i64, _>("certificate_revision") {
        return Err(ApiError::Conflict("部署台账已改变，停止材料分发".into()));
    }
    let target: CertificateTarget =
        serde_json::from_value(row.get("target")).map_err(anyhow::Error::from)?;
    let pem: String = row.get("public_chain");
    let key = validated_key(&state, row.get("key_secret_ref"), &pem).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, private"),
    );
    Ok((
        response_headers,
        Json(
            json!({"deployment_id":id,"certificate_id":certificate,"version_id":row.get::<Uuid,_>("version_id"),"certificate_path":target.certificate_path,"private_key_path":target.private_key_path,"service":target.service,"public_chain":pem,"private_key":key,"fingerprint":row.get::<String,_>("fingerprint"),"adopt_existing":row.get::<bool,_>("adopt_existing")}),
        ),
    ))
}

async fn inspection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let server = auth::require_agent(&state, &headers).await?;
    let row=sqlx::query("SELECT d.certificate_id,d.version_id,d.target,v.fingerprint FROM network_certificate_deployments d JOIN network_certificate_versions v ON v.id=d.version_id WHERE d.id=$1 AND d.server_id=$2 AND d.operation_id IS NOT NULL").bind(id).bind(server).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let target: CertificateTarget =
        serde_json::from_value(row.get("target")).map_err(anyhow::Error::from)?;
    Ok(Json(
        json!({"deployment_id":id,"certificate_id":row.get::<Uuid,_>("certificate_id"),"version_id":row.get::<Uuid,_>("version_id"),"certificate_path":target.certificate_path,"service":target.service,"fingerprint":row.get::<String,_>("fingerprint")}),
    ))
}

async fn validated_key(state: &AppState, id: Uuid, pem: &str) -> ApiResult<String> {
    let secret = crate::control_center::credentials::resolve_reference(
        state,
        id,
        "certificate",
        "certificate-deployment",
    )
    .await?;
    let key = secret["private_key"]
        .as_str()
        .filter(|value| value.len() <= 16384)
        .ok_or_else(|| ApiError::Conflict("证书凭据需包含有效private_key".into()))?;
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::Conflict("公开证书格式无效".into()))?;
    let private = PrivateKeyDer::from_pem_slice(key.as_bytes())
        .map_err(|_| ApiError::Conflict("私钥格式无效".into()))?;
    rustls::sign::CertifiedKey::from_der(chain, private, &rustls::crypto::ring::default_provider())
        .map_err(|_| ApiError::Conflict("私钥与选定证书不匹配".into()))?;
    Ok(key.into())
}
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    let document = documents::load(&state, id).await?;
    documents::access(
        &state,
        &headers,
        &documents::configuration(&document)?,
        false,
    )
    .await?;
    let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',d.id,'version_id',d.version_id,'target',d.target,'created_at',d.created_at,'operation_id',d.operation_id,'status',CASE WHEN o.status='dispatched' AND o.expires_at<$2 THEN 'unknown' ELSE COALESCE(o.status,d.status) END,'receipt',o.result) FROM network_certificate_deployments d LEFT JOIN fleet_operations o ON o.id=d.operation_id WHERE d.certificate_id=$1 ORDER BY d.created_at DESC LIMIT 200").bind(id).bind(sinan_protocol::now_timestamp()).fetch_all(&state.pool).await?;
    let mut visible = Vec::new();
    for row in rows {
        if let Some(server) = row["target"]["server_id"].as_i64()
            && crate::control_center::require_server(&state, &headers, server, "network:read")
                .await
                .is_ok()
        {
            visible.push(row);
        }
    }
    Ok(Json(visible))
}
