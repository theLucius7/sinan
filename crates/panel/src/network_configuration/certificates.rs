use super::{documents, models::Configuration, x509};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{net::SocketAddr, time::Duration};
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/certificates/{id}/versions",
            get(versions).post(import),
        )
        .route(
            "/api/network-configuration/certificates/{id}/select-version",
            post(select),
        )
        .route(
            "/api/network-configuration/certificates/{id}/verify",
            post(verify),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    public_chain: String,
    revision: i64,
}
async fn import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Import>,
) -> ApiResult<Json<Value>> {
    let document = documents::load(&state, id).await?;
    let config = documents::configuration(&document)?;
    documents::access(&state, &headers, &config, true).await?;
    let Configuration::Certificate { domain_ids, .. } = &config else {
        return Err(ApiError::BadRequest("请选择证书台账".into()));
    };
    let certificate = x509::parse(&input.public_chain).map_err(|_| {
        ApiError::BadRequest("公钥证书链、有效期或DNS覆盖域名无效；此接口拒绝私钥".into())
    })?;
    let now = sinan_protocol::now_timestamp();
    if certificate.not_after <= now || certificate.not_before > now + 60 {
        return Err(ApiError::BadRequest("证书尚未生效或已到期".into()));
    }
    for domain in domain_ids {
        let name: String = sqlx::query_scalar(
            "SELECT config->>'name' FROM network_documents WHERE id=$1 AND kind='domain'",
        )
        .bind(domain)
        .fetch_one(&state.pool)
        .await?;
        if !x509::covers(&certificate.names, &name) {
            return Err(ApiError::BadRequest("证书SAN未覆盖台账域名".into()));
        }
    }
    let mut tx = state.pool.begin().await?;
    let revision: i64 =
        sqlx::query_scalar("SELECT revision FROM network_documents WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if revision != input.revision {
        return Err(ApiError::Conflict("证书台账已改变，请刷新".into()));
    }
    let version = Uuid::new_v4();
    let version_revision: i64 = sqlx::query_scalar("SELECT COALESCE(max(revision),0)+1 FROM network_certificate_versions WHERE certificate_id=$1").bind(id).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO network_certificate_versions(id,certificate_id,revision,public_chain,fingerprint,not_before,not_after,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(version).bind(id).bind(version_revision).bind(input.public_chain).bind(&certificate.fingerprint).bind(certificate.not_before).bind(certificate.not_after).bind(now).execute(&mut *tx).await?;
    sqlx::query("UPDATE network_documents SET active_version=$2,revision=revision+1,updated_at=$3 WHERE id=$1").bind(id).bind(version).bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":version,"fingerprint":certificate.fingerprint,"not_before":certificate.not_before,"not_after":certificate.not_after,"names":certificate.names,"issued":"external_source","saved":true,"deployed":false,"handshake_verified":false}),
    ))
}

async fn versions(
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
    Ok(Json(sqlx::query_scalar("SELECT jsonb_build_object('id',id,'revision',revision,'fingerprint',fingerprint,'not_before',not_before,'not_after',not_after,'created_at',created_at) FROM network_certificate_versions WHERE certificate_id=$1 ORDER BY revision DESC LIMIT 100").bind(id).fetch_all(&state.pool).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Select {
    version_id: Uuid,
    revision: i64,
    confirmed: bool,
}
async fn select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Select>,
) -> ApiResult<Json<Value>> {
    let document = documents::load(&state, id).await?;
    let config = documents::configuration(&document)?;
    documents::access(&state, &headers, &config, true).await?;
    if !input.confirmed {
        return Err(ApiError::BadRequest(
            "切换期望证书版本需明确确认；部署须由维护方另行执行".into(),
        ));
    }
    let pem:String=sqlx::query_scalar("SELECT public_chain FROM network_certificate_versions WHERE certificate_id=$1 AND id=$2 AND not_after>$3").bind(id).bind(input.version_id).bind(sinan_protocol::now_timestamp()).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let cert = x509::parse(&pem)?;
    if let Configuration::Certificate { targets, .. } = config {
        for target in targets {
            if !x509::covers(&cert.names, &target.domain) {
                return Err(ApiError::Conflict("历史版本不覆盖当前部署目标域名".into()));
            }
        }
    } else {
        return Err(ApiError::BadRequest("请选择证书台账".into()));
    }
    let changed=sqlx::query("UPDATE network_documents SET active_version=$2,revision=revision+1,updated_at=$4 WHERE id=$1 AND revision=$3").bind(id).bind(input.version_id).bind(input.revision).bind(sinan_protocol::now_timestamp()).execute(&state.pool).await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::Conflict("台账版本已改变".into()));
    }
    Ok(Json(
        json!({"active_version":input.version_id,"deployment":"requires_explicit_target_preview","handshake":"not_verified"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verify {
    target_index: usize,
}
async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Verify>,
) -> ApiResult<Json<Value>> {
    let document = documents::load(&state, id).await?;
    let config = documents::configuration(&document)?;
    documents::access(&state, &headers, &config, true).await?;
    let Configuration::Certificate { targets, .. } = config else {
        return Err(ApiError::BadRequest("请选择证书台账".into()));
    };
    let target = targets
        .get(input.target_index)
        .ok_or_else(|| ApiError::BadRequest("证书部署目标不存在".into()))?;
    let version = document
        .active_version
        .ok_or_else(|| ApiError::Conflict("尚未保存期望证书版本".into()))?;
    let row=sqlx::query("SELECT fingerprint,not_after FROM network_certificate_versions WHERE certificate_id=$1 AND id=$2").bind(id).bind(version).fetch_one(&state.pool).await?;
    let expected: String = row.get("fingerprint");
    let result = handshake(&target.domain, target.port, &expected).await;
    let observed_at = sinan_protocol::now_timestamp();
    let value = match result {
        Ok(observed) => {
            json!({"status":"verified","fingerprint":observed,"version_id":version,"from":"panel","to":format!("{}:{}",target.domain,target.port),"trust_chain":"validated","hostname":"validated","observed_at":observed_at})
        }
        Err(code) => {
            json!({"status":"failed","error_code":code,"version_id":version,"from":"panel","to":format!("{}:{}",target.domain,target.port),"observed_at":observed_at})
        }
    };
    sqlx::query("INSERT INTO network_observations(id,document_id,server_id,source,result,observed_at) VALUES($1,$2,$3,'panel_tls_handshake',$4,$5)").bind(Uuid::new_v4()).bind(id).bind(target.server_id).bind(&value).bind(observed_at).execute(&state.pool).await?;
    Ok(Json(value))
}

async fn handshake(host: &str, port: u16, expected: &str) -> Result<String, &'static str> {
    let resolved: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| "dns_timeout")?
    .map_err(|_| "dns_failed")?
    .take(16)
    .collect();
    if resolved.is_empty()
        || resolved
            .iter()
            .any(|address| !crate::ip_quality::public_ip(address.ip()))
    {
        return Err("public_address_required");
    }
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "tls_configuration_failed")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| "invalid_tls_hostname")?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut connection = None;
        for address in resolved {
            if let Ok(Ok(stream)) = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(address),
            )
            .await
            {
                connection = Some(stream);
                break;
            }
        }
        let stream = connection.ok_or("connection_failed")?;
        let tls = connector
            .connect(name, stream)
            .await
            .map_err(|_| "tls_certificate_or_handshake_failed")?;
        let certificate = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or("certificate_unavailable")?;
        use sha2::{Digest, Sha256};
        let observed = format!("{:x}", Sha256::digest(certificate.as_ref()));
        if observed != expected {
            return Err("deployed_certificate_mismatch");
        }
        Ok(observed)
    })
    .await
    .map_err(|_| "handshake_timeout")?
}
