use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sinan_protocol::Artifact;

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
    pub agent_version: Option<String>,
    pub agent_target: Option<String>,
    pub platform: Option<String>,
}

#[derive(Serialize)]
pub struct ArtifactEntry {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub sha256: String,
    pub bytes: u64,
}

async fn verified_bytes(
    state: &AppState,
    name: &str,
    version: &str,
    arch: &str,
) -> ApiResult<(Vec<u8>, String)> {
    let (bytes, hash, _) = crate::releases::artifact(state, name, version, arch).await?;
    Ok((bytes, hash))
}

pub async fn descriptor(
    state: &AppState,
    name: &str,
    version: &str,
    arch: &str,
) -> ApiResult<Artifact> {
    let (_, sha256, proof) = crate::releases::artifact(state, name, version, arch).await?;
    Ok(Artifact {
        url: format!(
            "{}/api/agent/v1/artifacts/{name}/{version}/{arch}",
            state.config.public_url
        ),
        sha256,
        proof: Some(proof),
    })
}

pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, version, arch)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let server_id = auth::require_agent(&state, &headers).await?;
    require_signed_agent(&state, server_id).await?;
    if name == "agent" {
        return Err(ApiError::Conflict(
            "Agent 请从 GitHub Release 下载，面板不再提供二进制".into(),
        ));
    }
    bytes_response(&state, &name, &version, &arch).await
}

pub async fn bootstrap(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
    Path((_version, _arch)): Path<(String, String)>,
) -> ApiResult<Response> {
    crate::servers::validate_enrollment(&state.pool, &query.token).await?;
    Err(ApiError::Conflict(
        "Agent 请使用从 GitHub 下载的可信安装器，面板不再提供二进制".into(),
    ))
}

async fn bytes_response(
    state: &AppState,
    name: &str,
    version: &str,
    arch: &str,
) -> ApiResult<Response> {
    let (bytes, _) = verified_bytes(state, name, version, arch).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ArtifactEntry>>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(crate::releases::entries(&state).await?))
}

pub async fn require_signed_agent(state: &AppState, server_id: i64) -> ApiResult<()> {
    let capabilities: serde_json::Value =
        sqlx::query_scalar("SELECT capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL")
            .bind(server_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::Unauthorized)?;
    if !capabilities.as_array().is_some_and(|values| {
        values
            .iter()
            .any(|v| v.as_str() == Some(sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY))
    }) {
        return Err(ApiError::Conflict(
            "此 Agent 尚不支持制品验签，请先使用可信安装器升级；已运行配置和流量上报继续保留"
                .into(),
        ));
    }
    Ok(())
}

pub async fn install_script(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
) -> ApiResult<Response> {
    crate::servers::validate_enrollment(&state.pool, &query.token).await?;
    let installation = crate::installation::select(
        &state,
        query.agent_version.as_deref(),
        &query.token,
        query.platform.as_deref(),
        query.agent_target.as_deref(),
    )
    .await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(installation)).into_response())
}

pub async fn install_powershell(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
) -> ApiResult<Response> {
    crate::servers::validate_enrollment(&state.pool, &query.token).await?;
    let installation = crate::installation::select(
        &state,
        query.agent_version.as_deref(),
        &query.token,
        Some("windows"),
        query.agent_target.as_deref(),
    )
    .await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(installation)).into_response())
}
