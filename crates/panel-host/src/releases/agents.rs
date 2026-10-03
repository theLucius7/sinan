use super::*;
use axum::{
    extract::Query,
    http::header,
    response::{IntoResponse, Response},
};
use serde::Serialize;

const MINIMUM_INSTALLATION_VERSION: (u64, u64, u64) = (0, 3, 0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentVersion {
    pub version: String,
    pub tag: String,
    pub targets: Vec<String>,
    pub cached_targets: Vec<String>,
    pub protocol_min: u16,
    pub protocol_max: u16,
}

#[derive(Serialize)]
pub struct AgentVersions {
    pub policy: AgentInstallationPolicy,
    pub versions: Vec<AgentVersion>,
}

#[derive(Serialize)]
pub struct AgentInstallationPolicy {
    pub default_version: &'static str,
    pub selection: &'static str,
    pub minimum_version: String,
}

impl AgentVersions {
    fn new(versions: Vec<AgentVersion>) -> Self {
        let (major, minor, patch) = MINIMUM_INSTALLATION_VERSION;
        Self {
            policy: AgentInstallationPolicy {
                default_version: "latest",
                selection: "highest_stable_signed_protocol_compatible_for_target",
                minimum_version: format!("{major}.{minor}.{patch}"),
            },
            versions,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentVersionQuery {
    pub target: Option<String>,
    pub agent_version: Option<String>,
    pub platform: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapVersionQuery {
    pub token: String,
    pub target: Option<String>,
    pub agent_version: Option<String>,
    pub platform: Option<String>,
}

fn linux_target(target: &str) -> bool {
    matches!(target, "amd64" | "arm64") || target.starts_with("linux-")
}

fn version_key(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+']).next()?;
    let suffix = version.strip_prefix(core)?;
    if !suffix.is_empty()
        && (suffix.len() == 1
            || !suffix[1..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    {
        return None;
    }
    let parts: Vec<_> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

fn validate_filter(target: Option<&str>, platform: Option<&str>) -> ApiResult<()> {
    if let Some(target) = target {
        selection::validate_targets(&[target.into()])?;
    }
    if platform.is_some_and(|platform| !matches!(platform, "linux" | "unix" | "windows")) {
        return Err(ApiError::BadRequest("请选择有效的安装平台".into()));
    }
    Ok(())
}

fn valid_agent(release: &StoredRelease, artifact: &VerifiedArtifact) -> bool {
    let entry = artifact.metadata();
    let metadata = release.verified.metadata();
    let binary_name = if entry.arch.starts_with("windows-") {
        "sinan-agent.exe"
    } else {
        "sinan-agent"
    };
    entry.name == "agent"
        && entry.format == "raw"
        && entry.binary_name == binary_name
        && entry.archive_size <= 128 * 1024 * 1024
        // Pre-0.3 historical binaries lack the current installation/service CLI.
        // This policy is not proof of arbitrary newer bytes: signature, payload
        // and the Agent's independent installation/cache checks still apply.
        && version_key(&entry.version)
            .is_some_and(|version| version >= MINIMUM_INSTALLATION_VERSION)
        && (linux_target(&entry.arch) || sinan_protocol::release_version(&entry.version).is_some())
        && metadata.tag == format!("agent-v{}", entry.version)
        && metadata.protocol_min <= PROTOCOL_MAX
        && metadata.protocol_max >= PROTOCOL_MIN
}

async fn versions(
    state: &AppState,
    target: Option<&str>,
    version: Option<&str>,
    platform: Option<&str>,
) -> ApiResult<Vec<AgentVersion>> {
    let target = target.filter(|target| *target != "auto");
    validate_filter(target, platform)?;
    let version = version.filter(|version| *version != "latest");
    let targets = target.map(|target| selection::candidates(target, "raw"));
    let releases = released(state).await?;
    inventory(&releases).map_err(invalid)?;
    let mut values = BTreeMap::new();
    for release in &releases {
        let installer = ordinary_bytes(&release.directory.join("install.sh"), MAX_INSTALLER)
            .await
            .map_err(invalid)?;
        checked(
            storage::installer_valid(&release.verified, &installer),
            "signed installer digest differs",
        )?;
        for entry in &release.verified.metadata().artifacts {
            if entry.name != "agent" || version.is_some_and(|version| version != entry.version) {
                continue;
            }
            if version.is_none() && sinan_protocol::release_version(&entry.version).is_none() {
                continue;
            }
            let artifact = release
                .verified
                .artifact(&entry.name, &entry.version, &entry.arch)
                .map_err(invalid)?;
            if !valid_agent(release, &artifact)
                || targets
                    .as_ref()
                    .is_some_and(|targets| !targets.contains(&entry.arch))
                || match platform {
                    Some("linux") => !linux_target(&entry.arch),
                    Some("unix") => entry.arch.starts_with("windows-"),
                    Some("windows") => !entry.arch.starts_with("windows-"),
                    _ => false,
                }
            {
                continue;
            }
            let key = (
                version_key(&entry.version).expect("validated version"),
                entry.version.clone(),
            );
            let metadata = release.verified.metadata();
            let value = values.entry(key).or_insert_with(|| AgentVersion {
                version: entry.version.clone(),
                tag: metadata.tag.clone(),
                targets: Vec::new(),
                cached_targets: Vec::new(),
                protocol_min: metadata.protocol_min,
                protocol_max: metadata.protocol_max,
            });
            value.targets.push(entry.arch.clone());
            if release.paths.contains(artifact.path()) {
                let bytes =
                    storage::existing_bytes(&release.directory.join(artifact.path()), MAX_ARTIFACT)
                        .await
                        .map_err(invalid)?;
                if bytes.is_some_and(|bytes| verify_payload(&artifact, &bytes).is_ok()) {
                    value.cached_targets.push(entry.arch.clone());
                }
            }
        }
    }
    Ok(values
        .into_values()
        .rev()
        .map(|mut value| {
            value.targets.sort();
            value.cached_targets.sort();
            value
        })
        .collect())
}

/// Lists signed identities in the supported installation line and protocol range.
pub async fn agent_versions(
    state: &AppState,
    target: Option<&str>,
    version: Option<&str>,
) -> ApiResult<Vec<AgentVersion>> {
    versions(state, target, version, None).await
}

pub(crate) async fn selection_error(
    state: &AppState,
    version: Option<&str>,
) -> ApiResult<ApiError> {
    let Some(version) = version.filter(|version| *version != "latest") else {
        return Ok(ApiError::Conflict(
            "请先导入对应平台且协议兼容的已签名 Agent Release".into(),
        ));
    };
    let releases = released(state).await?;
    let matching: Vec<_> = releases
        .iter()
        .filter(|release| {
            release
                .verified
                .metadata()
                .artifacts
                .iter()
                .any(|entry| entry.name == "agent" && entry.version == version)
        })
        .collect();
    let reason = if matching.is_empty() {
        "所选 Agent 版本尚未导入已校验的签名 Release"
    } else if matching.iter().all(|release| {
        let metadata = release.verified.metadata();
        metadata.protocol_min > PROTOCOL_MAX || metadata.protocol_max < PROTOCOL_MIN
    }) {
        "所选 Agent 版本与当前面板协议不兼容，请选择兼容的已签名版本"
    } else if version_key(version).is_some_and(|version| version < MINIMUM_INSTALLATION_VERSION) {
        "所选历史 Agent 不支持当前标准安装与服务合同：0.1/0.2 原制品缺少所需的验签、缓存预检或 supervisor；补签元数据不能补齐这些命令。历史制品与身份保留，请选择 0.3.0 或更新的兼容已签版本"
    } else {
        "所选 Agent 版本不包含该平台可安装的制品，请核对平台、架构及稳定版本要求"
    };
    Ok(ApiError::Conflict(reason.into()))
}

pub async fn select_agent_for_target(
    state: &AppState,
    version: Option<&str>,
    target: Option<&str>,
) -> ApiResult<(String, String)> {
    let target = target.filter(|target| *target != "auto");
    let selected = versions(state, target, version, target.is_none().then_some("linux"))
        .await?
        .into_iter()
        .next();
    match selected {
        Some(release) => Ok((release.version, release.tag)),
        None => Err(selection_error(state, version).await?),
    }
}

pub async fn list_agent_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentVersionQuery>,
) -> ApiResult<Response> {
    auth::require_admin(&state, &headers).await?;
    let versions = versions(
        &state,
        query.target.as_deref(),
        query.agent_version.as_deref(),
        query.platform.as_deref(),
    )
    .await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(AgentVersions::new(versions)),
    )
        .into_response())
}

pub async fn bootstrap_agent_versions(
    State(state): State<AppState>,
    Query(query): Query<BootstrapVersionQuery>,
) -> ApiResult<Response> {
    crate::servers::validate_enrollment(&state.pool, &query.token).await?;
    let versions = versions(
        &state,
        query.target.as_deref(),
        query.agent_version.as_deref(),
        query.platform.as_deref(),
    )
    .await?;
    if versions.is_empty() {
        return Err(selection_error(&state, query.agent_version.as_deref()).await?);
    }
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(AgentVersions::new(versions)),
    )
        .into_response())
}
