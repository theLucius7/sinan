#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sinan_adapter_sdk::{
    BoxFuture, DiagnosticAdapter, DiagnosticDescriptor, DiagnosticOutput, DiagnosticSection,
    DiagnosticSpec, Privileged, ServiceJob,
};
use std::{
    collections::BTreeMap,
    path::{Component, Path},
    time::Duration,
};
use tokio::{
    fs,
    time::{Instant, timeout_at},
};
use uuid::Uuid;

mod files;
mod report;

pub const VERSION: &str = "87397e2c3196ec796f5477c83343c2354df601ea-node-r1";
pub const SOURCE_COMMIT: &str = "87397e2c3196ec796f5477c83343c2354df601ea";
pub const SOURCE_SHA256: &str = "b30df5a3c2204276c54e99dcc5080b46f8a627667730aee7de63b109b8ecaecf";
pub const CAPABILITY: &str = "diagnostic:ipquality-node-v1";
pub const BINARY: &str = "ipquality";
pub const AUXILIARY_FILES: [&str; 6] = [
    "rootfs.tar.gz",
    "rootfs-manifest.json",
    "build-info.json",
    "LICENSE",
    "source.tar.gz",
    "THIRD_PARTY_NOTICES.txt",
];
const OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub struct IpQualityAdapter;
impl IpQualityAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExecutionContext {
    schema: u32,
    job_id: String,
    version: String,
    ip_version: String,
    artifact_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildInfo {
    schema: u32,
    plugin: String,
    version: String,
    arch: String,
    profile: String,
    source_commit: String,
    source_sha256: String,
    source_lock_sha256: String,
    policy_sha256: String,
    transport_sha256: String,
    rootfs_sha256: String,
    rootfs_manifest_sha256: String,
    license_review_sha256: String,
    source_archive_sha256: String,
    factory_provenance_sha256: String,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn path(path: &Path) -> Result<String> {
    let value = path.to_str().context("IPQuality path is not UTF-8")?;
    ensure!(
        path.is_absolute()
            && path.parent().is_some()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'/' | b'_' | b'.' | b'-')),
        "IPQuality paths must be private absolute paths without expansion or traversal"
    );
    Ok(value.into())
}

fn validate(spec: &DiagnosticSpec) -> Result<&str> {
    let id = Uuid::parse_str(&spec.id).context("IPQuality task ID must be a UUID")?;
    ensure!(
        id.to_string() == spec.id
            && spec.version == VERSION
            && (1..=300).contains(&spec.timeout_secs),
        "unsupported IPQuality identity, version, or deadline"
    );
    path(&spec.binary_path)?;
    path(&spec.job_dir)?;
    ensure!(
        spec.binary_path.file_name().and_then(|name| name.to_str()) == Some(BINARY)
            && spec
                .binary_path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                == Some(VERSION)
            && spec.job_dir.file_name().and_then(|name| name.to_str()) == Some(spec.id.as_str()),
        "IPQuality artifact or workspace path differs from its task identity"
    );
    ensure!(
        spec.options
            .keys()
            .all(|key| matches!(key.as_str(), "ip_version" | "environment_section"))
            && spec
                .options
                .get("environment_section")
                .is_none_or(|value| matches!(value.as_str(), "true" | "false")),
        "unsupported IPQuality option"
    );
    let ip_version = spec
        .options
        .get("ip_version")
        .context("IPQuality address family is required")?
        .as_str();
    ensure!(
        matches!(ip_version, "4" | "6"),
        "IPQuality address family must be 4 or 6"
    );
    Ok(ip_version)
}

fn native_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        _ => anyhow::bail!("unsupported IPQuality architecture"),
    }
}

async fn required(
    path: &Path,
    maximum: usize,
    owner: u32,
    private: bool,
    deadline: Instant,
) -> Result<String> {
    files::read(path, maximum, owner, private, deadline)
        .await?
        .context("required IPQuality identity file is missing")
}

async fn signed_identity(spec: &DiagnosticSpec, owner: u32, deadline: Instant) -> Result<String> {
    let directory = spec
        .binary_path
        .parent()
        .context("IPQuality artifact directory is missing")?;
    let metadata: Value = serde_json::from_str(
        &required(
            &directory.join("release.json"),
            32 * 1024,
            owner,
            false,
            deadline,
        )
        .await?,
    )?;
    let arch = native_arch()?;
    let candidates: Vec<_> = metadata
        .get("artifacts")
        .and_then(Value::as_array)
        .context("signed release has no artifacts")?
        .iter()
        .filter(|entry| {
            entry["name"] == BINARY && entry["version"] == VERSION && entry["arch"] == arch
        })
        .collect();
    ensure!(
        candidates.len() == 1,
        "signed release must bind one IPQuality artifact for this architecture"
    );
    let entry = candidates[0];
    ensure!(
        entry["binary_name"] == BINARY && entry["format"] == "tar.gz",
        "signed IPQuality binary name or format differs"
    );
    let auxiliary = entry
        .get("auxiliary_files")
        .and_then(Value::as_object)
        .context("signed IPQuality auxiliary inventory is missing")?;
    ensure!(
        auxiliary.len() == AUXILIARY_FILES.len()
            && AUXILIARY_FILES
                .iter()
                .all(|name| auxiliary.contains_key(*name)),
        "signed IPQuality artifact has an incomplete or unexpected auxiliary inventory"
    );
    let build: BuildInfo = serde_json::from_str(
        &required(
            &directory.join("build-info.json"),
            16 * 1024,
            owner,
            false,
            deadline,
        )
        .await?,
    )?;
    ensure!(
        build.schema == 1
            && build.plugin == BINARY
            && build.version == VERSION
            && build.arch == arch
            && build.profile == "ipquality-node-v1"
            && build.source_commit == SOURCE_COMMIT
            && build.source_sha256 == SOURCE_SHA256,
        "IPQuality build identity differs from its fixed profile or source"
    );
    ensure!(
        [
            &build.source_sha256,
            &build.source_lock_sha256,
            &build.policy_sha256,
            &build.transport_sha256,
            &build.rootfs_sha256,
            &build.rootfs_manifest_sha256,
            &build.license_review_sha256,
            &build.source_archive_sha256,
            &build.factory_provenance_sha256
        ]
        .into_iter()
        .all(|value| digest(value)),
        "IPQuality build identity contains an invalid digest"
    );
    for (name, expected) in [
        ("rootfs.tar.gz", &build.rootfs_sha256),
        ("rootfs-manifest.json", &build.rootfs_manifest_sha256),
        ("source.tar.gz", &build.source_archive_sha256),
    ] {
        ensure!(
            auxiliary[name]["sha256"].as_str() == Some(expected.as_str())
                && auxiliary[name]["size"]
                    .as_u64()
                    .is_some_and(|size| size > 0),
            "IPQuality build identity differs from its signed auxiliary file"
        );
    }
    let checksums = required(
        &directory.join("SHA256SUMS"),
        8 * 1024,
        owner,
        false,
        deadline,
    )
    .await?;
    let mut rows = BTreeMap::new();
    for line in checksums.lines() {
        let (hash, name) = line
            .split_once("  ")
            .context("invalid signed checksum row")?;
        ensure!(
            digest(hash) && !name.is_empty() && rows.insert(name, hash).is_none(),
            "invalid or repeated signed checksum identity"
        );
    }
    rows.get(format!("ipquality/{VERSION}/{arch}").as_str())
        .map(|hash| (*hash).to_owned())
        .context("signed IPQuality archive checksum is missing")
}

async fn saved_context(
    spec: &DiagnosticSpec,
    owner: u32,
    deadline: Instant,
) -> Result<ExecutionContext> {
    let bytes = required(
        &spec.job_dir.join("execution.json"),
        4096,
        owner,
        true,
        deadline,
    )
    .await?;
    let context: ExecutionContext = serde_json::from_str(&bytes)?;
    ensure!(
        context.schema == 1
            && context.job_id == spec.id
            && context.version == VERSION
            && context.ip_version == validate(spec)?
            && digest(&context.artifact_sha256),
        "saved IPQuality execution identity differs from its task"
    );
    Ok(context)
}

async fn no_saved_output(spec: &DiagnosticSpec) -> Result<()> {
    for name in [
        "execution.json",
        "result.json",
        "section-ipquality_result.json",
        ".runner",
        ".runner.lock",
        "attempts.jsonl",
        "upstream.json",
        "partial.json",
        ".ipquality-run",
        "IpRoot",
    ] {
        match fs::symlink_metadata(spec.job_dir.join(name)).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => {
                anyhow::bail!("IPQuality workspace contains a previous execution; do not rerun it")
            }
        }
    }
    Ok(())
}

impl DiagnosticAdapter for IpQualityAdapter {
    fn describe(&self) -> DiagnosticDescriptor {
        DiagnosticDescriptor {
            plugin_name: BINARY.into(),
            binary_name: BINARY.into(),
        }
    }
    fn capabilities(&self) -> Vec<String> {
        vec![CAPABILITY.into()]
    }
    fn auxiliary_files(&self) -> Vec<String> {
        AUXILIARY_FILES.into_iter().map(str::to_owned).collect()
    }

    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob> {
        Box::pin(async move {
            let ip_version = validate(spec)?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let owner = files::binary(&spec.binary_path, deadline).await?;
            let artifact_sha256 = signed_identity(spec, owner, deadline).await?;
            let version = timeout_at(
                deadline.min(Instant::now() + files::IO_TIMEOUT),
                privileged.execute_bounded(&spec.binary_path, &["--version".into()], 2, 4096),
            )
            .await
            .context("IPQuality version verification timed out")??;
            let expected_version = format!("ipquality {VERSION}");
            ensure!(
                !version.timed_out
                    && !version.truncated
                    && version.output.success
                    && version.output.stderr.is_empty()
                    && (version.output.stdout == expected_version
                        || version.output.stdout == format!("{expected_version}\n")),
                "IPQuality wrapper version verification failed"
            );
            files::ancestors(&spec.job_dir, deadline).await?;
            if files::workspace(&spec.job_dir, Some(owner), deadline)
                .await?
                .is_some()
            {
                timeout_at(
                    deadline.min(Instant::now() + files::IO_TIMEOUT),
                    no_saved_output(spec),
                )
                .await
                .context("IPQuality saved-output inspection timed out")??;
            }
            timeout_at(
                deadline.min(Instant::now() + files::IO_TIMEOUT),
                privileged.create_dir(&spec.job_dir, 0o700, None),
            )
            .await
            .context("create IPQuality workspace timed out")??;
            ensure!(
                files::workspace(&spec.job_dir, Some(owner), deadline)
                    .await?
                    .is_some(),
                "IPQuality workspace was not created"
            );
            let context = ExecutionContext {
                schema: 1,
                job_id: spec.id.clone(),
                version: VERSION.into(),
                ip_version: ip_version.into(),
                artifact_sha256: artifact_sha256.clone(),
            };
            let bytes = serde_json::to_vec(&context)?;
            timeout_at(
                deadline.min(Instant::now() + files::IO_TIMEOUT),
                privileged.write_file(&spec.job_dir.join("execution.json"), &bytes, 0o600, None),
            )
            .await
            .context("write IPQuality execution identity timed out")??;
            ensure!(
                saved_context(spec, owner, deadline).await? == context && Instant::now() < deadline,
                "IPQuality execution identity publication mismatch or preparation deadline exceeded"
            );
            Ok(ServiceJob {
                unit: format!("sinan-diagnostic-{}.service", spec.id),
                program: spec.binary_path.clone(),
                args: vec![
                    "--workspace".into(),
                    path(&spec.job_dir)?,
                    "--job-id".into(),
                    spec.id.clone(),
                    "--ip-version".into(),
                    ip_version.into(),
                    "--artifact-sha256".into(),
                    artifact_sha256,
                ],
                working_directory: spec.job_dir.clone(),
                timeout_secs: spec.timeout_secs,
                memory_max: sinan_adapter_sdk::MemoryMax::new(128 * 1024 * 1024)?,
                tasks_max: sinan_adapter_sdk::TasksMax::new(64)?,
                cpu_max_percent: Default::default(),
                cpu_weight: sinan_adapter_sdk::CpuWeight::new(10)?,
                io_weight: sinan_adapter_sdk::IoWeight::new(10)?,
                oom_score_adjust: sinan_adapter_sdk::OomScoreAdjust::new(500)?,
            })
        })
    }

    fn collect<'a>(&'a self, spec: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async move {
            validate(spec)?;
            let deadline = Instant::now() + files::IO_TIMEOUT;
            let Some(owner) = files::workspace(&spec.job_dir, None, deadline).await? else {
                return Ok(None);
            };
            let Some(text) = files::read(
                &spec.job_dir.join("result.json"),
                OUTPUT_LIMIT,
                owner,
                true,
                deadline,
            )
            .await?
            else {
                return Ok(None);
            };
            let context = saved_context(spec, owner, deadline).await?;
            report::Report::parse(&text, &context, spec.timeout_secs)?;
            Ok(Some(DiagnosticOutput {
                text,
                report_url: None,
            }))
        })
    }

    fn collect_sections<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
    ) -> BoxFuture<'a, Vec<DiagnosticSection>> {
        Box::pin(async move {
            validate(spec)?;
            let deadline = Instant::now() + files::IO_TIMEOUT;
            let Some(owner) = files::workspace(&spec.job_dir, None, deadline).await? else {
                return Ok(Vec::new());
            };
            let Some(saved) = files::read(
                &spec.job_dir.join("section-ipquality_result.json"),
                512 * 1024,
                owner,
                true,
                deadline,
            )
            .await?
            else {
                return Ok(Vec::new());
            };
            let section: DiagnosticSection =
                serde_json::from_str(&saved).context("invalid IPQuality chapter")?;
            ensure!(
                section.name == "ipquality_result"
                    && !section.text.trim().is_empty()
                    && section.text.len() <= OUTPUT_LIMIT
                    && (1..=i64::MAX as u64).contains(&section.revision)
                    && section.collected_at > 0
                    && section.collected_at <= files::now()?.saturating_add(5),
                "invalid IPQuality chapter identity, size, revision, or time"
            );
            let context = saved_context(spec, owner, deadline).await?;
            let report = report::Report::parse(&section.text, &context, spec.timeout_secs)?;
            report.validate_section_time(section.collected_at, section.complete)?;
            Ok(vec![section])
        })
    }
}

#[cfg(test)]
mod tests;
