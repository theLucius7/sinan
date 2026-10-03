#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use sinan_adapter_sdk::{
    BoxFuture, DiagnosticAdapter, DiagnosticDescriptor, DiagnosticOutput, DiagnosticSection,
    DiagnosticSpec, Privileged, ServiceJob,
};
use std::{path::Path, time::Duration};
use tokio::{io::AsyncReadExt, time::timeout};

pub const VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r22";
/// Explicit offline environment preparation, never the panel default.
pub const OFFLINE_ROOTFS_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r20";
/// Configured official queries executed at the managed node egress.
pub const NODE_QUERY_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21";
pub const NODE_QUERY_CAPABILITY: &str = "diagnostic:nodequality-node-query";
/// Explicit namespaced preparation, never an alias for a historical signed version.
pub const NATIVE_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r2";
/// Exact historical native artifact identity retained for recovery and daily jobs.
pub const NATIVE_LEGACY_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-sinan-native-r1";
pub const NATIVE_OFFLINE_ROOTFS_VERSION: &str =
    "a92fca6c0067df29ddd03fdc2fee6f3000f64545-offline-rootfs-r1";
const ARTIFACT_ADMISSION_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r19";
const PUBLIC_ACCESS_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r18";
const BROWSER_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r17";
const REPORT_IO_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r16";
const INTEGRATED_QUERY_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r15";
const NETFLIX_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r14";
const IP_SCORE_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r13";
const PERCENTILE_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r12";
const SOURCE_DELIVERY_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r11";
const PINNED_DATA_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r10";
const OFFLINE_DEPENDENCIES_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r9";
const NO_SWAP_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r8";
const PUBLIC_REPORT_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r7";
const PINNED_SOURCES_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r6";
const PINNED_GATE_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r5";
const MODES_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r4";
pub const MODES_CAPABILITY: &str = "diagnostic:nodequality-modes";
pub const FULL_START_GATE_CAPABILITY: &str = "diagnostic:nodequality-full-start-gate";
pub const FULL_START_DENIAL: &str = "完整验机已暂停：离线受控工具链尚未就绪，旧工具链仍会下载在线代码、上传内层报告或修改宿主 swap。日常检查和已有报告回收、取消仍可使用。";
const LEGACY_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r2";
const CHAPTER_VERSION: &str = "a92fca6c0067df29ddd03fdc2fee6f3000f64545-r3";
mod modes;
pub const SECTION_NAMES: [&str; 5] = [
    "header_info",
    "hardware_quality",
    "ip_quality",
    "net_quality",
    "backroute_trace",
];
pub const MAX_REPORT_BYTES: u64 = 256 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default)]
pub struct NodeQualityAdapter;

impl NodeQualityAdapter {
    pub fn new() -> Self {
        Self
    }
}

fn path_argument(path: &Path) -> Result<String> {
    let value = path.to_str().context("diagnostic path is not UTF-8")?;
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || value
            .chars()
            .any(|c| c.is_control() || c == '$' || c == '%')
    {
        bail!("diagnostic paths must be absolute without expansion or traversal");
    }
    Ok(value.into())
}

fn supports_modes(version: &str) -> bool {
    matches!(
        version,
        VERSION
            | NATIVE_VERSION
            | NATIVE_LEGACY_VERSION
            | NATIVE_OFFLINE_ROOTFS_VERSION
            | OFFLINE_ROOTFS_VERSION
            | NODE_QUERY_VERSION
            | ARTIFACT_ADMISSION_VERSION
            | PUBLIC_ACCESS_VERSION
            | BROWSER_VERSION
            | REPORT_IO_VERSION
            | INTEGRATED_QUERY_VERSION
            | NETFLIX_VERSION
            | IP_SCORE_VERSION
            | PERCENTILE_VERSION
            | SOURCE_DELIVERY_VERSION
            | PINNED_DATA_VERSION
            | OFFLINE_DEPENDENCIES_VERSION
            | NO_SWAP_VERSION
            | PUBLIC_REPORT_VERSION
            | PINNED_SOURCES_VERSION
            | PINNED_GATE_VERSION
            | MODES_VERSION
    )
}

fn validate(spec: &DiagnosticSpec) -> Result<(String, String, String, String)> {
    if !matches!(
        spec.version.as_str(),
        VERSION
            | NATIVE_VERSION
            | NATIVE_LEGACY_VERSION
            | NATIVE_OFFLINE_ROOTFS_VERSION
            | OFFLINE_ROOTFS_VERSION
            | NODE_QUERY_VERSION
            | ARTIFACT_ADMISSION_VERSION
            | PUBLIC_ACCESS_VERSION
            | BROWSER_VERSION
            | REPORT_IO_VERSION
            | INTEGRATED_QUERY_VERSION
            | NETFLIX_VERSION
            | IP_SCORE_VERSION
            | PERCENTILE_VERSION
            | SOURCE_DELIVERY_VERSION
            | PINNED_DATA_VERSION
            | OFFLINE_DEPENDENCIES_VERSION
            | NO_SWAP_VERSION
            | PUBLIC_REPORT_VERSION
            | PINNED_SOURCES_VERSION
            | PINNED_GATE_VERSION
            | MODES_VERSION
            | CHAPTER_VERSION
            | LEGACY_VERSION
    ) {
        bail!("unsupported diagnostic version");
    }
    let id = spec.id.as_bytes();
    if id.len() != 36
        || id.iter().enumerate().any(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c != b'-'
            } else {
                !c.is_ascii_hexdigit()
            }
        })
    {
        bail!("diagnostic id must be a UUID");
    }
    if !(1..=3600).contains(&spec.timeout_secs) {
        bail!("diagnostic timeout must be between 1 and 3600 seconds");
    }
    path_argument(&spec.binary_path)?;
    let workspace = path_argument(&spec.job_dir)?;
    if !workspace
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'_' | b'.' | b'-'))
    {
        bail!("diagnostic workspace cannot contain whitespace or shell glob characters");
    }
    if spec.job_dir.parent().is_none() {
        bail!("diagnostic workspace must not be the filesystem root");
    }
    for key in spec.options.keys() {
        if !matches!(
            key.as_str(),
            "ip_version"
                | "network_mode"
                | "upload_report"
                | "mode"
                | "daily_targets"
                | "environment_section"
                | "node_ips"
        ) {
            bail!("unsupported diagnostic option");
        }
    }
    let ip_version = spec
        .options
        .get("ip_version")
        .map(String::as_str)
        .unwrap_or("both");
    let network_mode = spec
        .options
        .get("network_mode")
        .map(String::as_str)
        .unwrap_or("low");
    let upload_report = spec
        .options
        .get("upload_report")
        .map(String::as_str)
        .unwrap_or("false");
    if !matches!(ip_version, "both" | "ipv4" | "ipv6") {
        bail!("invalid diagnostic IP version");
    }
    if !matches!(network_mode, "low" | "normal") {
        bail!("invalid diagnostic network mode");
    }
    if !matches!(upload_report, "true" | "false") {
        bail!("invalid diagnostic report upload option");
    }
    modes::validate(spec)?;
    Ok((
        workspace,
        ip_version.into(),
        network_mode.into(),
        upload_report.into(),
    ))
}

async fn read_bounded(path: &Path, limit: u64) -> Result<Option<String>> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > limit {
        bail!("diagnostic output is not a bounded ordinary file");
    }
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > limit {
        bail!("diagnostic output exceeded its size limit");
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

fn valid_report_url(value: &str) -> bool {
    value
        .strip_prefix("https://nodequality.com/r/")
        .is_some_and(|token| {
            !token.is_empty()
                && token.len() <= 128
                && token
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
}

impl DiagnosticAdapter for NodeQualityAdapter {
    fn auxiliary_files_for_version(&self, version: &str) -> Vec<String> {
        if matches!(
            version,
            OFFLINE_ROOTFS_VERSION | NATIVE_OFFLINE_ROOTFS_VERSION
        ) {
            vec!["rootfs.tar.gz".into(), "rootfs-manifest.json".into()]
        } else {
            Vec::new()
        }
    }
    fn capabilities(&self) -> Vec<String> {
        vec![
            MODES_CAPABILITY.into(),
            FULL_START_GATE_CAPABILITY.into(),
            NODE_QUERY_CAPABILITY.into(),
        ]
    }
    fn describe(&self) -> DiagnosticDescriptor {
        DiagnosticDescriptor {
            plugin_name: "nodequality".into(),
            binary_name: "nodequality".into(),
        }
    }

    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob> {
        Box::pin(async move {
            let (workspace, ip_version, network_mode, upload_report) = validate(spec)?;
            let mode = modes::validate(spec)?;
            if mode.name == "full" {
                bail!(FULL_START_DENIAL);
            }
            timeout(
                IO_TIMEOUT,
                privileged.create_dir(&spec.job_dir, 0o700, None),
            )
            .await
            .context("create diagnostic workspace timed out")??;
            let version_args = ["--version".into()];
            let output = timeout(
                IO_TIMEOUT,
                privileged.execute(&spec.binary_path, &version_args),
            )
            .await
            .context("diagnostic version verification timed out")??;
            if !output.success || output.stdout.trim() != format!("nodequality {}", spec.version) {
                bail!("diagnostic artifact version verification failed");
            }
            let mut args = vec![
                "--workspace".into(),
                workspace,
                "--ip-version".into(),
                ip_version,
                "--network-mode".into(),
                network_mode,
                "--upload-report".into(),
                upload_report,
            ];
            if supports_modes(&spec.version) {
                args.extend(["--mode".into(), mode.name.into()]);
            }
            if let Some(targets) = &mode.targets {
                let path = spec.job_dir.join("daily-targets.json");
                timeout(
                    IO_TIMEOUT,
                    privileged.write_file(&path, targets.as_bytes(), 0o600, None),
                )
                .await
                .context("write daily targets timed out")??;
                args.extend(["--targets-file".into(), path_argument(&path)?]);
            }
            if let Some(ips) = &mode.ips {
                let path = spec.job_dir.join("node-ips.json");
                timeout(
                    IO_TIMEOUT,
                    privileged.write_file(&path, ips.as_bytes(), 0o600, None),
                )
                .await
                .context("write frozen node IPs timed out")??;
                args.extend(["--ips-file".into(), path_argument(&path)?]);
                args.extend(["--job-id".into(), spec.id.clone()]);
            }
            Ok(ServiceJob {
                unit: format!("sinan-diagnostic-{}.service", spec.id),
                program: spec.binary_path.clone(),
                args,
                working_directory: spec.job_dir.clone(),
                timeout_secs: spec.timeout_secs,
                memory_max: if matches!(mode.name, "daily" | "ip") {
                    sinan_adapter_sdk::MemoryMax::new(64 * 1024 * 1024)?
                } else {
                    Default::default()
                },
                tasks_max: if matches!(mode.name, "daily" | "ip") {
                    sinan_adapter_sdk::TasksMax::new(32)?
                } else {
                    Default::default()
                },
                cpu_weight: Default::default(),
                io_weight: Default::default(),
                oom_score_adjust: Default::default(),
            })
        })
    }

    fn collect<'a>(&'a self, spec: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async move {
            validate(spec)?;
            timeout(IO_TIMEOUT, async {
                let result =
                    read_bounded(&spec.job_dir.join("result.txt"), MAX_REPORT_BYTES).await?;
                let text = match result {
                    Some(text) => text,
                    None => return Ok(None),
                };
                if text.trim().is_empty() {
                    return Ok(None);
                }
                let report_url =
                    match read_bounded(&spec.job_dir.join("report-url.txt"), 256).await? {
                        Some(url) if valid_report_url(url.trim()) => Some(url.trim().into()),
                        Some(_) => bail!("invalid diagnostic report URL"),
                        None => None,
                    };
                Ok(Some(DiagnosticOutput { text, report_url }))
            })
            .await
            .context("read diagnostic output timed out")?
        })
    }
    fn collect_sections<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
    ) -> BoxFuture<'a, Vec<DiagnosticSection>> {
        Box::pin(async move {
            validate(spec)?;
            timeout(IO_TIMEOUT, async {
                let mut sections = Vec::new();
                for name in SECTION_NAMES {
                    let path = spec.job_dir.join(format!("section-{name}.json"));
                    // One malformed chapter must not hide the other saved chapters.
                    let saved = match read_bounded(&path, 512 * 1024).await {
                        Ok(Some(value)) => value,
                        Ok(None) | Err(_) => continue,
                    };
                    let Ok(section) = serde_json::from_str::<DiagnosticSection>(&saved) else {
                        continue;
                    };
                    if section.name == name
                        && !section.text.trim().is_empty()
                        && section.text.len() <= 64 * 1024
                        && section.revision > 0
                        && section.revision <= i64::MAX as u64
                        && section.collected_at > 0
                    {
                        sections.push(section);
                    }
                }
                Ok(sections)
            })
            .await
            .context("read diagnostic chapters timed out")?
        })
    }
}
