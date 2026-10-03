#![forbid(unsafe_code)]

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sinan_adapter_sdk::{
    BoxFuture, DiagnosticAdapter, DiagnosticDescriptor, DiagnosticOutput, DiagnosticSection,
    DiagnosticSpec, Privileged, ServiceJob,
};
use std::time::Duration;
use tokio::{
    fs,
    time::{Instant, timeout_at},
};

mod files;
pub mod workbench;
pub use workbench::WorkbenchAdapter;
mod input;
mod report;

pub const CAPABILITY: &str = "diagnostic:tcpquality-native-v1";
pub const AUXILIARY_FILES: [&str; 5] = [
    "build-info.json",
    "LICENSE",
    "source.tar.gz",
    "Cargo.lock",
    "THIRD_PARTY_NOTICES.txt",
];
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpQualityAdapter;
impl TcpQualityAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildInfo {
    version: String,
    source_repo: String,
    source_commit: Option<String>,
}

async fn identity(
    input: &input::Validated<'_>,
    privileged: &dyn Privileged,
    deadline: Instant,
) -> Result<()> {
    for flag in ["--version", "--build-info"] {
        let args = [flag.into()];
        let execution = timeout_at(
            deadline.min(Instant::now() + files::IO_TIMEOUT),
            privileged.execute_bounded(&input.spec.binary_path, &args, 2, 4096),
        )
        .await
        .context("TCP artifact identity verification timed out")??;
        ensure!(
            !execution.timed_out
                && !execution.truncated
                && execution.output.success
                && execution.output.stdout.len() <= 4096
                && execution.output.stderr.is_empty(),
            "TCP artifact identity verification failed"
        );
        let output = execution.output.stdout;
        if flag == "--version" {
            ensure!(
                output == format!("{} {}", input::BINARY, input::ENGINE_VERSION)
                    || output == format!("{} {}\n", input::BINARY, input::ENGINE_VERSION),
                "TCP binary version mismatch"
            );
        } else {
            let info: BuildInfo =
                serde_json::from_str(&output).context("invalid TCP build identity")?;
            ensure!(
                info.version == input::ENGINE_VERSION
                    && info.source_repo == "theLucius7/sinan"
                    && info.source_commit.as_deref() == Some(input.source),
                "TCP binary source pin mismatch"
            );
        }
    }
    Ok(())
}
async fn no_saved_output(spec: &DiagnosticSpec) -> Result<()> {
    for name in ["result.json", "sections"] {
        match fs::symlink_metadata(spec.job_dir.join(name)).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!("diagnostic workspace contains saved output; do not rerun it"),
        }
    }
    Ok(())
}

async fn saved_scope(input: &input::Validated<'_>, owner: u32, deadline: Instant) -> Result<()> {
    if let Some(saved) = files::read(
        &input.spec.job_dir.join("targets.json"),
        input::INPUT_LIMIT,
        owner,
        deadline,
    )
    .await?
    {
        ensure!(saved == input.bytes, "saved frozen target snapshot differs");
    }
    Ok(())
}

impl DiagnosticAdapter for TcpQualityAdapter {
    fn capabilities(&self) -> Vec<String> {
        vec![CAPABILITY.into()]
    }
    fn describe(&self) -> DiagnosticDescriptor {
        DiagnosticDescriptor {
            plugin_name: "tcpquality".into(),
            binary_name: input::BINARY.into(),
        }
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
            let input = input::validate(spec)?;
            let timeout_secs = spec.timeout_secs.min(60);
            let deadline = Instant::now() + Duration::from_secs(u64::from(timeout_secs));
            // Core installs the signed cache and job root through the same actor.
            let owner = files::binary(&spec.binary_path, deadline).await?;
            identity(&input, privileged, deadline).await?;
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
                .context("saved-output inspection timed out")??;
            }
            timeout_at(
                deadline.min(Instant::now() + files::IO_TIMEOUT),
                privileged.create_dir(&spec.job_dir, 0o700, None),
            )
            .await
            .context("create TCP workspace timed out")??;
            ensure!(
                files::workspace(&spec.job_dir, Some(owner), deadline)
                    .await?
                    .is_some(),
                "TCP workspace was not created"
            );
            let targets = spec.job_dir.join("targets.json");
            match files::read(&targets, input::INPUT_LIMIT, owner, deadline).await? {
                Some(saved) => ensure!(
                    saved == input.bytes,
                    "existing frozen target snapshot differs"
                ),
                None => timeout_at(
                    deadline.min(Instant::now() + files::IO_TIMEOUT),
                    privileged.write_file(&targets, input.bytes.as_bytes(), 0o600, None),
                )
                .await
                .context("write frozen targets timed out")??,
            }
            ensure!(
                files::read(&targets, input::INPUT_LIMIT, owner, deadline)
                    .await?
                    .as_deref()
                    == Some(input.bytes),
                "frozen target publication mismatch"
            );
            ensure!(
                Instant::now() < deadline,
                "TCP preparation exhausted its deadline"
            );
            Ok(ServiceJob {
                unit: format!("sinan-diagnostic-{}.service", spec.id),
                program: spec.binary_path.clone(),
                args: vec![
                    "--workspace".into(),
                    input::path(&spec.job_dir)?,
                    "--targets".into(),
                    "targets.json".into(),
                    "--target-digest".into(),
                    input.digest.into(),
                    "--ip-version".into(),
                    input.ip_version.into(),
                    "--count".into(),
                    input.count.to_string(),
                    "--concurrency".into(),
                    input.concurrency.to_string(),
                    "--no-rank-upload".into(),
                ],
                working_directory: spec.job_dir.clone(),
                timeout_secs,
                memory_max: sinan_adapter_sdk::MemoryMax::new(64 * 1024 * 1024)?,
                tasks_max: sinan_adapter_sdk::TasksMax::new(32)?,
                cpu_max_percent: Default::default(),
                cpu_weight: sinan_adapter_sdk::CpuWeight::new(10)?,
                io_weight: sinan_adapter_sdk::IoWeight::new(10)?,
                oom_score_adjust: sinan_adapter_sdk::OomScoreAdjust::new(500)?,
            })
        })
    }
    fn collect<'a>(&'a self, spec: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async move {
            let input = input::validate(spec)?;
            let deadline = Instant::now() + files::IO_TIMEOUT;
            // Historical output does not depend on the old binary still existing.
            let Some(owner) = files::workspace(&spec.job_dir, None, deadline).await? else {
                return Ok(None);
            };
            saved_scope(&input, owner, deadline).await?;
            let Some(text) = files::read(
                &spec.job_dir.join("result.json"),
                input::OUTPUT_LIMIT,
                owner,
                deadline,
            )
            .await?
            else {
                return Ok(None);
            };
            report::Report::parse(&text, &input)?;
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
            let input = input::validate(spec)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let Some(owner) = files::workspace(&spec.job_dir, None, deadline).await? else {
                return Ok(Vec::new());
            };
            saved_scope(&input, owner, deadline).await?;
            if !files::directory(&spec.job_dir.join("sections"), owner, deadline).await? {
                return Ok(Vec::new());
            }
            let mut expected = vec![
                ("tcp_scope".to_owned(), None),
                ("tcp_summary".to_owned(), None),
            ];
            expected.extend(input.snapshot.targets.iter().map(|target| {
                (
                    format!(
                        "tcp_target_{}",
                        target.id.replace('-', "").to_ascii_lowercase()
                    ),
                    Some(target),
                )
            }));
            let mut chapters = Vec::new();
            for (name, target) in expected {
                if Instant::now() >= deadline {
                    break;
                }
                let saved = match files::read(
                    &spec.job_dir.join("sections").join(format!("{name}.json")),
                    input::OUTPUT_LIMIT,
                    owner,
                    deadline,
                )
                .await
                {
                    Ok(Some(value)) => value,
                    Ok(None) | Err(_) => continue,
                };
                let Ok(chapter) = serde_json::from_str::<DiagnosticSection>(&saved) else {
                    continue;
                };
                if chapter.name != name
                    || chapter.text.is_empty()
                    || chapter.text.len() > input::OUTPUT_LIMIT
                    || chapter.revision == 0
                    || chapter.revision > i64::MAX as u64
                    || chapter.collected_at <= 0
                    || chapter.collected_at
                        > i64::try_from(files::now_millis()? / 1000)?.saturating_add(5)
                {
                    continue;
                }
                let valid = if let Some(target) = target {
                    report::target(&chapter.text, target, &input)
                        .is_ok_and(|value| chapter.complete == value.complete)
                } else {
                    report::Report::parse(&chapter.text, &input).is_ok_and(|value| {
                        if name == "tcp_scope" {
                            chapter.complete
                        } else {
                            chapter.complete == value.complete
                        }
                    })
                };
                if valid {
                    chapters.push(chapter);
                }
            }
            Ok(chapters)
        })
    }
}
