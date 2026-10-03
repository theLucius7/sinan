//! Offline signed workbench adapter; common core owns budgets and cancellation.
use crate::files;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sinan_adapter_sdk::{
    BoxFuture, DiagnosticAdapter, DiagnosticDescriptor, DiagnosticOutput, DiagnosticSection,
    DiagnosticSpec, Privileged, ServiceJob,
};
use std::time::Duration;
use tokio::time::Instant;
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkbenchAdapter;
impl WorkbenchAdapter {
    pub fn new() -> Self {
        Self
    }
}
fn execution(spec: &DiagnosticSpec) -> Result<Value> {
    ensure!(
        spec.version == "1.0.0",
        "unsupported network workbench artifact version"
    );
    let text = spec
        .options
        .get("execution")
        .context("missing frozen execution")?;
    ensure!(text.len() <= 64 * 1024, "execution too large");
    let value: Value = serde_json::from_str(text)?;
    ensure!(
        value["schema"] == 1 && value["check"].is_object() && value["budget"].is_object(),
        "invalid frozen execution"
    );
    ensure!(
        value["check"]["kind"] != "node_quality_full",
        "NodeQuality full-start gate cannot be bypassed"
    );
    ensure!(
        spec.timeout_secs <= 3630 && spec.timeout_secs > 0,
        "invalid workbench timeout"
    );
    Ok(value)
}
impl DiagnosticAdapter for WorkbenchAdapter {
    fn describe(&self) -> DiagnosticDescriptor {
        DiagnosticDescriptor {
            plugin_name: "network-workbench".into(),
            binary_name: "sinan-network-workbench".into(),
        }
    }
    fn capabilities(&self) -> Vec<String> {
        vec!["diagnostic:network-workbench-v1".into()]
    }
    fn auxiliary_files(&self) -> Vec<String> {
        vec!["tools-manifest.json".into(), "LICENSE".into()]
    }
    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob> {
        Box::pin(async move {
            let value = execution(spec)?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let owner = files::binary(&spec.binary_path, deadline).await?;
            files::ancestors(&spec.job_dir, deadline).await?;
            if files::workspace(&spec.job_dir, Some(owner), deadline)
                .await?
                .is_some()
            {
                ensure!(
                    files::read(
                        &spec.job_dir.join("result.json"),
                        64 * 1024,
                        owner,
                        deadline
                    )
                    .await?
                    .is_none(),
                    "saved execution must not rerun"
                );
            }
            privileged.create_dir(&spec.job_dir, 0o700, None).await?;
            let encoded = serde_json::to_vec(&value)?;
            let input = spec.job_dir.join("execution.json");
            if let Some(existing) = files::read(&input, 64 * 1024, owner, deadline).await? {
                ensure!(
                    existing.as_bytes() == encoded,
                    "saved frozen execution differs"
                );
            } else {
                privileged.write_file(&input, &encoded, 0o600, None).await?;
            }
            let args = vec![
                "--preflight".into(),
                "--input".into(),
                input.to_string_lossy().into_owned(),
                "--manifest".into(),
                spec.binary_path
                    .with_file_name("tools-manifest.json")
                    .to_string_lossy()
                    .into_owned(),
            ];
            let inspected = privileged
                .execute_bounded(&spec.binary_path, &args, 5, 4096)
                .await?;
            ensure!(
                inspected.output.success && !inspected.timed_out && !inspected.truncated,
                "offline tool, version, license or resource preflight failed: {}",
                inspected.output.stderr
            );
            Ok(ServiceJob {
                unit: format!("sinan-diagnostic-{}.service", spec.id),
                program: spec.binary_path.clone(),
                args: vec![
                    "--input".into(),
                    input.to_string_lossy().into_owned(),
                    "--workspace".into(),
                    spec.job_dir.to_string_lossy().into_owned(),
                    "--manifest".into(),
                    spec.binary_path
                        .with_file_name("tools-manifest.json")
                        .to_string_lossy()
                        .into_owned(),
                ],
                working_directory: spec.job_dir.clone(),
                timeout_secs: spec.timeout_secs,
                memory_max: sinan_adapter_sdk::MemoryMax::new(1024 * 1024 * 1024)?,
                tasks_max: sinan_adapter_sdk::TasksMax::new(64)?,
                cpu_weight: sinan_adapter_sdk::CpuWeight::new(100)?,
                cpu_max_percent: sinan_adapter_sdk::CpuMaxPercent::new(6400)?,
                io_weight: sinan_adapter_sdk::IoWeight::new(10)?,
                oom_score_adjust: sinan_adapter_sdk::OomScoreAdjust::new(500)?,
            })
        })
    }
    fn collect<'a>(&'a self, spec: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async move {
            let input = execution(spec)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            let Some(owner) = files::workspace(&spec.job_dir, None, deadline).await? else {
                return Ok(None);
            };
            let Some(text) = files::read(
                &spec.job_dir.join("result.json"),
                64 * 1024,
                owner,
                deadline,
            )
            .await?
            else {
                return Ok(None);
            };
            let report: Value = serde_json::from_str(&text)?;
            ensure!(
                report["schema"] == 1
                    && report["parameters"] == input["check"]
                    && report["source"] == input["source_label"]
                    && report["cleanup"]["process_stopped"] == true
                    && report["cleanup"]["files_removed"] == true
                    && report["cleanup"]["listeners_closed"] == true,
                "report source, frozen parameters or cleanup mismatch"
            );
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
            let input = execution(spec)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            let Some(owner) = files::workspace(&spec.job_dir, None, deadline).await? else {
                return Ok(vec![]);
            };
            let mut result = vec![];
            for name in ["workbench_scope", "workbench_result"] {
                if let Some(text) = files::read(
                    &spec.job_dir.join(format!("{name}.json")),
                    64 * 1024,
                    owner,
                    deadline,
                )
                .await?
                {
                    let section: DiagnosticSection = serde_json::from_str(&text)?;
                    ensure!(
                        section.name == name && section.revision > 0 && section.collected_at > 0,
                        "invalid workbench chapter"
                    );
                    let parsed: Value = serde_json::from_str(&section.text)?;
                    if name == "workbench_scope" {
                        ensure!(parsed["execution"] == input, "scope source mismatch");
                    } else {
                        ensure!(
                            parsed["parameters"] == input["check"],
                            "chapter frozen parameters differ"
                        );
                    }
                    result.push(section);
                }
            }
            Ok(result)
        })
    }
}
