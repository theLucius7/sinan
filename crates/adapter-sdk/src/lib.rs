#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

mod resources;
pub use resources::{CpuMaxPercent, CpuWeight, IoWeight, MemoryMax, OomScoreAdjust, TasksMax};
use std::{
    collections::BTreeMap,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Descriptor {
    pub module: String,
    pub plugin_name: String,
    pub binary_name: String,
    #[serde(default)]
    pub auxiliary_files: Vec<String>,
    pub service_unit: String,
    pub service_group: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSpec {
    pub revision: u64,
    pub kernel_version: String,
    pub config_hash: String,
    pub binary_path: PathBuf,
    pub revision_dir: PathBuf,
    pub stats_listen: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Prepared {
    pub spec: RuntimeSpec,
    pub listen_ports: Vec<u16>,
}

/// Private companion to the native configuration, covered by the bundle signature.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProbePlan {
    pub schema: u32,
    pub runtime_version: String,
    pub required_build_tags: Vec<String>,
    pub bindings: Vec<RuntimeProbeBinding>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProbeBinding {
    pub id: String,
    pub selector: String,
    pub target: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeProbeMeasurement {
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Noop,
    Reload,
    Restart,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counter {
    pub stat_name: String,
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticMemory {
    pub host_available_bytes: u64,
    pub cgroup_available_bytes: Option<u64>,
}

impl DiagnosticMemory {
    pub fn available_bytes(&self) -> u64 {
        self.cgroup_available_bytes
            .map_or(self.host_available_bytes, |available| {
                available.min(self.host_available_bytes)
            })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiagnosticResources {
    pub memory: DiagnosticMemory,
    pub disk_available_bytes: u64,
    pub load_one: f64,
    pub cpu_count: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Execution {
    pub output: CommandOutput,
    pub timed_out: bool,
    pub truncated: bool,
}

/// A service-manager observation of the currently controlled process.
/// Paths are internal observations and must never be accepted from a device request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInstance {
    pub instance_id: String,
    pub binary_path: PathBuf,
    /// The stable absolute command argument; configuration resolution is checked separately.
    pub config_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandProcessIdentity {
    pub pid: u32,
    pub started: String,
}

pub trait CommandObserver: Send + Sync {
    /// Persist the process identity before releasing the command's start gate.
    fn spawned(&self, process: &CommandProcessIdentity) -> anyhow::Result<()>;
    /// Persist the start notification after the gated process acknowledges start.
    fn started(&self) -> anyhow::Result<()>;
    fn cancellation_requested(&self) -> bool;
}

#[derive(Clone, Debug)]
pub struct ControlledExecution {
    pub execution: Execution,
    /// True only after the backend confirms that managed processes have stopped.
    pub cancelled: bool,
}

pub trait ManagedProcess: Send {
    fn id(&self) -> u32;
    fn try_wait(&mut self) -> anyhow::Result<Option<bool>>;
    fn exit_code(&self) -> Option<i32> {
        None
    }
    fn terminate(&mut self) -> BoxFuture<'_, ()>;
}

pub trait TerminalProcess: Send {
    fn read(&mut self) -> BoxFuture<'_, Option<String>>;
    fn input<'a>(
        &'a mut self,
        data: &'a str,
        columns: Option<u16>,
        rows: Option<u16>,
    ) -> BoxFuture<'a, ()>;
    fn close(&mut self) -> BoxFuture<'_, ()>;
}

pub trait Privileged: Send + Sync {
    fn read_managed_file<'a>(&'a self, _path: &'a Path, _maximum: usize) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async { anyhow::bail!("managed file reading is not supported") })
    }
    fn replace_managed_file<'a>(
        &'a self,
        _path: &'a Path,
        _bytes: &'a [u8],
        _previous_hash: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("managed file editing is not supported") })
    }

    fn upload_managed_file<'a>(
        &'a self,
        _path: &'a Path,
        _bytes: &'a [u8],
        _previous_hash: Option<&'a str>,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async { anyhow::bail!("managed file upload is not supported") })
    }
    fn inspect_managed_file<'a>(
        &'a self,
        _path: &'a Path,
        _maximum: usize,
    ) -> BoxFuture<'a, serde_json::Value> {
        Box::pin(async { anyhow::bail!("managed file inspection is not supported") })
    }
    fn open_terminal<'a>(
        &'a self,
        _account: &'a str,
        _columns: u16,
        _rows: u16,
    ) -> BoxFuture<'a, Box<dyn TerminalProcess>> {
        Box::pin(async { anyhow::bail!("interactive terminal is not supported") })
    }

    fn runtime_process<'a>(
        &'a self,
        _pid: u32,
        _control_group: &'a str,
    ) -> BoxFuture<'a, RuntimeInstance> {
        Box::pin(async { anyhow::bail!("runtime process inspection is not supported") })
    }

    fn execute_controlled<'a>(
        &'a self,
        _program: &'a Path,
        _args: &'a [String],
        _timeout_secs: u32,
        _maximum: usize,
        _observer: &'a dyn CommandObserver,
    ) -> BoxFuture<'a, ControlledExecution> {
        Box::pin(async { anyhow::bail!("controlled command execution is not supported") })
    }
    fn recover_command<'a>(&'a self, _process: &'a CommandProcessIdentity) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("command cleanup confirmation is not supported") })
    }
    fn diagnostic_memory(&self) -> BoxFuture<'_, DiagnosticMemory> {
        Box::pin(async { anyhow::bail!("diagnostic memory inspection is not supported") })
    }
    fn diagnostic_resources<'a>(
        &'a self,
        _directory: &'a Path,
    ) -> BoxFuture<'a, DiagnosticResources> {
        Box::pin(async { anyhow::bail!("diagnostic resource inspection is not supported") })
    }
    fn spawn_managed<'a>(
        &'a self,
        _program: &'a Path,
        _args: &'a [String],
    ) -> BoxFuture<'a, Box<dyn ManagedProcess>> {
        Box::pin(async { anyhow::bail!("managed process spawning is not supported") })
    }
    fn execute<'a>(&'a self, program: &'a Path, args: &'a [String])
    -> BoxFuture<'a, CommandOutput>;
    fn execute_bounded<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
        _timeout_secs: u32,
        maximum: usize,
    ) -> BoxFuture<'a, Execution> {
        Box::pin(async move {
            let mut output = self.execute(program, args).await?;
            let truncated = output.stdout.len() > maximum || output.stderr.len() > maximum;
            for value in [&mut output.stdout, &mut output.stderr] {
                let mut limit = value.len().min(maximum);
                while !value.is_char_boundary(limit) {
                    limit -= 1;
                }
                value.truncate(limit);
            }
            Ok(Execution {
                output,
                timed_out: false,
                truncated,
            })
        })
    }
    fn create_dir<'a>(
        &'a self,
        path: &'a Path,
        mode: u32,
        group: Option<&'a str>,
    ) -> BoxFuture<'a, ()>;
    fn write_file<'a>(
        &'a self,
        path: &'a Path,
        bytes: &'a [u8],
        mode: u32,
        group: Option<&'a str>,
    ) -> BoxFuture<'a, ()>;
    fn atomic_symlink<'a>(&'a self, link: &'a Path, target: &'a Path) -> BoxFuture<'a, ()>;
    fn remove_symlink<'a>(&'a self, link: &'a Path) -> BoxFuture<'a, ()>;
    fn remove_file<'a>(&'a self, _path: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("credential removal is not supported") })
    }
    fn remove_managed_directory<'a>(&'a self, _path: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("managed directory removal is not supported") })
    }
    /// Remove an ordinary temporary artifact path after publication or failure.
    fn remove_path<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let output = self
                .execute(
                    Path::new("rm"),
                    &[
                        "-rf".into(),
                        "--".into(),
                        path.to_string_lossy().into_owned(),
                    ],
                )
                .await?;
            anyhow::ensure!(
                output.success,
                "temporary artifact cleanup failed: {}",
                output.stderr
            );
            Ok(())
        })
    }
    /// Publish a verified sibling staging directory without replacing a version.
    fn publish_directory<'a>(
        &'a self,
        source: &'a Path,
        destination: &'a Path,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let output = self
                .execute(
                    Path::new("/bin/mv"),
                    &[
                        "--no-clobber".into(),
                        "--no-target-directory".into(),
                        "--".into(),
                        source.to_string_lossy().into_owned(),
                        destination.to_string_lossy().into_owned(),
                    ],
                )
                .await?;
            anyhow::ensure!(
                output.success,
                "artifact publication failed: {}",
                output.stderr
            );
            anyhow::ensure!(
                !source.try_exists()?,
                "artifact version appeared during publication"
            );
            Ok(())
        })
    }
    fn install_archive<'a>(
        &'a self,
        archive: &'a Path,
        directory: &'a Path,
        binary_name: &'a str,
    ) -> BoxFuture<'a, ()>;
    fn install_archive_files<'a>(
        &'a self,
        archive: &'a Path,
        directory: &'a Path,
        binary_name: &'a str,
        auxiliary_files: &'a [String],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            anyhow::ensure!(
                auxiliary_files.is_empty(),
                "additional artifact files are not supported"
            );
            self.install_archive(archive, directory, binary_name).await
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ServiceLogLine {
    pub timestamp: Option<i64>,
    pub priority: Option<u8>,
    pub text: String,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceLogs {
    pub lines: Vec<ServiceLogLine>,
    pub truncated: bool,
    pub service_events: bool,
}

pub trait ServiceManager: Send + Sync {
    fn retire_interactive_sessions(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("service start is not supported") })
    }
    fn set_startup<'a>(&'a self, _unit: &'a str, _enabled: bool) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("service startup configuration is not supported") })
    }
    fn status_details<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, String> {
        Box::pin(async move { Ok(format!("active={}", self.is_active(unit).await?)) })
    }

    fn supports_runtime_checkpoint(&self) -> bool {
        false
    }
    /// Inspect the configured privilege and service backend without changing it.
    fn preflight_access<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, serde_json::Value> {
        Box::pin(async { anyhow::bail!("service preflight inspection is not supported") })
    }
    fn runtime_instance<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, RuntimeInstance> {
        Box::pin(async { anyhow::bail!("runtime instance inspection is not supported") })
    }

    /// Read a fixed, bounded recent log window for a registered service.
    fn recent_logs<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, ServiceLogs> {
        Box::pin(async { anyhow::bail!("service log reading is not supported") })
    }
    fn supports_confirmed_cancellation(&self) -> bool {
        false
    }
    /// Proves that the bound diagnostic has no remaining processes or mounts.
    /// Automatic completion, cancellation and retirement use the same evidence.
    fn diagnostic_cleanup_confirmed<'a>(
        &'a self,
        _unit: &'a str,
        _directory: &'a Path,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async { anyhow::bail!("diagnostic cleanup confirmation is not supported") })
    }
    fn running_diagnostic_units(&self) -> BoxFuture<'_, Vec<String>> {
        Box::pin(async { anyhow::bail!("diagnostic conflict inspection is not supported") })
    }
    fn reload<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()>;
    fn restart<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()>;
    fn stop<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()>;
    fn is_active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, bool>;
    fn start_job<'a>(&'a self, _job: &'a ServiceJob) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("one-shot services are not supported") })
    }
    fn job_status<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, JobStatus> {
        Box::pin(async { anyhow::bail!("one-shot services are not supported") })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticDescriptor {
    pub plugin_name: String,
    pub binary_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticSpec {
    pub id: String,
    pub version: String,
    pub binary_path: PathBuf,
    pub job_dir: PathBuf,
    pub timeout_secs: u32,
    pub options: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceJob {
    pub unit: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub working_directory: PathBuf,
    pub timeout_secs: u32,
    /// The systemd cgroup memory limit; other backends may not enforce this budget.
    #[serde(default)]
    pub memory_max: MemoryMax,
    /// The systemd cgroup task limit; other backends may not enforce this budget.
    #[serde(default)]
    pub tasks_max: TasksMax,
    /// The hard aggregate CPU bandwidth ceiling; 100 is one logical CPU.
    #[serde(default)]
    pub cpu_max_percent: CpuMaxPercent,
    /// The systemd cgroup CPU contention weight.
    #[serde(default)]
    pub cpu_weight: CpuWeight,
    /// The systemd cgroup I/O contention weight.
    #[serde(default)]
    pub io_weight: IoWeight,
    /// The systemd diagnostic process OOM adjustment.
    #[serde(default)]
    pub oom_score_adjust: OomScoreAdjust,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Missing,
    Running,
    Succeeded,
    Failed { error: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticOutput {
    pub text: String,
    pub report_url: Option<String>,
}

/// A durable, independently readable report chapter. Revisions increase per chapter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSection {
    pub name: String,
    pub text: String,
    pub complete: bool,
    pub revision: u64,
    pub collected_at: i64,
}

pub trait DiagnosticAdapter: Send + Sync {
    fn auxiliary_files(&self) -> Vec<String> {
        Vec::new()
    }
    /// Select the exact signed inventory without changing older artifact versions.
    fn auxiliary_files_for_version(&self, _version: &str) -> Vec<String> {
        self.auxiliary_files()
    }
    fn describe(&self) -> DiagnosticDescriptor;
    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }
    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob>;
    fn collect<'a>(&'a self, spec: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>>;
    fn collect_sections<'a>(
        &'a self,
        _spec: &'a DiagnosticSpec,
    ) -> BoxFuture<'a, Vec<DiagnosticSection>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

pub trait UsageSource: Send + Sync {
    fn read_counters<'a>(&'a self, runtime: &'a Prepared) -> BoxFuture<'a, Vec<Counter>>;
}

pub trait Adapter: Send + Sync {
    fn supports_dependency_validation(&self) -> bool {
        false
    }
    /// Validate only an allowlisted dependency encoded in this prepared configuration.
    fn validate_dependency<'a>(
        &'a self,
        _runtime: &'a Prepared,
        _scope: &'a str,
        _generation: u64,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("runtime dependency validation is not supported") })
    }
    fn describe(&self) -> Descriptor;
    fn supports_runtime_probe(&self) -> bool {
        false
    }
    fn runtime_probe<'a>(
        &'a self,
        _runtime: &'a Prepared,
        _probe_id: &'a str,
    ) -> BoxFuture<'a, RuntimeProbeMeasurement> {
        Box::pin(async { anyhow::bail!("runtime path verification is unsupported") })
    }
    /// Optional startup budget; callers must impose their own upper bound.
    fn health_timeout(&self, _target: &Prepared) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn prepare<'a>(
        &'a self,
        runtime: RuntimeSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, Prepared>;
    fn plan<'a>(
        &'a self,
        previous: Option<&'a Prepared>,
        target: &'a Prepared,
    ) -> BoxFuture<'a, Plan>;
    fn apply<'a>(
        &'a self,
        plan: Plan,
        target: &'a Prepared,
        services: &'a dyn ServiceManager,
    ) -> BoxFuture<'a, ()>;
    fn health<'a>(
        &'a self,
        target: &'a Prepared,
        services: &'a dyn ServiceManager,
    ) -> BoxFuture<'a, bool>;
    fn usage_source(&self) -> Option<&dyn UsageSource> {
        None
    }
}
