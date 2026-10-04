use super::{COMMAND_TIMEOUT, Privileged, ServiceManager};
use anyhow::{Context, Result, ensure};
use sinan_adapter_sdk::{BoxFuture, CommandOutput, JobStatus, ServiceJob};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::time::timeout;

mod logs;
#[path = "services/runtime.rs"]
mod runtime;
mod terminals;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceBackend {
    Systemd,
    OpenRc,
    Launchd,
    FreeBsd,
    WindowsTask,
    Unmanaged,
}

impl ServiceBackend {
    pub fn detect() -> Result<Self> {
        if cfg!(target_os = "macos") {
            return Ok(Self::Launchd);
        }
        if cfg!(target_os = "freebsd") {
            return Ok(Self::FreeBsd);
        }
        if cfg!(windows) {
            return Ok(Self::WindowsTask);
        }
        Self::detect_at(
            Path::new("/run/systemd/system"),
            Path::new("/run/openrc/softlevel"),
        )
    }

    fn detect_at(systemd: &Path, openrc: &Path) -> Result<Self> {
        if systemd.is_dir() {
            Ok(Self::Systemd)
        } else if openrc.is_file() {
            Ok(Self::OpenRc)
        } else {
            anyhow::bail!("Agent 运行需要 Linux systemd 或 OpenRC")
        }
    }
}

pub struct SystemServiceManager {
    pub(super) privileged: Arc<dyn Privileged>,
    pub(super) backend: ServiceBackend,
    pub(super) job_root: PathBuf,
}

impl SystemServiceManager {
    pub fn new(privileged: Arc<dyn Privileged>, backend: ServiceBackend) -> Self {
        Self {
            privileged,
            backend,
            job_root: "/var/lib/sinan/core/service-jobs".into(),
        }
    }

    pub fn with_job_root(mut self, directory: PathBuf) -> Self {
        self.job_root = directory;
        self
    }

    async fn call(
        &self,
        action: &str,
        unit: &str,
        properties: Option<&str>,
    ) -> Result<CommandOutput> {
        let service = unit.strip_suffix(".service").unwrap_or(unit);
        ensure!(
            !service.is_empty()
                && !matches!(service, "." | "..")
                && !service.starts_with('-')
                && unit.len() <= 255
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@')),
            "invalid service unit"
        );
        let (program, args) = match self.backend {
            ServiceBackend::Systemd => {
                let mut args = vec![action.to_owned()];
                if let Some(properties) = properties {
                    args.push(format!("--property={properties}"));
                }
                args.extend(["--".into(), unit.to_owned()]);
                ("systemctl", args)
            }
            ServiceBackend::OpenRc => {
                let action = if action == "is-active" {
                    "status"
                } else {
                    action
                };
                (
                    "rc-service",
                    vec!["--".into(), service.into(), action.into()],
                )
            }
            ServiceBackend::FreeBsd => {
                let name = service.replace(['@', '-', '.'], "_");
                if action == "stop" {
                    let active = self
                        .privileged
                        .execute(Path::new("service"), &[name.clone(), "onestatus".into()])
                        .await?;
                    if !active.success {
                        return Ok(CommandOutput {
                            success: true,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }
                }
                let action = if action == "is-active" {
                    "onestatus"
                } else {
                    action
                };
                ("service", vec![name, action.into()])
            }
            ServiceBackend::Launchd => {
                let label = format!("system/org.sinan.{}", service.replace('@', "."));
                if matches!(action, "restart" | "stop") {
                    let loaded = self
                        .privileged
                        .execute(Path::new("launchctl"), &["print".into(), label.clone()])
                        .await?;
                    if action == "stop" && !loaded.success {
                        return Ok(CommandOutput {
                            success: true,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }
                    if action == "restart" && !loaded.success {
                        let path = format!(
                            "/Library/LaunchDaemons/org.sinan.{}.plist",
                            service.replace('@', ".")
                        );
                        let result = self
                            .privileged
                            .execute(
                                Path::new("launchctl"),
                                &["bootstrap".into(), "system".into(), path],
                            )
                            .await?;
                        ensure!(
                            result.success,
                            "cannot load runtime service: {}",
                            result.stderr
                        );
                    }
                }
                let args = match action {
                    "restart" => vec!["kickstart".into(), "-k".into(), label],
                    "reload" => vec!["kill".into(), "SIGHUP".into(), label],
                    "stop" => vec!["bootout".into(), label],
                    "is-active" => vec!["print".into(), label],
                    _ => anyhow::bail!("unsupported service action"),
                };
                ("launchctl", args)
            }
            ServiceBackend::WindowsTask => {
                let operation = match action {
                    "restart" | "reload" => {
                        "$task.Stop(0); $deadline=[DateTime]::UtcNow.AddSeconds(10); while($task.State -in @(2,4)) { if([DateTime]::UtcNow -ge $deadline) { throw 'Task did not stop' }; [Threading.Thread]::Sleep(100) }; $null=$task.Run($null)"
                    }
                    "stop" => "$task.Stop(0)",
                    "is-active" => {
                        "if ($task.State -in @(2,4)) { Write-Output 'state=active' } elseif ($task.State -in @(1,3)) { Write-Output 'state=stopped' } else { throw 'Task state is unknown' }"
                    }
                    _ => anyhow::bail!("unsupported service action"),
                };
                let script = format!(
                    "$ErrorActionPreference='Stop'; $scheduler=[Activator]::CreateInstance([Type]::GetTypeFromProgID('Schedule.Service')); $scheduler.Connect(); $task=$scheduler.GetFolder('\\').GetTask('{service}'); {operation}"
                );
                (
                    "powershell.exe",
                    vec![
                        "-NoProfile".into(),
                        "-NonInteractive".into(),
                        "-Command".into(),
                        script,
                    ],
                )
            }
            ServiceBackend::Unmanaged => {
                anyhow::bail!("monitor-only Agent has no runtime service manager")
            }
        };
        timeout(
            COMMAND_TIMEOUT,
            self.privileged.execute(Path::new(program), &args),
        )
        .await
        .context("service operation timed out")?
    }

    async fn change(&self, action: &str, unit: &str) -> Result<()> {
        let output = self.call(action, unit, None).await?;
        ensure!(
            output.success,
            "service operation failed: {}",
            output.stderr
        );
        Ok(())
    }
}

impl ServiceManager for SystemServiceManager {
    fn retire_interactive_sessions(&self) -> BoxFuture<'_, ()> {
        Box::pin(terminals::retire(self))
    }

    fn start<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.change("start", unit))
    }
    fn set_startup<'a>(&'a self, unit: &'a str, enabled: bool) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            ensure!(
                self.backend == ServiceBackend::Systemd,
                "startup configuration requires systemd"
            );
            self.change(if enabled { "enable" } else { "disable" }, unit)
                .await
        })
    }
    fn status_details<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, String> {
        Box::pin(async move {
            if self.backend == ServiceBackend::Systemd {
                let result = self.call("show", unit, Some("LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainStatus,MainPID,MemoryCurrent,CPUUsageNSec,User,Group")).await?;
                ensure!(result.success, "service details failed: {}", result.stderr);
                Ok(result.stdout)
            } else {
                Ok(format!("active={}", self.is_active(unit).await?))
            }
        })
    }

    fn supports_runtime_checkpoint(&self) -> bool {
        cfg!(target_os = "linux") && self.backend == ServiceBackend::Systemd
    }
    fn preflight_access<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, serde_json::Value> {
        Box::pin(async move {
            ensure!(
                !unit.is_empty()
                    && unit.len() <= 128
                    && unit.bytes().all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'_' | b'@' | b'.')),
                "invalid managed service inspection unit"
            );
            let (kind, program, args) = match self.backend {
                ServiceBackend::Systemd => (
                    "systemd",
                    "systemctl",
                    vec!["show".into(), "--property=Version,Features".into()],
                ),
                ServiceBackend::OpenRc => ("openrc", "rc-status", vec!["--all".into()]),
                _ => {
                    return Ok(
                        serde_json::json!({"kind":"unsupported","available":false,"management_authorized":null}),
                    );
                }
            };
            let identity = self
                .privileged
                .execute_bounded(Path::new("id"), &["-u".into()], 3, 1024)
                .await?;
            let uid = if identity.output.success && !identity.timed_out && !identity.truncated {
                identity.output.stdout.trim().parse::<u64>().ok()
            } else {
                None
            };
            let probe = self
                .privileged
                .execute_bounded(Path::new(program), &args, 5, 16 * 1024)
                .await?;
            let available = probe.output.success && !probe.timed_out && !probe.truncated;
            let mut managed_pid: Option<u32> = None;
            let mut account =
                serde_json::json!({"known":false,"source":"runtime_service_account_not_observed"});
            let mut load_state: Option<String> = None;
            if available && self.backend == ServiceBackend::Systemd {
                let details = self
                    .privileged
                    .execute_bounded(
                        Path::new("systemctl"),
                        &[
                            "show".into(),
                            "--property=LoadState,MainPID,User,Group,SupplementaryGroups".into(),
                            "--".into(),
                            unit.into(),
                        ],
                        5,
                        4096,
                    )
                    .await?;
                if details.output.success && !details.timed_out && !details.truncated {
                    let properties: std::collections::BTreeMap<_, _> = details
                        .output
                        .stdout
                        .lines()
                        .filter_map(|line| line.split_once('='))
                        .collect();
                    managed_pid = properties
                        .get("MainPID")
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|pid| *pid > 0);
                    load_state = properties.get("LoadState").map(|value| (*value).to_owned());
                    if load_state.as_deref() == Some("loaded")
                        && let Some(name) = properties.get("User")
                        && let Some(group) = properties.get("Group")
                        && let Some(supplementary) = properties.get("SupplementaryGroups")
                    {
                        account = serde_json::json!({"known":true,"name":if name.is_empty(){"root"}else{name},"group":group,"supplementary_groups":supplementary.split_whitespace().collect::<Vec<_>>(),"source":"loaded_systemd_unit_configuration","empty_account_semantics":"only_a_loaded_unit_with_an_observed_empty_account_field_has_systemd_default_root"});
                    }
                }
            }
            Ok(
                serde_json::json!({"kind":kind,"available":available,"privileged_effective_uid":uid,
                "managed_unit":unit,"managed_pid":managed_pid,"load_state":load_state,"runtime_account":account,
                "management_authorized":if available && uid==Some(0){Some(true)}else{None},
                "authorization_basis":"observed_privileged_effective_uid_0_and_connected_backend; no mutation attempted; later authorization may change"}),
            )
        })
    }
    fn runtime_instance<'a>(
        &'a self,
        unit: &'a str,
    ) -> BoxFuture<'a, sinan_adapter_sdk::RuntimeInstance> {
        Box::pin(runtime::inspect(self, unit))
    }

    fn recent_logs<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, sinan_adapter_sdk::ServiceLogs> {
        Box::pin(self.read_recent_logs(unit))
    }
    #[cfg(unix)]
    fn supports_confirmed_cancellation(&self) -> bool {
        super::cleanup::supported(self.backend)
    }
    fn supports_diagnostic_cpu_ceiling(&self) -> bool {
        self.backend == ServiceBackend::Systemd && super::diagnostic_cpu_ceiling_supported()
    }
    #[cfg(unix)]
    fn diagnostic_cleanup_confirmed<'a>(
        &'a self,
        unit: &'a str,
        directory: &'a std::path::Path,
    ) -> BoxFuture<'a, bool> {
        Box::pin(self.confirm_diagnostic_cleanup(unit, directory))
    }
    fn running_diagnostic_units(&self) -> BoxFuture<'_, Vec<String>> {
        self.diagnostic_running_units()
    }
    fn reload<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.change("reload", unit))
    }
    fn restart<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.change("restart", unit))
    }
    fn stop<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.change("stop", unit))
    }
    fn is_active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            if self.backend == ServiceBackend::Systemd {
                let output = self
                    .call(
                        "show",
                        unit,
                        Some("LoadState,ActiveState,MainPID,ControlPID"),
                    )
                    .await?;
                return parse_runtime_active(&output);
            }
            let output = self.call("is-active", unit, None).await?;
            match self.backend {
                ServiceBackend::OpenRc => {
                    if output.success {
                        return Ok(true);
                    }
                    let text = format!("{}\n{}", output.stdout, output.stderr);
                    ensure!(
                        text.lines().any(|line| matches!(
                            line.trim(),
                            "* status: stopped" | "* status: crashed"
                        )),
                        "OpenRC service status query failed: {text}"
                    );
                    Ok(false)
                }
                ServiceBackend::FreeBsd => {
                    if output.success {
                        return Ok(true);
                    }
                    ensure!(
                        output
                            .stdout
                            .lines()
                            .any(|line| line.trim().ends_with(" is not running.")),
                        "FreeBSD service status query failed: {}",
                        output.stderr
                    );
                    Ok(false)
                }
                ServiceBackend::WindowsTask => {
                    ensure!(
                        output.success,
                        "scheduled task status query failed: {}",
                        output.stderr
                    );
                    match output.stdout.trim() {
                        "state=active" => Ok(true),
                        "state=stopped" => Ok(false),
                        _ => anyhow::bail!("scheduled task state is unknown"),
                    }
                }
                ServiceBackend::Launchd => {
                    if !output.success {
                        ensure!(
                            output.stderr.contains("Could not find service"),
                            "launchd service status query failed: {}",
                            output.stderr
                        );
                        return Ok(false);
                    }
                    if output
                        .stdout
                        .lines()
                        .any(|line| line.trim() == "state = running")
                    {
                        return Ok(true);
                    }
                    ensure!(
                        output
                            .stdout
                            .lines()
                            .any(|line| line.trim() == "state = not running"),
                        "launchd service process state is unknown"
                    );
                    Ok(false)
                }
                _ => anyhow::bail!("unsupported runtime status backend"),
            }
        })
    }
    fn start_job<'a>(&'a self, job: &'a ServiceJob) -> BoxFuture<'a, ()> {
        self.start_diagnostic_job(job)
    }
    fn job_status<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, JobStatus> {
        self.diagnostic_job_status(unit)
    }
}

pub(super) fn parse_runtime_active(output: &CommandOutput) -> Result<bool> {
    ensure!(
        output.success,
        "runtime service status query failed: {}",
        output.stderr
    );
    let properties: std::collections::BTreeMap<_, _> = output
        .stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let pid = |name| -> Result<u32> {
        properties
            .get(name)
            .with_context(|| format!("service status is missing {name}"))?
            .parse()
            .with_context(|| format!("service status has invalid {name}"))
    };
    let load = properties.get("LoadState").copied();
    // A never-installed runtime is safe only when systemd explicitly reports
    // the missing unit and confirms that no main or control process exists.
    if load == Some("not-found") {
        ensure!(
            properties.get("ActiveState") == Some(&"inactive")
                && pid("MainPID")? == 0
                && pid("ControlPID")? == 0,
            "missing runtime service still has unknown or active processes"
        );
        return Ok(false);
    }
    ensure!(
        matches!(load, Some("loaded" | "masked")),
        "runtime service load state is unknown"
    );
    let running = pid("MainPID")? != 0 || pid("ControlPID")? != 0;
    match properties.get("ActiveState").copied() {
        Some("active" | "activating" | "deactivating" | "reloading") => Ok(true),
        Some("inactive" | "failed") => Ok(running),
        _ => anyhow::bail!("runtime service active state is unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ServiceBackend, ServiceManager, SystemServiceManager};

    #[test]
    fn diagnostic_cpu_ceiling_is_denied_without_explicit_backend_support() {
        assert!(!crate::fake::FakeServiceManager::default().supports_diagnostic_cpu_ceiling());
    }

    #[test]
    fn non_systemd_backends_never_advertise_diagnostic_cpu_ceiling() {
        for backend in [
            ServiceBackend::OpenRc,
            ServiceBackend::Launchd,
            ServiceBackend::FreeBsd,
            ServiceBackend::WindowsTask,
            ServiceBackend::Unmanaged,
        ] {
            let services =
                SystemServiceManager::new(std::sync::Arc::new(crate::system::SystemOps), backend);
            assert!(!services.supports_diagnostic_cpu_ceiling(), "{backend:?}");
        }
    }

    #[test]
    fn detects_active_init_and_prefers_systemd_over_openrc() {
        let root = std::env::temp_dir().join(format!("sinan-init-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let systemd = root.join("systemd");
        let openrc = root.join("softlevel");
        assert!(ServiceBackend::detect_at(&systemd, &openrc).is_err());
        std::fs::write(&openrc, "default\n").unwrap();
        assert_eq!(
            ServiceBackend::detect_at(&systemd, &openrc).unwrap(),
            ServiceBackend::OpenRc
        );
        std::fs::create_dir(&systemd).unwrap();
        assert_eq!(
            ServiceBackend::detect_at(&systemd, &openrc).unwrap(),
            ServiceBackend::Systemd
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
