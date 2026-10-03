use super::*;

pub(super) const DIAGNOSTIC_LOCK_PATH: &str = "/run/sinan-diagnostic/lock";
const DIAGNOSTIC_LOCK_DIRECTORY: &str = "/run/sinan-diagnostic";

pub(super) async fn prepare_diagnostic_lock(ops: &dyn Privileged) -> Result<()> {
    let directory = Path::new(DIAGNOSTIC_LOCK_DIRECTORY);
    // Only root can reach the persistent lock inode, even if flock opens it read-only.
    // Do not publish or remove the lock file: replacing it would split the exclusion.
    ops.create_dir(directory, 0o700, Some("root")).await?;
    let execution = ops
        .execute_bounded(
            Path::new("stat"),
            &[
                "-c".into(),
                "%f %u".into(),
                "--".into(),
                DIAGNOSTIC_LOCK_DIRECTORY.into(),
            ],
            5,
            1024,
        )
        .await?;
    ensure!(
        execution.output.success && !execution.timed_out && !execution.truncated,
        "diagnostic lock directory inspection failed"
    );
    let fields: Vec<_> = execution.output.stdout.split_whitespace().collect();
    ensure!(
        fields.len() == 2,
        "invalid diagnostic lock directory metadata"
    );
    let mode =
        u32::from_str_radix(fields[0], 16).context("invalid diagnostic lock directory mode")?;
    ensure!(
        mode & 0o170000 == 0o040000 && mode & 0o7777 == 0o700 && fields[1] == "0",
        "diagnostic lock directory must be an ordinary root-owned 0700 directory"
    );
    Ok(())
}

impl SystemServiceManager {
    pub(super) fn diagnostic_running_units(&self) -> BoxFuture<'_, Vec<String>> {
        Box::pin(async move {
            if self.backend == ServiceBackend::OpenRc {
                return self.openrc_running_units().await;
            }
            ensure!(
                self.backend == ServiceBackend::Systemd,
                "当前服务后端不支持安全诊断冲突检查"
            );
            let args = vec![
                "list-units".into(),
                "--type=service".into(),
                "--state=activating,active,deactivating,reloading".into(),
                "--no-legend".into(),
                "--plain".into(),
                "--no-pager".into(),
                "sinan-diagnostic-*.service".into(),
            ];
            let execution = self
                .privileged
                .execute_bounded(Path::new("systemctl"), &args, 5, 64 * 1024)
                .await?;
            ensure!(
                !execution.timed_out && !execution.truncated,
                "诊断服务列表读取超时或超限"
            );
            let output = execution.output;
            ensure!(
                output.success,
                "diagnostic conflict inspection failed: {}",
                output.stderr
            );
            parse_running_units(&output.stdout)
        })
    }
    pub(super) fn start_diagnostic_job<'a>(&'a self, job: &'a ServiceJob) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            ensure!(valid_job_unit(&job.unit), "invalid diagnostic service unit");
            ensure!(
                job.program.is_absolute()
                    && job.working_directory.is_absolute()
                    && (1..=3600).contains(&job.timeout_secs),
                "invalid diagnostic service configuration"
            );
            let program = job
                .program
                .to_str()
                .context("diagnostic program path is not UTF-8")?;
            let directory = job
                .working_directory
                .to_str()
                .context("diagnostic working directory is not UTF-8")?;
            ensure!(
                std::iter::once(program)
                    .chain(std::iter::once(directory))
                    .chain(job.args.iter().map(String::as_str))
                    .all(
                        |value| !value.chars().any(char::is_control) && !value.contains(['$', '%'])
                    ),
                "diagnostic arguments cannot contain systemd expansion syntax or control characters"
            );
            ensure!(
                self.backend == ServiceBackend::Systemd,
                "诊断启动需要 systemd/cgroup v2 的 CPU 硬上限与 swap 系统调用保护；当前后端无法验证保护，不允许降级运行"
            );
            prepare_diagnostic_lock(self.privileged.as_ref()).await?;
            super::syscall_protection::verify_support(self.privileged.as_ref()).await?;
            super::cpu_ceiling::verify_support(self.privileged.as_ref()).await?;
            let mut args = vec![
                format!("--unit={}", job.unit),
                "--no-block".into(),
                "--property=Type=oneshot".into(),
                "--property=RemainAfterExit=yes".into(),
                format!("--property=TimeoutStartSec={}s", job.timeout_secs),
                "--property=TimeoutStopSec=30s".into(),
                "--property=KillMode=control-group".into(),
                "--property=PrivateMounts=yes".into(),
                "--property=NoNewPrivileges=yes".into(),
                "--property=SystemCallArchitectures=native".into(),
                "--property=SystemCallFilter=~swapon swapoff".into(),
                "--property=SystemCallErrorNumber=EPERM".into(),
                "--property=UMask=0077".into(),
                "--property=StandardOutput=null".into(),
                "--property=StandardError=journal".into(),
                format!("--property=MemoryMax={}", job.memory_max.get()),
                "--property=MemorySwapMax=0".into(),
                format!("--property=TasksMax={}", job.tasks_max.get()),
                format!("--property=CPUWeight={}", job.cpu_weight.get()),
                format!("--property=CPUQuota={}%", job.cpu_max_percent.get()),
                "--property=CPUQuotaPeriodSec=100ms".into(),
                super::cpu_ceiling::pre_command(job.cpu_max_percent.get()),
                format!("--property=IOWeight={}", job.io_weight.get()),
                format!("--property=OOMScoreAdjust={}", job.oom_score_adjust.get()),
                format!("--property=WorkingDirectory={directory}"),
                "--".into(),
                "/usr/bin/flock".into(),
                "--exclusive".into(),
                "--nonblock".into(),
                "--conflict-exit-code=75".into(),
                DIAGNOSTIC_LOCK_PATH.into(),
                program.into(),
            ];
            args.extend(job.args.iter().cloned());
            let output = self
                .privileged
                .execute(Path::new("systemd-run"), &args)
                .await?;
            ensure!(
                output.success,
                "diagnostic service start failed: {}",
                output.stderr
            );
            Ok(())
        })
    }
    pub(super) fn diagnostic_job_status<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, JobStatus> {
        Box::pin(async move {
            ensure!(valid_job_unit(unit), "invalid diagnostic service unit");
            if self.backend == ServiceBackend::OpenRc {
                return self.openrc_job_status(unit).await;
            }
            ensure!(
                self.backend == ServiceBackend::Systemd,
                "diagnostic jobs require Linux"
            );
            let args = vec!["show".into(), "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,Job".into(), "--".into(), unit.into()];
            let output = self
                .privileged
                .execute(Path::new("systemctl"), &args)
                .await?;
            parse_job_status(&output)
        })
    }
}

fn parse_running_units(output: &str) -> Result<Vec<String>> {
    ensure!(
        output.len() <= 64 * 1024,
        "diagnostic service list is too large"
    );
    let mut units = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().take(4).collect();
        ensure!(
            fields.len() == 4 && valid_job_unit(fields[0]) && fields[1] == "loaded",
            "diagnostic service list has an unknown row"
        );
        ensure!(
            matches!(
                fields[2],
                "activating" | "active" | "deactivating" | "reloading"
            ),
            "diagnostic service list has an unknown state"
        );
        if !(fields[2] == "active" && fields[3] == "exited") {
            units.push(fields[0].into());
        }
    }
    Ok(units)
}

pub(super) fn valid_job_unit(unit: &str) -> bool {
    unit.strip_prefix("sinan-diagnostic-")
        .and_then(|value| value.strip_suffix(".service"))
        .is_some_and(|id| Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id))
}

fn parse_job_status(output: &CommandOutput) -> Result<JobStatus> {
    let properties: std::collections::BTreeMap<_, _> = output
        .stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    if properties.get("LoadState") == Some(&"not-found") {
        return Ok(JobStatus::Missing);
    }
    ensure!(
        output.success,
        "diagnostic service status query failed: {}",
        output.stderr
    );
    ensure!(
        properties.get("LoadState") == Some(&"loaded"),
        "diagnostic service load state is unknown"
    );
    match properties.get("ActiveState").copied() {
        Some("activating" | "deactivating" | "reloading") => Ok(JobStatus::Running),
        Some("active") if properties.get("SubState") != Some(&"exited") => Ok(JobStatus::Running),
        // --no-block can leave a start job queued while the unit is inactive.
        // Any outstanding job must settle before interpreting the last result.
        Some("active" | "inactive" | "failed")
            if properties.get("Job").is_some_and(|value| {
                value
                    .parse::<std::num::NonZeroU32>()
                    .is_ok_and(|id| id.to_string().as_str() == *value)
            }) =>
        {
            Ok(JobStatus::Running)
        }
        Some("active" | "inactive")
            if properties.get("Result") == Some(&"success")
                && properties.get("ExecMainStatus") == Some(&"0")
                && properties.get("ExecMainCode") == Some(&"1")
                && properties
                    .get("ExecMainStartTimestampMonotonic")
                    .is_some_and(|value| *value != "0" && !value.is_empty()) =>
        {
            Ok(JobStatus::Succeeded)
        }
        Some("failed" | "inactive" | "active") => Ok(JobStatus::Failed {
            error: if properties.get("ExecMainStatus") == Some(&"75") {
                "诊断失败（退出码 75）：同机独占锁被占用时不会执行测试，请确认原任务已结束后重试"
                    .into()
            } else {
                format!(
                    "diagnostic service failed: result={}, code={}, status={}",
                    properties.get("Result").unwrap_or(&"unknown"),
                    properties.get("ExecMainCode").unwrap_or(&"unknown"),
                    properties.get("ExecMainStatus").unwrap_or(&"unknown")
                )
            },
        }),
        _ => anyhow::bail!("diagnostic service active state is unknown"),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "locks.rs"]
mod lock_tests;
