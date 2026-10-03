#![forbid(unsafe_code)]
#![cfg(unix)]

use anyhow::{Result, bail};
use sinan_adapter_sdk::{
    BoxFuture, CommandOutput, JobStatus, Privileged, ServiceJob, ServiceManager,
};
use sinan_agent_core::system::{ServiceBackend, SystemServiceManager};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct RecordingOps {
    calls: Mutex<Vec<(PathBuf, Vec<String>)>>,
    output: Mutex<CommandOutput>,
    unavailable: Mutex<bool>,
    files: Mutex<Vec<(PathBuf, Vec<u8>)>>,
    directories: Mutex<Vec<(PathBuf, u32, Option<String>)>>,
    allow_files: bool,
    allow_diagnostic_lock: bool,
    lock_preparations: Mutex<usize>,
}

impl RecordingOps {
    fn successful() -> Arc<Self> {
        Arc::new(Self {
            output: Mutex::new(CommandOutput {
                success: true,
                stdout: "LoadState=loaded\nActiveState=active\nMainPID=123\nControlPID=0\n".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    fn diagnostic(allow_files: bool) -> Arc<Self> {
        Arc::new(Self {
            allow_files,
            allow_diagnostic_lock: true,
            output: Mutex::new(CommandOutput {
                success: true,
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}

impl Privileged for RecordingOps {
    fn execute<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
    ) -> BoxFuture<'a, CommandOutput> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((program.into(), args.into()));
            if *self.unavailable.lock().unwrap() {
                bail!("service command unavailable");
            }
            if program == Path::new("stat") {
                anyhow::ensure!(
                    self.allow_diagnostic_lock && *self.lock_preparations.lock().unwrap() > 0,
                    "unexpected diagnostic lock inspection"
                );
                assert_eq!(args, ["-c", "%f %u", "--", "/run/sinan-diagnostic"]);
                assert!(self.directories.lock().unwrap().contains(&(
                    PathBuf::from("/run/sinan-diagnostic"),
                    0o700,
                    Some("root".into()),
                )));
                return Ok(CommandOutput {
                    success: true,
                    stdout: "41c0 0\n".into(),
                    ..Default::default()
                });
            }
            let probe = if program == Path::new("systemctl")
                && args == ["show", "--property=Features", "--value"]
            {
                Some("+SECCOMP\n")
            } else if program == Path::new("cat") && args == ["/proc/1/comm", "/proc/1/status"] {
                Some("systemd\nSeccomp: 0\nSeccomp_filters: 0\n")
            } else if program == Path::new("cat")
                && args == ["/proc/sys/kernel/seccomp/actions_avail"]
            {
                Some("errno allow\n")
            } else if program == Path::new("cat") && args == ["/sys/fs/cgroup/cgroup.controllers"] {
                Some("cpu memory io pids\n")
            } else {
                None
            };
            if let Some(probe) = probe {
                return Ok(CommandOutput {
                    success: true,
                    stdout: probe.into(),
                    ..Default::default()
                });
            }
            Ok(self.output.lock().unwrap().clone())
        })
    }
    fn create_dir<'a>(
        &'a self,
        path: &'a Path,
        mode: u32,
        group: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if path == Path::new("/run/sinan-diagnostic") {
                anyhow::ensure!(
                    self.allow_diagnostic_lock && mode == 0o700 && group == Some("root"),
                    "unexpected diagnostic lock directory permissions"
                );
                *self.lock_preparations.lock().unwrap() += 1;
            } else {
                anyhow::ensure!(self.allow_files, "unexpected filesystem operation");
            }
            self.directories.lock().unwrap().push((
                path.to_owned(),
                mode,
                group.map(str::to_owned),
            ));
            Ok(())
        })
    }
    fn write_file<'a>(
        &'a self,
        path: &'a Path,
        bytes: &'a [u8],
        _mode: u32,
        _group: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            anyhow::ensure!(self.allow_files, "unexpected filesystem operation");
            self.files
                .lock()
                .unwrap()
                .push((path.to_owned(), bytes.to_vec()));
            Ok(())
        })
    }
    fn atomic_symlink<'a>(&'a self, _link: &'a Path, _target: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async { bail!("unexpected filesystem operation") })
    }
    fn remove_symlink<'a>(&'a self, _link: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async { bail!("unexpected filesystem operation") })
    }
    fn install_archive<'a>(
        &'a self,
        _archive: &'a Path,
        _directory: &'a Path,
        _binary_name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { bail!("unexpected filesystem operation") })
    }
}

#[tokio::test]
async fn routes_runtime_lifecycle_to_selected_init_without_changing_instance() -> Result<()> {
    let unit = "example-runtime@main.service";
    for backend in [ServiceBackend::Systemd, ServiceBackend::OpenRc] {
        let ops = RecordingOps::successful();
        let services = SystemServiceManager::new(ops.clone(), backend);
        services.restart(unit).await?;
        services.reload(unit).await?;
        assert!(services.is_active(unit).await?);
        services.stop(unit).await?;
        let calls = ops.calls.lock().unwrap();
        let expected = match backend {
            ServiceBackend::Systemd => vec![
                vec!["restart", "--", unit],
                vec!["reload", "--", unit],
                vec![
                    "show",
                    "--property=LoadState,ActiveState,MainPID,ControlPID",
                    "--",
                    unit,
                ],
                vec!["stop", "--", unit],
            ],
            ServiceBackend::OpenRc => vec![
                vec!["--", "example-runtime@main", "restart"],
                vec!["--", "example-runtime@main", "reload"],
                vec!["--", "example-runtime@main", "status"],
                vec!["--", "example-runtime@main", "stop"],
            ],
            _ => unreachable!(),
        };
        let program = match backend {
            ServiceBackend::Systemd => "systemctl",
            ServiceBackend::OpenRc => "rc-service",
            _ => unreachable!(),
        };
        for ((actual_program, args), expected_args) in calls.iter().zip(expected) {
            assert_eq!(actual_program, Path::new(program));
            assert_eq!(args, &expected_args);
        }
        assert_eq!(calls.len(), 4);
    }
    Ok(())
}

#[tokio::test]
async fn stopped_services_are_inactive_but_execution_errors_are_propagated() -> Result<()> {
    for backend in [ServiceBackend::Systemd, ServiceBackend::OpenRc] {
        let ops = Arc::new(RecordingOps::default());
        let services = SystemServiceManager::new(ops.clone(), backend);
        if backend == ServiceBackend::Systemd {
            assert!(services.is_active("example-runtime.service").await.is_err());
            *ops.output.lock().unwrap() = CommandOutput {
                success: true,
                stdout: "LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlPID=0\n".into(),
                stderr: String::new(),
            };
            assert!(!services.is_active("example-runtime.service").await?);
            ops.output.lock().unwrap().success = false;
        } else {
            assert!(services.is_active("example-runtime.service").await.is_err());
            ops.output.lock().unwrap().stdout = " * status: stopped\n".into();
            assert!(!services.is_active("example-runtime.service").await?);
        }
        assert!(services.restart("example-runtime.service").await.is_err());
        assert!(services.reload("example-runtime.service").await.is_err());
        assert!(services.stop("example-runtime.service").await.is_err());
        *ops.unavailable.lock().unwrap() = true;
        assert!(services.is_active("example-runtime.service").await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn ambiguous_native_service_queries_cannot_confirm_shutdown() -> Result<()> {
    for (backend, inactive, active) in [
        (
            ServiceBackend::FreeBsd,
            "example_runtime is not running.\n",
            "example_runtime is running as pid 123.\n",
        ),
        (
            ServiceBackend::WindowsTask,
            "state=stopped\n",
            "state=active\n",
        ),
        (
            ServiceBackend::Launchd,
            "state = not running\n",
            "state = running\n",
        ),
    ] {
        let ops = Arc::new(RecordingOps::default());
        let services = SystemServiceManager::new(ops.clone(), backend);
        assert!(services.is_active("example-runtime.service").await.is_err());
        *ops.output.lock().unwrap() = CommandOutput {
            success: backend != ServiceBackend::FreeBsd,
            stdout: inactive.into(),
            stderr: String::new(),
        };
        assert!(!services.is_active("example-runtime.service").await?);
        *ops.output.lock().unwrap() = CommandOutput {
            success: true,
            stdout: active.into(),
            stderr: String::new(),
        };
        assert!(services.is_active("example-runtime.service").await?);
        ops.output.lock().unwrap().success = false;
        ops.output.lock().unwrap().stdout.clear();
        ops.output.lock().unwrap().stderr = "permission denied".into();
        assert!(services.is_active("example-runtime.service").await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn rejects_untrusted_service_names_before_any_privileged_command() {
    for backend in [ServiceBackend::Systemd, ServiceBackend::OpenRc] {
        let ops = RecordingOps::successful();
        let services = SystemServiceManager::new(ops.clone(), backend);
        let oversized = "x".repeat(256);
        for unit in [
            "",
            ".",
            "..",
            ".service",
            "-option",
            "../other",
            "two services",
            "name;cmd",
            &oversized,
        ] {
            assert!(services.restart(unit).await.is_err());
            assert!(services.reload(unit).await.is_err());
            assert!(services.stop(unit).await.is_err());
            assert!(services.is_active(unit).await.is_err());
        }
        assert!(ops.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn openrc_refuses_diagnostic_starts_without_equivalent_swap_protection() -> Result<()> {
    let ops = RecordingOps::diagnostic(true);
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::OpenRc);
    let job = ServiceJob {
        unit: format!("sinan-diagnostic-{}.service", uuid::Uuid::new_v4()),
        program: "/bin/true".into(),
        args: Vec::new(),
        working_directory: "/tmp".into(),
        timeout_secs: 10,
        memory_max: Default::default(),
        tasks_max: Default::default(),
        cpu_max_percent: Default::default(),
        cpu_weight: Default::default(),
        io_weight: Default::default(),
        oom_score_adjust: Default::default(),
    };
    assert!(
        services
            .start_job(&job)
            .await
            .unwrap_err()
            .to_string()
            .contains("不允许降级运行")
    );
    assert_eq!(*ops.lock_preparations.lock().unwrap(), 0);
    assert!(ops.calls.lock().unwrap().is_empty());
    assert!(ops.files.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn systemd_diagnostic_jobs_keep_independent_supervision_and_status() -> Result<()> {
    let ops = RecordingOps::diagnostic(false);
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
    let job = ServiceJob {
        unit: format!("sinan-diagnostic-{}.service", uuid::Uuid::new_v4()),
        program: "/bin/true".into(),
        args: Vec::new(),
        working_directory: "/tmp".into(),
        timeout_secs: 10,
        memory_max: Default::default(),
        tasks_max: Default::default(),
        cpu_max_percent: Default::default(),
        cpu_weight: Default::default(),
        io_weight: Default::default(),
        oom_score_adjust: Default::default(),
    };
    services.start_job(&job).await?;
    assert_eq!(*ops.lock_preparations.lock().unwrap(), 1);
    ops.output.lock().unwrap().stdout = "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\nExecMainCode=1\nExecMainStartTimestampMonotonic=1\n".into();
    assert_eq!(services.job_status(&job.unit).await?, JobStatus::Succeeded);
    let calls = ops.calls.lock().unwrap();
    assert_eq!(calls.len(), 7);
    assert_eq!(calls[0].0, Path::new("stat"));
    assert_eq!(calls[5].0, Path::new("systemd-run"));
    assert!(
        calls[5]
            .1
            .contains(&"--property=KillMode=control-group".into())
    );
    assert!(calls[5].1.contains(&"--property=PrivateMounts=yes".into()));
    assert!(calls[5].1.contains(&"--property=UMask=0077".into()));
    assert!(
        calls[5]
            .1
            .contains(&"--property=TimeoutStartSec=10s".into())
    );
    let separator = calls[5].1.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(
        &calls[5].1[separator + 1..],
        [
            "/usr/bin/flock",
            "--exclusive",
            "--nonblock",
            "--conflict-exit-code=75",
            "/run/sinan-diagnostic/lock",
            "/bin/true",
        ]
    );
    assert_eq!(calls[6].0, Path::new("systemctl"));
    assert_eq!(calls[6].1.last(), Some(&job.unit));
    Ok(())
}

#[tokio::test]
async fn recent_runtime_logs_are_unit_scoped_bounded_and_do_not_accept_paths() -> Result<()> {
    let ops = RecordingOps::successful();
    ops.output.lock().unwrap().stdout = concat!(
        "{\"MESSAGE\":\"newest secret\",\"PRIORITY\":\"3\",\"__REALTIME_TIMESTAMP\":\"2000000\"}\n",
        "{\"MESSAGE\":\"older\",\"PRIORITY\":\"6\",\"__REALTIME_TIMESTAMP\":\"1000000\"}\n"
    )
    .into();
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
    let logs = services.recent_logs("demo@main.service").await?;
    assert_eq!(logs.lines.len(), 2);
    assert_eq!(logs.lines[0].timestamp, Some(1));
    assert_eq!(logs.lines[1].priority, Some(3));
    assert!(!logs.truncated);
    assert!(services.recent_logs("../../private").await.is_err());
    let calls = ops.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, Path::new("journalctl"));
    for argument in [
        "--unit=demo@main.service",
        "--lines=100",
        "--since=-1h",
        "--reverse",
    ] {
        assert!(calls[0].1.iter().any(|value| value == argument));
    }
    Ok(())
}
