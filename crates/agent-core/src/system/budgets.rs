use super::*;
use sinan_adapter_sdk::{CpuMaxPercent, CpuWeight, IoWeight, MemoryMax, OomScoreAdjust, TasksMax};
use std::{path::PathBuf, sync::Mutex};

#[derive(Default)]
struct RecordingOps(Mutex<Vec<(PathBuf, Vec<String>)>>);

#[tokio::test]
async fn conflict_probe_is_a_read_only_systemctl_query() -> Result<()> {
    let ops = Arc::new(RecordingOps::default());
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
    assert!(services.running_diagnostic_units().await?.is_empty());
    let calls = ops.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, Path::new("systemctl"));
    assert_eq!(
        calls[0].1,
        [
            "list-units",
            "--type=service",
            "--state=activating,active,deactivating,reloading",
            "--no-legend",
            "--plain",
            "--no-pager",
            "sinan-diagnostic-*.service"
        ]
    );
    Ok(())
}

impl Privileged for RecordingOps {
    fn execute<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
    ) -> BoxFuture<'a, CommandOutput> {
        Box::pin(async move {
            self.0.lock().unwrap().push((program.into(), args.to_vec()));
            Ok(CommandOutput {
                success: true,
                stdout: if program == Path::new("stat") {
                    "41c0 0\n".into()
                } else if let Some(output) =
                    crate::system::syscall_protection::fixture_output(program, args)
                {
                    output.into()
                } else {
                    String::new()
                },
                ..Default::default()
            })
        })
    }

    fn create_dir<'a>(
        &'a self,
        path: &'a Path,
        mode: u32,
        group: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            assert_eq!(path, Path::new("/run/sinan-diagnostic"));
            assert_eq!(mode, 0o700);
            assert_eq!(group, Some("root"));
            Ok(())
        })
    }
    fn write_file<'a>(
        &'a self,
        _: &'a Path,
        _: &'a [u8],
        _: u32,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        panic!("unexpected file write")
    }
    fn atomic_symlink<'a>(&'a self, _: &'a Path, _: &'a Path) -> BoxFuture<'a, ()> {
        panic!("unexpected symlink creation")
    }
    fn remove_symlink<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, ()> {
        panic!("unexpected symlink removal")
    }
    fn install_archive<'a>(&'a self, _: &'a Path, _: &'a Path, _: &'a str) -> BoxFuture<'a, ()> {
        panic!("unexpected archive installation")
    }
}

fn legacy_service() -> serde_json::Value {
    serde_json::json!({
        "unit": "sinan-diagnostic-12345678-1234-1234-1234-123456789abc.service",
        "program": "/usr/bin/true",
        "args": [],
        "working_directory": "/tmp",
        "timeout_secs": 30,
    })
}

#[tokio::test]
async fn service_command_applies_every_budget_before_the_program_separator() -> Result<()> {
    let ops = Arc::new(RecordingOps::default());
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
    let mut job: ServiceJob = serde_json::from_value(legacy_service())?;
    assert_eq!(job.memory_max.get(), 512 * 1024 * 1024);
    assert_eq!(job.tasks_max.get(), 128);
    assert_eq!(job.cpu_max_percent.get(), 100);
    assert_eq!(job.cpu_weight.get(), 10);
    assert_eq!(job.io_weight.get(), 10);
    assert_eq!(job.oom_score_adjust.get(), 500);
    for custom in [false, true] {
        if custom {
            job.memory_max = MemoryMax::new(64 * 1024 * 1024)?;
            job.tasks_max = TasksMax::new(16)?;
            job.cpu_max_percent = CpuMaxPercent::new(20)?;
            job.cpu_weight = CpuWeight::new(25)?;
            job.io_weight = IoWeight::new(30)?;
            job.oom_score_adjust = OomScoreAdjust::new(700)?;
        }
        // A payload argument that resembles a property must stay a payload argument.
        job.args = vec!["--property=MemoryMax=infinity".into()];
        services.start_job(&job).await?;
        let calls = ops.0.lock().unwrap();
        let (program, args) = calls.last().unwrap();
        assert_eq!(program, Path::new("systemd-run"));
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &args[separator + 1..],
            [
                "/usr/bin/flock",
                "--exclusive",
                "--nonblock",
                "--conflict-exit-code=75",
                "/run/sinan-diagnostic/lock",
                "/usr/bin/true",
                "--property=MemoryMax=infinity"
            ]
        );
        assert_eq!(
            args[..separator]
                .iter()
                .filter(|arg| arg.starts_with("--property=ExecStartPre="))
                .collect::<Vec<_>>(),
            [crate::system::cpu_ceiling::pre_command(
                job.cpu_max_percent.get()
            )]
            .iter()
            .collect::<Vec<_>>()
        );
        for (property, expected) in [
            ("MemoryMax", job.memory_max.get().to_string()),
            ("MemorySwapMax", "0".into()),
            ("NoNewPrivileges", "yes".into()),
            ("SystemCallArchitectures", "native".into()),
            ("SystemCallFilter", "~swapon swapoff".into()),
            ("SystemCallErrorNumber", "EPERM".into()),
            ("TasksMax", job.tasks_max.get().to_string()),
            ("CPUWeight", job.cpu_weight.get().to_string()),
            ("CPUQuota", format!("{}%", job.cpu_max_percent.get())),
            ("CPUQuotaPeriodSec", "100ms".into()),
            ("IOWeight", job.io_weight.get().to_string()),
            ("OOMScoreAdjust", job.oom_score_adjust.get().to_string()),
        ] {
            let prefix = format!("--property={property}=");
            let properties: Vec<_> = args[..separator]
                .iter()
                .filter(|arg| arg.starts_with(&prefix))
                .collect();
            assert_eq!(properties, vec![&format!("{prefix}{expected}")]);
        }
    }
    assert_eq!(ops.0.lock().unwrap().len(), 12);
    Ok(())
}

#[test]
fn persisted_budgets_reject_unlimited_and_invalid_values_without_defaulting() -> Result<()> {
    for (field, invalid) in [
        ("memory_max", serde_json::json!(0)),
        ("memory_max", serde_json::json!(u64::MAX)),
        ("memory_max", serde_json::json!("infinity")),
        ("memory_max", serde_json::json!(null)),
        ("tasks_max", serde_json::json!(0)),
        ("tasks_max", serde_json::json!(u32::MAX)),
        ("tasks_max", serde_json::json!("infinity")),
        ("cpu_weight", serde_json::json!(0)),
        ("cpu_weight", serde_json::json!(10001)),
        ("cpu_max_percent", serde_json::json!(0)),
        ("cpu_max_percent", serde_json::json!(6401)),
        ("cpu_max_percent", serde_json::json!(null)),
        ("io_weight", serde_json::json!(0)),
        ("io_weight", serde_json::json!(10001)),
        ("oom_score_adjust", serde_json::json!(-1000)),
        ("oom_score_adjust", serde_json::json!(1001)),
    ] {
        let mut saved = legacy_service();
        saved[field] = invalid;
        assert!(
            serde_json::from_value::<ServiceJob>(saved).is_err(),
            "{field}"
        );
    }
    let mut service: ServiceJob = serde_json::from_value(legacy_service())?;
    service.memory_max = MemoryMax::new(256 * 1024 * 1024)?;
    service.tasks_max = TasksMax::new(32)?;
    service.cpu_weight = CpuWeight::new(1)?;
    service.io_weight = IoWeight::new(10000)?;
    service.oom_score_adjust = OomScoreAdjust::new(1000)?;
    let saved = serde_json::to_string(&service)?;
    assert_eq!(serde_json::from_str::<ServiceJob>(&saved)?, service);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux cgroup v2, a running systemd system manager, Python 3, and root"]
async fn real_systemd_diagnostic_resource_budget_restricts_memory_and_children() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "requires Linux/systemd");
    ensure!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "requires cgroup v2"
    );
    let ops: Arc<dyn Privileged> = Arc::new(SystemOps);
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
    let directory = std::env::temp_dir().join(format!("sinan-budget-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory)?;
    let script = directory.join("children.py");
    std::fs::write(
        &script,
        r#"import errno
import os
import signal
import time

children = []
try:
    for attempt in range(64):
        try:
            child = os.fork()
        except OSError as error:
            if error.errno != errno.EAGAIN:
                raise
            with open("tasks-limit.txt", "w") as marker:
                marker.write(str(len(children)))
            break
        if child == 0:
            time.sleep(60)
            os._exit(0)
        children.append(child)
    else:
        raise RuntimeError("TasksMax did not restrict child creation")
finally:
    for child in children:
        os.kill(child, signal.SIGTERM)
    for child in children:
        os.waitpid(child, 0)
"#,
    )?;
    let mut units = Vec::new();
    let result = async {
        for memory_test in [true, false] {
            let mut job: ServiceJob = serde_json::from_value(legacy_service())?;
            job.unit = format!("sinan-diagnostic-{}.service", Uuid::new_v4());
            job.program = "/usr/bin/python3".into();
            job.args = if memory_test {
                vec!["-c".into(), "bytearray(256 * 1024 * 1024)".into()]
            } else {
                vec![script.to_str().unwrap().into()]
            };
            job.working_directory = directory.clone();
            job.memory_max = MemoryMax::new(64 * 1024 * 1024)?;
            job.tasks_max = TasksMax::new(8)?;
            units.push(job.unit.clone());
            services.start_job(&job).await?;
            let status = tokio::time::timeout(Duration::from_secs(40), async {
                loop {
                    // --no-block acknowledges the queued start before ExecStart runs.
                    // Never mistake the transient unit's initial inactive state for exit.
                    let started = ops
                        .execute(
                            Path::new("systemctl"),
                            &[
                                "show".into(),
                                "--property=ExecMainStartTimestampMonotonic".into(),
                                "--".into(),
                                job.unit.clone(),
                            ],
                        )
                        .await?;
                    if !started.success
                        || !started
                            .stdout
                            .trim()
                            .strip_prefix("ExecMainStartTimestampMonotonic=")
                            .and_then(|value| value.parse::<u64>().ok())
                            .is_some_and(|value| value > 0)
                    {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    let status = services.job_status(&job.unit).await?;
                    if status != JobStatus::Running {
                        return Ok::<_, anyhow::Error>(status);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await??;
            if memory_test {
                assert!(
                    matches!(&status, JobStatus::Failed { error } if error.contains("oom-kill")),
                    "memory budget result: {status:?}"
                );
            } else {
                assert_eq!(status, JobStatus::Succeeded);
                let children: u32 =
                    std::fs::read_to_string(directory.join("tasks-limit.txt"))?.parse()?;
                assert!(children > 0 && children < job.tasks_max.get());
            }
            services.stop(&job.unit).await?;
            let properties = ops
                .execute(
                    Path::new("systemctl"),
                    &[
                        "show".into(),
                        "--property=MainPID,ControlPID".into(),
                        "--".into(),
                        job.unit.clone(),
                    ],
                )
                .await?;
            ensure!(
                properties.success,
                "cannot inspect stopped budget fixture: stdout={}, stderr={}",
                properties.stdout,
                properties.stderr
            );
            let pids: std::collections::BTreeMap<_, _> = properties
                .stdout
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            assert_eq!(pids.get("MainPID"), Some(&"0"));
            assert_eq!(pids.get("ControlPID"), Some(&"0"));
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    for unit in units {
        let _ = services.stop(&unit).await;
        let _ = ops
            .execute(
                Path::new("systemctl"),
                &["reset-failed".into(), "--".into(), unit],
            )
            .await;
    }
    std::fs::remove_dir_all(directory)?;
    result
}
