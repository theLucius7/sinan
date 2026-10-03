use super::*;
use std::sync::Arc;

#[path = "budgets.rs"]
mod budgets;
#[path = "queued.rs"]
mod queued;

#[test]
fn activity_listing_includes_other_workers_and_excludes_completed_units() -> Result<()> {
    let first = format!("sinan-diagnostic-{}.service", Uuid::new_v4());
    let second = format!("sinan-diagnostic-{}.service", Uuid::new_v4());
    assert_eq!(
        parse_running_units(&format!(
            "{first} loaded activating start Diagnostic\n{second} loaded active exited Complete\n"
        ))?,
        vec![first]
    );
    for text in [
        "unrelated.service loaded active running",
        "sinan-diagnostic-bad.service loaded active running",
        "malformed row",
    ] {
        assert!(parse_running_units(text).is_err());
    }
    let refusal = parse_job_status(&CommandOutput { success: true, stdout: "LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=75\nExecMainStartTimestampMonotonic=123\n".into(), stderr: String::new() })?;
    assert!(matches!(refusal, JobStatus::Failed { error } if error.contains("独占锁")));
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux cgroup v2, root, flock, and a running systemd system manager"]
async fn real_systemd_diagnostic_preflight_reads_resources_and_enforces_exclusive_execution()
-> Result<()> {
    ensure!(cfg!(target_os = "linux"), "requires Linux/systemd");
    let ops: Arc<dyn Privileged> = Arc::new(SystemOps);
    let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
    let directory = std::env::temp_dir().join(format!("sinan-preflight-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory)?;
    let job = |program: &str, args: Vec<String>| ServiceJob {
        unit: format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
        program: program.into(),
        args,
        working_directory: directory.clone(),
        timeout_secs: 30,
        memory_max: Default::default(),
        tasks_max: Default::default(),
        cpu_max_percent: Default::default(),
        cpu_weight: Default::default(),
        io_weight: Default::default(),
        oom_score_adjust: Default::default(),
    };
    let script = directory.join("first.sh");
    std::fs::write(&script, "#!/bin/sh\n: > first-ran\nsleep 25\n")?;
    let first = job("/bin/sh", vec![script.to_str().unwrap().into()]);
    let second = job(
        "/usr/bin/touch",
        vec![directory.join("second-ran").to_str().unwrap().into()],
    );
    let result = async {
        let snapshot = ops.diagnostic_resources(&directory).await?;
        assert!(snapshot.memory.available_bytes() <= snapshot.memory.host_available_bytes);
        assert!(snapshot.cpu_count > 0 && snapshot.load_one.is_finite());
        services.start_job(&first).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if directory.join("first-ran").exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        assert!(
            services
                .running_diagnostic_units()
                .await?
                .contains(&first.unit)
        );
        services.start_job(&second).await?;
        let refusal = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = services.job_status(&second.unit).await?;
                if matches!(&status, JobStatus::Failed { error } if error.contains("独占锁")) {
                    return Ok::<_, anyhow::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        assert!(matches!(refusal, JobStatus::Failed { .. }));
        assert!(!directory.join("second-ran").exists());
        services.stop(&first.unit).await?;
        assert!(!services.is_active(&first.unit).await?);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    for unit in [&first.unit, &second.unit] {
        let _ = services.stop(unit).await;
        let _ = ops
            .execute(
                Path::new("systemctl"),
                &["reset-failed".into(), "--".into(), unit.clone()],
            )
            .await;
    }
    std::fs::remove_dir_all(directory)?;
    result
}

#[test]
fn runtime_status_requires_explicit_process_free_shutdown() -> Result<()> {
    let response = |success, load, active, main, control| CommandOutput {
        success,
        stdout: format!(
            "LoadState={load}\nActiveState={active}\nMainPID={main}\nControlPID={control}\n"
        ),
        stderr: String::new(),
    };
    for active in ["active", "activating", "deactivating", "reloading"] {
        assert!(parse_runtime_active(&response(
            true, "loaded", active, 0, 0
        ))?);
    }
    for active in ["inactive", "failed"] {
        assert!(!parse_runtime_active(&response(
            true, "loaded", active, 0, 0
        ))?);
        assert!(parse_runtime_active(&response(
            true, "loaded", active, 123, 0
        ))?);
        assert!(parse_runtime_active(&response(
            true, "loaded", active, 0, 456
        ))?);
    }
    assert!(!parse_runtime_active(&response(
        true,
        "not-found",
        "inactive",
        0,
        0
    ))?);
    assert!(!parse_runtime_active(&response(
        true, "masked", "inactive", 0, 0
    ))?);
    for output in [
        CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "Failed to connect to bus: Permission denied".into(),
        },
        response(false, "loaded", "inactive", 0, 0),
        response(false, "not-found", "inactive", 0, 0),
        response(true, "error", "inactive", 0, 0),
        response(true, "loaded", "unknown", 0, 0),
        response(true, "not-found", "activating", 0, 0),
        response(true, "not-found", "inactive", 123, 0),
        CommandOutput {
            success: true,
            stdout: "LoadState=loaded\nActiveState=inactive\n".into(),
            stderr: String::new(),
        },
    ] {
        assert!(parse_runtime_active(&output).is_err());
    }
    Ok(())
}

#[test]
fn job_status_distinguishes_running_exited_failed_and_missing() -> Result<()> {
    for (properties, expected) in [
        ("LoadState=not-found\n", JobStatus::Missing),
        (
            "LoadState=loaded\nActiveState=activating\nSubState=start\n",
            JobStatus::Running,
        ),
        (
            "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\nExecMainCode=1\nExecMainStartTimestampMonotonic=123\nJob=\n",
            JobStatus::Succeeded,
        ),
    ] {
        assert_eq!(
            parse_job_status(&CommandOutput {
                success: true,
                stdout: properties.into(),
                stderr: String::new()
            })?,
            expected
        );
    }
    let failed = parse_job_status(&CommandOutput { success: true, stdout: "LoadState=loaded\nActiveState=failed\nResult=timeout\nExecMainCode=2\nExecMainStatus=15\n".into(), stderr: String::new() })?;
    assert!(matches!(failed, JobStatus::Failed { error } if error.contains("timeout")));
    let never_started = parse_job_status(&CommandOutput { success: true, stdout: "LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainCode=0\nExecMainStatus=0\nExecMainStartTimestampMonotonic=0\n".into(), stderr: String::new() })?;
    assert!(matches!(never_started, JobStatus::Failed { .. }));
    assert!(
        parse_job_status(&CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "bus unavailable".into()
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn job_status_waits_for_a_proven_pending_job_without_accepting_unstarted_success() -> Result<()> {
    let response = |active, job| CommandOutput {
        success: true,
        stdout: format!(
            "LoadState=loaded\nActiveState={active}\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\nExecMainStartTimestampMonotonic=0\n{job}"
        ),
        stderr: String::new(),
    };
    for active in ["inactive", "active", "failed"] {
        let mut queued = response(active, "Job=505\n");
        assert_eq!(parse_job_status(&queued)?, JobStatus::Running);
        queued.success = false;
        assert!(parse_job_status(&queued).is_err());
    }
    let mut previously_completed = CommandOutput {
        success: true,
        stdout: "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainCode=1\nExecMainStatus=0\nExecMainStartTimestampMonotonic=123\nJob=505\n".into(),
        stderr: String::new(),
    };
    assert_eq!(parse_job_status(&previously_completed)?, JobStatus::Running);
    previously_completed.stdout = previously_completed.stdout.replace("Job=505", "Job=");
    assert_eq!(
        parse_job_status(&previously_completed)?,
        JobStatus::Succeeded
    );
    for job in [
        "",       // A missing property must not invent a queued start.
        "Job=\n", // systemd emits an empty value after the job completes.
        "Job=0\n",
        "Job=-1\n",
        "Job=+505\n",
        "Job=0505\n",
        "Job=505/start\n",
        "Job=505 \n",
        "Job=4294967296\n",
    ] {
        assert!(
            matches!(
                parse_job_status(&response("inactive", job))?,
                JobStatus::Failed { .. }
            ),
            "unstarted unit with {job:?} must not be reported as running or succeeded"
        );
    }
    assert!(parse_job_status(&response("unknown", "Job=505\n")).is_err());
    Ok(())
}

#[tokio::test]
async fn unsafe_unit_and_expansion_arguments_are_rejected_before_execution() -> Result<()> {
    let services = SystemServiceManager::new(Arc::new(SystemOps), ServiceBackend::Systemd);
    let mut job = ServiceJob {
        unit: format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
        program: "/usr/bin/true".into(),
        args: vec!["$HOME".into()],
        working_directory: "/tmp".into(),
        timeout_secs: 1,
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
            .contains("expansion")
    );
    job.args.clear();
    job.unit = "arbitrary.service".into();
    assert!(
        services
            .start_job(&job)
            .await
            .unwrap_err()
            .to_string()
            .contains("unit")
    );
    assert!(services.job_status("--bad").await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux, a running systemd system manager, and root to create isolated transient services"]
async fn real_systemd_diagnostic_jobs_survive_manager_recreation_and_enforce_timeout() -> Result<()>
{
    ensure!(
        cfg!(target_os = "linux"),
        "this integration test requires Linux/systemd"
    );
    let privileged: Arc<dyn Privileged> = Arc::new(SystemOps);
    let services = SystemServiceManager::new(privileged.clone(), ServiceBackend::Systemd);
    let directory = std::env::temp_dir().join(format!("sinan-service-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory)?;
    let mut units = Vec::new();
    let result = async {
        for (program, args, timeout_secs, succeeds) in [
            ("/usr/bin/printf", vec!["fixture report".into()], 10, true),
            ("/usr/bin/false", Vec::new(), 10, false),
            (
                "/bin/sh",
                vec!["-c".into(), "sleep 30 & wait".into()],
                1,
                false,
            ),
        ] {
            let job = ServiceJob {
                unit: format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
                program: program.into(),
                args,
                working_directory: directory.clone(),
                timeout_secs,
                memory_max: Default::default(),
                tasks_max: Default::default(),
                cpu_max_percent: Default::default(),
                cpu_weight: Default::default(),
                io_weight: Default::default(),
                oom_score_adjust: Default::default(),
            };
            units.push(job.unit.clone());
            services.start_job(&job).await?;
            // A fresh manager observes the system-owned service without another start.
            let recovered = SystemServiceManager::new(privileged.clone(), ServiceBackend::Systemd);
            let status = tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    let status = recovered.job_status(&job.unit).await?;
                    if status != JobStatus::Running {
                        return Ok::<_, anyhow::Error>(status);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await??;
            if succeeds {
                assert_eq!(status, JobStatus::Succeeded);
            } else {
                assert!(matches!(status, JobStatus::Failed { .. }));
            }
            if timeout_secs == 1 {
                assert!(matches!(status, JobStatus::Failed { error } if error.contains("timeout")));
            }
            let properties = privileged
                .execute(
                    Path::new("systemctl"),
                    &[
                        "show".into(),
                        "--property=PrivateMounts,KillMode,TimeoutStartUSec,MemoryMax,MemorySwapMax,TasksMax,CPUWeight,CPUQuotaPerSecUSec,IOWeight,OOMScoreAdjust".into(),
                        "--".into(),
                        job.unit.clone(),
                    ],
                )
                .await?;
            ensure!(properties.success, "cannot inspect diagnostic isolation");
            assert!(properties.stdout.contains("PrivateMounts=yes"));
            assert!(properties.stdout.contains("KillMode=control-group"));
            let resource_properties: std::collections::BTreeMap<_, _> = properties
                .stdout
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            for (property, expected) in [
                ("MemoryMax", job.memory_max.get().to_string()),
                ("MemorySwapMax", "0".into()),
                ("TasksMax", job.tasks_max.get().to_string()),
                ("CPUWeight", job.cpu_weight.get().to_string()),
                ("CPUQuotaPerSecUSec", "1s".into()),
                ("IOWeight", job.io_weight.get().to_string()),
                ("OOMScoreAdjust", job.oom_score_adjust.get().to_string()),
            ] {
                assert_eq!(resource_properties.get(property), Some(&expected.as_str()));
            }
            if timeout_secs == 1 {
                assert!(properties.stdout.contains("TimeoutStartUSec=1s"));
            }
            recovered.stop(&job.unit).await?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    for unit in units {
        let _ = services.stop(&unit).await;
        let _ = privileged
            .execute(
                Path::new("systemctl"),
                &["reset-failed".into(), "--".into(), unit],
            )
            .await;
    }
    std::fs::remove_dir_all(directory)?;
    result
}
