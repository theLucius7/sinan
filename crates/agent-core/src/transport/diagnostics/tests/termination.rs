use super::*;
use crate::transport::diagnostics::cancellation::CancellationControl;
use sinan_protocol::{DiagnosticCancelRequest, DiagnosticCancelResult};

struct CollectedReport {
    calls: AtomicUsize,
    text: Mutex<String>,
}

impl CollectedReport {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            text: Mutex::new("first partial report".into()),
        }
    }
}

impl DiagnosticAdapter for CollectedReport {
    fn describe(&self) -> DiagnosticDescriptor {
        TestAdapter.describe()
    }

    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob> {
        TestAdapter.prepare(spec, privileged)
    }

    fn collect<'a>(&'a self, _: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(Some(DiagnosticOutput {
                text: self.text.lock().unwrap().clone(),
                report_url: None,
            }))
        })
    }
}

fn reporting_worker(
    directory: &Directory,
    services: Arc<Services>,
    report: Arc<CollectedReport>,
    resources: Arc<FakeResourceOps>,
) -> Result<DiagnosticWorker> {
    let config = directory.config();
    Ok(DiagnosticWorker::new(
        config.clone(),
        Arc::new(Mutex::new(State::open(&config.state_db)?)),
        vec![report],
        resources,
        services,
    )?
    .with_trusted_keys(release_support::trusted_keys()))
}

fn assert_unfinished(worker: &DiagnosticWorker, id: Uuid, next: Uuid) -> Result<()> {
    assert!(worker.active()?.is_some());
    assert!(
        worker
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap_or_default()
            .is_empty()
    );
    assert!(
        !worker
            .read::<bool>(&format!("diagnostics:done:{id}"))?
            .unwrap_or(false)
    );
    worker.accept(vec![job(id), job(next)])?;
    assert!(matches!(
        worker.active()?,
        Some(Checkpoint::Started { spec, .. }) if spec.id == id.to_string()
    ));
    Ok(())
}

fn frozen_update(worker: &DiagnosticWorker) -> Result<DiagnosticUpdate> {
    let Some(Checkpoint::Started {
        terminal_update: Some(update),
        cleanup_error,
        ..
    }) = worker.active()?
    else {
        anyhow::bail!("terminal result was not durably retained while cleanup waits");
    };
    assert!(cleanup_error.is_some());
    Ok(*update)
}

#[tokio::test]
async fn natural_terminal_results_wait_for_cleanup_and_survive_restart_without_recollecting()
-> Result<()> {
    for status in [
        JobStatus::Succeeded,
        JobStatus::Failed {
            error: "original timeout failure".into(),
        },
        JobStatus::Missing,
    ] {
        let directory = Directory::new();
        let services = Arc::new(Services::new(status.clone()));
        services.cleanup_confirmed.store(false, Ordering::Relaxed);
        let report = Arc::new(CollectedReport::new());
        let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
        let id = Uuid::new_v4();
        let next = Uuid::new_v4();
        let chapter = sinan_protocol::DiagnosticSectionUpdate {
            id,
            name: "hardware_quality".into(),
            text: "saved partial chapter".into(),
            complete: false,
            revision: 1,
            collected_at: 1700000000,
        };
        let frozen;
        {
            let first = reporting_worker(
                &directory,
                services.clone(),
                report.clone(),
                resources.clone(),
            )?;
            first.save(&checkpoint(&first.config, id))?;
            first.queue_sections(vec![chapter.clone()])?;
            assert!(first.tick(None).await.is_err());
            assert_unfinished(&first, id, next)?;
            frozen = frozen_update(&first)?;
            assert_eq!(frozen.id, id);
            assert_eq!(frozen.report.as_ref().unwrap().text, "first partial report");
            match status {
                JobStatus::Succeeded => {
                    assert_eq!(frozen.status, DiagnosticStatus::Succeeded);
                    assert!(frozen.error.is_none());
                }
                JobStatus::Failed { error } => assert_eq!(frozen.error, Some(error)),
                JobStatus::Missing => {
                    assert_eq!(frozen.status, DiagnosticStatus::Failed);
                    assert!(frozen.error.as_ref().unwrap().contains("not repeated"));
                }
                JobStatus::Running => unreachable!(),
            }
            assert_eq!(report.calls.load(Ordering::Relaxed), 1);
            let active = first.active()?.unwrap();
            let progress = first.current_status_update(&active)?;
            assert_eq!(progress.status, DiagnosticStatus::Cleaning);
            assert_eq!(progress.report, frozen.report);
            assert!(progress.error.is_some());
        }
        // Stop mutates the system status to Missing. Neither that new status nor
        // subsequently changed report bytes may replace the original outcome.
        *report.text.lock().unwrap() = "later changed report".into();
        let recovered = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
        assert!(recovered.tick(None).await.is_err());
        assert_unfinished(&recovered, id, next)?;
        assert_eq!(
            recovered
                .read::<Vec<sinan_protocol::DiagnosticSectionUpdate>>(sections::SECTIONS_OUTBOX)?
                .unwrap(),
            vec![chapter.clone()]
        );
        assert_eq!(frozen_update(&recovered)?, frozen);
        assert_eq!(report.calls.load(Ordering::Relaxed), 1);
        services.cleanup_confirmed.store(true, Ordering::Relaxed);
        recovered.tick(None).await?;
        assert!(recovered.active()?.is_none());
        assert_eq!(
            recovered
                .read::<Vec<sinan_protocol::DiagnosticSectionUpdate>>(sections::SECTIONS_OUTBOX)?
                .unwrap(),
            vec![chapter]
        );
        assert_eq!(
            recovered.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap(),
            vec![frozen]
        );
        assert!(
            recovered
                .read::<bool>(&format!("diagnostics:done:{id}"))?
                .unwrap()
        );
        recovered.tick(None).await?;
        assert_eq!(
            recovered
                .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
                .unwrap()
                .len(),
            1
        );
        recovered.accept(vec![job(id), job(next)])?;
        assert!(matches!(
            recovered.active()?,
            Some(Checkpoint::Preparing(job)) if job.id == next
        ));
        assert_eq!(report.calls.load(Ordering::Relaxed), 1);
        assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    }
    Ok(())
}

#[tokio::test]
async fn terminal_stop_errors_cleanup_errors_and_timeouts_keep_the_same_frozen_result() -> Result<()>
{
    for case in 0..4 {
        let directory = Directory::new();
        let services = Arc::new(Services::new(JobStatus::Failed {
            error: "test failed before cleanup".into(),
        }));
        services.fail_stop.store(case == 0, Ordering::Relaxed);
        services.fail_cleanup.store(case == 1, Ordering::Relaxed);
        services.hang_cleanup.store(case == 2, Ordering::Relaxed);
        services.remain_active.store(case == 3, Ordering::Relaxed);
        let report = Arc::new(CollectedReport::new());
        let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
        let mut first = reporting_worker(
            &directory,
            services.clone(),
            report.clone(),
            resources.clone(),
        )?;
        first.config.operation_timeout_secs = 1;
        let id = Uuid::new_v4();
        let next = Uuid::new_v4();
        first.save(&checkpoint(&first.config, id))?;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), first.tick(None))
                .await?
                .is_err()
        );
        assert_unfinished(&first, id, next)?;
        let frozen = frozen_update(&first)?;
        assert_eq!(frozen.error.as_deref(), Some("test failed before cleanup"));
        assert_eq!(report.calls.load(Ordering::Relaxed), 1);
        drop(first);
        services.fail_stop.store(false, Ordering::Relaxed);
        services.fail_cleanup.store(false, Ordering::Relaxed);
        services.hang_cleanup.store(false, Ordering::Relaxed);
        services.remain_active.store(false, Ordering::Relaxed);
        let recovered = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
        recovered.tick(None).await?;
        assert!(recovered.active()?.is_none());
        assert_eq!(
            recovered.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap(),
            vec![frozen]
        );
        assert_eq!(report.calls.load(Ordering::Relaxed), 1);
        assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    }
    Ok(())
}

#[tokio::test]
async fn low_memory_and_deadlines_keep_the_original_reason_until_strong_cleanup_succeeds()
-> Result<()> {
    for case in 0..3 {
        let directory = Directory::new();
        let services = Arc::new(Services::new(JobStatus::Running));
        services.cleanup_confirmed.store(false, Ordering::Relaxed);
        let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
        let report = Arc::new(CollectedReport::new());
        let id = Uuid::new_v4();
        let next = Uuid::new_v4();
        let first = reporting_worker(
            &directory,
            services.clone(),
            report.clone(),
            resources.clone(),
        )?;
        let mut saved = checkpoint(&first.config, id);
        if let Checkpoint::Started {
            started_at,
            expires_at,
            ..
        } = &mut saved
        {
            match case {
                0 => {
                    resources
                        .resources
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .memory
                        .host_available_bytes = 127 * 1024 * 1024
                }
                1 => *expires_at = Some(unix_time() as i64 - 1),
                2 => *started_at = unix_time().saturating_sub(361),
                _ => unreachable!(),
            }
        }
        first.save(&saved)?;
        assert!(first.tick(None).await.is_err());
        assert_unfinished(&first, id, next)?;
        let frozen = frozen_update(&first)?;
        assert_eq!(frozen.status, DiagnosticStatus::Failed);
        assert!(frozen.error.as_ref().unwrap().contains(match case {
            0 => "低内存保护",
            1 => "absolute deadline",
            2 => "execution deadline",
            _ => unreachable!(),
        }));
        assert!(matches!(
            first.active()?,
            Some(Checkpoint::Started {
                protection_stop_reason: Some(_),
                ..
            })
        ));
        drop(first);
        *resources.resources.lock().unwrap() = FakeResourceOps::new(Arc::new(SystemOps))
            .resources
            .into_inner()
            .unwrap();
        *services.status.lock().unwrap() = JobStatus::Succeeded;
        let recovered = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
        assert!(recovered.tick(None).await.is_err());
        assert_eq!(frozen_update(&recovered)?, frozen);
        services.cleanup_confirmed.store(true, Ordering::Relaxed);
        recovered.tick(None).await?;
        assert_eq!(
            recovered.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap(),
            vec![frozen]
        );
        assert_eq!(report.calls.load(Ordering::Relaxed), 1);
        assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    }
    Ok(())
}

#[tokio::test]
async fn expired_running_checkpoint_stops_before_a_hung_status_query() -> Result<()> {
    for absolute in [false, true] {
        let directory = Directory::new();
        let services = Arc::new(Services::new(JobStatus::Running));
        services.hang.store(true, Ordering::Relaxed);
        let mut first = worker(&directory, services.clone())?;
        first.config.operation_timeout_secs = 15;
        let mut saved = checkpoint(&first.config, Uuid::new_v4());
        if let Checkpoint::Started {
            started_at,
            expires_at,
            ..
        } = &mut saved
        {
            if absolute {
                *expires_at = Some(unix_time() as i64 - 1);
            } else {
                *started_at = unix_time().saturating_sub(361);
            }
        }
        first.save(&saved)?;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), first.tick(None))
                .await
                .is_err()
        );
        assert_eq!(services.stops.load(Ordering::Relaxed), 1);
        assert!(matches!(
            first.active()?,
            Some(Checkpoint::Started {
                protection_stop_reason: Some(_),
                ..
            })
        ));
        assert!(
            first
                .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
                .unwrap_or_default()
                .is_empty()
        );
        services.hang.store(false, Ordering::Relaxed);
        first.tick(None).await?;
        let finished = first.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap();
        assert_eq!(finished[0].status, DiagnosticStatus::Failed);
        assert!(finished[0].error.as_ref().unwrap().contains(if absolute {
            "absolute deadline"
        } else {
            "execution deadline"
        }));
        assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    }
    Ok(())
}

#[tokio::test]
async fn backend_without_cleanup_proof_is_rejected_before_starting() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Running));
    services.cleanup_supported.store(false, Ordering::Relaxed);
    let first = worker(&directory, services.clone())?;
    let prepared = super::deadline::cached_job(&directory, Uuid::new_v4())?;
    first.save(&Checkpoint::Preparing(prepared))?;
    let client = PanelClient::new("http://127.0.0.1:1", "test-session")?
        .with_trusted_keys(release_support::trusted_keys());
    first.tick(Some(&client)).await?;
    assert!(first.active()?.is_none());
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    assert_eq!(services.cleanup_queries.load(Ordering::Relaxed), 0);
    let pending = first.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap();
    assert_eq!(pending[0].status, DiagnosticStatus::Failed);
    assert!(pending[0].error.as_ref().unwrap().contains("清理"));
    Ok(())
}

#[tokio::test]
async fn corrupted_saved_target_never_reaches_status_stop_or_cleanup_operations() -> Result<()> {
    for case in 0..10 {
        let directory = Directory::new();
        let services = Arc::new(Services::new(JobStatus::Succeeded));
        let first = worker(&directory, services.clone())?;
        let id = Uuid::new_v4();
        let mut saved = checkpoint(&first.config, id);
        if let Checkpoint::Started {
            spec,
            service,
            terminal_update,
            ..
        } = &mut saved
        {
            *terminal_update = Some(Box::new(DiagnosticUpdate {
                id,
                status: DiagnosticStatus::Succeeded,
                report: Some(DiagnosticReport {
                    text: "valid frozen report".into(),
                    report_url: None,
                }),
                error: None,
            }));
            match case {
                0 => service.unit = "sshd.service".into(),
                1 => service.working_directory = directory.0.join("outside"),
                2 => spec.job_dir = directory.0.join("outside"),
                3 => service.program = directory.0.join("outside"),
                4 => spec.binary_path = directory.0.join("outside"),
                5 => service.timeout_secs += 1,
                6 => spec.id = "not-a-task".into(),
                7 => {
                    spec.binary_path = first.config.install_root.join("../outside");
                    service.program = spec.binary_path.clone();
                }
                8 => service.unit = format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
                9 => {
                    spec.id = Uuid::nil().to_string();
                    spec.job_dir = first.config.runtime_root.join("diagnostics").join(&spec.id);
                    service.unit = format!("sinan-diagnostic-{}.service", spec.id);
                    service.working_directory = spec.job_dir.clone();
                    terminal_update.as_mut().unwrap().id = Uuid::nil();
                }
                _ => unreachable!(),
            }
        }
        first.save(&saved)?;
        assert!(first.tick(None).await.is_err(), "case {case}");
        assert!(first.active()?.is_some());
        assert_eq!(
            services.status_queries.load(Ordering::Relaxed),
            0,
            "case {case}"
        );
        assert_eq!(services.stops.load(Ordering::Relaxed), 0, "case {case}");
        assert_eq!(
            services.cleanup_queries.load(Ordering::Relaxed),
            0,
            "case {case}"
        );
        assert!(
            first
                .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
                .unwrap_or_default()
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
async fn frozen_terminal_cleanup_attempts_stop_despite_a_hung_status_after_restart() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Succeeded));
    services.cleanup_confirmed.store(false, Ordering::Relaxed);
    let report = Arc::new(CollectedReport::new());
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    let first = reporting_worker(
        &directory,
        services.clone(),
        report.clone(),
        resources.clone(),
    )?;
    let id = Uuid::new_v4();
    first.save(&checkpoint(&first.config, id))?;
    assert!(first.tick(None).await.is_err());
    let frozen = frozen_update(&first)?;
    drop(first);
    services.hang.store(true, Ordering::Relaxed);
    let mut recovered = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
    recovered.config.operation_timeout_secs = 1;
    let stops = services.stops.load(Ordering::Relaxed);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), recovered.tick(None))
            .await?
            .is_err()
    );
    assert!(services.stops.load(Ordering::Relaxed) > stops);
    assert_unfinished(&recovered, id, Uuid::new_v4())?;
    assert_eq!(frozen_update(&recovered)?, frozen);
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    // Even a positive process/mount proof cannot replace the final readable
    // manager state: a queued unit must still be excluded before releasing ACTIVE.
    services.cleanup_confirmed.store(true, Ordering::Relaxed);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), recovered.tick(None))
            .await?
            .is_err()
    );
    assert_unfinished(&recovered, id, Uuid::new_v4())?;
    services.hang.store(false, Ordering::Relaxed);
    recovered.tick(None).await?;
    assert!(recovered.active()?.is_none());
    assert_eq!(
        recovered.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap(),
        vec![frozen]
    );
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn low_memory_stop_runs_when_the_protection_checkpoint_cannot_be_written() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Running));
    services.cleanup_confirmed.store(false, Ordering::Relaxed);
    let report = Arc::new(CollectedReport::new());
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    resources
        .resources
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .memory
        .host_available_bytes = 127 * 1024 * 1024;
    let first = reporting_worker(
        &directory,
        services.clone(),
        report.clone(),
        resources.clone(),
    )?;
    let id = Uuid::new_v4();
    first.save(&checkpoint(&first.config, id))?;
    first
        .state
        .lock()
        .unwrap()
        .connection
        .execute_batch("PRAGMA query_only = ON")?;
    assert!(first.tick(None).await.is_err());
    assert_eq!(services.stops.load(Ordering::Relaxed), 1);
    assert_unfinished(&first, id, Uuid::new_v4())?;
    assert!(matches!(
        first.active()?,
        Some(Checkpoint::Started {
            terminal_update: None,
            ..
        })
    ));
    assert_eq!(report.calls.load(Ordering::Relaxed), 0);
    first
        .state
        .lock()
        .unwrap()
        .connection
        .execute_batch("PRAGMA query_only = OFF")?;
    *resources.resources.lock().unwrap() = FakeResourceOps::new(Arc::new(SystemOps))
        .resources
        .into_inner()
        .unwrap();
    drop(first);
    let recovered = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
    assert!(recovered.tick(None).await.is_err());
    assert_unfinished(&recovered, id, Uuid::new_v4())?;
    let frozen = frozen_update(&recovered)?;
    assert_eq!(frozen.status, DiagnosticStatus::Failed);
    assert!(frozen.report.is_some());
    services.cleanup_confirmed.store(true, Ordering::Relaxed);
    recovered.tick(None).await?;
    assert_eq!(
        recovered.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap(),
        vec![frozen]
    );
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn failed_state_write_after_an_uncertain_start_keeps_started_checkpoint_for_recovery()
-> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Running));
    services.fail_start.store(true, Ordering::Relaxed);
    let first = worker(&directory, services.clone())?;
    *services.read_only_on_start.lock().unwrap() = Some(first.state.clone());
    let prepared = super::deadline::cached_job(&directory, Uuid::new_v4())?;
    let id = prepared.id;
    first.save(&Checkpoint::Preparing(prepared))?;
    let client = PanelClient::new("http://127.0.0.1:1", "test-session")?
        .with_trusted_keys(release_support::trusted_keys());
    let _ = first.tick(Some(&client)).await;
    assert!(
        matches!(first.active()?, Some(Checkpoint::Started { spec, .. }) if spec.id == id.to_string())
    );
    assert_eq!(services.starts.load(Ordering::Relaxed), 1);
    assert_unfinished(&first, id, Uuid::new_v4())?;
    first
        .state
        .lock()
        .unwrap()
        .connection
        .execute_batch("PRAGMA query_only = OFF")?;
    *services.read_only_on_start.lock().unwrap() = None;
    drop(first);
    let recovered = worker(&directory, services.clone())?;
    recovered.tick(None).await?;
    assert!(recovered.active()?.is_some());
    *services.status.lock().unwrap() = JobStatus::Succeeded;
    recovered.tick(None).await?;
    assert!(recovered.active()?.is_none());
    assert_eq!(services.starts.load(Ordering::Relaxed), 1);
    assert_eq!(
        recovered
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap()
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_while_terminal_cleanup_waits_keeps_the_frozen_report() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Failed {
        error: "runner failed".into(),
    }));
    services.cleanup_confirmed.store(false, Ordering::Relaxed);
    let report = Arc::new(CollectedReport::new());
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    let first = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
    let control = Arc::new(CancellationControl::new(
        first.state.clone(),
        7,
        vec!["diagnostic-fixture".into()],
    ));
    let first = first.with_cancellations(control.clone());
    let id = Uuid::new_v4();
    first.save(&checkpoint(&first.config, id))?;
    assert!(first.tick(None).await.is_err());
    let frozen = frozen_update(&first)?;
    *report.text.lock().unwrap() = "changed after terminal freeze".into();
    control.request(DiagnosticCancelRequest {
        server_id: 7,
        job: job(id),
    })?;
    let _ = first.tick(None).await;
    let negative = first
        .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
        .unwrap();
    assert!(!negative[0].confirmed);
    assert!(first.active()?.is_some());
    services.cleanup_confirmed.store(true, Ordering::Relaxed);
    first.tick(None).await?;
    let confirmed = first
        .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
        .unwrap();
    assert!(confirmed[0].confirmed);
    assert_eq!(confirmed[0].report, frozen.report);
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    assert!(first.active()?.is_none());
    assert!(
        first
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn cancellation_preserves_a_frozen_absent_report_without_collecting_later_output()
-> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Failed {
        error: "runner failed before producing a report".into(),
    }));
    services.cleanup_confirmed.store(false, Ordering::Relaxed);
    let report = Arc::new(CollectedReport::new());
    *report.text.lock().unwrap() = "   ".into();
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    let first = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
    let control = Arc::new(CancellationControl::new(
        first.state.clone(),
        7,
        vec!["diagnostic-fixture".into()],
    ));
    let first = first.with_cancellations(control.clone());
    let id = Uuid::new_v4();
    first.save(&checkpoint(&first.config, id))?;
    assert!(first.tick(None).await.is_err());
    let frozen = frozen_update(&first)?;
    assert!(frozen.report.is_none());
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    *report.text.lock().unwrap() = "later output must not become the frozen report".into();
    control.request(DiagnosticCancelRequest {
        server_id: 7,
        job: job(id),
    })?;
    services.cleanup_confirmed.store(true, Ordering::Relaxed);
    first.tick(None).await?;
    let results = first
        .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
        .unwrap();
    assert!(results[0].confirmed);
    assert!(results[0].report.is_none());
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    assert!(first.active()?.is_none());
    assert!(
        first
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn unrelated_hung_cancellation_waits_for_the_active_diagnostic_protection_and_cleanup()
-> Result<()> {
    for memory_pressure in [false, true] {
        let directory = Directory::new();
        let services = Arc::new(Services::new(JobStatus::Running));
        let report = Arc::new(CollectedReport::new());
        let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
        if memory_pressure {
            resources
                .resources
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .memory
                .host_available_bytes = 127 * 1024 * 1024;
        }
        let mut first = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
        first.config.operation_timeout_secs = 1;
        let control = Arc::new(CancellationControl::new(
            first.state.clone(),
            7,
            vec!["diagnostic-fixture".into()],
        ));
        let first = first.with_cancellations(control.clone());
        let active_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let active_unit = format!("sinan-diagnostic-{active_id}.service");
        let other_unit = format!("sinan-diagnostic-{other_id}.service");
        *services.hung_cleanup_unit.lock().unwrap() = Some(other_unit.clone());
        let mut saved = checkpoint(&first.config, active_id);
        if !memory_pressure && let Checkpoint::Started { expires_at, .. } = &mut saved {
            *expires_at = Some(unix_time() as i64 - 1);
        }
        first.save(&saved)?;
        control.request(DiagnosticCancelRequest {
            server_id: 7,
            job: job(other_id),
        })?;
        // A cancellation for another UUID must not consume its one-second proof
        // timeout while an active task needs immediate memory/deadline protection.
        tokio::time::timeout(Duration::from_millis(500), first.tick(None)).await??;
        assert!(first.active()?.is_none());
        assert_eq!(
            *services.stopped_units.lock().unwrap(),
            vec![active_unit.clone()]
        );
        assert_eq!(*services.cleanup_units.lock().unwrap(), vec![active_unit]);
        let pending = first
            .read::<Vec<DiagnosticCancelRequest>>("diagnostics:cancellations")?
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].job.id, other_id);
        assert!(
            first
                .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
                .unwrap_or_default()
                .is_empty()
        );
        let terminal = first.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].id, active_id);
        assert_eq!(terminal[0].status, DiagnosticStatus::Failed);
        assert!(
            terminal[0]
                .error
                .as_ref()
                .unwrap()
                .contains(if memory_pressure {
                    "低内存保护"
                } else {
                    "absolute deadline"
                })
        );
        assert_eq!(report.calls.load(Ordering::Relaxed), 1);
        // Once ACTIVE has actually been released, the unrelated request is
        // attempted under its normal bound and its negative receipt stays pending.
        tokio::time::timeout(Duration::from_secs(2), first.tick(None)).await??;
        let results = first
            .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
            .unwrap();
        assert_eq!(results[0].id, other_id);
        assert!(!results[0].confirmed);
        assert_eq!(
            services.cleanup_units.lock().unwrap().last(),
            Some(&other_unit)
        );
        assert_eq!(
            first
                .read::<Vec<DiagnosticCancelRequest>>("diagnostics:cancellations")?
                .unwrap()
                .len(),
            1
        );
        *services.hung_cleanup_unit.lock().unwrap() = None;
        first.tick(None).await?;
        let results = first
            .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
            .unwrap();
        assert!(results[0].confirmed);
        assert!(
            first
                .read::<Vec<DiagnosticCancelRequest>>("diagnostics:cancellations")?
                .unwrap()
                .is_empty()
        );
        assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    }
    Ok(())
}

#[tokio::test]
async fn an_existing_started_task_is_stopped_when_cleanup_capability_is_unavailable() -> Result<()>
{
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Succeeded));
    services.cleanup_supported.store(false, Ordering::Relaxed);
    let report = Arc::new(CollectedReport::new());
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    let first = reporting_worker(
        &directory,
        services.clone(),
        report.clone(),
        resources.clone(),
    )?;
    let id = Uuid::new_v4();
    first.save(&checkpoint(&first.config, id))?;
    assert!(first.tick(None).await.is_err());
    assert_eq!(
        *services.stopped_units.lock().unwrap(),
        vec![format!("sinan-diagnostic-{id}.service")]
    );
    assert_eq!(*services.status.lock().unwrap(), JobStatus::Missing);
    assert_eq!(services.cleanup_queries.load(Ordering::Relaxed), 0);
    assert_unfinished(&first, id, Uuid::new_v4())?;
    let frozen = frozen_update(&first)?;
    assert_eq!(frozen.status, DiagnosticStatus::Succeeded);
    assert_eq!(frozen.report.as_ref().unwrap().text, "first partial report");
    drop(first);
    services.cleanup_supported.store(true, Ordering::Relaxed);
    let recovered = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
    recovered.tick(None).await?;
    assert!(recovered.active()?.is_none());
    assert_eq!(
        recovered.read::<Vec<DiagnosticUpdate>>(OUTBOX)?.unwrap(),
        vec![frozen]
    );
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

struct SuspendedNaturalReport {
    calls: AtomicUsize,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    natural_completed: AtomicBool,
}

impl DiagnosticAdapter for SuspendedNaturalReport {
    fn describe(&self) -> DiagnosticDescriptor {
        TestAdapter.describe()
    }
    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob> {
        TestAdapter.prepare(spec, privileged)
    }
    fn collect<'a>(&'a self, _: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            let text = if call == 0 {
                self.started.notify_one();
                self.release.notified().await;
                self.natural_completed.store(true, Ordering::Relaxed);
                "late natural report"
            } else {
                "cancelled final report"
            };
            Ok(Some(DiagnosticOutput {
                text: text.into(),
                report_url: None,
            }))
        })
    }
}

#[tokio::test]
async fn cancellation_interrupts_a_suspended_natural_collection_without_reviving_the_task()
-> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Succeeded));
    let report = Arc::new(SuspendedNaturalReport {
        calls: AtomicUsize::new(0),
        started: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        natural_completed: AtomicBool::new(false),
    });
    let config = directory.config();
    let first = DiagnosticWorker::new(
        config.clone(),
        Arc::new(Mutex::new(State::open(&config.state_db)?)),
        vec![report.clone()],
        Arc::new(FakeResourceOps::new(Arc::new(SystemOps))),
        services.clone(),
    )?
    .with_trusted_keys(release_support::trusted_keys());
    let control = Arc::new(CancellationControl::new(
        first.state.clone(),
        7,
        vec!["diagnostic-fixture".into()],
    ));
    let first = Arc::new(first.with_cancellations(control.clone()));
    let id = Uuid::new_v4();
    first.save(&checkpoint(&first.config, id))?;
    let observing = first.clone();
    let polling = tokio::spawn(async move { observing.monitored_tick(None).await });
    tokio::time::timeout(Duration::from_secs(2), report.started.notified()).await?;
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    control.request(DiagnosticCancelRequest {
        server_id: 7,
        job: job(id),
    })?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let results = first
                .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
                .unwrap_or_default();
            if results
                .iter()
                .any(|result| result.id == id && result.confirmed)
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    // Release the old producer only after cancellation has committed ACTIVE=null
    // and cleared its intent. That old future must have been dropped already.
    report.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), polling).await???;
    assert!(!report.natural_completed.load(Ordering::Relaxed));
    assert_eq!(report.calls.load(Ordering::Relaxed), 2);
    assert!(first.active()?.is_none());
    assert!(
        first
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap_or_default()
            .is_empty()
    );
    assert!(
        first
            .read::<bool>(&format!("diagnostics:done:{id}"))?
            .unwrap()
    );
    let results = first
        .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
        .unwrap();
    assert_eq!(
        results[0].report.as_ref().unwrap().text,
        "cancelled final report"
    );
    first.accept(vec![job(id)])?;
    assert!(first.active()?.is_none());
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn a_stale_observation_cannot_restore_a_checkpoint_after_cancellation_commits() -> Result<()>
{
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Succeeded));
    let report = Arc::new(CollectedReport::new());
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    let first = reporting_worker(&directory, services.clone(), report.clone(), resources)?;
    let control = Arc::new(CancellationControl::new(
        first.state.clone(),
        7,
        vec!["diagnostic-fixture".into()],
    ));
    let first = first.with_cancellations(control.clone());
    let id = Uuid::new_v4();
    let old_snapshot = checkpoint(&first.config, id);
    first.save(&old_snapshot)?;
    control.request(DiagnosticCancelRequest {
        server_id: 7,
        job: job(id),
    })?;
    first.process_cancellations().await?;
    assert!(first.active()?.is_none());
    let before = first
        .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
        .unwrap();
    assert!(before[0].confirmed);
    assert_eq!(
        before[0].report.as_ref().unwrap().text,
        "first partial report"
    );
    *report.text.lock().unwrap() = "stale observation result must never be committed".into();
    let _ = first.observe(&old_snapshot).await;
    assert!(first.active()?.is_none());
    assert!(
        first
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(
        first
            .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
            .unwrap(),
        before
    );
    assert!(
        first
            .read::<bool>(&format!("diagnostics:done:{id}"))?
            .unwrap()
    );
    first.accept(vec![job(id)])?;
    assert!(first.active()?.is_none());
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn late_running_status_cannot_restore_cancelled_ownership_under_memory_pressure() -> Result<()>
{
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Running));
    let report = Arc::new(CollectedReport::new());
    let resources = Arc::new(FakeResourceOps::new(Arc::new(SystemOps)));
    let first = reporting_worker(
        &directory,
        services.clone(),
        report.clone(),
        resources.clone(),
    )?;
    let control = Arc::new(CancellationControl::new(
        first.state.clone(),
        7,
        vec!["diagnostic-fixture".into()],
    ));
    let first = first.with_cancellations(control.clone());
    let id = Uuid::new_v4();
    let saved = checkpoint(&first.config, id);
    first.save(&saved)?;
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *services.suspended_status.lock().unwrap() = Some((started.clone(), release.clone()));
    let observing = first.observe(&saved);
    tokio::pin!(observing);
    tokio::select! {
        _ = started.notified() => {}
        result = &mut observing => panic!("observation returned before suspended status: {result:?}"),
    }
    control.request(DiagnosticCancelRequest {
        server_id: 7,
        job: job(id),
    })?;
    first.process_cancellations().await?;
    assert!(first.active()?.is_none());
    let receipts = first
        .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
        .unwrap();
    assert!(receipts[0].confirmed);
    resources
        .resources
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .memory
        .host_available_bytes = 127 * 1024 * 1024;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), &mut observing).await??;
    assert!(first.active()?.is_none());
    assert!(
        first
            .read::<Vec<DiagnosticUpdate>>(OUTBOX)?
            .unwrap_or_default()
            .is_empty()
    );
    assert_eq!(
        first
            .read::<Vec<DiagnosticCancelResult>>("diagnostics:cancellation-results")?
            .unwrap(),
        receipts
    );
    assert!(
        first
            .read::<bool>(&format!("diagnostics:done:{id}"))?
            .unwrap()
    );
    assert_eq!(services.stops.load(Ordering::Relaxed), 1);
    assert_eq!(report.calls.load(Ordering::Relaxed), 1);
    Ok(())
}
