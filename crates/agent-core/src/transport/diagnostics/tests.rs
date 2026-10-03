#[path = "tests/budget.rs"]
mod budget;
#[path = "tests/environment.rs"]
mod environment;
use super::*;
use crate::release_test_support as release_support;
use crate::{
    State,
    fake::{FakeResourceOps, FakeServiceManager},
    system::SystemOps,
};
use sinan_adapter_sdk::{BoxFuture, DiagnosticDescriptor, DiagnosticOutput};
use sinan_protocol::Artifact;
use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("sinan-diagnostic-{}", Uuid::new_v4())))
    }
    fn config(&self) -> Config {
        Config {
            panel_url: "http://127.0.0.1:8080".into(),
            state_db: self.0.join("state.db"),
            identity_dir: self.0.join("identity"),
            runtime_root: self.0.join("runtime"),
            install_root: self.0.join("install"),
            status_socket: self.0.join("status.sock"),
            ..Config::default()
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TestAdapter;
impl DiagnosticAdapter for TestAdapter {
    fn describe(&self) -> DiagnosticDescriptor {
        DiagnosticDescriptor {
            plugin_name: "diagnostic-fixture".into(),
            binary_name: "runner".into(),
        }
    }
    fn prepare<'a>(
        &'a self,
        spec: &'a DiagnosticSpec,
        privileged: &'a dyn Privileged,
    ) -> BoxFuture<'a, ServiceJob> {
        Box::pin(async move {
            privileged.create_dir(&spec.job_dir, 0o700, None).await?;
            Ok(ServiceJob {
                unit: format!("sinan-diagnostic-{}.service", spec.id),
                program: spec.binary_path.clone(),
                args: vec![],
                working_directory: spec.job_dir.clone(),
                timeout_secs: spec.timeout_secs,
                memory_max: Default::default(),
                tasks_max: Default::default(),
                cpu_max_percent: Default::default(),
                cpu_weight: Default::default(),
                io_weight: Default::default(),
                oom_score_adjust: Default::default(),
            })
        })
    }
    fn collect<'a>(&'a self, _spec: &'a DiagnosticSpec) -> BoxFuture<'a, Option<DiagnosticOutput>> {
        Box::pin(async {
            Ok(Some(DiagnosticOutput {
                text: "fixture report".into(),
                report_url: None,
            }))
        })
    }
}

type SuspendedStatus = (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

struct Services {
    status: Mutex<JobStatus>,
    starts: AtomicUsize,
    hang: AtomicBool,
    status_queries: AtomicUsize,
    last_job: Mutex<Option<ServiceJob>>,
    stops: AtomicUsize,
    conflicts: Mutex<Result<Vec<String>, String>>,
    fail_stop: AtomicBool,
    fail_status: AtomicBool,
    remain_active: AtomicBool,
    cleanup_confirmed: AtomicBool,
    cleanup_supported: AtomicBool,
    fail_cleanup: AtomicBool,
    hang_cleanup: AtomicBool,
    cleanup_queries: AtomicUsize,
    cleanup_units: Mutex<Vec<String>>,
    hung_cleanup_unit: Mutex<Option<String>>,
    fail_start: AtomicBool,
    read_only_on_start: Mutex<Option<SharedState>>,
    stopped_units: Mutex<Vec<String>>,
    suspended_status: Mutex<Option<SuspendedStatus>>,
}
impl Services {
    fn new(status: JobStatus) -> Self {
        Self {
            status: Mutex::new(status),
            starts: AtomicUsize::new(0),
            hang: AtomicBool::new(false),
            status_queries: AtomicUsize::new(0),
            last_job: Mutex::new(None),
            stops: AtomicUsize::new(0),
            conflicts: Mutex::new(Ok(Vec::new())),
            fail_stop: AtomicBool::new(false),
            fail_status: AtomicBool::new(false),
            remain_active: AtomicBool::new(false),
            cleanup_confirmed: AtomicBool::new(true),
            cleanup_supported: AtomicBool::new(true),
            fail_cleanup: AtomicBool::new(false),
            hang_cleanup: AtomicBool::new(false),
            cleanup_queries: AtomicUsize::new(0),
            cleanup_units: Mutex::new(Vec::new()),
            hung_cleanup_unit: Mutex::new(None),
            fail_start: AtomicBool::new(false),
            read_only_on_start: Mutex::new(None),
            stopped_units: Mutex::new(Vec::new()),
            suspended_status: Mutex::new(None),
        }
    }
}
impl ServiceManager for Services {
    fn supports_confirmed_cancellation(&self) -> bool {
        self.cleanup_supported.load(Ordering::Relaxed)
    }
    fn diagnostic_cleanup_confirmed<'a>(
        &'a self,
        unit: &'a str,
        _directory: &'a Path,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            self.cleanup_queries.fetch_add(1, Ordering::Relaxed);
            self.cleanup_units.lock().unwrap().push(unit.into());
            let hangs_for_unit = self.hung_cleanup_unit.lock().unwrap().as_deref() == Some(unit);
            if self.hang_cleanup.load(Ordering::Relaxed) || hangs_for_unit {
                return std::future::pending().await;
            }
            ensure!(
                !self.fail_cleanup.load(Ordering::Relaxed),
                "fixture cleanup evidence failure"
            );
            Ok(self.cleanup_confirmed.load(Ordering::Relaxed)
                && !self.remain_active.load(Ordering::Relaxed))
        })
    }
    fn running_diagnostic_units(&self) -> BoxFuture<'_, Vec<String>> {
        Box::pin(async {
            self.conflicts
                .lock()
                .unwrap()
                .clone()
                .map_err(anyhow::Error::msg)
        })
    }
    fn reload<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn restart<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn stop<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.stops.fetch_add(1, Ordering::Relaxed);
            self.stopped_units.lock().unwrap().push(unit.into());
            ensure!(
                !self.fail_stop.load(Ordering::Relaxed),
                "fixture stop failure"
            );
            if !self.remain_active.load(Ordering::Relaxed) {
                *self.status.lock().unwrap() = JobStatus::Missing;
            }
            Ok(())
        })
    }
    fn is_active<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async { Ok(self.remain_active.load(Ordering::Relaxed)) })
    }
    fn start_job<'a>(&'a self, job: &'a ServiceJob) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            *self.last_job.lock().unwrap() = Some(job.clone());
            self.starts.fetch_add(1, Ordering::Relaxed);
            if let Some(state) = self.read_only_on_start.lock().unwrap().as_ref() {
                state
                    .lock()
                    .unwrap()
                    .connection
                    .execute_batch("PRAGMA query_only = ON")?;
            }
            ensure!(
                !self.fail_start.load(Ordering::Relaxed),
                "fixture uncertain start failure"
            );
            Ok(())
        })
    }
    fn job_status<'a>(&'a self, _unit: &'a str) -> BoxFuture<'a, JobStatus> {
        Box::pin(async move {
            self.status_queries.fetch_add(1, Ordering::Relaxed);
            let suspended = self.suspended_status.lock().unwrap().take();
            if let Some((started, release)) = suspended {
                let old_status = self.status.lock().unwrap().clone();
                started.notify_one();
                release.notified().await;
                return Ok(old_status);
            }
            if self.hang.load(Ordering::Relaxed) {
                return std::future::pending().await;
            }
            ensure!(
                !self.fail_status.load(Ordering::Relaxed),
                "fixture status failure"
            );
            Ok(self.status.lock().unwrap().clone())
        })
    }
}

fn worker(directory: &Directory, services: Arc<Services>) -> Result<DiagnosticWorker> {
    let config = directory.config();
    Ok(DiagnosticWorker::new(
        config.clone(),
        Arc::new(Mutex::new(State::open(&config.state_db)?)),
        vec![Arc::new(TestAdapter)],
        Arc::new(FakeResourceOps::new(Arc::new(SystemOps))),
        services,
    )?
    .with_trusted_keys(release_support::trusted_keys()))
}

fn checkpoint(config: &Config, id: Uuid) -> Checkpoint {
    let directory = config.runtime_root.join("diagnostics").join(id.to_string());
    Checkpoint::Started {
        spec: DiagnosticSpec {
            id: id.to_string(),
            version: "v1".into(),
            binary_path: config.install_root.join("runner"),
            job_dir: directory.clone(),
            timeout_secs: 300,
            options: BTreeMap::new(),
        },
        service: ServiceJob {
            unit: format!("sinan-diagnostic-{id}.service"),
            program: config.install_root.join("runner"),
            args: vec![],
            working_directory: directory,
            timeout_secs: 300,
            memory_max: Default::default(),
            tasks_max: Default::default(),
            cpu_max_percent: Default::default(),
            cpu_weight: Default::default(),
            io_weight: Default::default(),
            oom_score_adjust: Default::default(),
        },
        started_at: unix_time(),
        plugin: "diagnostic-fixture".into(),
        start_error: None,
        expires_at: None,
        protection_stop_reason: None,
        environment: None,
        terminal_update: None,
        cleanup_error: None,
    }
}

fn job(id: Uuid) -> DiagnosticJob {
    DiagnosticJob {
        id,
        plugin: "diagnostic-fixture".into(),
        version: "v1".into(),
        artifact: Artifact {
            proof: None,
            url: "http://127.0.0.1:8080/fixture".into(),
            sha256: "0".repeat(64),
        },
        timeout_secs: 300,
        resource_budget: None,
        expires_at: None,
        options: BTreeMap::new(),
    }
}

#[tokio::test]
async fn legacy_running_checkpoint_recovers_without_restarting_or_losing_report() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Running));
    let id = Uuid::new_v4();
    {
        let first = worker(&directory, services.clone())?;
        let mut saved = serde_json::to_value(checkpoint(&first.config, id))?;
        let started = saved["Started"].as_object_mut().unwrap();
        started.remove("terminal_update");
        started.remove("cleanup_error");
        let service = saved["Started"]["service"].as_object_mut().unwrap();
        for field in [
            "memory_max",
            "tasks_max",
            "cpu_max_percent",
            "cpu_weight",
            "io_weight",
            "oom_score_adjust",
        ] {
            service.remove(field);
        }
        first.state.lock().unwrap().set_json(ACTIVE, &Some(saved))?;
    }
    let recovered = worker(&directory, services.clone())?;
    recovered.tick(None).await?;
    let Some(Checkpoint::Started { service, .. }) = recovered.active()? else {
        anyhow::bail!("legacy diagnostic was lost");
    };
    assert_eq!(service.memory_max.get(), 512 * 1024 * 1024);
    *services.status.lock().unwrap() = JobStatus::Succeeded;
    recovered.tick(None).await?;
    let pending: Vec<DiagnosticUpdate> = recovered.read(OUTBOX)?.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert_eq!(pending[0].report.as_ref().unwrap().text, "fixture report");
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn restarting_worker_observes_running_service_and_durably_finishes_once() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Running));
    let id = Uuid::new_v4();
    {
        let first = worker(&directory, services.clone())?;
        first.save(&checkpoint(&first.config, id))?;
    }
    let recovered = worker(&directory, services.clone())?;
    recovered.tick(None).await?;
    assert!(recovered.active()?.is_some());
    *services.status.lock().unwrap() = JobStatus::Succeeded;
    recovered.tick(None).await?;
    assert!(recovered.active()?.is_none());
    let pending: Vec<DiagnosticUpdate> = recovered.read(OUTBOX)?.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, DiagnosticStatus::Succeeded);
    assert_eq!(pending[0].report.as_ref().unwrap().text, "fixture report");
    recovered.accept(vec![job(id)])?;
    assert!(recovered.active()?.is_none());
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn uncertain_missing_start_fails_without_running_again() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Missing));
    let first = worker(&directory, services.clone())?;
    let mut saved = checkpoint(&first.config, Uuid::new_v4());
    if let Checkpoint::Started { start_error, .. } = &mut saved {
        *start_error = Some("permission denied".into());
    }
    first.save(&saved)?;
    drop(first);
    let recovered = worker(&directory, services.clone())?;
    recovered.tick(None).await?;
    let pending: Vec<DiagnosticUpdate> = recovered.read(OUTBOX)?.unwrap();
    assert_eq!(pending[0].status, DiagnosticStatus::Failed);
    assert!(pending[0].error.as_ref().unwrap().contains("not repeated"));
    assert!(
        pending[0]
            .error
            .as_ref()
            .unwrap()
            .contains("permission denied")
    );
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test]
async fn failed_service_keeps_partial_report_and_next_job_is_serialized() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Failed {
        error: "timeout".into(),
    }));
    let worker = worker(&directory, services)?;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    worker.save(&checkpoint(&worker.config, first))?;
    worker.accept(vec![job(second)])?;
    assert!(
        matches!(worker.active()?, Some(Checkpoint::Started { spec, .. }) if spec.id == first.to_string())
    );
    worker.tick(None).await?;
    let pending: Vec<DiagnosticUpdate> = worker.read(OUTBOX)?.unwrap();
    assert_eq!(pending[0].status, DiagnosticStatus::Failed);
    assert_eq!(pending[0].error.as_deref(), Some("timeout"));
    assert!(pending[0].report.is_some());
    worker.accept(vec![job(first), job(second)])?;
    assert!(matches!(worker.active()?, Some(Checkpoint::Preparing(job)) if job.id == second));
    Ok(())
}

#[test]
fn unknown_plugins_and_invalid_timeouts_never_become_services() -> Result<()> {
    let directory = Directory::new();
    let worker = worker(&directory, Arc::new(Services::new(JobStatus::Missing)))?;
    let mut unknown = job(Uuid::new_v4());
    unknown.plugin = "arbitrary-command".into();
    let mut invalid = job(Uuid::new_v4());
    invalid.timeout_secs = 0;
    worker.accept(vec![unknown, invalid])?;
    assert!(worker.active()?.is_none());
    let pending: Vec<DiagnosticUpdate> = worker.read(OUTBOX)?.unwrap();
    assert_eq!(pending.len(), 2);
    assert!(
        pending
            .iter()
            .all(|update| update.status == DiagnosticStatus::Failed)
    );
    Ok(())
}

#[tokio::test]
async fn existing_service_implementations_default_to_unsupported_jobs() -> Result<()> {
    let services = FakeServiceManager::default();
    let job = ServiceJob {
        unit: format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
        program: Path::new("/usr/bin/true").into(),
        args: vec![],
        working_directory: Path::new("/tmp").into(),
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
            .contains("not supported")
    );
    assert!(
        services
            .job_status(&job.unit)
            .await
            .unwrap_err()
            .to_string()
            .contains("not supported")
    );
    Ok(())
}

#[tokio::test]
async fn hung_status_query_is_bounded_and_recovers_without_starting_again() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Succeeded));
    services.hang.store(true, Ordering::Relaxed);
    let mut worker = worker(&directory, services.clone())?;
    worker.config.operation_timeout_secs = 1;
    worker.save(&checkpoint(&worker.config, Uuid::new_v4()))?;
    let error = tokio::time::timeout(Duration::from_secs(2), worker.tick(None))
        .await?
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(worker.active()?.is_some());
    services.hang.store(false, Ordering::Relaxed);
    worker.tick(None).await?;
    assert!(worker.active()?.is_none());
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn expired_queued_job_is_failed_without_preparing_a_service() -> Result<()> {
    let directory = Directory::new();
    let worker = worker(&directory, Arc::new(Services::new(JobStatus::Missing)))?;
    let mut expired = job(Uuid::new_v4());
    expired.expires_at = Some(unix_time() as i64 - 1);
    worker.accept(vec![expired])?;
    assert!(worker.active()?.is_none());
    let pending: Vec<DiagnosticUpdate> = worker.read(OUTBOX)?.unwrap();
    assert_eq!(pending[0].status, DiagnosticStatus::Failed);
    assert!(pending[0].error.as_ref().unwrap().contains("expired"));
    Ok(())
}

#[tokio::test]
async fn expired_preparation_checkpoint_is_not_started_after_reconnect() -> Result<()> {
    let directory = Directory::new();
    let services = Arc::new(Services::new(JobStatus::Missing));
    let first = worker(&directory, services.clone())?;
    let mut expired = job(Uuid::new_v4());
    expired.expires_at = Some(unix_time() as i64 - 1);
    first.save(&Checkpoint::Preparing(expired))?;
    drop(first);
    let recovered = worker(&directory, services.clone())?;
    let client = PanelClient::new("http://127.0.0.1:1", "test-session")?;
    recovered.tick(Some(&client)).await?;
    assert!(recovered.active()?.is_none());
    let pending: Vec<DiagnosticUpdate> = recovered.read(OUTBOX)?.unwrap();
    assert!(pending[0].error.as_ref().unwrap().contains("expired"));
    assert_eq!(services.starts.load(Ordering::Relaxed), 0);
    Ok(())
}

#[path = "tests/outbox.rs"]
mod outbox;

#[path = "tests/deadline.rs"]
mod deadline;

#[path = "tests/safety.rs"]
mod safety;

#[path = "tests/cancellation.rs"]
mod cancellation;
#[path = "tests/report_sections.rs"]
mod report_sections;

#[path = "tests/provenance.rs"]
mod provenance;

#[path = "tests/termination.rs"]
mod termination;
