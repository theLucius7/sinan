use super::*;
use crate::{
    fake::{FakeAdapter, FakeServiceManager},
    state::IntentRecord,
    system::{SystemOps, SystemServiceManager},
};
use ed25519_dalek::{Signature, Verifier};
use sinan_adapter_sdk::{BoxFuture, CommandOutput, Counter, RuntimeSpec};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    config: Config,
    state: SharedState,
    services: Arc<FakeServiceManager>,
    identity: Identity,
    retirement: Arc<Retirement>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!("sinan-retirement-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        let root = fs::canonicalize(root)?;
        let config = Config {
            panel_url: "http://127.0.0.1:9".into(),
            identity_dir: root.join("identity"),
            state_db: root.join("state.db"),
            runtime_root: root.join("runtime"),
            install_root: root.join("install"),
            status_socket: root.join("status.sock"),
            operation_timeout_secs: 1,
            public_ips: vec![],
            ..Config::default()
        };
        fs::create_dir(&config.identity_dir)?;
        fs::write(config.identity_dir.join("device.key"), [19_u8; 32])?;
        fs::set_permissions(
            config.identity_dir.join("device.key"),
            fs::Permissions::from_mode(0o600),
        )?;
        fs::write(config.identity_dir.join("server_id"), "7")?;
        fs::write(config.identity_dir.join("panel_origin"), &config.panel_url)?;
        let identity = crate::identity::load(&config)?;
        let revision = config.runtime_root.join("demo@main/revisions/1");
        fs::create_dir_all(&revision)?;
        fs::write(
            revision.join("config.json"),
            "TEST_ONLY_runtime_credentials",
        )?;
        symlink(&revision, config.runtime_root.join("demo@main/current"))?;
        let mut state = State::open(&config.state_db)?;
        state.set_json(
            "applied:demo",
            &Prepared {
                spec: RuntimeSpec {
                    revision: 1,
                    kernel_version: "1.0.0".into(),
                    config_hash: "hash".into(),
                    binary_path: config.install_root.join("demo/1.0.0/demo"),
                    revision_dir: revision,
                    stats_listen: "127.0.0.1:18085".into(),
                    files: BTreeMap::from([(
                        "config.json".into(),
                        "TEST_ONLY_runtime_credentials".into(),
                    )]),
                },
                listen_ports: vec![],
            },
        )?;
        state.begin_intent(&IntentRecord {
            op_id: Uuid::new_v4(),
            module: "demo".into(),
            payload: serde_json::json!({"credentials":"TEST_ONLY_intent"}),
        })?;
        let state = Arc::new(Mutex::new(state));
        let services = Arc::new(FakeServiceManager::default());
        services.active.store(true, Ordering::SeqCst);
        let retirement = Arc::new(Retirement::new(
            config.clone(),
            state.clone(),
            vec![Arc::new(FakeAdapter::default())],
            Arc::new(SystemOps),
            services.clone(),
        )?);
        Ok(Self {
            root,
            config,
            state,
            services,
            identity,
            retirement,
        })
    }
    fn request(&self) -> Result<Uuid> {
        let id = Uuid::new_v4();
        self.retirement
            .request(&self.identity, RetirementRequest { request_id: id })?;
        Ok(id)
    }
}

#[tokio::test]
async fn private_panel_ca_delivers_signed_retirement_after_identity_removal() -> Result<()> {
    use crate::panel_tls::test_support::{CertificateKind, HttpServer, Material};
    let fixture = Fixture::new()?;
    let material = Material::new().await?;
    let mut server = HttpServer::start(&material, CertificateKind::Valid, 204, Vec::new()).await?;
    let mut config = fixture.config.clone();
    config.panel_url = server.origin.clone();
    config.panel_ca_file = Some(material.ca.clone());
    config.operation_timeout_secs = 3;
    fs::write(config.identity_dir.join("panel_origin"), &config.panel_url)?;
    let trusted = Retirement::new(
        config.clone(),
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        fixture.services.clone(),
    )?;
    let request_id = Uuid::new_v4();
    trusted.request(&fixture.identity, RetirementRequest { request_id })?;
    trusted.prepare().await?;
    trusted.complete(&fixture.identity).await?;
    assert_eq!(trusted.read()?.unwrap().phase, Phase::Completed);
    for name in ["device.key", "server_id", "panel_origin"] {
        assert!(!config.identity_dir.join(name).exists());
    }
    assert!(!config.runtime_root.join("demo@main").exists());
    assert!(
        material.ca.exists(),
        "panel trust must survive removal of device credentials"
    );

    let mut without_ca = config;
    without_ca.panel_ca_file = None;
    let untrusted = Retirement::new(
        without_ca,
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        fixture.services.clone(),
    )?;
    let rejected = untrusted.deliver_receipt().await.unwrap_err();
    assert!(rejected.chain().any(|source| {
        source
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_connect)
    }));
    assert_eq!(trusted.read()?.unwrap().phase, Phase::Completed);
    assert!(!server.has_pending_request());
    trusted.deliver_receipt().await?;
    let received = server.next().await?;
    assert_eq!(received.target, "/api/agent/v1/retirement/receipt");
    let receipt: RetirementReceipt = serde_json::from_slice(&received.body)?;
    assert_eq!(receipt.request_id, request_id);
    assert_eq!(receipt.server_id, fixture.identity.server_id);
    fixture.identity.signing_key.verifying_key().verify(
        &retirement_receipt_message(receipt.server_id, receipt.request_id),
        &Signature::from_slice(&URL_SAFE_NO_PAD.decode(receipt.signature)?)?,
    )?;
    assert_eq!(trusted.read()?.unwrap().phase, Phase::Acknowledged);
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn monitor_only_cannot_abandon_a_managed_installation() -> Result<()> {
    let fixture = Fixture::new()?;
    assert!(ensure_monitor_only_allowed(&fixture.config).is_err());
    let error = crate::transport::run_with_diagnostics(
        fixture.config.clone(),
        Vec::new(),
        Vec::new(),
        Arc::new(SystemOps),
        fixture.services.clone(),
        "fixture-agent",
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("monitor-only"));
    assert!(!fixture.config.status_socket.exists());

    let mut missing_state = fixture.config.clone();
    missing_state.state_db = fixture.root.join("absent/state.db");
    missing_state.status_socket = fixture.root.join("absent/status.sock");
    let error = crate::transport::run_with_diagnostics(
        missing_state,
        Vec::new(),
        Vec::new(),
        Arc::new(SystemOps),
        fixture.services.clone(),
        "fixture-agent",
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("monitor-only"));
    assert!(!fixture.root.join("absent").exists());
    assert!(fixture.services.active.load(Ordering::SeqCst));
    assert!(fixture.config.identity_dir.join("device.key").exists());
    assert!(
        fixture
            .config
            .runtime_root
            .join("demo@main/current")
            .exists()
    );
    let state = fixture.state.lock().unwrap();
    assert!(state.get_json::<Prepared>("applied:demo")?.is_some());
    assert_eq!(state.pending_intents()?.len(), 1);
    assert!(state.get_json::<Record>(KEY)?.is_none());
    Ok(())
}

#[test]
fn monitor_only_rejects_persisted_management_history_without_runtime_files() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut config = fixture.config.clone();
    config.runtime_root = fixture.root.join("absent-runtime");
    config.install_root = fixture.root.join("absent-artifacts");
    let cases = [
        "INSERT INTO kv VALUES ('applied:demo', '{}')",
        "INSERT INTO kv VALUES ('health:demo', 'false')",
        "INSERT INTO kv VALUES ('usage:module:demo', '{}')",
        "INSERT INTO kv VALUES ('diagnostics:active', '{}')",
        "INSERT INTO intents VALUES ('fixture-op', 'demo', '{}', 1)",
        "INSERT INTO usage_baselines VALUES ('demo', 'u1_n1', 'fixture-epoch', '1', '2', 1)",
        "INSERT INTO usage_outbox VALUES ('fixture-epoch', '1', '{}', 1)",
    ];
    for sql in cases {
        {
            let state = fixture.state.lock().unwrap();
            state.connection.execute_batch(
                "DELETE FROM kv; DELETE FROM intents; DELETE FROM usage_baselines; DELETE FROM usage_outbox",
            )?;
            state.connection.execute(sql, [])?;
        }
        assert!(ensure_monitor_only_allowed(&config).is_err(), "{sql}");
    }
    assert!(!config.runtime_root.exists());
    assert!(!config.install_root.exists());
    Ok(())
}

#[test]
fn monitor_only_unknown_state_and_directory_aliases_fail_closed() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut config = fixture.config.clone();
    config.runtime_root = fixture.root.join("empty-runtime");
    config.install_root = fixture.root.join("empty-artifacts");
    config.state_db = fixture.root.join("invalid-state.db");
    fs::write(&config.state_db, "not a ledger")?;
    assert!(ensure_monitor_only_allowed(&config).is_err());
    assert_eq!(fs::read_to_string(&config.state_db)?, "not a ledger");
    fs::remove_file(&config.state_db)?;
    symlink(fixture.root.join("missing-target"), &config.state_db)?;
    assert!(ensure_monitor_only_allowed(&config).is_err());
    fs::remove_file(&config.state_db)?;
    fs::create_dir(&config.install_root)?;
    symlink(&config.install_root, &config.runtime_root)?;
    assert!(ensure_monitor_only_allowed(&config).is_err());
    Ok(())
}

#[tokio::test]
async fn pure_monitor_can_retire_without_managed_history() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut config = fixture.config.clone();
    config.runtime_root = fixture.root.join("monitor-runtime");
    config.install_root = fixture.root.join("monitor-artifacts");
    config.state_db = fixture.root.join("monitor-state.db");
    ensure_monitor_only_allowed(&config)?;
    assert!(
        !config.state_db.exists(),
        "the guard must not create a ledger"
    );
    fs::create_dir(&config.runtime_root)?;
    fs::create_dir(&config.install_root)?;
    let mut state = State::open(&config.state_db)?;
    state.set_json("agent_settings", &sinan_protocol::AgentSettings::default())?;
    // A previously rejected diagnostic is not an active managed service.
    state.set_json("diagnostics:active", &serde_json::Value::Null)?;
    state.set_json("diagnostics:done:fixture", &true)?;
    ensure_monitor_only_allowed(&config)?;
    let state = Arc::new(Mutex::new(state));
    let retirement = Retirement::new(
        config.clone(),
        state.clone(),
        Vec::new(),
        Arc::new(SystemOps),
        Arc::new(FakeServiceManager::default()),
    )?;
    retirement.request(
        &fixture.identity,
        RetirementRequest {
            request_id: Uuid::new_v4(),
        },
    )?;
    retirement.prepare().await?;
    retirement.complete(&fixture.identity).await?;
    assert_eq!(retirement.read()?.unwrap().phase, Phase::Completed);
    assert!(!config.identity_dir.join("device.key").exists());
    assert_eq!(state.lock().unwrap().pending_usage_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn request_is_durable_idempotent_and_blocks_reenrollment() -> Result<()> {
    let fixture = Fixture::new()?;
    let id = fixture.request()?;
    fixture
        .retirement
        .request(&fixture.identity, RetirementRequest { request_id: id })?;
    assert!(
        fixture
            .retirement
            .request(
                &fixture.identity,
                RetirementRequest {
                    request_id: Uuid::new_v4()
                }
            )
            .is_err()
    );
    let recovered = Retirement::new(
        fixture.config.clone(),
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        fixture.services.clone(),
    )?;
    assert!(recovered.requested());
    assert!(ensure_enrollment_allowed(&fixture.config).is_err());
    assert!(!recovered.recover_completion().await?);
    assert!(!fixture.services.active.load(Ordering::SeqCst));
    assert!(
        !fixture
            .config
            .runtime_root
            .join("demo@main/current")
            .exists()
    );
    assert!(fixture.config.identity_dir.join("device.key").exists());
    Ok(())
}

#[tokio::test]
async fn shutdown_waits_for_inflight_operations_and_failure_keeps_credentials() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.request()?;
    let guard = fixture.retirement.gate.read().await;
    let retirement = fixture.retirement.clone();
    let task = tokio::spawn(async move { retirement.prepare().await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(fixture.services.actions.lock().unwrap().is_empty());
    fixture.services.fail_next.store(true, Ordering::SeqCst);
    drop(guard);
    assert!(task.await?.is_err());
    assert_eq!(fixture.retirement.read()?.unwrap().phase, Phase::Requested);
    assert!(fixture.config.identity_dir.join("device.key").exists());
    fixture.retirement.prepare().await?;
    assert!(!fixture.services.active.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn acknowledged_usage_is_preserved_while_keys_and_configuration_are_removed() -> Result<()> {
    let fixture = Fixture::new()?;
    {
        let mut state = fixture.state.lock().unwrap();
        let command = sinan_protocol::RemoteCommand {
            id: Uuid::new_v4(),
            command: "TEST_ONLY_command_secret".into(),
            timeout_secs: 1,
            expires_at: sinan_protocol::now_timestamp() + 600,
        };
        state.begin_command(&command)?;
        state.finish_command(&sinan_protocol::CommandResult {
            id: command.id,
            status: sinan_protocol::CommandStatus::Succeeded,
            finished_at: sinan_protocol::now_timestamp(),
            stdout: "TEST_ONLY_command_output".into(),
            stderr: String::new(),
            timed_out: false,
            truncated: false,
        })?;
        state.save_probe_result(&sinan_protocol::ProbeResult {
            id: Uuid::new_v4(),
            probe_id: Uuid::new_v4(),
            sampled_at: sinan_protocol::telemetry::now_millis(),
            latency_ms: None,
            loss_percent: 100.0,
            address_family: None,
            error: Some("TEST_ONLY_probe_error".into()),
            attempts: None,
            execution: None,
        })?;
        state.save_telemetry(&sinan_protocol::TelemetrySample {
            id: Uuid::new_v4(),
            sampled_at: sinan_protocol::telemetry::now_millis(),
            metrics: sinan_protocol::Metrics::default(),
        })?;
        for table in ["command_journal", "probe_outbox", "telemetry_outbox"] {
            assert_eq!(
                state.connection.query_row(
                    &format!("SELECT COUNT(*) FROM {table}"),
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
        }
    }
    fixture.request()?;
    let batch = fixture
        .state
        .lock()
        .unwrap()
        .sample_usage(
            "demo",
            &[Counter {
                stat_name: "u1_n1".into(),
                uplink: 31,
                downlink: 73,
            }],
            sinan_protocol::now_timestamp(),
        )?
        .unwrap();
    fixture.retirement.prepare().await?;
    assert!(
        fixture
            .retirement
            .complete(&fixture.identity)
            .await
            .is_err()
    );
    assert!(fixture.config.identity_dir.join("device.key").exists());
    fixture
        .state
        .lock()
        .unwrap()
        .acknowledge_usage(batch.epoch, batch.seq)?;
    let receipt = fixture.retirement.complete(&fixture.identity).await?;
    fixture.identity.signing_key.verifying_key().verify(
        &retirement_receipt_message(receipt.server_id, receipt.request_id),
        &Signature::from_slice(&URL_SAFE_NO_PAD.decode(&receipt.signature)?)?,
    )?;
    assert!(
        fixture
            .identity
            .signing_key
            .verifying_key()
            .verify(
                b"an-authentication-nonce",
                &Signature::from_slice(&URL_SAFE_NO_PAD.decode(&receipt.signature)?)?
            )
            .is_err()
    );
    assert!(
        fixture
            .identity
            .signing_key
            .verifying_key()
            .verify(
                &retirement_receipt_message(receipt.server_id, Uuid::new_v4()),
                &Signature::from_slice(&URL_SAFE_NO_PAD.decode(&receipt.signature)?)?
            )
            .is_err()
    );
    for name in ["device.key", "server_id", "panel_origin"] {
        assert!(!fixture.config.identity_dir.join(name).exists());
    }
    assert!(!fixture.config.runtime_root.join("demo@main").exists());
    let state = fixture.state.lock().unwrap();
    assert!(state.pending_intents()?.is_empty());
    assert!(
        state
            .get_json::<serde_json::Value>("applied:demo")?
            .is_none()
    );
    assert!(
        state
            .get_json::<serde_json::Value>("usage:module:demo")?
            .is_some()
    );
    assert_eq!(
        state
            .connection
            .query_row("SELECT COUNT(*) FROM usage_outbox", [], |row| row
                .get::<_, i64>(0))?,
        1
    );
    for table in ["command_journal", "probe_outbox", "telemetry_outbox"] {
        assert_eq!(
            state
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
            0,
            "retirement retained {table}"
        );
    }
    assert_eq!(state.pending_usage_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn interrupted_credential_cleanup_resumes_without_loading_a_deleted_key() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.request()?;
    fixture.retirement.prepare().await?;
    let outside = fixture.root.join("outside");
    fs::write(&outside, "untouched")?;
    fs::remove_file(fixture.config.identity_dir.join("server_id"))?;
    symlink(&outside, fixture.config.identity_dir.join("server_id"))?;
    assert!(
        fixture
            .retirement
            .complete(&fixture.identity)
            .await
            .is_err()
    );
    assert!(!fixture.config.identity_dir.join("device.key").exists());
    assert_eq!(fixture.retirement.read()?.unwrap().phase, Phase::Clearing);
    assert_eq!(fs::read_to_string(&outside)?, "untouched");
    fs::remove_file(fixture.config.identity_dir.join("server_id"))?;
    let recovered = Retirement::new(
        fixture.config.clone(),
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        fixture.services.clone(),
    )?;
    // The panel is unavailable, but credential cleanup must complete before a receipt retry.
    assert!(recovered.recover_completion().await.is_err());
    assert_eq!(recovered.read()?.unwrap().phase, Phase::Completed);
    assert!(!fixture.config.identity_dir.join("panel_origin").exists());
    assert_eq!(fs::read_to_string(outside)?, "untouched");
    Ok(())
}

#[tokio::test]
async fn managed_directory_alias_is_rejected_before_any_credential_deletion() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.request()?;
    let original = fixture.config.runtime_root.join("demo@main");
    let outside = fixture.root.join("outside-runtime");
    fs::rename(&original, &outside)?;
    symlink(&outside, &original)?;
    assert!(fixture.retirement.prepare().await.is_err());
    assert!(outside.join("revisions/1/config.json").exists());
    assert!(fixture.config.identity_dir.join("device.key").exists());
    Ok(())
}

struct DiagnosticServices {
    runtime: FakeServiceManager,
    job_running: AtomicBool,
    fail_stop: AtomicBool,
    cleanup_confirmed: AtomicBool,
    fail_cleanup: AtomicBool,
    hang_cleanup: AtomicBool,
    cleanup_supported: AtomicBool,
    stopped_units: Mutex<Vec<String>>,
    cleanup_targets: Mutex<Vec<(String, PathBuf)>>,
}
impl DiagnosticServices {
    fn new(running: bool) -> Self {
        Self {
            runtime: FakeServiceManager::default(),
            job_running: AtomicBool::new(running),
            fail_stop: AtomicBool::new(false),
            cleanup_confirmed: AtomicBool::new(true),
            fail_cleanup: AtomicBool::new(false),
            hang_cleanup: AtomicBool::new(false),
            cleanup_supported: AtomicBool::new(true),
            stopped_units: Mutex::new(Vec::new()),
            cleanup_targets: Mutex::new(Vec::new()),
        }
    }
}
impl ServiceManager for DiagnosticServices {
    fn supports_confirmed_cancellation(&self) -> bool {
        self.cleanup_supported.load(Ordering::SeqCst)
    }
    fn diagnostic_cleanup_confirmed<'a>(
        &'a self,
        unit: &'a str,
        directory: &'a Path,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            self.cleanup_targets
                .lock()
                .unwrap()
                .push((unit.into(), directory.into()));
            if self.hang_cleanup.load(Ordering::SeqCst) {
                return std::future::pending().await;
            }
            ensure!(
                !self.fail_cleanup.load(Ordering::SeqCst),
                "injected diagnostic cleanup evidence failure"
            );
            Ok(self.cleanup_confirmed.load(Ordering::SeqCst)
                && !self.job_running.load(Ordering::SeqCst))
        })
    }
    fn reload<'a>(&'a self, unit: &'a str) -> sinan_adapter_sdk::BoxFuture<'a, ()> {
        self.runtime.reload(unit)
    }
    fn restart<'a>(&'a self, unit: &'a str) -> sinan_adapter_sdk::BoxFuture<'a, ()> {
        self.runtime.restart(unit)
    }
    fn is_active<'a>(&'a self, unit: &'a str) -> sinan_adapter_sdk::BoxFuture<'a, bool> {
        self.runtime.is_active(unit)
    }
    fn stop<'a>(&'a self, unit: &'a str) -> sinan_adapter_sdk::BoxFuture<'a, ()> {
        Box::pin(async move {
            if unit.starts_with("sinan-diagnostic-") {
                self.stopped_units.lock().unwrap().push(unit.into());
                ensure!(
                    !self.fail_stop.swap(false, Ordering::SeqCst),
                    "injected diagnostic stop failure"
                );
                self.job_running.store(false, Ordering::SeqCst);
                Ok(())
            } else {
                self.runtime.stop(unit).await
            }
        })
    }
    fn job_status<'a>(
        &'a self,
        _: &'a str,
    ) -> sinan_adapter_sdk::BoxFuture<'a, sinan_adapter_sdk::JobStatus> {
        Box::pin(async move {
            Ok(if self.job_running.load(Ordering::SeqCst) {
                sinan_adapter_sdk::JobStatus::Running
            } else {
                sinan_adapter_sdk::JobStatus::Missing
            })
        })
    }
}

#[tokio::test]
async fn diagnostic_shutdown_failure_prevents_success_and_can_be_retried() -> Result<()> {
    let fixture = Fixture::new()?;
    let job_id = Uuid::new_v4();
    let spec = sinan_adapter_sdk::DiagnosticSpec {
        id: job_id.to_string(),
        version: "test".into(),
        binary_path: fixture.config.install_root.join("diagnostic/test/tool"),
        job_dir: fixture
            .config
            .runtime_root
            .join("diagnostics")
            .join(job_id.to_string()),
        timeout_secs: 60,
        options: BTreeMap::new(),
    };
    let service = sinan_adapter_sdk::ServiceJob {
        unit: format!("sinan-diagnostic-{job_id}.service"),
        program: spec.binary_path.clone(),
        args: vec![],
        working_directory: spec.job_dir.clone(),
        timeout_secs: 60,
        memory_max: Default::default(),
        tasks_max: Default::default(),
        cpu_max_percent: Default::default(),
        cpu_weight: Default::default(),
        io_weight: Default::default(),
        oom_score_adjust: Default::default(),
    };
    fixture.state.lock().unwrap().set_json("diagnostics:active", &serde_json::json!({
        "Started": { "spec": spec, "service": service, "started_at": 0, "plugin": "test", "start_error": null, "expires_at": null }
    }))?;
    let services = Arc::new(DiagnosticServices::new(true));
    services.fail_stop.store(true, Ordering::SeqCst);
    let retirement = Retirement::new(
        fixture.config.clone(),
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        services.clone(),
    )?;
    retirement.request(
        &fixture.identity,
        RetirementRequest {
            request_id: Uuid::new_v4(),
        },
    )?;
    assert!(retirement.prepare().await.is_err());
    assert!(services.job_running.load(Ordering::SeqCst));
    assert!(fixture.config.identity_dir.join("device.key").exists());
    retirement.prepare().await?;
    assert!(!services.job_running.load(Ordering::SeqCst));
    retirement.complete(&fixture.identity).await?;
    assert!(!fixture.config.identity_dir.join("device.key").exists());
    Ok(())
}

fn saved_diagnostic(fixture: &Fixture, id: Uuid) -> serde_json::Value {
    let directory = fixture
        .config
        .runtime_root
        .join("diagnostics")
        .join(id.to_string());
    let binary = fixture.config.install_root.join("diagnostic/test/tool");
    serde_json::json!({
        "Started": {
            "spec": {
                "id": id.to_string(), "version": "test", "binary_path": binary,
                "job_dir": directory, "timeout_secs": 60, "options": {}
            },
            "service": {
                "unit": format!("sinan-diagnostic-{id}.service"), "program": binary,
                "args": [], "working_directory": directory, "timeout_secs": 60
            },
            "started_at": 0, "plugin": "test", "start_error": null, "expires_at": null,
            "terminal_update": {
                "id": id, "status": "failed", "report": {"text": "retained original report"},
                "error": "original diagnostic failure"
            },
            "cleanup_error": "waiting for proof"
        }
    })
}

#[tokio::test]
async fn inactive_diagnostic_without_cleanup_proof_blocks_retirement_and_preserves_evidence()
-> Result<()> {
    for case in 0..4 {
        let fixture = Fixture::new()?;
        let id = Uuid::new_v4();
        let saved = saved_diagnostic(&fixture, id);
        fixture
            .state
            .lock()
            .unwrap()
            .set_json("diagnostics:active", &saved)?;
        let services = Arc::new(DiagnosticServices::new(case == 3));
        services
            .cleanup_confirmed
            .store(case != 0, Ordering::SeqCst);
        services.fail_cleanup.store(case == 1, Ordering::SeqCst);
        services.hang_cleanup.store(case == 2, Ordering::SeqCst);
        services
            .cleanup_supported
            .store(case != 3, Ordering::SeqCst);
        {
            let first = Retirement::new(
                fixture.config.clone(),
                fixture.state.clone(),
                vec![Arc::new(FakeAdapter::default())],
                Arc::new(SystemOps),
                services.clone(),
            )?;
            first.request(
                &fixture.identity,
                RetirementRequest {
                    request_id: Uuid::new_v4(),
                },
            )?;
            assert!(
                tokio::time::timeout(Duration::from_secs(2), first.prepare())
                    .await?
                    .is_err(),
                "case {case}"
            );
            assert_eq!(first.read()?.unwrap().phase, Phase::Requested);
            assert!(first.complete(&fixture.identity).await.is_err());
            assert!(first.deliver_receipt().await.is_err());
            if case == 3 {
                assert!(!services.job_running.load(Ordering::SeqCst));
                assert_eq!(
                    *services.stopped_units.lock().unwrap(),
                    vec![format!("sinan-diagnostic-{id}.service")]
                );
                assert!(services.cleanup_targets.lock().unwrap().is_empty());
            }
            assert!(fixture.config.identity_dir.join("device.key").exists());
            assert!(
                fixture
                    .config
                    .runtime_root
                    .join("demo@main/current")
                    .exists()
            );
            assert_eq!(
                fixture
                    .state
                    .lock()
                    .unwrap()
                    .get_json::<serde_json::Value>("diagnostics:active")?
                    .unwrap(),
                saved
            );
        }
        services.cleanup_confirmed.store(true, Ordering::SeqCst);
        services.fail_cleanup.store(false, Ordering::SeqCst);
        services.hang_cleanup.store(false, Ordering::SeqCst);
        services.cleanup_supported.store(true, Ordering::SeqCst);
        let recovered = Retirement::new(
            fixture.config.clone(),
            fixture.state.clone(),
            vec![Arc::new(FakeAdapter::default())],
            Arc::new(SystemOps),
            services.clone(),
        )?;
        recovered.prepare().await?;
        assert_eq!(recovered.read()?.unwrap().phase, Phase::Stopped);
        assert!(!services.job_running.load(Ordering::SeqCst));
        assert!(
            services
                .cleanup_targets
                .lock()
                .unwrap()
                .iter()
                .all(|(unit, directory)| {
                    unit == &format!("sinan-diagnostic-{id}.service")
                        && directory
                            == &fixture
                                .config
                                .runtime_root
                                .join("diagnostics")
                                .join(id.to_string())
                })
        );
        recovered.complete(&fixture.identity).await?;
        assert!(!fixture.config.identity_dir.join("device.key").exists());
    }
    Ok(())
}

#[tokio::test]
async fn corrupted_diagnostic_target_cannot_stop_or_clear_an_unrelated_resource_during_retirement()
-> Result<()> {
    for case in 0..6 {
        let fixture = Fixture::new()?;
        let id = Uuid::new_v4();
        let mut saved = saved_diagnostic(&fixture, id);
        match case {
            0 => saved["Started"]["service"]["unit"] = serde_json::json!("sshd.service"),
            1 => {
                saved["Started"]["service"]["working_directory"] =
                    serde_json::json!(fixture.root.join("outside"))
            }
            2 => {
                saved["Started"]["spec"]["job_dir"] =
                    serde_json::json!(fixture.root.join("outside"))
            }
            3 => {
                saved["Started"]["service"]["program"] =
                    serde_json::json!(fixture.root.join("outside"))
            }
            4 => saved["Started"]["service"]["timeout_secs"] = serde_json::json!(61),
            5 => {
                let outside = serde_json::json!(fixture.root.join("outside"));
                saved["Started"]["spec"]["binary_path"] = outside.clone();
                saved["Started"]["service"]["program"] = outside;
            }
            _ => unreachable!(),
        }
        fixture
            .state
            .lock()
            .unwrap()
            .set_json("diagnostics:active", &saved)?;
        let services = Arc::new(DiagnosticServices::new(true));
        let retirement = Retirement::new(
            fixture.config.clone(),
            fixture.state.clone(),
            vec![Arc::new(FakeAdapter::default())],
            Arc::new(SystemOps),
            services.clone(),
        )?;
        retirement.request(
            &fixture.identity,
            RetirementRequest {
                request_id: Uuid::new_v4(),
            },
        )?;
        assert!(retirement.prepare().await.is_err(), "case {case}");
        assert!(
            services.stopped_units.lock().unwrap().is_empty(),
            "case {case}"
        );
        assert!(
            services.cleanup_targets.lock().unwrap().is_empty(),
            "case {case}"
        );
        assert!(services.job_running.load(Ordering::SeqCst));
        assert!(fixture.config.identity_dir.join("device.key").exists());
        assert!(
            fixture
                .config
                .runtime_root
                .join("demo@main/current")
                .exists()
        );
        assert_eq!(retirement.read()?.unwrap().phase, Phase::Requested);
        assert_eq!(
            fixture
                .state
                .lock()
                .unwrap()
                .get_json::<serde_json::Value>("diagnostics:active")?
                .unwrap(),
            saved
        );
    }
    Ok(())
}

#[tokio::test]
async fn diagnostic_cleanup_is_rechecked_before_retirement_deletes_credentials() -> Result<()> {
    let fixture = Fixture::new()?;
    let id = Uuid::new_v4();
    fixture
        .state
        .lock()
        .unwrap()
        .set_json("diagnostics:active", &saved_diagnostic(&fixture, id))?;
    let services = Arc::new(DiagnosticServices::new(false));
    let retirement = Retirement::new(
        fixture.config.clone(),
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        services.clone(),
    )?;
    retirement.request(
        &fixture.identity,
        RetirementRequest {
            request_id: Uuid::new_v4(),
        },
    )?;
    retirement.prepare().await?;
    services.cleanup_confirmed.store(false, Ordering::SeqCst);
    assert!(retirement.complete(&fixture.identity).await.is_err());
    assert_eq!(retirement.read()?.unwrap().phase, Phase::Clearing);
    assert!(fixture.config.identity_dir.join("device.key").exists());
    assert!(
        fixture
            .state
            .lock()
            .unwrap()
            .get_json::<serde_json::Value>("diagnostics:active")?
            .is_some()
    );
    assert!(retirement.deliver_receipt().await.is_err());
    services.cleanup_confirmed.store(true, Ordering::SeqCst);
    // Local cleanup succeeds even while the panel cannot receive the receipt.
    assert!(retirement.recover_completion().await.is_err());
    assert_eq!(retirement.read()?.unwrap().phase, Phase::Completed);
    assert!(!fixture.config.identity_dir.join("device.key").exists());
    Ok(())
}

#[tokio::test]
async fn runtime_root_alias_cannot_remove_an_outside_current_link() -> Result<()> {
    let fixture = Fixture::new()?;
    let alias = fixture.root.join("runtime-alias");
    symlink(&fixture.config.runtime_root, &alias)?;
    let mut config = fixture.config.clone();
    config.runtime_root = alias;
    let retirement = Retirement::new(
        config,
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        fixture.services.clone(),
    )?;
    retirement.request(
        &fixture.identity,
        RetirementRequest {
            request_id: Uuid::new_v4(),
        },
    )?;
    assert!(retirement.prepare().await.is_err());
    assert!(
        fixture
            .config
            .runtime_root
            .join("demo@main/current")
            .exists()
    );
    assert!(fixture.config.identity_dir.join("device.key").exists());
    Ok(())
}

struct ControlledSystemctl {
    query_fails: AtomicBool,
    running: AtomicBool,
}

impl Privileged for ControlledSystemctl {
    fn execute<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
    ) -> BoxFuture<'a, CommandOutput> {
        Box::pin(async move {
            ensure!(program == Path::new("systemctl"), "unexpected program");
            match args.first().map(String::as_str) {
                Some("list-units")
                    if args.last().map(String::as_str)
                        == Some("sinan-fleet-terminal-*.service") =>
                {
                    Ok(CommandOutput {
                        success: !self.query_fails.load(Ordering::SeqCst),
                        stdout: String::new(),
                        stderr: if self.query_fails.load(Ordering::SeqCst) {
                            "Failed to connect to bus: Permission denied".into()
                        } else {
                            String::new()
                        },
                    })
                }
                Some("show") if self.query_fails.load(Ordering::SeqCst) => Ok(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "Failed to connect to bus: Permission denied".into(),
                }),
                Some("show") => {
                    let (state, pid) = if self.running.load(Ordering::SeqCst) {
                        ("active", 123)
                    } else {
                        ("inactive", 0)
                    };
                    Ok(CommandOutput {
                        success: true,
                        stdout: format!(
                            "LoadState=loaded\nActiveState={state}\nMainPID={pid}\nControlPID=0\n"
                        ),
                        stderr: String::new(),
                    })
                }
                Some("stop") => {
                    self.running.store(false, Ordering::SeqCst);
                    Ok(CommandOutput {
                        success: true,
                        ..Default::default()
                    })
                }
                // Reproduces the previous is-active behavior on a bus failure.
                Some("is-active") => Ok(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "Failed to connect to bus: Permission denied".into(),
                }),
                _ => anyhow::bail!("unexpected systemctl action"),
            }
        })
    }
    fn create_dir<'a>(&'a self, _: &'a Path, _: u32, _: Option<&'a str>) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("unexpected create_dir") })
    }
    fn write_file<'a>(
        &'a self,
        _: &'a Path,
        _: &'a [u8],
        _: u32,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("unexpected write_file") })
    }
    fn atomic_symlink<'a>(&'a self, _: &'a Path, _: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("unexpected atomic_symlink") })
    }
    fn remove_symlink<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("unexpected remove_symlink") })
    }
    fn install_archive<'a>(&'a self, _: &'a Path, _: &'a Path, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { anyhow::bail!("unexpected install_archive") })
    }
}

#[tokio::test]
async fn systemd_query_failure_cannot_clear_credentials_or_confirm_retirement() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.request()?;
    let systemctl = Arc::new(ControlledSystemctl {
        query_fails: AtomicBool::new(true),
        running: AtomicBool::new(true),
    });
    let retirement = Retirement::new(
        fixture.config.clone(),
        fixture.state.clone(),
        vec![Arc::new(FakeAdapter::default())],
        Arc::new(SystemOps),
        Arc::new(SystemServiceManager::new(
            systemctl.clone(),
            crate::system::ServiceBackend::Systemd,
        )),
    )?;
    assert!(retirement.prepare().await.is_err());
    assert!(systemctl.running.load(Ordering::SeqCst));
    assert_eq!(retirement.read()?.unwrap().phase, Phase::Requested);
    assert!(retirement.complete(&fixture.identity).await.is_err());
    assert!(retirement.deliver_receipt().await.is_err());
    assert!(fixture.config.identity_dir.join("device.key").exists());
    assert!(
        fixture
            .config
            .runtime_root
            .join("demo@main/current")
            .exists()
    );

    systemctl.query_fails.store(false, Ordering::SeqCst);
    retirement.prepare().await?;
    assert!(!systemctl.running.load(Ordering::SeqCst));
    assert_eq!(retirement.read()?.unwrap().phase, Phase::Stopped);

    // A status failure during the final check must also preserve credentials,
    // even though the public receipt has already been saved for crash recovery.
    systemctl.running.store(true, Ordering::SeqCst);
    systemctl.query_fails.store(true, Ordering::SeqCst);
    assert!(retirement.complete(&fixture.identity).await.is_err());
    assert_eq!(retirement.read()?.unwrap().phase, Phase::Clearing);
    assert!(retirement.deliver_receipt().await.is_err());
    assert!(retirement.recover_completion().await.is_err());
    assert!(systemctl.running.load(Ordering::SeqCst));
    for name in ["device.key", "server_id", "panel_origin"] {
        assert!(fixture.config.identity_dir.join(name).exists());
    }
    assert!(
        fixture
            .config
            .runtime_root
            .join("demo@main/revisions/1/config.json")
            .exists()
    );
    assert!(ensure_enrollment_allowed(&fixture.config).is_err());
    Ok(())
}

#[tokio::test]
async fn requested_retirement_quiesces_task_update_and_telemetry_workers() -> Result<()> {
    use crate::artifacts::PanelClient;
    use sinan_protocol::{RemoteCommand, now_timestamp};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::watch,
        task::JoinSet,
        time::timeout,
    };
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let captured = requests.clone();
    let marker = fixture.root.join("unexpected-command");
    let command = RemoteCommand {
        id: Uuid::new_v4(),
        command: format!(": > '{}';", marker.display()),
        timeout_secs: 1,
        expires_at: now_timestamp() + 600,
    };
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = vec![0; 16 * 1024];
            let length = stream.read(&mut buffer).await.unwrap_or(0);
            captured.fetch_add(1, Ordering::SeqCst);
            let request = String::from_utf8_lossy(&buffer[..length]);
            let body = if request.starts_with("GET /api/agent/v1/commands ") {
                serde_json::to_vec(&vec![command.clone()]).unwrap()
            } else if request.starts_with("GET /api/agent/v1/probes ") {
                b"[]".to_vec()
            } else {
                b"null".to_vec()
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    });
    fixture.request()?;
    fixture.retirement.prepare().await?;
    fixture.retirement.complete(&fixture.identity).await?;
    let mut config = fixture.config.clone();
    config.panel_url = origin.clone();
    config.agent_root = fixture.root.join("core");
    config.settings.auto_update = true;
    fs::create_dir(&config.agent_root)?;
    fs::write(
        config.agent_root.join("update-state.json"),
        serde_json::to_vec(&crate::upgrade::UpgradeState {
            current: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        })?,
    )?;
    let client = Arc::new(PanelClient::new(&origin, "retirement-worker-fixture")?);
    let (_clients, receiver) = watch::channel(Some(client));
    let mut workers = JoinSet::new();
    workers.spawn(crate::tasks::run(
        fixture.identity.server_id,
        true,
        fixture.state.clone(),
        Arc::new(SystemOps),
        receiver.clone(),
        fixture.retirement.clone(),
    ));
    workers.spawn(crate::upgrade::run(
        config.clone(),
        fixture.state.clone(),
        Arc::new(SystemOps),
        receiver.clone(),
        fixture.retirement.clone(),
        env!("CARGO_PKG_VERSION"),
    ));
    let sampling = crate::telemetry::cache::Sampling::start(
        Arc::new(SystemOps),
        crate::telemetry::worker::initial_control(&config, &fixture.state)?,
    )?;
    workers.spawn(crate::telemetry::worker::run(
        config.clone(),
        fixture.state.clone(),
        sampling.snapshots.clone(),
        sampling.control.clone(),
        receiver,
        fixture.retirement.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Quiescent workers must release the read gate before their timer waits.
    drop(timeout(Duration::from_secs(1), fixture.retirement.gate.write()).await?);
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "retired workers must not fetch or accept new panel work"
    );
    assert!(
        !marker.exists(),
        "a queued command executed after retirement"
    );
    assert!(!config.agent_root.join("pending-update.json").exists());
    {
        let state = fixture.state.lock().unwrap();
        assert!(state.pending_telemetry()?.is_empty());
        assert!(state.command_results()?.is_empty());
        assert!(state.probe_results()?.is_empty());
        assert!(
            state
                .get_json::<serde_json::Value>("probes:configuration")?
                .is_none()
        );
        assert!(
            state
                .get_json::<serde_json::Value>("agent_settings")?
                .is_none()
        );
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn blocked_sampling_does_not_hold_retirement_gate_or_offline_uploads() -> Result<()> {
    use crate::{
        artifacts::PanelClient,
        telemetry::{cache::tests::BlockingFixture, worker},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::watch,
        task::JoinSet,
        time::timeout,
    };
    let fixture = Fixture::new()?;
    let blocked = BlockingFixture::new()?;
    let sample = blocked.wait_until_blocked().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let captured = attempts.clone();
    let sample_id = sample.id;
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = vec![0; 16 * 1024];
            let length = stream.read(&mut buffer).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..length]);
            let (status, body) = if request.starts_with("GET /api/agent/v1/settings ") {
                (
                    "200 OK",
                    serde_json::to_vec(&sinan_protocol::AgentSettings::default()).unwrap(),
                )
            } else if request.starts_with("POST /api/agent/v1/telemetry ") {
                if captured.fetch_add(1, Ordering::SeqCst) == 0 {
                    ("503 Service Unavailable", b"{}".to_vec())
                } else {
                    (
                        "200 OK",
                        serde_json::to_vec(&sinan_protocol::TelemetryAck {
                            ids: vec![sample_id],
                        })
                        .unwrap(),
                    )
                }
            } else {
                ("404 Not Found", b"{}".to_vec())
            };
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    });
    let mut config = fixture.config.clone();
    config.panel_url = origin.clone();
    let client = Arc::new(PanelClient::new(&origin, "TEST_ONLY_cache_fixture")?);
    let (_clients, receiver) = watch::channel(Some(client));
    let mut workers = JoinSet::new();
    workers.spawn(worker::run(
        config.clone(),
        fixture.state.clone(),
        blocked.sampling.snapshots.clone(),
        blocked.sampling.control.clone(),
        receiver,
        fixture.retirement.clone(),
    ));
    timeout(Duration::from_secs(8), async {
        loop {
            if attempts.load(Ordering::SeqCst) >= 2
                && fixture.state.lock().unwrap().pending_telemetry_count()? == 0
            {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    assert_eq!(
        blocked.sampling.snapshots.borrow().sample.as_ref(),
        Some(&sample)
    );
    assert_eq!(blocked.starts.load(Ordering::SeqCst), 1);
    drop(timeout(Duration::from_secs(1), fixture.retirement.gate.write()).await?);
    // Even while the collection call is blocked, retirement can stop managed work.
    fixture.request()?;
    timeout(Duration::from_secs(1), fixture.retirement.prepare()).await??;
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    let reopened = Arc::new(Mutex::new(State::open(&config.state_db)?));
    assert_eq!(
        worker::initial_control(&config, &reopened)?.minimum_timestamp,
        sample.sampled_at
    );
    server.abort();
    Ok(())
}
