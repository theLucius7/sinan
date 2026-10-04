mod connection;
pub mod diagnostics;
mod public_ips;
mod runtime_control;
#[cfg(unix)]
mod status;
#[cfg(windows)]
#[path = "status_windows.rs"]
mod status;
mod status_snapshot;
mod worker;

pub use status::status;

use crate::{Config, SharedState, State, artifacts::PanelClient, identity, reconcile::Reconciler};
use anyhow::{Context, Result};
use sinan_adapter_sdk::{Adapter, DiagnosticAdapter, Prepared, Privileged, ServiceManager};
use sinan_protocol::AppliedRevisions;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::Instant,
};

#[derive(Clone)]
struct Runtime {
    state: SharedState,
    modules: Arc<Vec<String>>,
    capabilities: Arc<Vec<String>>,
    connected: Arc<AtomicBool>,
    public_ips: Arc<Vec<String>>,
    agent_version: &'static str,
    retirement: Option<Arc<crate::retirement::Retirement>>,
    cancellation: Option<Arc<diagnostics::cancellation::CancellationControl>>,
    runtime_control: Option<runtime_control::Control>,
    telemetry: watch::Receiver<Arc<crate::telemetry::cache::Snapshot>>,
}

impl Runtime {
    fn static_info(&self) -> Result<Option<sinan_protocol::StaticInfo>> {
        let mut info = {
            let snapshot = self.telemetry.borrow();
            // Keep enrollment metadata until the collector has identified the host.
            // Compiled ABI alone cannot identify the installed runtime's ABI.
            if snapshot.sample.is_none() {
                return Ok(None);
            }
            snapshot.static_info.clone()
        };
        info.agent_version = Some(self.agent_version.into());
        info.ip_addresses = crate::telemetry::normalized_addresses(
            info.ip_addresses
                .iter()
                .chain(self.public_ips.iter())
                .filter_map(|address| address.parse().ok()),
        );
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
        if let Some(records) = state.get_json::<Vec<(String, i64)>>("discovered_ips")? {
            info.discovered_public_ips = crate::telemetry::normalized_addresses(
                records
                    .iter()
                    .filter(|(_, expires)| *expires > sinan_protocol::now_timestamp())
                    .filter_map(|(address, _)| address.parse().ok()),
            );
            let discovered = info
                .discovered_public_ips
                .iter()
                .filter_map(|address| address.parse::<std::net::IpAddr>().ok());
            info.ip_addresses = crate::telemetry::normalized_addresses(
                info.ip_addresses
                    .iter()
                    .filter_map(|address| address.parse().ok())
                    .chain(discovered),
            );
        }
        for module in self.modules.iter() {
            if let Some(prepared) = state.get_json::<Prepared>(&format!("applied:{module}"))? {
                info.runtime_version = Some(prepared.spec.kernel_version);
                break;
            }
        }
        Ok(Some(info))
    }

    fn applied(&self) -> Result<AppliedRevisions> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
        let mut applied = BTreeMap::new();
        for module in self.modules.iter() {
            if let Some(prepared) = state.get_json::<Prepared>(&format!("applied:{module}"))? {
                applied.insert(module.clone(), prepared.spec.revision);
            }
        }
        Ok(applied)
    }
}

pub async fn run(
    config: Config,
    adapters: Vec<Arc<dyn Adapter>>,
    privileged: Arc<dyn Privileged>,
    services: Arc<dyn ServiceManager>,
    agent_version: &'static str,
) -> Result<()> {
    run_with_diagnostics(
        config,
        adapters,
        Vec::new(),
        privileged,
        services,
        agent_version,
    )
    .await
}

pub async fn run_with_diagnostics(
    config: Config,
    adapters: Vec<Arc<dyn Adapter>>,
    diagnostics: Vec<Arc<dyn DiagnosticAdapter>>,
    privileged: Arc<dyn Privileged>,
    services: Arc<dyn ServiceManager>,
    agent_version: &'static str,
) -> Result<()> {
    config.validate()?;
    // Diagnostic-only Agents still own managed jobs and must recover them.
    // Check a truly module-free mode before reserving or opening local state.
    if adapters.is_empty() && diagnostics.is_empty() {
        crate::retirement::ensure_monitor_only_allowed(&config)?;
    }
    // Reserve the instance before inspecting or recovering another process's intents.
    let listener = status::bind(&config.status_socket).await?;
    let state = Arc::new(Mutex::new(State::open(&config.state_db)?));
    let retirement = Arc::new(crate::retirement::Retirement::new(
        config.clone(),
        state.clone(),
        adapters.clone(),
        privileged.clone(),
        services.clone(),
    )?);
    retirement.recover_completion().await?;
    let identity = identity::load(&config)?;
    let mut modules = Vec::new();
    let supports_validation = adapters
        .iter()
        .any(|adapter| adapter.supports_dependency_validation());
    let fleet_descriptors = adapters.iter().map(|adapter| adapter.describe()).collect();
    let mut reconcilers = Vec::new();
    for adapter in adapters {
        let module = adapter.describe().module;
        anyhow::ensure!(!modules.contains(&module), "duplicate adapter module");
        modules.push(module.clone());
        let reconciler = Arc::new(Reconciler::new(
            config.clone(),
            state.clone(),
            adapter,
            privileged.clone(),
            services.clone(),
        ));
        if !retirement.requested()
            && let Err(error) = reconciler.recover().await
        {
            if !reconciler.management_recovery_allowed(&error) {
                return Err(error);
            }
            tracing::error!(%module, %error, "recovery barrier blocked rollback; Agent remains connected for management");
        }
        reconcilers.push((module, reconciler));
    }
    let mut capabilities = modules.clone();
    capabilities.extend(crate::fleet::capabilities(&config));
    let exact_runtime_supported = !reconcilers.is_empty() && services.supports_runtime_checkpoint();
    if exact_runtime_supported {
        capabilities.push(sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY.into());
        capabilities.push(sinan_protocol::RUNTIME_RECOVERY_BARRIER_CAPABILITY.into());
        if reconcilers
            .iter()
            .any(|(_, reconciler)| reconciler.supports_runtime_probe())
        {
            capabilities.push(sinan_protocol::RUNTIME_PATH_PROBE_CAPABILITY.into());
        }
    }

    if supports_validation {
        capabilities.push(sinan_protocol::RUNTIME_VALIDATION_CAPABILITY.into());
    }
    if !modules.is_empty() {
        capabilities.push(sinan_protocol::RUNTIME_OPERATIONS_CAPABILITY.into());
    }
    capabilities.push(sinan_protocol::RETIREMENT_CAPABILITY.into());
    capabilities.push(sinan_protocol::PROBE_LEASE_CAPABILITY.into());
    capabilities.push(sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY.into());
    capabilities.extend(
        [
            "telemetry:batch",
            "telemetry:live:v1",
            "agent:settings",
            "ip:discovery",
            "probe:tcp",
            "probe:icmp",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    if config.allow_remote_commands {
        capabilities.push("command:execute".into());
        capabilities.push("command:lifecycle:v1".into());
        if cfg!(unix) {
            capabilities.push("command:cancel:v1".into());
        }
    }
    if !diagnostics.is_empty() {
        capabilities.push(sinan_protocol::DIAGNOSTIC_SECTIONS_CAPABILITY.into());
        capabilities.push(sinan_protocol::DIAGNOSTIC_SERVICE_CAPABILITY.into());
    }
    capabilities.extend(
        diagnostics
            .iter()
            .flat_map(|adapter| adapter.capabilities()),
    );
    capabilities.extend(
        diagnostics
            .iter()
            .map(|adapter| format!("diagnostic:{}", adapter.describe().plugin_name)),
    );
    let (client_tx, client_rx) = watch::channel::<Option<Arc<PanelClient>>>(None);
    let (trigger_tx, trigger_rx) = mpsc::channel(1);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel(64);
    let (runtime_control, control_receiver) = runtime_control::Control::channel();
    let cancellation = if !diagnostics.is_empty() && services.supports_confirmed_cancellation() {
        capabilities.push(sinan_protocol::DIAGNOSTIC_CANCEL_CAPABILITY.into());
        capabilities.push(sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY.into());
        if services.supports_diagnostic_cpu_ceiling() {
            capabilities.push(sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY.into());
        }
        Some(Arc::new(
            diagnostics::cancellation::CancellationControl::new(
                state.clone(),
                identity.server_id,
                diagnostics
                    .iter()
                    .map(|adapter| adapter.describe().plugin_name)
                    .collect(),
            )
            .with_outgoing(outgoing_tx.clone()),
        ))
    } else {
        None
    };
    let mut collection_control = crate::telemetry::worker::initial_control(&config, &state)?;
    collection_control.enabled = !retirement.requested();
    let sampling =
        crate::telemetry::cache::Sampling::start(privileged.clone(), collection_control)?;
    let runtime = Runtime {
        state: state.clone(),
        modules: Arc::new(modules),
        capabilities: Arc::new(capabilities),
        connected: Arc::new(AtomicBool::new(false)),
        public_ips: Arc::new(config.public_ips.clone()),
        agent_version,
        retirement: Some(retirement.clone()),
        cancellation: cancellation.clone(),
        runtime_control: Some(runtime_control),
        telemetry: sampling.snapshots.clone(),
    };
    let mut tasks = JoinSet::new();
    tasks.spawn(runtime_control::run(
        reconcilers.clone(),
        runtime.clone(),
        control_receiver,
        outgoing_tx.clone(),
    ));
    tasks.spawn(crate::upgrade::run(
        config.clone(),
        state.clone(),
        privileged.clone(),
        client_rx.clone(),
        retirement.clone(),
        agent_version,
    ));
    tasks.spawn(crate::fleet::run(
        config.clone(),
        state.clone(),
        privileged.clone(),
        services.clone(),
        client_rx.clone(),
        retirement.clone(),
        fleet_descriptors,
    ));
    tasks.spawn(crate::tasks::run(
        identity.server_id,
        config.allow_remote_commands,
        state.clone(),
        privileged.clone(),
        client_rx.clone(),
        retirement.clone(),
    ));
    tasks.spawn(public_ips::run(
        config.clone(),
        runtime.clone(),
        outgoing_tx.clone(),
        retirement.clone(),
    ));
    tasks.spawn(status::serve(listener, runtime.clone()));
    tasks.spawn(crate::telemetry::worker::run(
        config.clone(),
        state.clone(),
        sampling.snapshots.clone(),
        sampling.control.clone(),
        client_rx.clone(),
        retirement.clone(),
    ));
    let diagnostic_worker = diagnostics::DiagnosticWorker::new(
        config.clone(),
        state,
        diagnostics,
        privileged,
        services,
    )?;
    let diagnostic_worker = if let Some(control) = cancellation {
        tasks.spawn(control.clone().run(client_rx.clone(), retirement.clone()));
        diagnostic_worker.with_cancellations(control)
    } else {
        diagnostic_worker
    };
    tasks.spawn(diagnostic_worker.run_guarded(client_rx.clone(), retirement.clone()));
    tasks.spawn(worker::run(
        reconcilers,
        runtime.clone(),
        client_rx,
        trigger_rx,
        outgoing_tx,
    ));
    let mut attempt = 0;
    loop {
        retirement.recover_completion().await?;
        let started = Instant::now();
        let result = tokio::select! {
            result = connection::run(&config, &identity, &runtime, &client_tx, &trigger_tx, &mut outgoing_rx) => result,
            task = tasks.join_next() => {
                task.context("runtime has no background workers")???;
                anyhow::bail!("runtime worker stopped unexpectedly");
            }
        };
        runtime.connected.store(false, Ordering::Relaxed);
        client_tx.send_replace(None);
        if let Err(error) = result {
            if error.downcast_ref::<crate::retirement::Retired>().is_some() {
                return Err(error);
            }
            tracing::warn!(%error, "panel connection interrupted");
        }
        if started.elapsed() >= Duration::from_secs(60) {
            attempt = 0;
        }
        let delay = reconnect_delay(attempt, rand::random());
        attempt = attempt.saturating_add(1);
        tokio::select! {
            _ = tokio::time::sleep(delay) => {},
            task = tasks.join_next() => {
                task.context("runtime has no background workers")???;
                anyhow::bail!("runtime worker stopped unexpectedly");
            }
        }
    }
}

fn reconnect_delay(attempt: u32, jitter: f64) -> Duration {
    let base = (1_u64 << attempt.min(6)).min(60);
    Duration::from_secs_f64(base as f64 * (1.0 + 0.3 * jitter.clamp(0.0, 1.0)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        fake::{FakeAdapter, FakeServiceManager},
        reconcile::ApplyIntent,
        state::IntentRecord,
        system::SystemOps,
    };
    use sinan_adapter_sdk::{Plan, RuntimeSpec};
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    use uuid::Uuid;

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reconnect_backoff_is_bounded_and_jittered() {
        assert_eq!(reconnect_delay(0, 0.0), Duration::from_secs(1));
        assert_eq!(reconnect_delay(4, 0.0), Duration::from_secs(16));
        assert_eq!(reconnect_delay(100, 0.0), Duration::from_secs(60));
        assert_eq!(reconnect_delay(100, 1.0), Duration::from_secs(78));
    }

    #[tokio::test]
    async fn second_runtime_cannot_recover_an_active_instances_intent() -> Result<()> {
        let directory =
            Directory(PathBuf::from("/tmp").join(format!("sn-instance-{}", Uuid::new_v4())));
        let panel = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let config = Config {
            settings: sinan_protocol::AgentSettings::default(),
            panel_url: format!("http://{}", panel.local_addr()?),
            panel_ca_file: None,
            identity_dir: directory.0.join("identity"),
            state_db: directory.0.join("state.db"),
            runtime_root: directory.0.join("runtime"),
            install_root: directory.0.join("install"),
            agent_root: directory.0.join("core"),
            status_socket: directory.0.join("status.sock"),
            operation_timeout_secs: 1,
            public_ips: vec![],
            allow_remote_commands: false,
        };
        std::fs::create_dir_all(&config.identity_dir)?;
        std::fs::write(config.identity_dir.join("device.key"), [7_u8; 32])?;
        std::fs::set_permissions(
            config.identity_dir.join("device.key"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        std::fs::write(config.identity_dir.join("server_id"), "1")?;
        std::fs::write(config.identity_dir.join("panel_origin"), &config.panel_url)?;
        let adapter = Arc::new(FakeAdapter::default());
        let services = Arc::new(FakeServiceManager::default());
        let mut tasks = JoinSet::new();
        tasks.spawn(run(
            config.clone(),
            vec![adapter.clone()],
            Arc::new(SystemOps),
            services.clone(),
            "fixture-agent",
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if status(&config.status_socket).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let record = IntentRecord {
            op_id: Uuid::new_v4(),
            module: "demo".into(),
            payload: serde_json::to_value(ApplyIntent {
                previous: None,
                plan: Plan::Restart,
                target: Prepared {
                    spec: RuntimeSpec {
                        revision: 1,
                        kernel_version: "1.0.0".into(),
                        config_hash: "test-hash".into(),
                        binary_path: config.install_root.join("demo/1.0.0/demo"),
                        revision_dir: config.runtime_root.join("demo@main/revisions/1"),
                        stats_listen: "127.0.0.1:18085".into(),
                        files: BTreeMap::new(),
                    },
                    listen_ports: vec![],
                },
            })?,
        };
        let mut state = State::open(&config.state_db)?;
        state.begin_intent(&record)?;
        let error = run(
            config.clone(),
            vec![adapter],
            Arc::new(SystemOps),
            services.clone(),
            "fixture-agent",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already active"));
        assert_eq!(state.pending_intents()?, vec![record]);
        assert!(services.actions.lock().unwrap().is_empty());
        assert!(status(&config.status_socket).await.is_ok());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert!(!config.status_socket.exists());
        Ok(())
    }
}
