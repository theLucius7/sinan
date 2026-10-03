use crate::{Config, SharedState, State, artifacts::safe_component, identity::Identity};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sinan_adapter_sdk::{Adapter, Prepared, Privileged, ServiceManager};
use sinan_protocol::{RetirementReceipt, RetirementRequest, retirement_receipt_message};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;

const KEY: &str = "retirement";
pub const RETIRED_EXIT_CODE: i32 = 78;

#[derive(Debug, thiserror::Error)]
#[error("this Agent has retired; its enrollment credentials have been removed")]
pub struct Retired;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Requested,
    Stopped,
    Clearing,
    Completed,
    Acknowledged,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    request_id: uuid::Uuid,
    server_id: i64,
    panel_origin: String,
    phase: Phase,
    receipt: Option<RetirementReceipt>,
}

pub struct Retirement {
    config: Config,
    state: SharedState,
    adapters: Vec<Arc<dyn Adapter>>,
    privileged: Arc<dyn Privileged>,
    services: Arc<dyn ServiceManager>,
    requested: AtomicBool,
    pub(crate) gate: RwLock<()>,
}

impl Retirement {
    pub(crate) fn new(
        config: Config,
        state: SharedState,
        adapters: Vec<Arc<dyn Adapter>>,
        privileged: Arc<dyn Privileged>,
        services: Arc<dyn ServiceManager>,
    ) -> Result<Self> {
        let requested = state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
            .get_json::<Record>(KEY)?
            .is_some();
        for adapter in &adapters {
            let descriptor = adapter.describe();
            ensure!(
                safe_component(&descriptor.plugin_name) && safe_component(&descriptor.module),
                "invalid retirement adapter descriptor"
            );
        }
        Ok(Self {
            config,
            state,
            adapters,
            privileged,
            services,
            requested: AtomicBool::new(requested),
            gate: RwLock::new(()),
        })
    }

    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn read(&self) -> Result<Option<Record>> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
            .get_json(KEY)
    }

    fn save(&self, record: &Record) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
            .set_json(KEY, record)
    }

    pub(crate) fn request(&self, identity: &Identity, request: RetirementRequest) -> Result<()> {
        ensure!(
            !request.request_id.is_nil(),
            "retirement request ID must not be nil"
        );
        if let Some(existing) = self.read()? {
            ensure!(
                existing.request_id == request.request_id
                    && existing.server_id == identity.server_id,
                "a different retirement request is already pending"
            );
        } else {
            self.save(&Record {
                request_id: request.request_id,
                server_id: identity.server_id,
                panel_origin: self.config.panel_url.clone(),
                phase: Phase::Requested,
                receipt: None,
            })?;
        }
        self.requested.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn request_id(&self) -> Result<Option<uuid::Uuid>> {
        Ok(self.read()?.map(|record| record.request_id))
    }

    pub(crate) async fn prepare(&self) -> Result<()> {
        let _guard = self.gate.write().await;
        self.services.retire_interactive_sessions().await?;
        let mut record = self.read()?.context("retirement has not been requested")?;
        if record.phase != Phase::Requested {
            return Ok(());
        }
        for adapter in &self.adapters {
            let descriptor = adapter.describe();
            if self.services.is_active(&descriptor.service_unit).await? {
                let runtime = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
                    .get_json::<Prepared>(&format!("applied:{}", descriptor.module))?;
                if let (Some(runtime), Some(source)) = (runtime, adapter.usage_source()) {
                    let sampled = tokio::time::timeout(
                        Duration::from_secs(self.config.operation_timeout_secs),
                        source.read_counters(&runtime),
                    )
                    .await;
                    match sampled {
                        Ok(Ok(counters)) => {
                            self.state
                                .lock()
                                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
                                .sample_usage(
                                    &descriptor.module,
                                    &counters,
                                    sinan_protocol::now_timestamp(),
                                )?;
                        }
                        other => tracing::warn!(module=%descriptor.module, result=?other,
                            "terminal runtime counters could not be read; persisted usage remains available"),
                    }
                }
            }
        }
        self.stop_services().await?;
        crate::tasks::cleanup_commands_for_retirement(&self.state, self.privileged.as_ref())
            .await?;
        record.phase = Phase::Stopped;
        self.save(&record)
    }

    async fn stop_services(&self) -> Result<()> {
        for adapter in &self.adapters {
            let descriptor = adapter.describe();
            tokio::time::timeout(
                Duration::from_secs(self.config.operation_timeout_secs),
                async {
                    if self.services.is_active(&descriptor.service_unit).await? {
                        self.services.stop(&descriptor.service_unit).await?;
                    }
                    ensure!(
                        !self.services.is_active(&descriptor.service_unit).await?,
                        "runtime service remains active during retirement"
                    );
                    Ok::<_, anyhow::Error>(())
                },
            )
            .await
            .context("runtime retirement timed out")??;
        }
        crate::transport::diagnostics::stop_for_retirement(
            &self.config,
            &self.state,
            self.services.as_ref(),
            self.config.operation_timeout_secs,
        )
        .await?;
        for adapter in &self.adapters {
            let directory = self
                .config
                .runtime_root
                .join(format!("{}@main", adapter.describe().plugin_name));
            match std::fs::symlink_metadata(&directory) {
                Ok(metadata) => {
                    ensure!(
                        metadata.is_dir() && !metadata.file_type().is_symlink(),
                        "managed runtime directory must not be a symbolic link"
                    );
                    for ancestor in directory.ancestors().skip(1) {
                        let metadata = std::fs::symlink_metadata(ancestor)?;
                        ensure!(
                            metadata.is_dir() && !metadata.file_type().is_symlink(),
                            "managed runtime ancestors must not be symbolic links"
                        );
                    }
                    self.privileged
                        .remove_symlink(&directory.join("current"))
                        .await?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub(crate) async fn complete(&self, identity: &Identity) -> Result<RetirementReceipt> {
        let _guard = self.gate.write().await;
        let mut record = self.read()?.context("retirement has not been requested")?;
        ensure!(
            record.phase == Phase::Stopped,
            "runtime shutdown is not confirmed"
        );
        crate::tasks::cleanup_commands_for_retirement(&self.state, self.privileged.as_ref())
            .await?;
        ensure!(
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
                .pending_usage_count()?
                == 0,
            "retirement awaits usage acknowledgements"
        );
        let receipt = RetirementReceipt {
            server_id: record.server_id,
            request_id: record.request_id,
            signature: URL_SAFE_NO_PAD.encode(
                identity
                    .signing_key
                    .sign(&retirement_receipt_message(
                        record.server_id,
                        record.request_id,
                    ))
                    .to_bytes(),
            ),
        };
        record.receipt = Some(receipt.clone());
        record.phase = Phase::Clearing;
        self.save(&record)?;
        self.clear_credentials(&mut record).await?;
        Ok(receipt)
    }

    async fn clear_credentials(&self, record: &mut Record) -> Result<()> {
        self.stop_services().await?;
        crate::tasks::cleanup_commands_for_retirement(&self.state, self.privileged.as_ref())
            .await?;
        for adapter in &self.adapters {
            let directory = self
                .config
                .runtime_root
                .join(format!("{}@main", adapter.describe().plugin_name));
            match std::fs::symlink_metadata(&directory) {
                Ok(_) => self.privileged.remove_managed_directory(&directory).await?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
            .clear_retired_configuration()?;
        for name in ["device.key", "server_id", "panel_origin"] {
            self.privileged
                .remove_file(&self.config.identity_dir.join(name))
                .await?;
        }
        record.phase = Phase::Completed;
        self.save(record)
    }

    /// Recovery precedes loading identity or recovering any apply intent.
    pub(crate) async fn recover_completion(&self) -> Result<bool> {
        let Some(mut record) = self.read()? else {
            return Ok(false);
        };
        ensure!(
            record.panel_origin == self.config.panel_url,
            "retirement belongs to another panel"
        );
        if record.phase == Phase::Clearing {
            self.clear_credentials(&mut record).await?;
        }
        if record.phase == Phase::Acknowledged {
            return Err(Retired.into());
        }
        if record.phase == Phase::Requested {
            self.prepare().await?;
            return Ok(false);
        }
        if record.phase == Phase::Stopped {
            self.stop_services().await?;
            crate::tasks::cleanup_commands_for_retirement(&self.state, self.privileged.as_ref())
                .await?;
            return Ok(false);
        }
        if record.phase != Phase::Completed {
            return Ok(false);
        }
        self.deliver_receipt().await?;
        Err(Retired.into())
    }

    pub(crate) async fn deliver_receipt(&self) -> Result<()> {
        let mut record = self.read()?.context("missing retirement record")?;
        ensure!(
            record.phase == Phase::Completed,
            "credentials have not been cleared"
        );
        let receipt = record
            .receipt
            .as_ref()
            .context("missing signed retirement receipt")?;
        let client = crate::panel_tls::client_builder(self.config.panel_ca_file.as_deref())?
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(self.config.operation_timeout_secs))
            .build()?;
        let response = client
            .post(
                crate::config::validate_panel_url(&record.panel_origin)?
                    .join("api/agent/v1/retirement/receipt")?,
            )
            .json(receipt)
            .send()
            .await?;
        ensure!(
            response.status() == reqwest::StatusCode::NO_CONTENT,
            "panel has not acknowledged the retirement receipt: {}",
            response.status()
        );
        record.phase = Phase::Acknowledged;
        self.save(&record)
    }
}

pub(crate) fn ensure_enrollment_allowed(config: &Config) -> Result<()> {
    if config.state_db.try_exists()?
        && State::open(&config.state_db)?
            .get_json::<Record>(KEY)?
            .is_some()
    {
        anyhow::bail!(
            "this Agent is retiring or retired; a new installation requires explicit local cleanup"
        );
    }
    Ok(())
}

/// A monitor must not abandon services or credentials owned by a previous mode.
/// Inspect existing state without creating, migrating, or clearing the ledger.
pub fn ensure_monitor_only_allowed(config: &Config) -> Result<()> {
    for directory in [&config.runtime_root, &config.install_root] {
        match std::fs::symlink_metadata(directory) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "monitor-only requires ordinary runtime and artifact directories"
                );
                ensure!(
                    std::fs::read_dir(directory)?.next().transpose()?.is_none(),
                    "monitor-only refuses existing managed runtime or artifact files; keep the managed mode to retire this installation"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    match std::fs::symlink_metadata(&config.state_db) {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "monitor-only requires an ordinary ledger database"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let connection = rusqlite::Connection::open_with_flags(
        &config.state_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.busy_timeout(Duration::from_secs(10))?;
    let managed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM kv WHERE key LIKE 'applied:%' OR key LIKE 'health:%'
         OR key LIKE 'usage:%' OR (key = 'diagnostics:active' AND value <> 'null'))
         OR EXISTS(SELECT 1 FROM intents) OR EXISTS(SELECT 1 FROM usage_baselines)
         OR EXISTS(SELECT 1 FROM usage_outbox)",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        !managed,
        "monitor-only refuses existing managed state; keep the managed mode to retire this installation"
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
