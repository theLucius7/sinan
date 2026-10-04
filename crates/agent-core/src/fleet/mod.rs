mod operations;
mod runtime_permissions;
mod terminals;

use crate::{Config, SharedState, artifacts::PanelClient};
use anyhow::{Result, ensure};
use sinan_adapter_sdk::{Descriptor, Privileged, ServiceManager};
use sinan_protocol::fleet::{AccessPolicy, JobResult, Work};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::{Mutex, watch};

struct ExecutionControl {
    retirement: Arc<crate::retirement::Retirement>,
    lock: Arc<Mutex<()>>,
    descriptors: Arc<Vec<Descriptor>>,
}

pub(crate) fn local_policy(config: &Config) -> Result<AccessPolicy> {
    let path = config
        .identity_dir
        .parent()
        .unwrap_or(Path::new("/etc/sinan"))
        .join("fleet-policy.json");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AccessPolicy::default());
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => {
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= 32 * 1024,
                "fleet policy must be a bounded regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    metadata.permissions().mode() & 0o077 == 0,
                    "fleet policy must be private to its owner"
                );
            }
        }
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

pub(crate) fn capabilities(config: &Config) -> Vec<String> {
    let mut result = Vec::new();
    if cfg!(target_os = "linux") {
        result.push(sinan_protocol::fleet::OPERATIONS_CAPABILITY.into());
        result.push("system:network:v1".into());
        if let Ok(policy) = local_policy(config) {
            if policy.runtime_inspection && Path::new("/usr/bin/python3").is_file() {
                result.push(sinan_protocol::fleet::RUNTIME_PREFLIGHT_CAPABILITY.into());
            }
            if !policy.terminal_accounts.is_empty()
                && Path::new("/usr/bin/python3").is_file()
                && Path::new("/run/systemd/system").is_dir()
            {
                result.push(sinan_protocol::fleet::TERMINAL_CAPABILITY.into());
            }
            if (!policy.read_directories.is_empty() || !policy.write_directories.is_empty())
                && Path::new("/usr/bin/python3").is_file()
            {
                result.push("fleet:files:v1".into());
                result.push("fleet:files:transfer:v1".into());
            }
            if !policy.services.is_empty() {
                result.push("fleet:services:v1".into());
            }
            if policy.system_network && Path::new("/run/systemd/system").is_dir() {
                result.push("system:network:apply:v1".into());
            }
            if policy.private_mesh
                && Path::new("/usr/bin/wg").is_file()
                && Path::new("/usr/bin/wg-quick").is_file()
            {
                result.push("system:private-mesh:v1".into());
            }
            if policy.reverse_tunnel
                && Path::new("/usr/bin/ssh").is_file()
                && Path::new("/usr/bin/ssh-keygen").is_file()
                && Path::new("/run/systemd/system").is_dir()
            {
                result.push("system:reverse-tunnel:v1".into());
            }
            if policy.firewall
                && Path::new("/usr/sbin/nft").is_file()
                && Path::new("/run/systemd/system").is_dir()
            {
                result.push("system:firewall:v1".into());
            }
            if policy.port_forward
                && Path::new("/run/systemd/system").is_dir()
                && Path::new("/usr/bin/socat").is_file()
                && Path::new("/usr/bin/ss").is_file()
            {
                result.push("system:forwarding:v1".into());
            }
            if policy.certificate_deploy
                && !policy.write_directories.is_empty()
                && !policy.services.is_empty()
            {
                result.push("system:certificate-deploy:v1".into());
            }
        }
    }
    result
}

pub(crate) async fn run(
    config: Config,
    state: SharedState,
    ops: Arc<dyn Privileged>,
    services: Arc<dyn ServiceManager>,
    mut client: watch::Receiver<Option<Arc<PanelClient>>>,
    retirement: Arc<crate::retirement::Retirement>,
    descriptors: Vec<Descriptor>,
) -> Result<()> {
    let mut terminals = terminals::Sessions::default();
    let execution = ExecutionControl {
        retirement: retirement.clone(),
        lock: Arc::new(Mutex::new(())),
        descriptors: Arc::new(descriptors),
    };
    loop {
        // Local expiry and policy revocation do not depend on successful panel delivery.
        match local_policy(&config) {
            Ok(policy) => terminals.enforce_local(&policy).await,
            Err(_) => terminals.close_all().await,
        }
        terminals.disconnect().await;
        let active = client.borrow_and_update().clone();
        let retired = retirement.requested();
        if retired {
            terminals.close_all().await;
        }
        if !retired && let Some(active) = active {
            if let Err(error) = tick(
                &config,
                &state,
                ops.clone(),
                services.clone(),
                &active,
                &mut terminals,
                &execution,
            )
            .await
            {
                tracing::warn!(%error,"fleet management polling failed");
                terminals.disconnect().await;
            } else {
                terminals.connected();
            }
        } else {
            terminals.disconnect().await;
        }
        let delay = if terminals.has_live() {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(2)
        };
        tokio::select! {_=tokio::time::sleep(delay)=>{},changed=client.changed()=>{changed?;}}
    }
}

async fn tick(
    config: &Config,
    state: &SharedState,
    ops: Arc<dyn Privileged>,
    services: Arc<dyn ServiceManager>,
    client: &PanelClient,
    terminals: &mut terminals::Sessions,
    control: &ExecutionControl,
) -> Result<()> {
    let retirement = &control.retirement;
    let _guard = retirement.gate.read().await;
    if retirement.requested() {
        terminals.close_all().await;
        return Ok(());
    }
    let pending = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
        .get_json::<Vec<JobResult>>("fleet_results")?
        .unwrap_or_default();
    for result in &pending {
        tokio::time::timeout(
            Duration::from_secs(2),
            client.post_json::<serde_json::Value>("/api/agent/v1/fleet/results", result),
        )
        .await??;
        let mut durable = state
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
        let mut records = durable
            .get_json::<Vec<JobResult>>("fleet_results")?
            .unwrap_or_default();
        records.retain(|record| record.id != result.id);
        durable.set_json("fleet_results", &records)?;
    }
    let work: Work = tokio::time::timeout(
        Duration::from_secs(2),
        client.get_json("/api/agent/v1/fleet/work"),
    )
    .await??;
    let policy = local_policy(config)?;
    terminals
        .tick(&work.terminals, &policy, ops.as_ref(), state, client)
        .await?;
    for job in work.jobs {
        let key = format!("fleet_intent:{}", job.id);
        {
            let mut durable = state
                .lock()
                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
            ensure!(
                durable.get_json::<bool>(&key)?.is_none(),
                "operation already attempted; remote state must be reconciled"
            );
            durable.set_json(&key, &true)?;
        }
        let config = config.clone();
        let state = state.clone();
        let ops = ops.clone();
        let services = services.clone();
        let retirement = retirement.clone();
        let client = client.clone();
        let execution_lock = control.lock.clone();
        let descriptors = control.descriptors.clone();
        tokio::spawn(async move {
            let result = async {
                let _exclusive = execution_lock.lock().await;
                let _guard = retirement.gate.read().await;
                let execution = if retirement.requested()
                    || job.expires_at <= sinan_protocol::now_timestamp()
                {
                    Err(anyhow::anyhow!("operation expired before execution"))
                } else {
                    match local_policy(&config) {
                        Ok(policy) => {
                            operations::execute(
                                &config,
                                &policy,
                                &job,
                                ops.as_ref(),
                                services.as_ref(),
                                &client,
                                &descriptors,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    }
                };
                let result = match execution {
                    Ok(result) => JobResult {
                        id: job.id,
                        succeeded: true,
                        result,
                        error: None,
                        completed_at: sinan_protocol::now_timestamp(),
                    },
                    Err(error) => JobResult {
                        id: job.id,
                        succeeded: false,
                        result: serde_json::Value::Null,
                        error: Some(error.to_string().chars().take(2048).collect()),
                        completed_at: sinan_protocol::now_timestamp(),
                    },
                };
                {
                    let mut durable = state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
                    let mut records = durable
                        .get_json::<Vec<JobResult>>("fleet_results")?
                        .unwrap_or_default();
                    ensure!(records.len() < 32, "fleet result outbox full");
                    records.push(result);
                    durable.set_json("fleet_results", &records)?;
                    durable.remove_json(&key)?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(error) = result {
                tracing::error!(%error,"fleet outcome could not be persisted; operation will not be replayed");
            }
        });
    }
    Ok(())
}
