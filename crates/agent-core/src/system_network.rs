use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sinan_adapter_sdk::Privileged;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[path = "system_network/certificates.rs"]
mod certificates;
#[path = "system_network/firewall.rs"]
mod firewall;
#[path = "system_network/mesh.rs"]
mod mesh;
#[path = "system_network/tunnel.rs"]
mod tunnel;
pub use certificates::{deploy_certificate, inspect_certificate};

const KEYS: &[&str] = &[
    "net.ipv4.tcp_congestion_control",
    "net.core.default_qdisc",
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem",
    "net.core.somaxconn",
    "net.core.netdev_max_backlog",
    "net.netfilter.nf_conntrack_max",
    "net.ipv4.ip_local_port_range",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    id: String,
    before: BTreeMap<String, String>,
    desired: BTreeMap<String, String>,
    created_at: i64,
    restore_at: i64,
    confirmed: bool,
    #[serde(default)]
    persisted: bool,
    #[serde(default)]
    persistent_after: Option<String>,
}

/// Fleet policy must authorize this operation before invoking this function.
/// Every system change crosses the existing privilege boundary.
pub async fn execute(
    privileged: &dyn Privileged,
    state_dir: &Path,
    operation: &Value,
) -> anyhow::Result<Value> {
    ensure!(cfg!(target_os = "linux"), "network tuning requires Linux");
    let action = operation["action"]
        .as_str()
        .context("network action missing")?;
    if action.starts_with("mesh_") {
        return mesh::execute(privileged, state_dir, operation).await;
    }
    if action.starts_with("tunnel_") {
        return tunnel::execute(privileged, state_dir, operation).await;
    }
    if action.starts_with("firewall_") {
        let _lock = recovery_lock(privileged, state_dir).await?;
        return firewall::execute(privileged, state_dir, operation).await;
    }
    if action == "inventory" {
        return inventory(privileged).await;
    }
    let _lock = recovery_lock(privileged, state_dir).await?;
    let id = operation["snapshot_id"]
        .as_str()
        .context("snapshot identifier missing")?;
    ensure!(valid_id(id), "invalid snapshot identifier");
    let directory = state_dir.join("network-snapshots").join(id);
    let snapshot_path = directory.join("snapshot.json");
    match action {
        "temporary" => {
            require_available_recovery(state_dir, "sysctl").await?;
            ensure!(
                !snapshot_path.try_exists()?,
                "snapshot already exists; inspect its result"
            );
            let desired: BTreeMap<String, String> =
                serde_json::from_value(operation["parameters"].clone())?;
            ensure!(
                !desired.is_empty() && desired.len() <= KEYS.len(),
                "invalid parameter count"
            );
            for (key, value) in &desired {
                validate(key, value)?;
            }
            let seconds = operation["restore_after_secs"].as_u64().unwrap_or(180);
            ensure!(
                (60..=900).contains(&seconds),
                "recovery delay must be 60–900 seconds"
            );
            let mut before = BTreeMap::new();
            for key in desired.keys() {
                before.insert(key.clone(), read(privileged, key).await?);
            }
            if let Some(algorithm) = desired.get("net.ipv4.tcp_congestion_control") {
                let available =
                    read(privileged, "net.ipv4.tcp_available_congestion_control").await?;
                ensure!(
                    available.split_whitespace().any(|item| item == algorithm),
                    "requested congestion control is unavailable"
                );
            }
            privileged.create_dir(&directory, 0o700, None).await?;
            let now = sinan_protocol::now_timestamp();
            let snapshot = Snapshot {
                id: id.into(),
                before,
                desired,
                created_at: now,
                restore_at: now + seconds as i64,
                confirmed: false,
                persisted: false,
                persistent_after: None,
            };
            let script_path = directory.join("restore.sh");
            let script = recovery_script(state_dir, "sysctl", id, &snapshot_path)?;
            ensure!(
                !script_path
                    .to_string_lossy()
                    .contains(['\n', '\r', '\\', '"', '$', '`']),
                "unsafe state directory"
            );
            privileged
                .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                .await?;
            privileged
                .write_file(&script_path, script.as_bytes(), 0o700, None)
                .await?;
            record_recovery(privileged, state_dir, "sysctl", id, "armed").await?;
            // A local service manager owns the recovery timer, independent of panel connectivity.
            // Refuse the change if arming that timer fails.
            let armed = command(
                privileged,
                "/usr/bin/systemd-run",
                &[
                    format!("--unit=sinan-network-recovery-{id}"),
                    format!("--on-active={seconds}s"),
                    "--property=Type=oneshot".into(),
                    "--property=MemoryMax=64M".into(),
                    "--property=TasksMax=16".into(),
                    "--property=RuntimeMaxSec=90s".into(),
                    "--collect".into(),
                    "/bin/sh".into(),
                    script_path.to_string_lossy().into_owned(),
                ],
            )
            .await;
            if let Err(error) = armed {
                record_recovery(privileged, state_dir, "sysctl", id, "refused").await?;
                return Err(error.context("could not arm local recovery; runtime was not modified"));
            }
            for (key, value) in &snapshot.desired {
                if let Err(error) = write(privileged, key, value).await {
                    return Err(
                        error.context("temporary apply failed; local recovery remains armed")
                    );
                }
            }
            let observed = matching(privileged, &snapshot.desired).await?;
            Ok(
                json!({"snapshot_id":id,"status":"temporary_applied","before":snapshot.before,"desired":snapshot.desired,"observed":observed,"restore_at":snapshot.restore_at,"local_recovery":"armed"}),
            )
        }
        "confirm" | "persist" | "restore" => {
            let bytes = tokio::fs::read(&snapshot_path).await?;
            ensure!(bytes.len() <= 32768, "snapshot exceeds limit");
            let mut snapshot: Snapshot = serde_json::from_slice(&bytes)?;
            ensure!(snapshot.id == id, "snapshot identity mismatch");
            require_current_recovery(state_dir, "sysctl", id).await?;
            if action == "restore" {
                for (key, before) in &snapshot.before {
                    let actual = read(privileged, key).await?;
                    ensure!(
                        &actual == before || snapshot.desired.get(key) == Some(&actual),
                        "runtime parameter changed outside this snapshot; refuse automatic recovery"
                    );
                }
                command(
                    privileged,
                    "/usr/bin/systemctl",
                    &[
                        "stop".into(),
                        format!("sinan-network-recovery-{id}.timer"),
                        format!("sinan-network-recovery-{id}.service"),
                    ],
                )
                .await?;
                if snapshot.persisted {
                    let path = Path::new("/etc/sysctl.d/95-sinan-network.conf");
                    ensure!(
                        tokio::fs::read_to_string(path).await?
                            == snapshot
                                .persistent_after
                                .clone()
                                .unwrap_or_else(|| persistent_content(&snapshot.desired)),
                        "persistent configuration changed; refuse to overwrite external changes"
                    );
                    let previous_path = directory.join("persistent-before.conf");
                    if previous_path.try_exists()? {
                        privileged
                            .write_file(path, &tokio::fs::read(&previous_path).await?, 0o644, None)
                            .await?;
                    } else {
                        privileged.remove_file(path).await?;
                    }
                    snapshot.persisted = false;
                    snapshot.persistent_after = None;
                    privileged
                        .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                        .await?;
                }
                for (key, value) in &snapshot.before {
                    validate(key, value)?;
                    write(privileged, key, value).await?;
                }
                let observed = matching(privileged, &snapshot.before).await?;
                record_recovery(privileged, state_dir, "sysctl", id, "restored").await?;
                return Ok(json!({"snapshot_id":id,"status":"restored","observed":observed}));
            }
            ensure!(
                sinan_protocol::now_timestamp() < snapshot.restore_at
                    && !directory.join("restored").try_exists()?,
                "recovery window expired; take a new snapshot"
            );
            let observed = matching(privileged, &snapshot.desired).await?;
            if action == "persist" {
                ensure!(
                    snapshot.confirmed,
                    "confirm temporary results before persistence"
                );
                ensure!(
                    !snapshot.persisted,
                    "snapshot is already persisted; inspect its saved result"
                );
                let path = Path::new("/etc/sysctl.d/95-sinan-network.conf");
                let mut parameters = BTreeMap::new();
                if path.try_exists()? {
                    let previous = tokio::fs::read(path).await?;
                    ensure!(
                        previous.len() <= 32768 && previous.starts_with(b"# Managed by Sinan\n"),
                        "existing sysctl file is not owned by Sinan"
                    );
                    parameters = parse_persistent(std::str::from_utf8(&previous)?)?;
                    privileged
                        .write_file(
                            &directory.join("persistent-before.conf"),
                            &previous,
                            0o600,
                            None,
                        )
                        .await?;
                }
                for (key, value) in &snapshot.desired {
                    validate(key, value)?;
                }
                parameters.extend(snapshot.desired.clone());
                let content = persistent_content(&parameters);
                privileged
                    .write_file(path, content.as_bytes(), 0o644, None)
                    .await?;
                snapshot.persisted = true;
                snapshot.persistent_after = Some(content);
                privileged
                    .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                    .await?;
                return Ok(
                    json!({"snapshot_id":id,"status":"persisted","observed":observed,"path":"/etc/sysctl.d/95-sinan-network.conf"}),
                );
            }
            command(
                privileged,
                "/usr/bin/systemctl",
                &[
                    "stop".into(),
                    format!("sinan-network-recovery-{id}.timer"),
                    format!("sinan-network-recovery-{id}.service"),
                ],
            )
            .await?;
            // Recheck after the stop to detect a timer that already started its restore service.
            matching(privileged, &snapshot.desired).await?;
            snapshot.confirmed = true;
            snapshot.restore_at = sinan_protocol::now_timestamp() + 900;
            privileged
                .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                .await?;
            record_recovery(privileged, state_dir, "sysctl", id, "confirmed").await?;
            Ok(
                json!({"snapshot_id":id,"status":"confirmed","observed":observed,"local_recovery":"disarmed"}),
            )
        }
        _ => bail!("unsupported network action"),
    }
}

async fn recovery_lock(
    privileged: &dyn Privileged,
    state_dir: &Path,
) -> anyhow::Result<Box<dyn sinan_adapter_sdk::ManagedStateLock>> {
    ensure!(
        Path::new("/usr/bin/python3").is_file() && Path::new("/usr/bin/flock").is_file(),
        "network recovery requires installed Python and flock"
    );
    let directory = state_dir.join("network-recovery");
    privileged.create_dir(&directory, 0o700, None).await?;
    let path = directory.join("lock");
    let snapshot = privileged.snapshot_managed_file(&path, 4096).await?;
    if snapshot["exists"] == false {
        privileged
            .update_managed_file(
                &path,
                Some(b""),
                &snapshot,
                &json!({"mode":0o600,"uid":0,"gid":0}),
            )
            .await?;
    }
    privileged.lock_managed_state(&path).await
}
fn recovery_marker(state_dir: &Path, kind: &str) -> PathBuf {
    state_dir
        .join("network-recovery")
        .join(format!("current-{kind}.json"))
}
async fn require_available_recovery(state_dir: &Path, kind: &str) -> anyhow::Result<()> {
    let path = recovery_marker(state_dir, kind);
    if path.try_exists()? {
        let record: Value = serde_json::from_slice(&tokio::fs::read(path).await?)?;
        ensure!(
            matches!(
                record["state"].as_str(),
                Some("confirmed" | "restored" | "refused")
            ),
            "prior network recovery is still armed; resolve its snapshot before another temporary change"
        );
    }
    Ok(())
}
async fn require_current_recovery(state_dir: &Path, kind: &str, id: &str) -> anyhow::Result<()> {
    let record: Value =
        serde_json::from_slice(&tokio::fs::read(recovery_marker(state_dir, kind)).await?)?;
    ensure!(
        record["id"] == id && record["kind"] == kind,
        "snapshot was superseded; refuse stale network operation"
    );
    Ok(())
}
async fn record_recovery(
    privileged: &dyn Privileged,
    state_dir: &Path,
    kind: &str,
    id: &str,
    state: &str,
) -> anyhow::Result<()> {
    privileged
        .write_file(
            &recovery_marker(state_dir, kind),
            &serde_json::to_vec(&json!({"id":id,"kind":kind,"state":state}))?,
            0o600,
            None,
        )
        .await
}
fn recovery_script(
    state_dir: &Path,
    kind: &str,
    id: &str,
    snapshot: &Path,
) -> anyhow::Result<String> {
    for path in [state_dir, snapshot] {
        ensure!(
            path.is_absolute()
                && !path
                    .to_string_lossy()
                    .contains(['\n', '\r', '\'', '"', '\\', '$', '`']),
            "unsafe network recovery directory"
        );
    }
    ensure!(
        valid_id(id) && matches!(kind, "sysctl" | "firewall"),
        "invalid network recovery scope"
    );
    Ok(format!(
        "#!/bin/sh\nset -eu\nexec /usr/bin/flock --exclusive --wait 10 '{}' /usr/bin/python3 -I -c '{}' '{}' '{}' '{}' '{}'\n",
        state_dir.join("network-recovery/lock").display(),
        include_str!("system_network/recovery.py").replace('\'', "'\\''"),
        state_dir.display(),
        kind,
        id,
        snapshot.display()
    ))
}

async fn inventory(privileged: &dyn Privileged) -> anyhow::Result<Value> {
    let mut values = BTreeMap::new();
    let mut errors = BTreeMap::new();
    for key in KEYS
        .iter()
        .copied()
        .chain(["net.ipv4.tcp_available_congestion_control"])
    {
        match read(privileged, key).await {
            Ok(value) => {
                values.insert(key, value);
            }
            Err(_) => {
                errors.insert(key, "unavailable");
            }
        }
    }
    Ok(
        json!({"sampled_at":sinan_protocol::now_timestamp(),"parameters":values,"errors":errors,"firewall":"separate_authorized_capability","temporary_recovery":"systemd_timer_required","tools":{"sysctl":Path::new("/sbin/sysctl").is_file(),"systemd_run":Path::new("/usr/bin/systemd-run").is_file(),"nft":Path::new("/usr/sbin/nft").is_file(),"wireguard":Path::new("/usr/bin/wg").is_file(),"ssh":Path::new("/usr/bin/ssh").is_file()}}),
    )
}

async fn read(privileged: &dyn Privileged, key: &str) -> anyhow::Result<String> {
    let output = command(privileged, "/sbin/sysctl", &["-n".into(), key.into()]).await?;
    let value = output.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!(value.len() <= 256, "parameter response exceeds limit");
    Ok(value)
}

async fn write(privileged: &dyn Privileged, key: &str, value: &str) -> anyhow::Result<()> {
    validate(key, value)?;
    command(
        privileged,
        "/sbin/sysctl",
        &["-w".into(), format!("{key}={value}")],
    )
    .await?;
    Ok(())
}

async fn matching(
    privileged: &dyn Privileged,
    values: &BTreeMap<String, String>,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut observed = BTreeMap::new();
    for (key, value) in values {
        let actual = read(privileged, key).await?;
        ensure!(
            &actual == value,
            "parameter changed or recovered; inspect current state"
        );
        observed.insert(key.clone(), actual);
    }
    Ok(observed)
}

async fn command(
    privileged: &dyn Privileged,
    program: &str,
    args: &[String],
) -> anyhow::Result<String> {
    let output = privileged
        .execute_bounded(Path::new(program), args, 10, 4096)
        .await?;
    ensure!(
        output.output.success && !output.timed_out && !output.truncated,
        "system network command failed"
    );
    Ok(output.output.stdout)
}

fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn persistent_content(parameters: &BTreeMap<String, String>) -> String {
    let mut content = String::from("# Managed by Sinan\n");
    for (key, value) in parameters {
        content.push_str(&format!("{key} = {value}\n"));
    }
    content
}

fn parse_persistent(content: &str) -> anyhow::Result<BTreeMap<String, String>> {
    ensure!(
        content.starts_with("# Managed by Sinan\n"),
        "persistent file is outside managed scope"
    );
    let mut parameters = BTreeMap::new();
    for line in content
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let (key, value) = line
            .split_once('=')
            .context("managed persistent parameter is invalid")?;
        let key = key.trim();
        let value = value.trim();
        validate(key, value)?;
        ensure!(
            parameters
                .insert(key.to_owned(), value.to_owned())
                .is_none(),
            "persistent parameter is duplicated"
        );
    }
    Ok(parameters)
}

fn validate(key: &str, value: &str) -> anyhow::Result<()> {
    ensure!(
        KEYS.contains(&key) && !value.is_empty() && value.len() <= 256,
        "parameter is outside managed scope"
    );
    match key {
        "net.ipv4.tcp_congestion_control" | "net.core.default_qdisc" => {
            ensure!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "invalid algorithm"
            );
        }
        _ => {
            let numbers = value
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()?;
            let count = match key {
                "net.ipv4.tcp_rmem" | "net.ipv4.tcp_wmem" => 3,
                "net.ipv4.ip_local_port_range" => 2,
                _ => 1,
            };
            ensure!(
                numbers.len() == count
                    && numbers
                        .iter()
                        .all(|number| (1..=1_073_741_824).contains(number)),
                "invalid numeric parameter"
            );
            ensure!(
                numbers.windows(2).all(|pair| pair[0] <= pair[1]),
                "parameter values must be increasing"
            );
            if key == "net.ipv4.ip_local_port_range" {
                ensure!(
                    numbers[0] >= 1024 && numbers[1] <= 65535,
                    "invalid ephemeral port range"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_script_uses_shared_inode_lock_and_source_bound_helper() {
        let id = "00000000-0000-0000-0000-000000000001";
        let script = recovery_script(
            Path::new("/var/lib/sinan/core"),
            "sysctl",
            id,
            Path::new("/var/lib/sinan/core/network-snapshots/example/snapshot.json"),
        )
        .unwrap();
        assert!(script.contains("/usr/bin/flock --exclusive --wait 10"));
        assert!(script.contains("network-recovery/lock"));
        assert!(script.contains("/usr/bin/python3 -I -c"));
        assert!(script.contains("refused"));
        assert!(
            recovery_script(
                Path::new("/var/lib/sinan/\"unsafe"),
                "sysctl",
                id,
                Path::new("/var/lib/sinan/snapshot.json")
            )
            .is_err()
        );
        assert!(
            recovery_script(
                Path::new("/var/lib/sinan"),
                "foreign",
                id,
                Path::new("/var/lib/sinan/snapshot.json")
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn current_snapshot_binding_rejects_stale_confirm_or_restore() {
        let directory =
            std::env::temp_dir().join(format!("sinan-network-slot-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(directory.join("network-recovery"))
            .await
            .unwrap();
        tokio::fs::write(
            recovery_marker(&directory, "sysctl"),
            br#"{"id":"new","kind":"sysctl","state":"armed"}"#,
        )
        .await
        .unwrap();
        assert!(
            require_available_recovery(&directory, "sysctl")
                .await
                .is_err()
        );
        assert!(
            require_current_recovery(&directory, "sysctl", "old")
                .await
                .is_err()
        );
        assert!(
            require_current_recovery(&directory, "sysctl", "new")
                .await
                .is_ok()
        );
        tokio::fs::write(
            recovery_marker(&directory, "sysctl"),
            br#"{"id":"new","kind":"sysctl","state":"confirmed"}"#,
        )
        .await
        .unwrap();
        assert!(
            require_available_recovery(&directory, "sysctl")
                .await
                .is_ok()
        );
        tokio::fs::remove_dir_all(&directory).await.unwrap();
    }
}
