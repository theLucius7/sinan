use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_adapter_sdk::Privileged;
use std::{net::IpAddr, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    source: String,
    protocol: String,
    port: u16,
    action: String,
}
#[derive(Serialize, Deserialize)]
struct Snapshot {
    table: String,
    previous: Option<String>,
    observed_hash: String,
    restore_at: i64,
    confirmed: bool,
    persisted: bool,
    #[serde(default)]
    persistent_hash: Option<String>,
    #[serde(default)]
    unit_hash: Option<String>,
}

pub(super) async fn execute(
    privileged: &dyn Privileged,
    state_dir: &Path,
    operation: &Value,
) -> anyhow::Result<Value> {
    ensure!(
        cfg!(target_os = "linux") && Path::new("/usr/sbin/nft").is_file(),
        "nftables tools unavailable"
    );
    let id = operation["firewall_id"]
        .as_str()
        .context("firewall identifier missing")?;
    let snapshot_id = operation["snapshot_id"]
        .as_str()
        .context("firewall snapshot identifier missing")?;
    for id in [id, snapshot_id] {
        ensure!(
            id.len() == 36
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
            "invalid firewall identifier"
        );
    }
    let table = format!(
        "sinan_{}",
        id.chars()
            .filter(|character| *character != '-')
            .take(12)
            .collect::<String>()
    );
    let directory = state_dir.join("network-firewall").join(snapshot_id);
    let snapshot_path = directory.join("snapshot.json");
    let timer = format!("sinan-firewall-recovery-{snapshot_id}");
    match operation["action"].as_str() {
        Some("firewall_temporary") => {
            super::require_available_recovery(state_dir, "firewall").await?;
            ensure!(
                !snapshot_path.try_exists()?,
                "snapshot exists; inspect prior result before retry"
            );
            let seconds = operation["restore_after_secs"].as_u64().unwrap_or(180);
            ensure!(
                (60..=900).contains(&seconds),
                "firewall recovery delay invalid"
            );
            let rules: Vec<Rule> = serde_json::from_value(operation["rules"].clone())?;
            ensure!(rules.len() <= 128, "too many firewall rules");
            let management: Vec<u16> =
                serde_json::from_value(operation["management_ports"].clone())?;
            ensure!(
                !management.is_empty()
                    && management.len() <= 16
                    && management.iter().all(|port| *port > 0),
                "declare management ports before applying firewall"
            );
            let previous = table_text(privileged, &table).await?;
            ensure!(
                previous
                    .as_ref()
                    .is_none_or(|value| value.contains("comment \"Managed by Sinan\"")),
                "existing firewall table is not owned by Sinan"
            );
            privileged.create_dir(&directory, 0o700, None).await?;
            let content = render(&table, &rules, &management)?;
            let apply = directory.join("apply.nft");
            let batch = format!(
                "{}{content}",
                if previous.is_some() {
                    format!("delete table inet {table}\n")
                } else {
                    String::new()
                }
            );
            privileged
                .write_file(&apply, batch.as_bytes(), 0o600, None)
                .await?;
            command(
                privileged,
                "/usr/sbin/nft",
                &[
                    "-c".into(),
                    "-f".into(),
                    apply.to_string_lossy().into_owned(),
                ],
            )
            .await?;
            let restore_rules = directory.join("restore.nft");
            let restore = directory.join("restore.sh");
            if let Some(value) = &previous {
                privileged
                    .write_file(&restore_rules, value.as_bytes(), 0o600, None)
                    .await?;
            }
            let path = restore_rules.to_string_lossy();
            ensure!(
                !path.contains(['\n', '\r', '\"', '\\', '$', '`']),
                "unsafe firewall recovery path"
            );
            let script =
                super::recovery_script(state_dir, "firewall", snapshot_id, &snapshot_path)?;
            privileged
                .write_file(&restore, script.as_bytes(), 0o700, None)
                .await?;
            let mut snapshot = Snapshot {
                table: table.clone(),
                previous,
                observed_hash: String::new(),
                restore_at: sinan_protocol::now_timestamp() + seconds as i64,
                confirmed: false,
                persisted: false,
                persistent_hash: None,
                unit_hash: None,
            };
            privileged
                .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                .await?;
            super::record_recovery(privileged, state_dir, "firewall", snapshot_id, "armed").await?;
            let armed = command(
                privileged,
                "/usr/bin/systemd-run",
                &[
                    format!("--unit={timer}"),
                    format!("--on-active={seconds}s"),
                    "--property=Type=oneshot".into(),
                    "--property=MemoryMax=64M".into(),
                    "--property=TasksMax=16".into(),
                    "--property=RuntimeMaxSec=90s".into(),
                    "--collect".into(),
                    "/bin/sh".into(),
                    restore.to_string_lossy().into_owned(),
                ],
            )
            .await;
            if let Err(error) = armed {
                super::record_recovery(privileged, state_dir, "firewall", snapshot_id, "refused")
                    .await?;
                return Err(
                    error.context("could not arm firewall recovery; table was not modified")
                );
            }
            command(
                privileged,
                "/usr/sbin/nft",
                &["-f".into(), apply.to_string_lossy().into_owned()],
            )
            .await
            .context("firewall apply failed; local recovery remains armed")?;
            let actual = table_text(privileged, &table)
                .await?
                .context("managed firewall table missing after apply")?;
            snapshot.observed_hash = hash(&actual);
            privileged
                .write_file(
                    &directory.join("desired.nft"),
                    content.as_bytes(),
                    0o600,
                    None,
                )
                .await?;
            privileged
                .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                .await?;
            Ok(
                json!({"firewall_id":id,"snapshot_id":snapshot_id,"status":"temporary_applied","table":table,"observed":actual,"restore_at":snapshot.restore_at,"local_recovery":"armed","management_ports":management,"scope":"managed_input_table_only"}),
            )
        }
        Some("firewall_confirm")
        | Some("firewall_persist")
        | Some("firewall_restore")
        | Some("firewall_status") => {
            let mut snapshot: Snapshot =
                serde_json::from_slice(&tokio::fs::read(&snapshot_path).await?)?;
            ensure!(
                snapshot.table == table,
                "snapshot does not belong to firewall"
            );
            let actual = table_text(privileged, &table).await?;
            if operation["action"] == "firewall_status" {
                return Ok(
                    json!({"table":table,"observed":actual,"snapshot_id":snapshot_id,"matches_applied":actual.as_ref().is_some_and(|value|hash(value)==snapshot.observed_hash),"sampled_at":sinan_protocol::now_timestamp()}),
                );
            }
            super::require_current_recovery(state_dir, "firewall", snapshot_id).await?;
            ensure!(
                actual
                    .as_ref()
                    .is_some_and(|value| hash(value) == snapshot.observed_hash),
                "managed firewall changed or recovered; refuse to overwrite"
            );
            if operation["action"] == "firewall_restore" {
                if snapshot.persisted {
                    let rule_path = Path::new("/etc/nftables.d").join(format!("sinan-{id}.nft"));
                    let unit_path = Path::new("/etc/systemd/system")
                        .join(format!("sinan-firewall-{id}.service"));
                    ensure!(
                        snapshot.persistent_hash.as_ref()
                            == Some(&hash(&tokio::fs::read_to_string(&rule_path).await?))
                            && snapshot.unit_hash.as_ref()
                                == Some(&hash(&tokio::fs::read_to_string(&unit_path).await?)),
                        "persistent firewall files changed externally; refuse removal"
                    );
                }
                command(
                    privileged,
                    "/usr/bin/systemctl",
                    &[
                        "stop".into(),
                        format!("{timer}.timer"),
                        format!("{timer}.service"),
                    ],
                )
                .await?;
                ensure!(
                    table_text(privileged, &table)
                        .await?
                        .as_ref()
                        .is_some_and(|value| hash(value) == snapshot.observed_hash),
                    "firewall recovery already started; inspect actual table"
                );
                let restore_path = directory.join("restore-batch.nft");
                privileged
                    .write_file(
                        &restore_path,
                        format!(
                            "delete table inet {table}\n{}",
                            snapshot.previous.as_deref().unwrap_or("")
                        )
                        .as_bytes(),
                        0o600,
                        None,
                    )
                    .await?;
                command(
                    privileged,
                    "/usr/sbin/nft",
                    &["-f".into(), restore_path.to_string_lossy().into_owned()],
                )
                .await?;
                if snapshot.persisted {
                    let unit = format!("sinan-firewall-{id}.service");
                    command(
                        privileged,
                        "/usr/bin/systemctl",
                        &["disable".into(), unit.clone()],
                    )
                    .await?;
                    privileged
                        .remove_file(&Path::new("/etc/systemd/system").join(unit))
                        .await?;
                    privileged
                        .remove_file(&Path::new("/etc/nftables.d").join(format!("sinan-{id}.nft")))
                        .await?;
                    command(privileged, "/usr/bin/systemctl", &["daemon-reload".into()]).await?;
                }
                super::record_recovery(privileged, state_dir, "firewall", snapshot_id, "restored")
                    .await?;
                Ok(
                    json!({"status":"restored","table":table,"observed":table_text(privileged,&table).await?}),
                )
            } else if operation["action"] == "firewall_confirm" {
                ensure!(
                    sinan_protocol::now_timestamp() < snapshot.restore_at,
                    "firewall recovery window expired"
                );
                command(
                    privileged,
                    "/usr/bin/systemctl",
                    &[
                        "stop".into(),
                        format!("{timer}.timer"),
                        format!("{timer}.service"),
                    ],
                )
                .await?;
                ensure!(
                    table_text(privileged, &table)
                        .await?
                        .as_ref()
                        .is_some_and(|value| hash(value) == snapshot.observed_hash),
                    "firewall recovery already started"
                );
                snapshot.confirmed = true;
                privileged
                    .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                    .await?;
                super::record_recovery(privileged, state_dir, "firewall", snapshot_id, "confirmed")
                    .await?;
                Ok(json!({"status":"confirmed","local_recovery":"disarmed","table":table}))
            } else {
                ensure!(
                    snapshot.confirmed,
                    "confirm temporary firewall before persistence"
                );
                let path = Path::new("/etc/nftables.d").join(format!("sinan-{id}.nft"));
                ensure!(
                    !path.try_exists()?,
                    "persistent rule file exists; restore before replacing"
                );
                privileged
                    .create_dir(Path::new("/etc/nftables.d"), 0o755, None)
                    .await?;
                let content = tokio::fs::read(directory.join("desired.nft")).await?;
                privileged.write_file(&path, &content, 0o600, None).await?;
                let unit = format!("sinan-firewall-{id}.service");
                let service = format!(
                    "[Unit]\nDescription=Sinan managed firewall\nAfter=nftables.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f {}\nExecStop=/usr/sbin/nft delete table inet {table}\n[Install]\nWantedBy=multi-user.target\n",
                    path.display()
                );
                privileged
                    .write_file(
                        &Path::new("/etc/systemd/system").join(&unit),
                        service.as_bytes(),
                        0o644,
                        None,
                    )
                    .await?;
                command(privileged, "/usr/bin/systemctl", &["daemon-reload".into()]).await?;
                command(privileged, "/usr/bin/systemctl", &["enable".into(), unit]).await?;
                snapshot.persisted = true;
                snapshot.persistent_hash = Some(hash(std::str::from_utf8(&content)?));
                snapshot.unit_hash = Some(hash(&service));
                privileged
                    .write_file(&snapshot_path, &serde_json::to_vec(&snapshot)?, 0o600, None)
                    .await?;
                Ok(json!({"status":"persisted","table":table,"scope":"managed_input_table_only"}))
            }
        }
        _ => anyhow::bail!("unknown firewall action"),
    }
}

fn render(table: &str, rules: &[Rule], management: &[u16]) -> anyhow::Result<String> {
    let ports = management
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut content = format!(
        "table inet {table} {{\n comment \"Managed by Sinan\";\n chain input {{\n  type filter hook input priority 0; policy accept;\n  iifname \"lo\" accept\n  ct state established,related accept\n  tcp dport {{ {ports} }} accept\n"
    );
    for rule in rules {
        let (ip, prefix) = rule
            .source
            .split_once('/')
            .context("firewall source must be CIDR")?;
        let ip: IpAddr = ip.parse()?;
        let prefix: u8 = prefix.parse()?;
        ensure!(
            prefix <= if ip.is_ipv4() { 32 } else { 128 },
            "firewall prefix invalid"
        );
        ensure!(
            rule.port > 0
                && matches!(rule.protocol.as_str(), "tcp" | "udp")
                && matches!(rule.action.as_str(), "accept" | "drop"),
            "firewall rule invalid"
        );
        content.push_str(&format!(
            "  {} saddr {}/{} {} dport {} {}\n",
            if ip.is_ipv4() { "ip" } else { "ip6" },
            ip,
            prefix,
            rule.protocol,
            rule.port,
            rule.action
        ));
    }
    content.push_str(" }\n}\n");
    Ok(content)
}
async fn table_text(privileged: &dyn Privileged, table: &str) -> anyhow::Result<Option<String>> {
    let result = privileged
        .execute_bounded(
            Path::new("/usr/sbin/nft"),
            &["list".into(), "table".into(), "inet".into(), table.into()],
            10,
            65536,
        )
        .await?;
    ensure!(
        !result.timed_out && !result.truncated,
        "firewall observation is unavailable"
    );
    if result.output.success {
        Ok(Some(result.output.stdout))
    } else {
        // Distinguish a missing managed table from an unavailable tool or denied inspection.
        let tables = command(
            privileged,
            "/usr/sbin/nft",
            &["list".into(), "tables".into()],
        )
        .await?;
        ensure!(
            !tables
                .lines()
                .any(|line| line == format!("table inet {table}")),
            "managed table could not be inspected"
        );
        Ok(None)
    }
}
fn hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
async fn command(
    privileged: &dyn Privileged,
    program: &str,
    args: &[String],
) -> anyhow::Result<String> {
    let output = privileged
        .execute_bounded(Path::new(program), args, 10, 65536)
        .await?;
    ensure!(
        output.output.success && !output.timed_out && !output.truncated,
        "managed firewall operation failed"
    );
    Ok(output.output.stdout)
}
