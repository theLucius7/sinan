use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sinan_adapter_sdk::Privileged;
use std::{net::Ipv4Addr, path::Path};

pub(super) async fn execute(
    privileged: &dyn Privileged,
    state_dir: &Path,
    operation: &Value,
) -> anyhow::Result<Value> {
    ensure!(
        cfg!(target_os = "linux")
            && Path::new("/usr/bin/ssh").is_file()
            && Path::new("/usr/bin/ssh-keygen").is_file(),
        "SSH tunnel tools are unavailable"
    );
    let id = operation["tunnel_id"]
        .as_str()
        .context("tunnel identifier missing")?;
    ensure!(
        id.len() == 36
            && id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "invalid tunnel identifier"
    );
    let directory = state_dir.join("network-tunnels").join(id);
    let key_path = directory.join("key");
    let unit = format!("sinan-tunnel-{id}.service");
    if operation["action"] == "tunnel_key" {
        privileged.create_dir(&directory, 0o700, None).await?;
        if !key_path.try_exists()? {
            command(
                privileged,
                "/usr/bin/ssh-keygen",
                &[
                    "-q".into(),
                    "-t".into(),
                    "ed25519".into(),
                    "-N".into(),
                    String::new(),
                    "-f".into(),
                    key_path.to_string_lossy().into_owned(),
                    "-C".into(),
                    format!("sinan-tunnel:{id}"),
                ],
            )
            .await?;
        }
        let public = tokio::fs::read_to_string(key_path.with_extension("pub")).await?;
        ensure!(public.len() <= 1024, "tunnel public key exceeds limit");
        return Ok(
            json!({"tunnel_id":id,"public_key":public.trim(),"private_key":"local_protected_file","relay_authorization":"required_before_start"}),
        );
    }
    match operation["action"].as_str() {
        Some("tunnel_start") => {
            ensure!(
                key_path.try_exists()?,
                "initialize the local tunnel key before start"
            );
            let relay: Ipv4Addr = operation["relay_address"]
                .as_str()
                .context("relay address missing")?
                .parse()?;
            ensure!(
                !relay.is_unspecified() && !relay.is_multicast(),
                "invalid relay address"
            );
            let target: Ipv4Addr = operation["target_address"]
                .as_str()
                .context("target address missing")?
                .parse()?;
            ensure!(
                !target.is_unspecified() && !target.is_multicast(),
                "invalid target address"
            );
            let listen: Ipv4Addr = operation["listen_address"]
                .as_str()
                .context("listen address missing")?
                .parse()?;
            ensure!(!listen.is_multicast(), "invalid tunnel listener");
            let relay_port = port(&operation["relay_port"])?;
            let listen_port = port(&operation["listen_port"])?;
            let target_port = port(&operation["target_port"])?;
            let account = operation["relay_account"]
                .as_str()
                .context("relay account missing")?;
            ensure!(
                !account.is_empty()
                    && account.len() <= 32
                    && !account.starts_with('-')
                    && account
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
                "invalid relay account"
            );
            let hostkey = operation["relay_host_key"]
                .as_str()
                .context("explicit relay host key missing")?;
            let parts: Vec<_> = hostkey.split_whitespace().collect();
            ensure!(
                parts.len() == 2
                    && parts[0] == "ssh-ed25519"
                    && parts[1].len() <= 256
                    && parts[1]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte)),
                "invalid relay host key"
            );
            let known = directory.join("known_hosts");
            privileged
                .write_file(
                    &known,
                    format!("[{relay}]:{relay_port} {hostkey}\n{relay} {hostkey}\n").as_bytes(),
                    0o600,
                    None,
                )
                .await?;
            command(
                privileged,
                "/usr/bin/systemd-run",
                &[
                    format!("--unit={unit}"),
                    "--collect".into(),
                    "--property=Type=exec".into(),
                    "--property=NoNewPrivileges=yes".into(),
                    "--property=PrivateTmp=yes".into(),
                    "/usr/bin/ssh".into(),
                    "-N".into(),
                    "-T".into(),
                    "-i".into(),
                    key_path.to_string_lossy().into_owned(),
                    "-o".into(),
                    "BatchMode=yes".into(),
                    "-o".into(),
                    "StrictHostKeyChecking=yes".into(),
                    "-o".into(),
                    format!("UserKnownHostsFile={}", known.display()),
                    "-o".into(),
                    "ExitOnForwardFailure=yes".into(),
                    "-o".into(),
                    "ServerAliveInterval=30".into(),
                    "-o".into(),
                    "ServerAliveCountMax=3".into(),
                    "-p".into(),
                    relay_port.to_string(),
                    "-l".into(),
                    account.into(),
                    "-R".into(),
                    format!("{listen}:{listen_port}:{target}:{target_port}"),
                    relay.to_string(),
                ],
            )
            .await?;
            status(privileged, id, &unit).await
        }
        Some("tunnel_stop") => {
            command(
                privileged,
                "/usr/bin/systemctl",
                &["stop".into(), unit.clone()],
            )
            .await?;
            status(privileged, id, &unit).await
        }
        Some("tunnel_status") => status(privileged, id, &unit).await,
        _ => anyhow::bail!("unknown tunnel action"),
    }
}
async fn status(privileged: &dyn Privileged, id: &str, unit: &str) -> anyhow::Result<Value> {
    let value = command(
        privileged,
        "/usr/bin/systemctl",
        &[
            "show".into(),
            unit.into(),
            "--property=ActiveState,SubState,Result".into(),
        ],
    )
    .await?;
    Ok(
        json!({"tunnel_id":id,"service_observation":value,"reachability":"requires_external_source_probe","relay_gateway_ports":"controlled_by_relay_ssh_configuration","persistent":false,"sampled_at":sinan_protocol::now_timestamp()}),
    )
}
fn port(value: &Value) -> anyhow::Result<u16> {
    value
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .map(|port| port as u16)
        .context("invalid tunnel port")
}
async fn command(
    privileged: &dyn Privileged,
    program: &str,
    args: &[String],
) -> anyhow::Result<String> {
    let result = privileged
        .execute_bounded(Path::new(program), args, 20, 8192)
        .await?;
    ensure!(
        result.output.success && !result.timed_out && !result.truncated,
        "tunnel operation failed"
    );
    Ok(result.output.stdout)
}
