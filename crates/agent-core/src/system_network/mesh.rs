use anyhow::{Context, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_adapter_sdk::Privileged;
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    public_key: String,
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    persistent_keepalive: u16,
}

pub(super) async fn execute(
    privileged: &dyn Privileged,
    state_dir: &Path,
    operation: &Value,
) -> anyhow::Result<Value> {
    ensure!(
        cfg!(target_os = "linux")
            && Path::new("/usr/bin/wg").is_file()
            && Path::new("/usr/bin/wg-quick").is_file(),
        "WireGuard tools are not available"
    );
    let id = operation["mesh_id"]
        .as_str()
        .context("mesh identifier missing")?;
    ensure!(
        id.len() == 36
            && id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "invalid mesh identifier"
    );
    let name = format!(
        "snw{}",
        id.chars()
            .filter(|character| *character != '-')
            .take(12)
            .collect::<String>()
    );
    let directory = state_dir.join("network-mesh").join(id);
    let config_path = Path::new("/etc/wireguard").join(format!("{name}.conf"));
    match operation["action"].as_str() {
        Some("mesh_apply") => {
            privileged.create_dir(&directory, 0o700, None).await?;
            let key_path = directory.join("private.key");
            let private = if key_path.try_exists()? {
                tokio::fs::read_to_string(&key_path).await?
            } else {
                let value = command(privileged, "/usr/bin/wg", &["genkey".into()])
                    .await?
                    .trim()
                    .to_owned();
                key(&value)?;
                privileged
                    .write_file(&key_path, value.as_bytes(), 0o600, None)
                    .await?;
                value
            };
            key(&private)?;
            let address = operation["address"]
                .as_str()
                .context("mesh address missing")?;
            private_cidr(address)?;
            let port = operation["listen_port"]
                .as_u64()
                .filter(|port| (1..=65535).contains(port))
                .context("mesh port invalid")?;
            let peers: Vec<Peer> = serde_json::from_value(operation["peers"].clone())?;
            ensure!(peers.len() <= 64, "too many mesh peers");
            let mut content = format!(
                "# Managed by Sinan {id}\n[Interface]\nPrivateKey = {private}\nAddress = {address}\nListenPort = {port}\n"
            );
            let mut seen = std::collections::BTreeSet::new();
            for peer in peers {
                key(&peer.public_key)?;
                ensure!(
                    seen.insert(peer.public_key.clone())
                        && !peer.allowed_ips.is_empty()
                        && peer.allowed_ips.len() <= 16
                        && peer.persistent_keepalive <= 120,
                    "invalid or duplicate peer"
                );
                for value in &peer.allowed_ips {
                    private_cidr(value)?;
                }
                content.push_str(&format!(
                    "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\n",
                    peer.public_key,
                    peer.allowed_ips.join(", "),
                    peer.persistent_keepalive
                ));
                if let Some(endpoint) = peer.endpoint {
                    let endpoint: SocketAddr = endpoint.parse()?;
                    ensure!(
                        !endpoint.ip().is_unspecified()
                            && !endpoint.ip().is_multicast()
                            && endpoint.port() > 0,
                        "invalid peer endpoint"
                    );
                    content.push_str(&format!("Endpoint = {endpoint}\n"));
                }
            }
            let previous = if config_path.try_exists()? {
                let bytes = tokio::fs::read(&config_path).await?;
                ensure!(
                    bytes.len() <= 65536
                        && bytes.starts_with(format!("# Managed by Sinan {id}\n").as_bytes()),
                    "mesh configuration is not owned"
                );
                Some(bytes)
            } else {
                None
            };
            let interfaces = command(
                privileged,
                "/usr/bin/wg",
                &["show".into(), "interfaces".into()],
            )
            .await?;
            let was_active = interfaces
                .split_whitespace()
                .any(|interface| interface == name);
            if let Some(bytes) = &previous {
                privileged
                    .write_file(&directory.join("previous.conf"), bytes, 0o600, None)
                    .await?;
                privileged
                    .write_file(
                        &directory.join("previous-active"),
                        if was_active { b"true" } else { b"false" },
                        0o600,
                        None,
                    )
                    .await?;
                if was_active {
                    command(
                        privileged,
                        "/usr/bin/wg-quick",
                        &["down".into(), name.clone()],
                    )
                    .await?;
                }
            }
            privileged
                .create_dir(Path::new("/etc/wireguard"), 0o700, None)
                .await?;
            privileged
                .write_file(&config_path, content.as_bytes(), 0o600, None)
                .await?;
            if let Err(error) = command(
                privileged,
                "/usr/bin/wg-quick",
                &["up".into(), name.clone()],
            )
            .await
            {
                let _ = command(
                    privileged,
                    "/usr/bin/wg-quick",
                    &["down".into(), name.clone()],
                )
                .await;
                if let Some(bytes) = previous {
                    privileged
                        .write_file(&config_path, &bytes, 0o600, None)
                        .await?;
                    if was_active {
                        command(
                            privileged,
                            "/usr/bin/wg-quick",
                            &["up".into(), name.clone()],
                        )
                        .await
                        .context("mesh apply failed and prior mesh could not recover")?;
                    }
                } else {
                    privileged.remove_file(&config_path).await?;
                }
                return Err(error.context("mesh apply failed; prior configuration restored"));
            }
            status(privileged, id, &name).await
        }
        Some("mesh_stop") => {
            command(
                privileged,
                "/usr/bin/wg-quick",
                &["down".into(), name.clone()],
            )
            .await?;
            Ok(
                json!({"mesh_id":id,"interface":name,"status":"stopped","configuration_retained":true}),
            )
        }
        Some("mesh_restore") => {
            let previous = tokio::fs::read(directory.join("previous.conf")).await?;
            ensure!(
                previous.starts_with(format!("# Managed by Sinan {id}\n").as_bytes())
                    && previous.len() <= 65536,
                "mesh recovery file invalid"
            );
            let interfaces = command(
                privileged,
                "/usr/bin/wg",
                &["show".into(), "interfaces".into()],
            )
            .await?;
            if interfaces
                .split_whitespace()
                .any(|interface| interface == name)
            {
                command(
                    privileged,
                    "/usr/bin/wg-quick",
                    &["down".into(), name.clone()],
                )
                .await?;
            }
            privileged
                .write_file(&config_path, &previous, 0o600, None)
                .await?;
            let was_active =
                tokio::fs::read_to_string(directory.join("previous-active")).await? == "true";
            if was_active {
                command(
                    privileged,
                    "/usr/bin/wg-quick",
                    &["up".into(), name.clone()],
                )
                .await?;
                status(privileged, id, &name).await
            } else {
                Ok(json!({"mesh_id":id,"status":"restored","interface_active":false}))
            }
        }
        Some("mesh_persist") => {
            ensure!(config_path.try_exists()?, "apply mesh before persistence");
            command(
                privileged,
                "/usr/bin/systemctl",
                &["enable".into(), format!("wg-quick@{name}.service")],
            )
            .await?;
            Ok(json!({"mesh_id":id,"interface":name,"boot_enabled":true}))
        }
        Some("mesh_status") => status(privileged, id, &name).await,
        _ => anyhow::bail!("unknown mesh action"),
    }
}

async fn status(privileged: &dyn Privileged, id: &str, name: &str) -> anyhow::Result<Value> {
    // Avoid `wg show all dump`: it includes the interface's private key.
    let public = command(
        privileged,
        "/usr/bin/wg",
        &["show".into(), name.into(), "public-key".into()],
    )
    .await?;
    let handshakes = command(
        privileged,
        "/usr/bin/wg",
        &["show".into(), name.into(), "latest-handshakes".into()],
    )
    .await?;
    let transfer = command(
        privileged,
        "/usr/bin/wg",
        &["show".into(), name.into(), "transfer".into()],
    )
    .await?;
    Ok(
        json!({"mesh_id":id,"interface":name,"public_key":public.trim(),"handshakes":handshakes,"transfer":transfer,"sampled_at":sinan_protocol::now_timestamp(),"reachability":"requires_peer_probe","private_key":"local_protected_file"}),
    )
}
fn key(value: &str) -> anyhow::Result<()> {
    ensure!(STANDARD.decode(value)?.len() == 32, "invalid WireGuard key");
    Ok(())
}
fn private_cidr(value: &str) -> anyhow::Result<()> {
    let (ip, prefix) = value.split_once('/').context("CIDR is required")?;
    let ip: IpAddr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    let valid = match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            let minimum = if a == 10 {
                8
            } else if a == 172 && (16..=31).contains(&b) {
                12
            } else if a == 192 && b == 168 {
                16
            } else {
                33
            };
            (minimum..=32).contains(&prefix)
        }
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00 && (7..=128).contains(&prefix),
    };
    ensure!(
        valid,
        "mesh routes must stay within private networks; default routes are prohibited"
    );
    Ok(())
}
async fn command(
    privileged: &dyn Privileged,
    program: &str,
    args: &[String],
) -> anyhow::Result<String> {
    let output = privileged
        .execute_bounded(Path::new(program), args, 20, 16384)
        .await?;
    ensure!(
        output.output.success && !output.timed_out && !output.truncated,
        "mesh operation failed"
    );
    Ok(output.output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_cannot_expand_outside_private_networks() {
        assert!(private_cidr("10.1.0.1/8").is_ok());
        assert!(private_cidr("192.168.0.1/8").is_err());
        assert!(private_cidr("172.16.0.1/8").is_err());
        assert!(private_cidr("0.0.0.0/0").is_err());
        assert!(private_cidr("fd17::1/64").is_ok());
    }
}
