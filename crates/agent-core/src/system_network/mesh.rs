use anyhow::{Context, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
            owned_interface(was_active, previous.is_some())?;
            if was_active {
                verify_ownership(privileged, &directory, &config_path, &name).await?;
            }
            let public_key = command(privileged, "/usr/bin/python3", &["-I".into(), "-c".into(), "import os,stat,subprocess,sys; f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); m=os.fstat(f); assert stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1 and m.st_mode&0o077==0 and m.st_size<=64; key=os.read(f,65); os.close(f); r=subprocess.run(['/usr/bin/wg','pubkey'],input=key,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3); assert r.returncode==0 and len(r.stdout)<=64; sys.stdout.buffer.write(r.stdout)".into(), key_path.to_string_lossy().into_owned()]).await?.trim().to_owned();
            key(&public_key)?;
            if previous.is_some() {
                let prior_public = privileged
                    .read_managed_file(&directory.join("applied-public"), 64)
                    .await?;
                same_recovery_key(&prior_public, &public_key)?;
            }
            privileged
                .create_dir(Path::new("/etc/wireguard"), 0o700, None)
                .await?;
            let original = privileged
                .snapshot_managed_file(&config_path, 65536)
                .await?;
            ensure!(
                original["exists"].as_bool() == Some(previous.is_some())
                    && previous
                        .as_ref()
                        .is_none_or(|bytes| original["file"]["sha256"] == digest(bytes)),
                "mesh configuration changed during preparation"
            );
            if let Some(bytes) = &previous {
                privileged
                    .write_file(
                        &directory.join("previous-public"),
                        public_key.as_bytes(),
                        0o600,
                        None,
                    )
                    .await?;
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
                    let down = command(
                        privileged,
                        "/usr/bin/wg-quick",
                        &["down".into(), name.clone()],
                    )
                    .await;
                    if let Err(error) = down {
                        if !interface_present(privileged, &name).await? {
                            verify_config(privileged, &directory, &config_path).await?;
                            command(
                                privileged,
                                "/usr/bin/wg-quick",
                                &["up".into(), name.clone()],
                            )
                            .await
                            .context("prior mesh stop failed and recovery is unconfirmed")?;
                            let expected = privileged
                                .read_managed_file(&directory.join("applied-public"), 64)
                                .await?;
                            verify_public(privileged, &name, std::str::from_utf8(&expected)?)
                                .await?;
                        }
                        return Err(error.context(
                            "prior mesh stop failed; inspect retained interface identity",
                        ));
                    }
                    ensure!(
                        !interface_present(privileged, &name).await?,
                        "prior mesh cleanup is unconfirmed; retain recovery identity"
                    );
                }
            }
            let apply = async {
                privileged
                    .update_managed_file(
                        &config_path,
                        Some(content.as_bytes()),
                        &original,
                        &json!({"mode":0o600,"uid":0,"gid":0}),
                    )
                    .await?;
                privileged
                    .write_file(
                        &directory.join("applied-sha256"),
                        digest(content.as_bytes()).as_bytes(),
                        0o600,
                        None,
                    )
                    .await?;
                privileged
                    .write_file(
                        &directory.join("applied-public"),
                        public_key.as_bytes(),
                        0o600,
                        None,
                    )
                    .await?;
                command(
                    privileged,
                    "/usr/bin/wg-quick",
                    &["up".into(), name.clone()],
                )
                .await?;
                verify_public(privileged, &name, &public_key).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(error) = apply {
                if interface_present(privileged, &name).await? {
                    verify_public(privileged, &name, &public_key).await.context("mesh apply failed; current interface is not confirmed owned; recovery identity retained")?;
                    command(
                        privileged,
                        "/usr/bin/wg-quick",
                        &["down".into(), name.clone()],
                    )
                    .await
                    .context(
                        "mesh apply failed; cleanup unconfirmed; recovery identity retained",
                    )?;
                    ensure!(
                        !interface_present(privileged, &name).await?,
                        "mesh apply failed; interface cleanup is unconfirmed"
                    );
                }
                let actual = privileged
                    .snapshot_managed_file(&config_path, 65536)
                    .await?;
                ensure!(
                    actual["parents"] == original["parents"]
                        && (actual["file"]["sha256"] == digest(content.as_bytes())
                            || actual["file"] == original["file"]),
                    "mesh apply outcome or external configuration changed; recovery remains unconfirmed"
                );
                if let Some(bytes) = previous {
                    if actual["file"] != original["file"] {
                        privileged
                            .update_managed_file(
                                &config_path,
                                Some(&bytes),
                                &actual,
                                &original["file"],
                            )
                            .await?;
                    }
                    privileged
                        .write_file(
                            &directory.join("applied-sha256"),
                            digest(&bytes).as_bytes(),
                            0o600,
                            None,
                        )
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
                    privileged
                        .update_managed_file(
                            &config_path,
                            None,
                            &actual,
                            &json!({"mode":0o600,"uid":0,"gid":0}),
                        )
                        .await?;
                }
                return Err(error.context("mesh apply failed; prior configuration restored"));
            }
            status(privileged, id, &name).await
        }
        Some("mesh_stop") => {
            verify_ownership(privileged, &directory, &config_path, &name).await?;
            command(
                privileged,
                "/usr/bin/wg-quick",
                &["down".into(), name.clone()],
            )
            .await?;
            ensure!(
                !interface_present(privileged, &name).await?,
                "mesh stop cleanup is unconfirmed; retain identity"
            );
            Ok(
                json!({"mesh_id":id,"interface":name,"status":"stopped","configuration_retained":true}),
            )
        }
        Some("mesh_restore") => {
            verify_config(privileged, &directory, &config_path).await?;
            let original = privileged
                .snapshot_managed_file(&config_path, 65536)
                .await?;
            let current_bytes = privileged.read_managed_file(&config_path, 65536).await?;
            let public_key = String::from_utf8(
                privileged
                    .read_managed_file(&directory.join("applied-public"), 64)
                    .await?,
            )?;
            same_recovery_key(
                &privileged
                    .read_managed_file(&directory.join("previous-public"), 64)
                    .await?,
                &public_key,
            )?;
            let previous = tokio::fs::read(directory.join("previous.conf")).await?;
            ensure!(
                previous.starts_with(format!("# Managed by Sinan {id}\n").as_bytes())
                    && previous.len() <= 65536,
                "mesh recovery file invalid"
            );
            let was_active =
                tokio::fs::read_to_string(directory.join("previous-active")).await? == "true";
            let interfaces = command(
                privileged,
                "/usr/bin/wg",
                &["show".into(), "interfaces".into()],
            )
            .await?;
            let originally_active = interfaces
                .split_whitespace()
                .any(|interface| interface == name);
            if originally_active {
                verify_ownership(privileged, &directory, &config_path, &name).await?;
                let down = command(
                    privileged,
                    "/usr/bin/wg-quick",
                    &["down".into(), name.clone()],
                )
                .await;
                if let Err(error) = down {
                    if !interface_present(privileged, &name).await? {
                        verify_config(privileged, &directory, &config_path).await?;
                        command(
                            privileged,
                            "/usr/bin/wg-quick",
                            &["up".into(), name.clone()],
                        )
                        .await
                        .context(
                            "mesh restore stop failed and original runtime recovery is unconfirmed",
                        )?;
                        verify_public(privileged, &name, &public_key).await?;
                    }
                    return Err(
                        error.context("mesh restore stop failed; original identity retained")
                    );
                }
                ensure!(
                    !interface_present(privileged, &name).await?,
                    "mesh restore cleanup is unconfirmed"
                );
            }
            verify_config(privileged, &directory, &config_path).await?;
            let restore = async {
                privileged
                    .update_managed_file(
                        &config_path,
                        Some(&previous),
                        &original,
                        &json!({"mode":0o600,"uid":0,"gid":0}),
                    )
                    .await?;
                privileged
                    .write_file(
                        &directory.join("applied-sha256"),
                        digest(&previous).as_bytes(),
                        0o600,
                        None,
                    )
                    .await?;
                if was_active {
                    command(
                        privileged,
                        "/usr/bin/wg-quick",
                        &["up".into(), name.clone()],
                    )
                    .await?;
                    verify_public(privileged, &name, &public_key).await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(error) = restore {
                if interface_present(privileged, &name).await? {
                    verify_public(privileged, &name, &public_key).await?;
                    command(
                        privileged,
                        "/usr/bin/wg-quick",
                        &["down".into(), name.clone()],
                    )
                    .await?;
                    ensure!(
                        !interface_present(privileged, &name).await?,
                        "mesh restore failed; cleanup unconfirmed"
                    );
                }
                let actual = privileged
                    .snapshot_managed_file(&config_path, 65536)
                    .await?;
                ensure!(
                    actual["parents"] == original["parents"]
                        && (actual["file"]["sha256"] == digest(&previous)
                            || actual["file"] == original["file"]),
                    "mesh restore outcome or external configuration is unknown; recovery remains unconfirmed"
                );
                if actual["file"] != original["file"] {
                    privileged
                        .update_managed_file(
                            &config_path,
                            Some(&current_bytes),
                            &actual,
                            &original["file"],
                        )
                        .await?;
                }
                privileged
                    .write_file(
                        &directory.join("applied-sha256"),
                        digest(&current_bytes).as_bytes(),
                        0o600,
                        None,
                    )
                    .await?;
                if originally_active {
                    command(
                        privileged,
                        "/usr/bin/wg-quick",
                        &["up".into(), name.clone()],
                    )
                    .await
                    .context(
                        "mesh restore failed and original active mesh recovery is unconfirmed",
                    )?;
                    verify_public(privileged, &name, &public_key).await?;
                }
                return Err(error.context("mesh restore failed; original configuration recovered"));
            }
            if was_active {
                status(privileged, id, &name).await
            } else {
                Ok(json!({"mesh_id":id,"status":"restored","interface_active":false}))
            }
        }
        Some("mesh_persist") => {
            verify_ownership(privileged, &directory, &config_path, &name).await?;
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

fn owned_interface(active: bool, owned_configuration: bool) -> anyhow::Result<()> {
    ensure!(
        !active || owned_configuration,
        "existing same-name interface has no owned configuration; refuse mesh apply"
    );
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
async fn interface_present(privileged: &dyn Privileged, name: &str) -> anyhow::Result<bool> {
    Ok(command(
        privileged,
        "/usr/bin/wg",
        &["show".into(), "interfaces".into()],
    )
    .await?
    .split_whitespace()
    .any(|interface| interface == name))
}
async fn verify_config(
    privileged: &dyn Privileged,
    directory: &Path,
    path: &Path,
) -> anyhow::Result<()> {
    let expected = privileged
        .read_managed_file(&directory.join("applied-sha256"), 64)
        .await?;
    ensure!(
        expected.as_slice() == digest(&privileged.read_managed_file(path, 65536).await?).as_bytes(),
        "mesh configuration changed externally; refuse overwrite"
    );
    Ok(())
}
async fn verify_ownership(
    privileged: &dyn Privileged,
    directory: &Path,
    path: &Path,
    name: &str,
) -> anyhow::Result<()> {
    verify_config(privileged, directory, path).await?;
    if interface_present(privileged, name).await? {
        let expected = privileged
            .read_managed_file(&directory.join("applied-public"), 64)
            .await?;
        verify_public(privileged, name, std::str::from_utf8(&expected)?).await?;
    }
    Ok(())
}
async fn verify_public(
    privileged: &dyn Privileged,
    name: &str,
    expected: &str,
) -> anyhow::Result<()> {
    let actual = command(
        privileged,
        "/usr/bin/wg",
        &["show".into(), name.into(), "public-key".into()],
    )
    .await?;
    ensure!(
        actual.trim() == expected,
        "same-name interface identity changed; refuse to stop foreign mesh"
    );
    Ok(())
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
fn same_recovery_key(previous: &[u8], current: &str) -> anyhow::Result<()> {
    ensure!(
        previous == current.as_bytes(),
        "mesh recovery key identity changed; refuse rotation or restoration under another key"
    );
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
    fn live_interface_without_owned_configuration_is_rejected() {
        assert!(owned_interface(true, false).is_err());
        assert!(owned_interface(false, false).is_ok());
        assert!(owned_interface(true, true).is_ok());
    }
    #[test]
    fn key_drift_cannot_relabel_previous_mesh_configuration() {
        assert!(same_recovery_key(b"TEST_ONLY original", "TEST_ONLY original").is_ok());
        assert!(same_recovery_key(b"TEST_ONLY original", "TEST_ONLY regenerated").is_err());
        assert!(same_recovery_key(b"", "TEST_ONLY original").is_err());
    }
    #[test]
    fn routes_cannot_expand_outside_private_networks() {
        assert!(private_cidr("10.1.0.1/8").is_ok());
        assert!(private_cidr("192.168.0.1/8").is_err());
        assert!(private_cidr("172.16.0.1/8").is_err());
        assert!(private_cidr("0.0.0.0/0").is_err());
        assert!(private_cidr("fd17::1/64").is_ok());
    }
}
