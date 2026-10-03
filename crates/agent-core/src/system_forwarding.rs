use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sinan_adapter_sdk::Privileged;
use std::{net::IpAddr, path::Path};

/// This executor requires separate local `port_forward` authorization.
pub async fn execute(privileged: &dyn Privileged, operation: &Value) -> anyhow::Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "managed forwarding requires Linux and systemd"
    );
    let id = operation["rule_id"]
        .as_str()
        .context("forwarding rule identifier missing")?;
    ensure!(
        id.len() == 36
            && id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "invalid forwarding rule identifier"
    );
    let unit = format!("sinan-forward-{id}.service");
    match operation["action"].as_str() {
        Some("start") => {
            let listen: IpAddr = operation["listen_address"]
                .as_str()
                .context("listen address missing")?
                .parse()?;
            let target: IpAddr = operation["target_address"]
                .as_str()
                .context("target address missing")?
                .parse()?;
            ensure!(
                !listen.is_multicast() && !target.is_multicast() && !target.is_unspecified(),
                "unsupported forwarding address"
            );
            let listen_port = port(&operation["listen_port"])?;
            let target_port = port(&operation["target_port"])?;
            let protocol = operation["protocol"]
                .as_str()
                .context("forwarding protocol missing")?;
            ensure!(
                matches!(protocol, "tcp" | "udp"),
                "forwarding protocol must be TCP or UDP"
            );
            ensure!(
                Path::new("/usr/bin/ss").is_file(),
                "socket inventory tool is not installed; cannot preflight port conflicts"
            );
            let sockets = command(
                privileged,
                "/usr/bin/ss",
                &[
                    "-H".into(),
                    "-n".into(),
                    "-l".into(),
                    if protocol == "tcp" {
                        "-t".into()
                    } else {
                        "-u".into()
                    },
                    "sport".into(),
                    "=".into(),
                    format!(":{listen_port}"),
                ],
            )
            .await?;
            ensure!(
                !listener_conflict(&sockets, listen, listen_port)?,
                "listening endpoint conflicts with an actual socket"
            );
            let source_family = if listen.is_ipv4() { "4" } else { "6" };
            let target_family = if target.is_ipv4() { "4" } else { "6" };
            let bind = if listen.is_ipv4() {
                listen.to_string()
            } else {
                format!("[{listen}]")
            };
            let destination_address = if target.is_ipv4() {
                target.to_string()
            } else {
                format!("[{target}]")
            };
            let family_option = if listen.is_ipv6() { ",ipv6only=1" } else { "" };
            let (source, destination) = match operation["protocol"].as_str() {
                Some("tcp") => (
                    format!(
                        "TCP{source_family}-LISTEN:{listen_port},bind={bind},reuseaddr,fork{family_option}"
                    ),
                    format!("TCP{target_family}:{destination_address}:{target_port}"),
                ),
                Some("udp") => (
                    format!(
                        "UDP{source_family}-RECVFROM:{listen_port},bind={bind},fork{family_option}"
                    ),
                    format!("UDP{target_family}-SENDTO:{destination_address}:{target_port}"),
                ),
                _ => anyhow::bail!("forwarding protocol must be TCP or UDP"),
            };
            ensure!(
                Path::new("/usr/bin/socat").is_file(),
                "socat is not installed; tool installation is separate"
            );
            command(
                privileged,
                "/usr/bin/systemd-run",
                &[
                    format!("--unit={unit}"),
                    "--collect".into(),
                    "--property=Type=exec".into(),
                    "--property=NoNewPrivileges=yes".into(),
                    "--property=ProtectSystem=strict".into(),
                    "--property=ProtectHome=yes".into(),
                    "--property=PrivateTmp=yes".into(),
                    "--property=TasksMax=128".into(),
                    "--property=MemoryMax=67108864".into(),
                    "/usr/bin/socat".into(),
                    source,
                    destination,
                ],
            )
            .await?;
            // This observation proves only that the forwarding process is active.
            // End-to-end reachability must be measured from the selected observer.
            let result = status(privileged, &unit, id).await?;
            ensure!(
                result["active_state"] == "active",
                "forwarding service exited during startup; inspect service logs"
            );
            Ok(result)
        }
        Some("stop") => {
            command(
                privileged,
                "/usr/bin/systemctl",
                &["stop".into(), unit.clone()],
            )
            .await?;
            status(privileged, &unit, id).await
        }
        Some("status") => status(privileged, &unit, id).await,
        _ => anyhow::bail!("unknown forwarding action"),
    }
}

async fn status(privileged: &dyn Privileged, unit: &str, id: &str) -> anyhow::Result<Value> {
    let text = command(
        privileged,
        "/usr/bin/systemctl",
        &[
            "show".into(),
            unit.into(),
            "--property=ActiveState,SubState,Result,MainPID,LoadState".into(),
        ],
    )
    .await?;
    let fields: std::collections::BTreeMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    Ok(
        json!({"rule_id":id,"sampled_at":sinan_protocol::now_timestamp(),"active_state":fields.get("ActiveState"),"sub_state":fields.get("SubState"),"result":fields.get("Result"),"process_id":fields.get("MainPID"),"load_state":fields.get("LoadState"),"reachability":"not_measured","persistent":false}),
    )
}

fn port(value: &Value) -> anyhow::Result<u16> {
    value
        .as_u64()
        .filter(|port| (1..=65535).contains(port))
        .map(|port| port as u16)
        .context("invalid forwarding port")
}

fn listener_conflict(sockets: &str, listen: IpAddr, port: u16) -> anyhow::Result<bool> {
    for line in sockets.lines() {
        let endpoint = line
            .split_whitespace()
            .nth(3)
            .context("socket inventory format is unsupported")?;
        let (address, bound_port) = endpoint
            .rsplit_once(':')
            .context("socket inventory endpoint is invalid")?;
        ensure!(
            bound_port.parse::<u16>()? == port,
            "socket inventory filter did not constrain the requested port"
        );
        let address = address.trim_matches(['[', ']']);
        if address == "*" {
            return Ok(true);
        }
        let bound: IpAddr = address.parse()?;
        // A wildcard IPv6 listener may also accept IPv4 sockets; refuse that overlap.
        if bound.is_unspecified() || listen.is_unspecified() || bound == listen {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn command(
    privileged: &dyn Privileged,
    program: &str,
    args: &[String],
) -> anyhow::Result<String> {
    let output = privileged
        .execute_bounded(Path::new(program), args, 10, 8192)
        .await?;
    ensure!(
        output.output.success && !output.timed_out && !output.truncated,
        "forwarding service operation failed"
    );
    Ok(output.output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_and_dual_stack_listeners_conflict() {
        let listen: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(listener_conflict("LISTEN 0 128 [::]:8080 [::]:*", listen, 8080).unwrap());
        assert!(!listener_conflict("LISTEN 0 128 192.0.2.1:8080 0.0.0.0:*", listen, 8080).unwrap());
        assert!(listener_conflict("LISTEN 0 128 127.0.0.1:8081 0.0.0.0:*", listen, 8080).is_err());
    }
}
