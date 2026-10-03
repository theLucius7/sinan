use anyhow::{Context, Result, ensure};
use sinan_adapter_sdk::{BoxFuture, TerminalProcess};
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
};

struct Pty {
    child: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
    unit: String,
}
pub(super) async fn open(
    account: &str,
    columns: u16,
    rows: u16,
) -> Result<Box<dyn TerminalProcess>> {
    ensure!(
        !account.is_empty()
            && account.len() <= 64
            && account
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "invalid execution account"
    );
    ensure!(
        std::path::Path::new("/run/systemd/system").is_dir(),
        "PTY process cleanup requires Linux systemd"
    );
    let unit = format!("sinan-fleet-terminal-{}.service", uuid::Uuid::new_v4());
    let mut child = Command::new("systemd-run")
        .args([
            "--quiet",
            "--pipe",
            "--wait",
            "--collect",
            "--service-type=exec",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=5s",
            "--property=RuntimeMaxSec=1800s",
            "--unit",
            &unit,
            "/usr/bin/python3",
            "-I",
            "-u",
            "-c",
            include_str!("terminal/pty.py"),
            account,
            &columns.to_string(),
            &rows.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("start PTY helper")?;
    let input = child.stdin.take().context("PTY input unavailable")?;
    let mut output = BufReader::new(child.stdout.take().context("PTY output unavailable")?).lines();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), output.next_line())
        .await??
        .context("PTY helper ended before readiness")?;
    let ready: serde_json::Value = serde_json::from_str(&ready)?;
    ensure!(
        ready["ready"].as_bool() == Some(true),
        "PTY helper refused account: {}",
        ready["error"]
    );
    Ok(Box::new(Pty {
        child,
        input,
        output,
        unit,
    }))
}
impl TerminalProcess for Pty {
    fn read(&mut self) -> BoxFuture<'_, Option<String>> {
        Box::pin(async move {
            let line = self.output.next_line().await?;
            line.map(|line| -> Result<String> {
                let value: serde_json::Value = serde_json::from_str(&line)?;
                Ok(value["data"]
                    .as_str()
                    .unwrap_or("")
                    .replace('\0', "\u{fffd}"))
            })
            .transpose()
        })
    }
    fn input<'a>(
        &'a mut self,
        data: &'a str,
        columns: Option<u16>,
        rows: Option<u16>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut bytes = serde_json::to_vec(
                &serde_json::json!({"data":data,"columns":columns,"rows":rows}),
            )?;
            bytes.push(b'\n');
            self.input.write_all(&bytes).await?;
            self.input.flush().await?;
            Ok(())
        })
    }
    fn close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.input.write_all(b"{\"close\":true}\n").await;
            let _ = self.input.flush().await;
            let stop = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                Command::new("systemctl")
                    .args(["stop", "--", &self.unit])
                    .kill_on_drop(true)
                    .output(),
            )
            .await??;
            let status = Command::new("systemctl")
                .args([
                    "show",
                    "--property=ActiveState,ControlGroup,LoadState",
                    "--",
                    &self.unit,
                ])
                .kill_on_drop(true)
                .output()
                .await?;
            let status = String::from_utf8_lossy(&status.stdout);
            ensure!(
                status
                    .lines()
                    .any(|line| line == "ActiveState=inactive" || line == "ActiveState=failed")
                    && status.lines().any(|line| line == "ControlGroup="),
                "PTY stop lacks process-group cleanup confirmation: {}",
                String::from_utf8_lossy(&stop.stderr)
            );
            let _ = self.child.wait().await?;
            Ok(())
        })
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "--", &self.unit])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}
