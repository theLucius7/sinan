use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

async fn call(path: &Path, input: Value) -> Result<Value> {
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-c", include_str!("managed_files.py")])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .context("file helper input unavailable")?;
    let encoded = serde_json::to_vec(&input)?;
    let write = async {
        stdin.write_all(&encoded).await?;
        stdin.shutdown().await?;
        drop(stdin);
        Ok::<_, std::io::Error>(())
    };
    let output = async {
        let output = child.wait_with_output().await?;
        ensure!(
            output.status.success(),
            "managed file operation rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            output.stdout.len() <= 512 * 1024,
            "file helper output exceeds budget"
        );
        Ok::<_, anyhow::Error>(output)
    };
    let (_, output) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(async { write.await.map_err(anyhow::Error::from) }, output)
    })
    .await??;
    Ok(serde_json::from_slice(&output.stdout)?)
}
pub(super) async fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let result = call(
        path,
        json!({"action":"read","maximum":maximum.min(256*1024)}),
    )
    .await?;
    Ok(STANDARD.decode(result["content"].as_str().context("missing file payload")?)?)
}
pub(super) async fn replace(path: &Path, bytes: &[u8], previous_hash: &str) -> Result<()> {
    call(path,json!({"action":"replace","maximum":256*1024,"content":STANDARD.encode(bytes),"previous_hash":previous_hash})).await?;
    Ok(())
}
pub(super) async fn upload(path: &Path, bytes: &[u8], previous_hash: Option<&str>) -> Result<bool> {
    let result=call(path,json!({"action":"upload","maximum":256*1024,"content":STANDARD.encode(bytes),"previous_hash":previous_hash})).await?;
    result["created"]
        .as_bool()
        .context("file helper omitted upload outcome")
}
pub(super) async fn inspect(path: &Path, maximum: usize) -> Result<Value> {
    call(
        path,
        json!({"action":"inspect","maximum":maximum.min(256*1024)}),
    )
    .await
}
