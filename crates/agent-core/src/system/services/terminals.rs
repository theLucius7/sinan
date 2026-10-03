use super::{ServiceBackend, SystemServiceManager};
use anyhow::{Result, ensure};
use sinan_adapter_sdk::ServiceManager;
use std::path::Path;

pub(super) async fn retire(manager: &SystemServiceManager) -> Result<()> {
    if manager.backend != ServiceBackend::Systemd {
        return Ok(());
    }
    let args = vec![
        "list-units".into(),
        "--all".into(),
        "--no-legend".into(),
        "--plain".into(),
        "sinan-fleet-terminal-*.service".into(),
    ];
    let units = manager
        .privileged
        .execute_bounded(Path::new("systemctl"), &args, 10, 32768)
        .await?;
    ensure!(
        units.output.success && !units.timed_out && !units.truncated,
        "terminal retirement inventory is unavailable"
    );
    for unit in units
        .output
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
    {
        let id = unit
            .strip_prefix("sinan-fleet-terminal-")
            .and_then(|value| value.strip_suffix(".service"));
        ensure!(
            id.is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()),
            "unexpected terminal service identity"
        );
        manager.stop(unit).await?;
        let observed = manager
            .call("show", unit, Some("ActiveState,ControlGroup"))
            .await?;
        ensure!(
            observed.success
                && observed.stdout.lines().any(|line| line == "ControlGroup=")
                && observed
                    .stdout
                    .lines()
                    .any(|line| line == "ActiveState=inactive" || line == "ActiveState=failed"),
            "terminal retirement cleanup is not confirmed"
        );
    }
    Ok(())
}
