use super::*;
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires root, Linux cgroup v2, systemd, flock and private tmpfs mounts on a dedicated test node"]
async fn real_systemd_diagnostic_cancellation_confirms_process_and_private_mount_cleanup()
-> Result<()> {
    let privileged: Arc<dyn Privileged> = Arc::new(SystemOps);
    let services = SystemServiceManager::new(privileged.clone(), ServiceBackend::Systemd);
    let unit = format!("sinan-diagnostic-{}.service", Uuid::new_v4());
    let directory = std::env::temp_dir().join(format!("sinan-cancel-test-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let result = async {
        ensure!(services.diagnostic_cleanup_confirmed(&unit, &directory).await?, "unstarted unit cannot be confirmed clean");
        let script = directory.join("runner.sh");
        std::fs::write(&script, "set -eu\nmkdir mounted\nmount -t tmpfs -o size=1m tmpfs mounted\nsleep 30 &\nprintf '%s\\n' $! > child-pid\n: > ready\nwait\n")?;
        let job = ServiceJob {
            unit: unit.clone(), program: "/bin/sh".into(), args: vec![script.to_str().context("fixture path is not UTF-8")?.into()],
            working_directory: directory.clone(), timeout_secs: 45,
            memory_max: Default::default(), tasks_max: Default::default(), cpu_max_percent: Default::default(), cpu_weight: Default::default(),
            io_weight: Default::default(), oom_score_adjust: Default::default(),
        };
        services.start_job(&job).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !directory.join("ready").is_file() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.context("mount fixture did not become ready")?;
        let pid: u32 = std::fs::read_to_string(directory.join("child-pid"))?.trim().parse()?;
        ensure!(Path::new(&format!("/proc/{pid}")).exists(), "fixture child was never active");
        ensure!(!services.diagnostic_cleanup_confirmed(&unit, &directory).await?, "live fixture was prematurely confirmed clean");
        services.stop(&unit).await?;
        ensure!(services.diagnostic_cleanup_confirmed(&unit, &directory).await?, "stopped fixture still has processes or mounts");
        ensure!(!Path::new(&format!("/proc/{pid}")).exists(), "cancelled fixture child remains alive");
        Ok::<_, anyhow::Error>(())
    }.await;
    let stopped = services.stop(&unit).await;
    let _ = privileged
        .execute(
            Path::new("systemctl"),
            &["reset-failed".into(), "--".into(), unit],
        )
        .await;
    if stopped.is_ok() {
        std::fs::remove_dir_all(directory)?;
    }
    result
}
