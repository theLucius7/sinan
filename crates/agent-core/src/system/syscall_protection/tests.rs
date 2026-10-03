use super::*;
use sinan_adapter_sdk::Execution;
use std::sync::{Arc, Mutex};

struct Probe {
    fail_at: usize,
    replacement: Execution,
    calls: Mutex<usize>,
}

impl Privileged for Probe {
    fn execute<'a>(&'a self, _: &'a Path, _: &'a [String]) -> BoxFuture<'a, CommandOutput> {
        panic!("probe must use bounded execution and never start a payload")
    }
    fn execute_bounded<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
        seconds: u32,
        maximum: usize,
    ) -> BoxFuture<'a, Execution> {
        Box::pin(async move {
            if program == Path::new("stat") {
                assert_eq!((seconds, maximum), (5, 1024));
                return Ok(Execution {
                    output: CommandOutput {
                        success: true,
                        stdout: "41c0 0\n".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                });
            }
            assert_eq!((seconds, maximum), (3, 16 * 1024));
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls == self.fail_at {
                return Ok(self.replacement.clone());
            }
            Ok(Execution {
                output: CommandOutput {
                    success: true,
                    stdout: fixture_output(program, args)
                        .expect("unexpected probe")
                        .into(),
                    ..Default::default()
                },
                ..Default::default()
            })
        })
    }
    fn create_dir<'a>(
        &'a self,
        path: &'a Path,
        mode: u32,
        group: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            assert_eq!(path, Path::new("/run/sinan-diagnostic"));
            assert_eq!((mode, group), (0o700, Some("root")));
            Ok(())
        })
    }
    fn write_file<'a>(
        &'a self,
        _: &'a Path,
        _: &'a [u8],
        _: u32,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        panic!("probe cannot write files")
    }
    fn atomic_symlink<'a>(&'a self, _: &'a Path, _: &'a Path) -> BoxFuture<'a, ()> {
        panic!("unexpected symlink")
    }
    fn remove_symlink<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, ()> {
        panic!("unexpected symlink")
    }
    fn install_archive<'a>(&'a self, _: &'a Path, _: &'a Path, _: &'a str) -> BoxFuture<'a, ()> {
        panic!("unexpected archive")
    }
}

#[tokio::test]
async fn support_probe_is_bounded_and_fails_closed_at_every_step() -> Result<()> {
    let job: ServiceJob = serde_json::from_value(serde_json::json!({
        "unit": format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
        "program": "/usr/bin/true", "args": [], "working_directory": "/tmp", "timeout_secs": 5,
    }))?;
    for fail_at in 1..=4 {
        for failure in ["failed", "timeout", "truncated", "unknown"] {
            let replacement = Execution {
                output: CommandOutput {
                    success: failure != "failed",
                    stdout: "unverified".into(),
                    ..Default::default()
                },
                timed_out: failure == "timeout",
                truncated: failure == "truncated",
            };
            let ops = Arc::new(Probe {
                fail_at,
                replacement,
                calls: Mutex::new(0),
            });
            let services = SystemServiceManager::new(ops.clone(), ServiceBackend::Systemd);
            assert!(
                services.start_job(&job).await.is_err(),
                "{fail_at}: {failure}"
            );
            assert_eq!(*ops.calls.lock().unwrap(), fail_at);
        }
    }
    let ops = Probe {
        fail_at: 0,
        replacement: Default::default(),
        calls: Mutex::new(0),
    };
    verify_support(&ops).await?;
    assert_eq!(*ops.calls.lock().unwrap(), 3);
    Ok(())
}

#[test]
fn ambiguous_or_inherited_manager_filters_are_rejected() {
    for text in [
        "not-systemd\nSeccomp: 0\nSeccomp_filters: 0\n",
        "systemd\nSeccomp: 2\nSeccomp_filters: 1\n",
        "systemd\nSeccomp: 0\n",
        "systemd\nSeccomp: 0\nSeccomp: 0\nSeccomp_filters: 0\n",
        "systemd\nSeccomp: 0\nSeccomp_filters: 0\nSeccomp_filters: 0\n",
    ] {
        assert!(verify_manager(text).is_err());
    }
}

#[tokio::test]
async fn pre_command_rejects_missing_single_filter_and_missing_privilege_guard() -> Result<()> {
    let expression = FILTER_CHECK
        .strip_prefix("--property=ExecStartPre=/usr/bin/awk '")
        .and_then(|value| value.strip_suffix("' /proc/self/status"))
        .expect("fixed pre-command must have one quoted awk expression and one input path");
    assert!(!expression.contains(['$', '%', '\'']));
    let file = std::env::temp_dir().join(format!("sinan-seccomp-status-{}", Uuid::new_v4()));
    let result = async {
        for (nnp, mode, count, allowed) in [
            (1, 2, 2, true),
            (1, 2, 4, true),
            (0, 2, 2, false),
            (1, 0, 0, false),
            (1, 2, 1, false),
            (1, 1, 2, false),
        ] {
            fs::write(
                &file,
                format!("NoNewPrivs:\t{nnp}\nSeccomp:\t{mode}\nSeccomp_filters:\t{count}\n"),
            )?;
            let response = SystemOps
                .execute_bounded(
                    Path::new("/usr/bin/awk"),
                    &[expression.into(), file.to_str().unwrap().into()],
                    3,
                    1024,
                )
                .await?;
            assert!(!response.timed_out && !response.truncated);
            assert_eq!(response.output.success, allowed, "{nnp}, {mode}, {count}");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fs::remove_file(file)?;
    result
}

#[tokio::test]
async fn unsupported_backend_cannot_start_or_fall_back() -> Result<()> {
    let ops = Arc::new(Probe {
        fail_at: 0,
        replacement: Default::default(),
        calls: Mutex::new(0),
    });
    let job: ServiceJob = serde_json::from_value(serde_json::json!({
        "unit": format!("sinan-diagnostic-{}.service", Uuid::new_v4()),
        "program": "/usr/bin/true", "args": [], "working_directory": "/tmp", "timeout_secs": 5,
    }))?;
    for backend in [ServiceBackend::OpenRc, ServiceBackend::Unmanaged] {
        let services = SystemServiceManager::new(ops.clone(), backend);
        assert!(
            services
                .start_job(&job)
                .await
                .unwrap_err()
                .to_string()
                .contains("不允许降级运行")
        );
    }
    assert_eq!(*ops.calls.lock().unwrap(), 0);
    Ok(())
}

#[path = "acceptance.rs"]
mod acceptance;
