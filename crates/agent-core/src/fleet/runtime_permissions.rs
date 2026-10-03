use crate::Config;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sinan_adapter_sdk::{Descriptor, Privileged, ServiceManager};
use std::path::Path;

pub(super) async fn inspect(
    config: &Config,
    descriptor: &Descriptor,
    ops: &dyn Privileged,
    services: &dyn ServiceManager,
) -> Result<Value> {
    let module = &descriptor.plugin_name;
    ensure!(
        cfg!(target_os = "linux")
            && !module.is_empty()
            && module.len() <= 64
            && module
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid runtime inspection module or unsupported platform"
    );
    let path = config.runtime_root.join(format!("{module}@main"));
    let manager = match services.preflight_access(&descriptor.service_unit).await {
        Ok(value) => value,
        Err(_) => {
            json!({"kind":"unsupported","available":false,"management_authorized":null,"runtime_account":{"known":false},"authorization_basis":"service_backend_inspection_failed"})
        }
    };
    let account = serde_json::to_string(&manager["runtime_account"])?;
    let result = ops
        .execute_bounded(
            Path::new("/usr/bin/python3"),
            &[
                "-I".into(),
                "-c".into(),
                include_str!("runtime_permissions.py").into(),
                path.to_string_lossy().into_owned(),
                account,
            ],
            5,
            16 * 1024,
        )
        .await?;
    ensure!(
        result.output.success && !result.timed_out && !result.truncated,
        "runtime directory inspection failed"
    );
    let mut value: Value = serde_json::from_str(&result.output.stdout)?;
    value["module"] = json!(module);
    value["sampled_at"] = json!(sinan_protocol::now_timestamp());
    value["service_manager"] = manager;
    value["secret_values_recorded"] = json!(false);
    Ok(value)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::system::SystemOps;
    use sinan_adapter_sdk::{BoxFuture, CommandOutput, Execution};
    use std::sync::{Arc, Mutex};

    struct MetadataOps {
        observed: Mutex<Option<String>>,
        load: &'static str,
        account: &'static str,
    }
    impl Privileged for MetadataOps {
        fn execute<'a>(
            &'a self,
            _program: &'a Path,
            _args: &'a [String],
        ) -> BoxFuture<'a, CommandOutput> {
            Box::pin(async { anyhow::bail!("only bounded read-only inspection is allowed") })
        }
        fn execute_bounded<'a>(
            &'a self,
            program: &'a Path,
            args: &'a [String],
            seconds: u32,
            maximum: usize,
        ) -> BoxFuture<'a, Execution> {
            Box::pin(async move {
                if program == Path::new("/usr/bin/python3") {
                    return SystemOps
                        .execute_bounded(program, args, seconds, maximum)
                        .await;
                }
                let stdout = if program == Path::new("id") {
                    ensure!(
                        args.len() == 1 && args[0] == "-u",
                        "unexpected identity fixture query"
                    );
                    "0\n".into()
                } else if program == Path::new("systemctl")
                    && args.len() == 2
                    && args[0] == "show"
                    && args[1] == "--property=Version,Features"
                {
                    "Version=257\nFeatures=TEST_ONLY\n".into()
                } else {
                    ensure!(
                        program == Path::new("systemctl")
                            && args.len() == 4
                            && args[0] == "show"
                            && args[2] == "--",
                        "unexpected service fixture query"
                    );
                    ensure!(
                        args[3] == "sinan-example-runtime@main.service",
                        "runtime inspection queried a guessed unit instead of its descriptor"
                    );
                    *self.observed.lock().expect("observed native unit") = Some(args[3].clone());
                    let fields: Vec<_> = args[1]
                        .strip_prefix("--property=")
                        .expect("bounded properties")
                        .split(',')
                        .collect();
                    ensure!(
                        fields.len() == 5,
                        "complete installed-account properties are required"
                    );
                    fields
                        .into_iter()
                        .zip([
                            self.load,
                            if self.load == "loaded" { "42" } else { "0" },
                            self.account,
                            "",
                            "",
                        ])
                        .map(|(field, value)| format!("{field}={value}\n"))
                        .collect()
                };
                Ok(Execution {
                    output: CommandOutput {
                        success: true,
                        stdout,
                        stderr: String::new(),
                    },
                    timed_out: false,
                    truncated: false,
                })
            })
        }
        fn create_dir<'a>(
            &'a self,
            _path: &'a Path,
            _mode: u32,
            _group: Option<&'a str>,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("read-only fixture") })
        }
        fn write_file<'a>(
            &'a self,
            _path: &'a Path,
            _bytes: &'a [u8],
            _mode: u32,
            _group: Option<&'a str>,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("read-only fixture") })
        }
        fn atomic_symlink<'a>(&'a self, _link: &'a Path, _target: &'a Path) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("read-only fixture") })
        }
        fn remove_symlink<'a>(&'a self, _link: &'a Path) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("read-only fixture") })
        }
        fn install_archive<'a>(
            &'a self,
            _archive: &'a Path,
            _directory: &'a Path,
            _binary_name: &'a str,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("read-only fixture") })
        }
    }

    async fn probe_account(path: &Path, account: Value) -> Result<Value> {
        let result = SystemOps
            .execute_bounded(
                Path::new("/usr/bin/python3"),
                &[
                    "-I".into(),
                    "-c".into(),
                    include_str!("runtime_permissions.py").into(),
                    path.to_string_lossy().into_owned(),
                    serde_json::to_string(&account)?,
                ],
                5,
                16 * 1024,
            )
            .await?;
        ensure!(
            result.output.success && !result.timed_out && !result.truncated,
            "native permission probe fixture failed"
        );
        Ok(serde_json::from_str(&result.output.stdout)?)
    }

    #[tokio::test]
    async fn registered_unit_is_used_and_missing_accounts_never_inherit_root_permissions()
    -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "sinan-registered-permissions-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root)?;
        let outcome=async {
            let config=Config{runtime_root:root.clone(),..Default::default()};
            let descriptor=Descriptor{module:"example-wire".into(),plugin_name:"example-runtime".into(),binary_name:"example".into(),auxiliary_files:Vec::new(),service_unit:"sinan-example-runtime@main.service".into(),service_group:"example-runtime".into()};
            let ops=Arc::new(MetadataOps{observed:Mutex::new(None),load:"not-found",account:""});
            let backend=crate::system::SystemServiceManager::new(ops.clone(),crate::system::ServiceBackend::Systemd);
            let receipt=inspect(&config,&descriptor,ops.as_ref(),&backend).await?;
            assert_eq!(ops.observed.lock().expect("observed unit").as_deref(),Some(descriptor.service_unit.as_str()));
            assert_eq!(receipt["service_manager"]["load_state"],"not-found");
            assert_eq!(receipt["service_manager"]["runtime_account"]["known"],false);
            assert_eq!(receipt["runtime_directory"]["path"],json!(root.join("example-runtime@main")));
            assert_eq!(receipt["runtime_account"]["known"],false);
            assert!(receipt["runtime_directory"]["runtime_readable"].is_null());
            assert!(!receipt["runtime_directory"]["runtime_error"].is_null());
            assert!(!root.join("example-runtime@main").exists());
            let missing=probe_account(&root,json!({"known":true,"name":format!("sinan-account-{}",uuid::Uuid::new_v4()),"group":"","supplementary_groups":[]})).await?;
            assert_eq!(missing["runtime_account"]["known"],false);
            assert!(missing["certificate_directory"]["runtime_writable"].is_null());
            Ok::<_,anyhow::Error>(())
        }.await;
        std::fs::remove_dir_all(root)?;
        outcome
    }

    #[tokio::test]
    #[ignore = "requires Linux root, Python 3 and a non-root NSS account 65534 for actual identity transition"]
    async fn actual_runtime_identity_cannot_read_root_only_certificate_directory() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let identity = SystemOps
            .execute_bounded(Path::new("id"), &["-u".into()], 3, 1024)
            .await?;
        ensure!(
            identity.output.success && identity.output.stdout.trim() == "0",
            "requires root for actual runtime identity transition"
        );
        let root =
            std::env::temp_dir().join(format!("sinan-runtime-account-{}", uuid::Uuid::new_v4()));
        let runtime = root.join("example-runtime@main");
        std::fs::create_dir_all(runtime.join("data/certificates"))?;
        for path in [&root, &runtime, &runtime.join("data")] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::set_permissions(
            runtime.join("data/certificates"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        let outcome = async {
            let metadata =
                json!({"known":true,"name":"65534","group":"","supplementary_groups":[]});
            let observed = probe_account(&runtime, metadata.clone()).await?;
            assert_eq!(observed["privileged_effective_uid"], 0);
            assert_eq!(observed["runtime_account"]["known"], true);
            assert_eq!(observed["runtime_account"]["uid"], 65534);
            assert_eq!(observed["certificate_directory"]["writable"], true);
            assert_eq!(observed["certificate_directory"]["runtime_readable"], false);
            assert_eq!(observed["certificate_directory"]["runtime_writable"], false);
            assert_eq!(
                observed["certificate_directory"]["runtime_executable"],
                false
            );
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))?;
            let blocked = probe_account(&runtime, metadata).await?;
            assert_eq!(blocked["runtime_directory"]["runtime_executable"], false);
            assert!(!blocked["data_directory"]["runtime_error"].is_null());
            assert!(!blocked["certificate_directory"]["runtime_error"].is_null());
            Ok::<_, anyhow::Error>(())
        }
        .await;
        std::fs::remove_dir_all(root)?;
        outcome
    }

    #[tokio::test]
    async fn directory_probe_does_not_create_targets_and_rejects_symlink_ancestors() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "sinan-runtime-permissions-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root)?;
        let probe = async |path: &Path| -> Result<Value> {
            let output = SystemOps
                .execute_bounded(
                    Path::new("/usr/bin/python3"),
                    &[
                        "-I".into(),
                        "-c".into(),
                        include_str!("runtime_permissions.py").into(),
                        path.to_string_lossy().into_owned(),
                    ],
                    5,
                    16 * 1024,
                )
                .await?;
            ensure!(output.output.success, "directory fixture failed");
            Ok(serde_json::from_str(&output.output.stdout)?)
        };
        let outcome = async {
            let target = root.join("uncreated/child");
            let observation = probe(&target).await?;
            assert_eq!(observation["runtime_directory"]["exists"], false);
            assert_eq!(observation["runtime_directory"]["symlink_free"], true);
            assert_eq!(
                observation["runtime_directory"]["nearest_existing_parent"],
                json!(root)
            );
            assert_eq!(observation["data_directory"]["exists"], false);
            assert_eq!(observation["certificate_directory"]["symlink_free"], true);
            assert!(!target.exists());
            std::os::unix::fs::symlink(&root, root.join("alias"))?;
            let observation = probe(&root.join("alias/child")).await?;
            assert_eq!(observation["runtime_directory"]["symlink_free"], false);
            assert!(!root.join("child").exists());
            let runtime = root.join("managed");
            std::fs::create_dir_all(runtime.join("data"))?;
            std::os::unix::fs::symlink(&root, runtime.join("data/certificates"))?;
            let observation = probe(&runtime).await?;
            assert_eq!(observation["runtime_directory"]["symlink_free"], true);
            assert_eq!(observation["data_directory"]["symlink_free"], true);
            assert_eq!(observation["certificate_directory"]["symlink_free"], false);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        std::fs::remove_dir_all(root)?;
        outcome
    }
}
