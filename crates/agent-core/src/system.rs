mod archive;
mod command_process;
mod cpu_ceiling;
mod execution;
mod openrc_jobs;
#[cfg(target_os = "linux")]
mod terminal;
pub use openrc_jobs::run_job;
mod cleanup;
pub mod deploy;
mod jobs;
#[cfg(target_os = "linux")]
mod managed_files;
mod publication;
mod resources;
mod runtime_process;
mod syscall_protection;

pub use sinan_adapter_sdk::{Privileged, ServiceManager};

mod services;
#[cfg(test)]
use services::parse_runtime_active;
pub use services::{ServiceBackend, SystemServiceManager};

use crate::artifacts::safe_component;
use anyhow::{Context, Result, ensure};
use sinan_adapter_sdk::{BoxFuture, CommandOutput, JobStatus, ServiceJob};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::Path,
    time::Duration,
};
use tokio::{process::Command, time::timeout};
use uuid::Uuid;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct SystemOps;

pub(crate) fn diagnostic_cpu_ceiling_supported() -> bool {
    cpu_ceiling::supported()
}

fn ensure_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_dir()
                || (metadata.file_type().is_symlink() && fs::metadata(path)?.is_dir()),
            "directory path is not a directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                ensure_directory(parent)?;
            }
            match fs::create_dir(path) {
                Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o755))?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure!(
                        fs::symlink_metadata(path)?.is_dir(),
                        "directory was replaced"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn parent_directory(path: &Path) -> Result<&Path> {
    let parent = path.parent().context("path has no parent")?;
    ensure!(
        !parent.as_os_str().is_empty(),
        "path must have an explicit parent"
    );
    Ok(parent)
}

impl SystemOps {
    async fn assign_group(&self, path: &Path, group: Option<&str>) -> Result<()> {
        if let Some(group) = group.filter(|value| !value.is_empty()) {
            ensure!(safe_component(group), "invalid group name");
            let output = self
                .execute(
                    Path::new("chown"),
                    &[
                        "--".into(),
                        format!(":{group}"),
                        path.to_string_lossy().into_owned(),
                    ],
                )
                .await?;
            ensure!(
                output.success,
                "setting file group failed: {}",
                output.stderr
            );
        }
        Ok(())
    }
}

impl Privileged for SystemOps {
    fn lock_managed_state<'a>(
        &'a self,
        path: &'a Path,
    ) -> sinan_adapter_sdk::BoxFuture<'a, Box<dyn sinan_adapter_sdk::ManagedStateLock>> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                managed_files::lock(path).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = path;
                anyhow::bail!("managed state locking requires Linux")
            }
        })
    }
    fn snapshot_managed_file<'a>(
        &'a self,
        path: &'a Path,
        maximum: usize,
    ) -> sinan_adapter_sdk::BoxFuture<'a, serde_json::Value> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                managed_files::snapshot(path, maximum).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (path, maximum);
                anyhow::bail!("managed snapshots require Linux")
            }
        })
    }
    fn update_managed_file<'a>(
        &'a self,
        path: &'a Path,
        bytes: Option<&'a [u8]>,
        expected: &'a serde_json::Value,
        metadata: &'a serde_json::Value,
    ) -> sinan_adapter_sdk::BoxFuture<'a, serde_json::Value> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                managed_files::update(path, bytes, expected, metadata).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (path, bytes, expected, metadata);
                anyhow::bail!("managed metadata updates require Linux")
            }
        })
    }
    #[cfg(target_os = "linux")]
    fn read_managed_file<'a>(&'a self, path: &'a Path, maximum: usize) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(managed_files::read(path, maximum))
    }
    #[cfg(target_os = "linux")]
    fn replace_managed_file<'a>(
        &'a self,
        path: &'a Path,
        bytes: &'a [u8],
        previous_hash: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(managed_files::replace(path, bytes, previous_hash))
    }
    #[cfg(target_os = "linux")]
    fn upload_managed_file<'a>(
        &'a self,
        path: &'a Path,
        bytes: &'a [u8],
        previous_hash: Option<&'a str>,
    ) -> BoxFuture<'a, bool> {
        Box::pin(managed_files::upload(path, bytes, previous_hash))
    }
    #[cfg(target_os = "linux")]
    fn inspect_managed_file<'a>(
        &'a self,
        path: &'a Path,
        maximum: usize,
    ) -> BoxFuture<'a, serde_json::Value> {
        Box::pin(managed_files::inspect(path, maximum))
    }

    #[cfg(target_os = "linux")]
    fn open_terminal<'a>(
        &'a self,
        account: &'a str,
        columns: u16,
        rows: u16,
    ) -> BoxFuture<'a, Box<dyn sinan_adapter_sdk::TerminalProcess>> {
        Box::pin(terminal::open(account, columns, rows))
    }

    fn runtime_process<'a>(
        &'a self,
        pid: u32,
        control_group: &'a str,
    ) -> BoxFuture<'a, sinan_adapter_sdk::RuntimeInstance> {
        Box::pin(runtime_process::inspect(pid, control_group))
    }

    fn execute_controlled<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
        seconds: u32,
        maximum: usize,
        observer: &'a dyn sinan_adapter_sdk::CommandObserver,
    ) -> BoxFuture<'a, sinan_adapter_sdk::ControlledExecution> {
        Box::pin(command_process::execute(
            program, args, seconds, maximum, observer,
        ))
    }
    fn recover_command<'a>(
        &'a self,
        process: &'a sinan_adapter_sdk::CommandProcessIdentity,
    ) -> BoxFuture<'a, ()> {
        Box::pin(command_process::recover(process))
    }
    fn diagnostic_memory(&self) -> BoxFuture<'_, sinan_adapter_sdk::DiagnosticMemory> {
        Box::pin(resources::memory())
    }
    fn diagnostic_resources<'a>(
        &'a self,
        directory: &'a Path,
    ) -> BoxFuture<'a, sinan_adapter_sdk::DiagnosticResources> {
        Box::pin(resources::snapshot(self, directory))
    }
    fn spawn_managed<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
    ) -> BoxFuture<'a, Box<dyn sinan_adapter_sdk::ManagedProcess>> {
        Box::pin(async move { execution::spawn(program, args) })
    }
    fn execute_bounded<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
        seconds: u32,
        maximum: usize,
    ) -> BoxFuture<'a, sinan_adapter_sdk::Execution> {
        Box::pin(execution::execute(program, args, seconds, maximum))
    }
    fn execute<'a>(
        &'a self,
        program: &'a Path,
        args: &'a [String],
    ) -> BoxFuture<'a, CommandOutput> {
        Box::pin(async move {
            let publication = publication::is_request(program, args);
            if publication {
                publication::validate(args)?;
            }
            #[cfg(not(target_os = "linux"))]
            if publication {
                return publication::simulate(args).await;
            }
            #[cfg(not(target_os = "linux"))]
            ensure!(
                program.file_name().is_none_or(|name| {
                    name != "systemctl" && name != "rc-service" && name != "systemd-run"
                }),
                "service management requires Linux"
            );
            let output = timeout(
                COMMAND_TIMEOUT,
                Command::new(program).args(args).kill_on_drop(true).output(),
            )
            .await
            .context("command exceeded 30 seconds")??;
            if publication && output.status.success() {
                publication::sync(args).await?;
            }
            Ok(CommandOutput {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
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
            ensure!(mode & !0o7777 == 0, "invalid permission mode");
            let owned = path.to_owned();
            tokio::task::spawn_blocking(move || ensure_directory(&owned)).await??;
            self.assign_group(path, group).await?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            sync_directory(path)?;
            Ok(())
        })
    }

    fn write_file<'a>(
        &'a self,
        path: &'a Path,
        bytes: &'a [u8],
        mode: u32,
        group: Option<&'a str>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            ensure!(mode & !0o7777 == 0, "invalid permission mode");
            let parent = parent_directory(path)?;
            ensure_directory(parent)?;
            let temporary = parent.join(format!(".write-{}", Uuid::new_v4()));
            let result: Result<()> = async {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                self.assign_group(&temporary, group).await?;
                file.set_permissions(fs::Permissions::from_mode(mode))?;
                file.sync_all()?;
                fs::rename(&temporary, path)?;
                sync_directory(parent)?;
                Ok(())
            }
            .await;
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
    }

    fn atomic_symlink<'a>(&'a self, link: &'a Path, target: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let parent = parent_directory(link)?;
            ensure_directory(parent)?;
            if let Ok(metadata) = fs::symlink_metadata(link) {
                ensure!(
                    metadata.file_type().is_symlink(),
                    "refusing to replace a non-symlink"
                );
            }
            let temporary = parent.join(format!(".link-{}", Uuid::new_v4()));
            symlink(target, &temporary)?;
            let result: Result<()> = async {
                #[cfg(target_os = "macos")]
                {
                    // Darwin applies umask to symlinks and checks their read bits.
                    // Change only the unpublished link, never its protected target.
                    let output = self
                        .execute(
                            Path::new("/bin/chmod"),
                            &[
                                "-h".into(),
                                "755".into(),
                                temporary.to_string_lossy().into_owned(),
                            ],
                        )
                        .await?;
                    ensure!(output.success, "setting symbolic link permissions failed");
                }
                fs::rename(&temporary, link)?;
                sync_directory(parent)
            }
            .await;
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result
        })
    }

    fn remove_symlink<'a>(&'a self, link: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match fs::symlink_metadata(link) {
                Ok(metadata) => {
                    ensure!(
                        metadata.file_type().is_symlink(),
                        "refusing to remove a non-symlink"
                    );
                    fs::remove_file(link)?;
                    sync_directory(parent_directory(link)?)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })
    }

    fn remove_path<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            remove_managed(path, metadata.is_dir())
        })
    }
    fn remove_file<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async move { remove_managed(path, false) })
    }
    fn remove_managed_directory<'a>(&'a self, path: &'a Path) -> BoxFuture<'a, ()> {
        Box::pin(async move { remove_managed(path, true) })
    }
    fn install_archive<'a>(
        &'a self,
        archive: &'a Path,
        directory: &'a Path,
        binary_name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let archive = archive.to_owned();
            let directory = directory.to_owned();
            let binary_name = binary_name.to_owned();
            tokio::task::spawn_blocking(move || {
                archive::install(&archive, &directory, &binary_name, &[])
            })
            .await?
        })
    }
    fn install_archive_files<'a>(
        &'a self,
        path: &'a Path,
        directory: &'a Path,
        binary_name: &'a str,
        extras: &'a [String],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (path, directory, binary_name, extras) = (
                path.to_owned(),
                directory.to_owned(),
                binary_name.to_owned(),
                extras.to_vec(),
            );
            tokio::task::spawn_blocking(move || {
                archive::install(&path, &directory, &binary_name, &extras)
            })
            .await?
        })
    }
}
fn remove_managed(path: &Path, directory: bool) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "managed removal requires an absolute path"
    );
    let parent = parent_directory(path)?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "managed removal refuses symbolic link ancestors"
        );
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        !metadata.file_type().is_symlink(),
        "managed removal refuses symbolic links"
    );
    if directory {
        ensure!(metadata.is_dir(), "managed removal requires a directory");
        fs::remove_dir_all(path)?;
    } else {
        ensure!(
            metadata.is_file(),
            "credential removal requires a regular file"
        );
        fs::remove_file(path)?;
    }
    sync_directory(parent)
}
