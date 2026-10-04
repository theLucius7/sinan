use anyhow::{Context, ensure};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_adapter_sdk::{Privileged, ServiceManager};
use sinan_protocol::fleet::AccessPolicy;
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Material {
    deployment_id: String,
    certificate_id: String,
    version_id: String,
    certificate_path: String,
    private_key_path: String,
    service: String,
    public_chain: String,
    private_key: String,
    fingerprint: String,
    adopt_existing: bool,
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    certificate_id: String,
    version_id: String,
    public_sha256: String,
    key_sha256: String,
    fingerprint: String,
}
struct PreviousFile {
    bytes: Option<Vec<u8>>,
    snapshot: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    deployment_id: String,
    certificate_id: String,
    version_id: String,
    certificate_path: String,
    service: String,
    fingerprint: String,
}

pub async fn inspect_certificate(
    privileged: &dyn Privileged,
    services: &dyn ServiceManager,
    local: &AccessPolicy,
    remote: &AccessPolicy,
    material: &Value,
) -> anyhow::Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "certificate inspection requires Linux service metadata"
    );
    ensure!(
        local.certificate_deploy && remote.certificate_deploy,
        "certificate inspection is outside authorized capabilities"
    );
    let material: Inspection = serde_json::from_value(material.clone())?;
    ensure!(
        local.services.contains(&material.service) && remote.services.contains(&material.service),
        "certificate service is outside authorized scope"
    );
    let public = allowed(local, remote, &material.certificate_path)?;
    let bytes = privileged.read_managed_file(&public, 65536).await?;
    let leaf = CertificateDer::pem_slice_iter(&bytes)
        .next()
        .context("certificate chain is empty")??;
    let fingerprint = format!("{:x}", Sha256::digest(leaf.as_ref()));
    let details = services.status_details(&material.service).await?;
    let fields: std::collections::BTreeMap<_, _> = details
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| ["ActiveState", "SubState", "Result", "MainPID"].contains(name))
        .collect();
    Ok(
        json!({"deployment_id":material.deployment_id,"certificate_id":material.certificate_id,"version_id":material.version_id,"fingerprint":fingerprint,"matches_expected":fingerprint==material.fingerprint,"service":material.service,"service_state":fields,"handshake_verified":false,"sampled_at":sinan_protocol::now_timestamp(),"source":"agent_public_certificate_file"}),
    )
}

/// The runner must reject its Config's identity, state and artifact paths before invoking this.
pub async fn deploy_certificate(
    privileged: &dyn Privileged,
    services: &dyn ServiceManager,
    local: &AccessPolicy,
    remote: &AccessPolicy,
    material: &Value,
) -> anyhow::Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "managed certificate deployment requires Linux ownership and service metadata"
    );
    ensure!(
        local.certificate_deploy && remote.certificate_deploy,
        "certificate deployment is not authorized on both sides"
    );
    let material: Material = serde_json::from_value(material.clone())?;
    ensure!(
        material.public_chain.len() <= 65536 && material.private_key.len() <= 16384,
        "certificate material exceeds limit"
    );
    let chain = CertificateDer::pem_slice_iter(material.public_chain.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = chain.first().context("certificate chain is empty")?;
    ensure!(
        format!("{:x}", Sha256::digest(leaf.as_ref())) == material.fingerprint,
        "certificate fingerprint mismatch"
    );
    let key = PrivateKeyDer::from_pem_slice(material.private_key.as_bytes())?;
    rustls::sign::CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .map_err(|_| anyhow::anyhow!("certificate and private key do not match"))?;
    ensure!(
        local.services.contains(&material.service) && remote.services.contains(&material.service),
        "certificate service is outside authorized scope"
    );
    let public = allowed(local, remote, &material.certificate_path)?;
    let private = allowed(local, remote, &material.private_key_path)?;
    ensure!(public != private, "certificate and key paths must differ");
    ensure!(
        public
            .extension()
            .is_some_and(|extension| extension == "pem" || extension == "crt")
            && private
                .extension()
                .is_some_and(|extension| extension == "pem" || extension == "key"),
        "certificate target extensions are invalid"
    );
    let receipt_path = allowed(
        local,
        remote,
        &public
            .with_extension("sinan-certificate.json")
            .to_string_lossy(),
    )?;
    let old_public = existing(privileged, &public, 65536).await?;
    let old_private = existing(privileged, &private, 16384).await?;
    let old_receipt = existing(privileged, &receipt_path, 4096).await?;
    let properties: std::collections::BTreeMap<_, _> = services
        .status_details(&material.service)
        .await?
        .lines()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
        })
        .collect();
    let account = service_account(&properties)?;
    ensure!(
        valid_account(account),
        "service account is not supported for certificate deployment"
    );
    let group = if let Some(group) = properties.get("Group").filter(|value| !value.is_empty()) {
        group.clone()
    } else {
        bounded(
            privileged,
            "/usr/bin/id",
            &["-gn".into(), "--".into(), account.into()],
        )
        .await?
        .trim()
        .to_owned()
    };
    ensure!(
        valid_account(&group),
        "service group is not supported for certificate deployment"
    );
    let key_mode = if account == "root" || account == "0" {
        0o600
    } else {
        0o640
    };
    let group_record = bounded(
        privileged,
        "/usr/bin/getent",
        &["group".into(), group.clone()],
    )
    .await?;
    let group_id: u32 = group_record
        .trim()
        .split(':')
        .nth(2)
        .context("actual service group could not be resolved")?
        .parse()?;
    if old_public.bytes.is_some() || old_private.bytes.is_some() {
        if !material.adopt_existing {
            let previous: Receipt =
                serde_json::from_slice(&privileged.read_managed_file(&receipt_path, 4096).await?)
                    .map_err(|_| {
                    anyhow::anyhow!(
                        "existing certificate is not managed; explicit adoption is required"
                    )
                })?;
            ensure!(
                previous.certificate_id == material.certificate_id
                    && old_public
                        .bytes
                        .as_ref()
                        .is_some_and(|bytes| hash(bytes) == previous.public_sha256)
                    && old_private
                        .bytes
                        .as_ref()
                        .is_some_and(|bytes| hash(bytes) == previous.key_sha256),
                "existing certificate changed outside management; refuse overwrite"
            );
        }
        if let Some(bytes) = &old_public.bytes {
            let path = allowed(
                local,
                remote,
                &public
                    .with_extension(format!(
                        "sinan-previous-{}.crt",
                        uuid::Uuid::parse_str(&material.deployment_id)?
                    ))
                    .to_string_lossy(),
            )?;
            private_backup(privileged, &path, bytes).await?;
        }
        if let Some(bytes) = &old_private.bytes {
            let path = allowed(
                local,
                remote,
                &private
                    .with_extension(format!(
                        "sinan-previous-{}.key",
                        uuid::Uuid::parse_str(&material.deployment_id)?
                    ))
                    .to_string_lossy(),
            )?;
            private_backup(privileged, &path, bytes).await?;
        }
    }
    let mut current_public = old_public.snapshot.clone();
    let mut current_private = old_private.snapshot.clone();
    let mut current_receipt = old_receipt.snapshot.clone();
    let receipt = Receipt {
        certificate_id: material.certificate_id.clone(),
        version_id: material.version_id.clone(),
        public_sha256: hash(material.public_chain.as_bytes()),
        key_sha256: hash(material.private_key.as_bytes()),
        fingerprint: material.fingerprint.clone(),
    };
    let receipt_bytes = serde_json::to_vec(&receipt)?;
    let apply = async {
        current_public = privileged
            .update_managed_file(
                &public,
                Some(material.public_chain.as_bytes()),
                &old_public.snapshot,
                &json!({"mode":0o644,"uid":0,"gid":0}),
            )
            .await?;
        current_private = privileged
            .update_managed_file(
                &private,
                Some(material.private_key.as_bytes()),
                &old_private.snapshot,
                &json!({"mode":key_mode,"uid":0,"gid":group_id}),
            )
            .await?;
        services
            .reload(&material.service)
            .await
            .map_err(|_| anyhow::anyhow!("certificate service reload failed"))?;
        ensure!(
            services.is_active(&material.service).await?,
            "certificate service is not active after reload"
        );
        current_receipt = privileged
            .update_managed_file(
                &receipt_path,
                Some(&receipt_bytes),
                &old_receipt.snapshot,
                &json!({"mode":0o600,"uid":0,"gid":0}),
            )
            .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if apply.is_err() {
        let recovery = async {
            current_public = reconcile(
                privileged,
                &public,
                &old_public,
                &current_public,
                material.public_chain.as_bytes(),
                &json!({"mode":0o644,"uid":0,"gid":0}),
            )
            .await?;
            current_private = reconcile(
                privileged,
                &private,
                &old_private,
                &current_private,
                material.private_key.as_bytes(),
                &json!({"mode":key_mode,"uid":0,"gid":group_id}),
            )
            .await?;
            current_receipt = reconcile(
                privileged,
                &receipt_path,
                &old_receipt,
                &current_receipt,
                &receipt_bytes,
                &json!({"mode":0o600,"uid":0,"gid":0}),
            )
            .await?;
            restore(privileged, &public, &old_public, &current_public).await?;
            restore(privileged, &private, &old_private, &current_private).await?;
            restore(privileged, &receipt_path, &old_receipt, &current_receipt).await?;
            services.reload(&material.service).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if recovery.is_err() {
            anyhow::bail!("certificate deployment failed and local recovery is unconfirmed");
        }
        anyhow::bail!(
            "certificate deployment failed; previous files restored and service reloaded"
        );
    }
    Ok(
        json!({"deployment_id":material.deployment_id,"certificate_id":material.certificate_id,"version_id":material.version_id,"fingerprint":material.fingerprint,"deployed":true,"service_reloaded":true,"service":material.service,"handshake_verified":false,"completed_at":sinan_protocol::now_timestamp(),"private_key":"protected_local_file","key_mode":format!("{key_mode:o}"),"previous_files":"protected_local_recovery"}),
    )
}
async fn reconcile(
    privileged: &dyn Privileged,
    path: &Path,
    previous: &PreviousFile,
    reported: &Value,
    desired: &[u8],
    metadata: &Value,
) -> anyhow::Result<Value> {
    let actual = existing(privileged, path, 65536).await?;
    recovery_snapshot(
        &previous.snapshot,
        reported,
        actual.snapshot,
        desired,
        metadata,
    )
}
fn recovery_snapshot(
    previous: &Value,
    reported: &Value,
    actual: Value,
    desired: &[u8],
    metadata: &Value,
) -> anyhow::Result<Value> {
    ensure!(
        actual["parents"] == previous["parents"],
        "certificate parent changed; local recovery is unconfirmed"
    );
    if actual == *previous || actual == *reported {
        return Ok(actual);
    }
    let file = &actual["file"];
    ensure!(
        file["sha256"] == hash(desired)
            && ["mode", "uid", "gid"]
                .iter()
                .all(|field| file[*field] == metadata[*field]),
        "certificate helper outcome or external changes are unknown; refuse recovery overwrite"
    );
    Ok(actual)
}

fn allowed(local: &AccessPolicy, remote: &AccessPolicy, value: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute()
            && value.len() <= 4096
            && !value.contains(['\0', '\n', '\r'])
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "certificate path invalid"
    );
    let blocked: BTreeSet<_> = [
        "identity",
        ".ssh",
        "shadow",
        "gshadow",
        "fleet-policy.json",
        "agent.toml",
        "device.key",
    ]
    .into_iter()
    .collect();
    ensure!(
        !path
            .components()
            .any(|part| blocked.contains(part.as_os_str().to_string_lossy().as_ref()))
            && !["/proc", "/sys", "/dev"]
                .iter()
                .any(|scope| path.starts_with(scope)),
        "certificate target is protected"
    );
    ensure!(
        [&local.write_directories, &remote.write_directories]
            .iter()
            .all(
                |directories| directories.iter().any(|directory| directory != "/"
                    && Path::new(directory).is_absolute()
                    && path.starts_with(directory))
            ),
        "certificate path is outside granted directories"
    );
    let mut parent = path.parent();
    while let Some(directory) = parent {
        let metadata = std::fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "certificate parent is not ordinary"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o022 == 0,
                "certificate parent is writable by another account"
            );
        }
        parent = directory.parent();
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "certificate target is not ordinary"
        );
    }
    Ok(path.to_path_buf())
}
async fn existing(
    privileged: &dyn Privileged,
    path: &Path,
    maximum: usize,
) -> anyhow::Result<PreviousFile> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut snapshot = privileged.snapshot_managed_file(path, maximum).await?;
    let bytes = snapshot
        .get("content")
        .and_then(Value::as_str)
        .map(|content| STANDARD.decode(content))
        .transpose()?;
    snapshot
        .as_object_mut()
        .context("invalid file snapshot")?
        .remove("content");
    Ok(PreviousFile { bytes, snapshot })
}
async fn restore(
    privileged: &dyn Privileged,
    path: &Path,
    previous: &PreviousFile,
    current: &Value,
) -> anyhow::Result<()> {
    if current == &previous.snapshot {
        return Ok(());
    }
    let metadata = previous
        .snapshot
        .get("file")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| json!({"mode":0o600,"uid":0,"gid":0}));
    privileged
        .update_managed_file(path, previous.bytes.as_deref(), current, &metadata)
        .await?;
    Ok(())
}
async fn private_backup(
    privileged: &dyn Privileged,
    path: &Path,
    bytes: &[u8],
) -> anyhow::Result<()> {
    let previous = privileged.snapshot_managed_file(path, 65536).await?;
    ensure!(
        previous["exists"] == false,
        "certificate recovery backup already exists; refuse replacement"
    );
    privileged
        .update_managed_file(
            path,
            Some(bytes),
            &previous,
            &json!({"mode":0o600,"uid":0,"gid":0}),
        )
        .await?;
    Ok(())
}
fn service_account(
    properties: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<&str> {
    ensure!(
        properties.get("LoadState").map(String::as_str) == Some("loaded"),
        "actual loaded service metadata is required for certificate deployment"
    );
    let account = properties
        .get("User")
        .context("actual service account is unknown; refuse certificate deployment")?;
    Ok(if account.is_empty() {
        "root"
    } else {
        account.as_str()
    })
}
async fn bounded(
    privileged: &dyn Privileged,
    program: &str,
    arguments: &[String],
) -> anyhow::Result<String> {
    let result = privileged
        .execute_bounded(Path::new(program), arguments, 10, 4096)
        .await?;
    ensure!(
        result.output.success && !result.timed_out && !result.truncated,
        "certificate file ownership inspection or restoration failed"
    );
    Ok(result.output.stdout)
}
fn valid_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_helper_reply_recovers_only_exact_desired_identity_under_original_parents() {
        let previous = json!({"parents":[{"dev":1,"ino":2}],"exists":true,"file":{"sha256":hash(b"TEST_ONLY old"),"mode":0o600,"uid":0,"gid":0}});
        let metadata = json!({"mode":0o640,"uid":0,"gid":123});
        let mut actual = json!({"parents":[{"dev":1,"ino":2}],"exists":true,"file":{"sha256":hash(b"TEST_ONLY new"),"mode":0o640,"uid":0,"gid":123}});
        assert_eq!(
            recovery_snapshot(
                &previous,
                &previous,
                actual.clone(),
                b"TEST_ONLY new",
                &metadata
            )
            .unwrap(),
            actual
        );
        actual["file"]["sha256"] = json!(hash(b"TEST_ONLY external"));
        assert!(
            recovery_snapshot(
                &previous,
                &previous,
                actual.clone(),
                b"TEST_ONLY new",
                &metadata
            )
            .is_err()
        );
        actual["file"]["sha256"] = json!(hash(b"TEST_ONLY new"));
        actual["parents"][0]["ino"] = json!(3);
        assert!(
            recovery_snapshot(&previous, &previous, actual, b"TEST_ONLY new", &metadata).is_err()
        );
    }
    #[test]
    fn actual_loaded_account_is_required_instead_of_inferred_root() {
        let unknown = [("active".into(), "true".into())].into_iter().collect();
        assert!(service_account(&unknown).is_err());
        let mut loaded = [("LoadState".into(), "loaded".into())]
            .into_iter()
            .collect();
        assert!(service_account(&loaded).is_err());
        loaded.insert("User".into(), "operator".into());
        assert_eq!(service_account(&loaded).unwrap(), "operator");
        loaded.insert("User".into(), String::new());
        assert_eq!(service_account(&loaded).unwrap(), "root");
        loaded.insert("LoadState".into(), "not-found".into());
        assert!(service_account(&loaded).is_err());
    }
    #[test]
    fn certificate_targets_require_both_scopes() {
        let policy = AccessPolicy {
            write_directories: vec!["/srv/example-certificates".into()],
            certificate_deploy: true,
            ..AccessPolicy::default()
        };
        assert!(
            allowed(
                &policy,
                &AccessPolicy::default(),
                "/srv/example-certificates/tls.key"
            )
            .is_err()
        );
        assert!(
            allowed(
                &policy,
                &policy,
                "/srv/example-certificates/../identity/device.key"
            )
            .is_err()
        );
    }
}
