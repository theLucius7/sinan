use super::{acme::Plan, documents, models::Configuration, x509};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use uuid::Uuid;

pub(super) async fn execute(
    state: &AppState,
    job: Uuid,
    certificate_id: Uuid,
    plan: &Plan,
    plan_revision: i64,
    actor: i64,
) -> ApiResult<Value> {
    if !cfg!(unix) {
        return Err(ApiError::Conflict("acme_executor_requires_unix".into()));
    }
    let document = documents::load(state, certificate_id).await?;
    let job_scope = sqlx::query(
        "SELECT certificate_revision,domain_snapshot FROM network_acme_jobs WHERE id=$1",
    )
    .bind(job)
    .fetch_one(&state.pool)
    .await?;
    if document.revision != job_scope.get::<i64, _>("certificate_revision") {
        return Err(ApiError::Conflict("issuance_scope_changed".into()));
    }
    crate::control_center::require_actor_capability(state, actor, "dns:write").await?;
    crate::control_center::require_actor_capability(state, actor, "network:write").await?;
    let config = documents::configuration(&document)?;
    for server in config.servers() {
        crate::control_center::require_actor_server(state, actor, server, "network:write").await?;
    }
    let Configuration::Certificate {
        renewal: super::models::RenewalPolicy::Dns01 { ddns_rule_id, .. },
        ..
    } = &config
    else {
        return Err(ApiError::Conflict(
            "issuer_dns01_maintenance_owner_missing".into(),
        ));
    };
    let dns_server: i64 = sqlx::query_scalar("SELECT server_id FROM ddns_rules WHERE id=$1")
        .bind(ddns_rule_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    crate::control_center::require_actor_server(state, actor, dns_server, "dns:write").await?;
    let Configuration::Certificate { domain_ids, .. } = documents::configuration(&document)? else {
        return Err(ApiError::Conflict(
            "certificate_configuration_missing".into(),
        ));
    };
    let current = sqlx::query(
        "SELECT revision,account_secret_ref FROM network_acme_plans WHERE certificate_id=$1",
    )
    .bind(certificate_id)
    .fetch_one(&state.pool)
    .await?;
    if current.get::<i64, _>("revision") != plan_revision {
        return Err(ApiError::Conflict("issuance_plan_changed".into()));
    }
    let mut domains = Vec::new();
    for id in domain_ids {
        let domain = documents::load(state, id).await?;
        let snapshot: Value = job_scope.get("domain_snapshot");
        if !snapshot.as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value["id"].as_str() == Some(id.to_string().as_str())
                    && value["revision"].as_i64() == Some(domain.revision)
            })
        }) {
            return Err(ApiError::Conflict("issuance_scope_changed".into()));
        }
        for server in documents::configuration(&domain)?.servers() {
            crate::control_center::require_actor_server(state, actor, server, "network:write")
                .await?;
        }
        let Configuration::Domain { name, .. } = documents::configuration(&domain)? else {
            return Err(ApiError::Conflict("certificate_domain_missing".into()));
        };
        domains.push(name);
    }
    let credentials = crate::control_center::credentials::resolve_reference(
        state,
        plan.credential_id,
        "dns",
        "acme-issuer",
    )
    .await?;
    if credentials
        .get("provider")
        .is_some_and(|value| value.as_str() != Some("cloudflare"))
    {
        return Err(ApiError::Conflict("issuer_dns_provider_unsupported".into()));
    }
    let token = credentials["api_token"]
        .as_str()
        .filter(|value| !value.is_empty() && !value.contains(['\0', '\n', '\r']))
        .ok_or_else(|| ApiError::Conflict("cloudflare_dns_token_missing".into()))?;
    let target = sinan_protocol::release::native_target()
        .map_err(|_| ApiError::Conflict("unsupported_issuer_platform".into()))?;
    let ((bytes, _, proof), artifact_arch) =
        match crate::releases::artifact(state, "lego", &plan.tool_version, &target).await {
            Ok(value) => (value, target),
            Err(ApiError::NotFound) => {
                let arch = sinan_protocol::release::native_arch()
                    .map_err(|_| ApiError::Conflict("unsupported_issuer_platform".into()))?;
                (
                    crate::releases::artifact(state, "lego", &plan.tool_version, arch).await?,
                    arch.to_owned(),
                )
            }
            Err(error) => return Err(error),
        };
    let keys = state
        .release_keys
        .as_ref()
        .ok_or_else(|| ApiError::Conflict("release_trust_root_missing".into()))?;
    let verified = sinan_protocol::release::verify_release(&proof, keys)
        .map_err(|_| ApiError::Conflict("issuer_signature_invalid".into()))?;
    let artifact = verified
        .artifact("lego", &plan.tool_version, &artifact_arch)
        .map_err(|_| ApiError::Conflict("issuer_platform_artifact_missing".into()))?;
    let binary = extract(&bytes, &artifact)
        .map_err(|_| ApiError::Conflict("issuer_artifact_invalid".into()))?;
    let root = state.config.data_dir.join("network-acme-work");
    secure_directory(&root)
        .await
        .map_err(|_| ApiError::Conflict("issuer_work_directory_unavailable".into()))?;
    let workspace = root.join(job.to_string());
    tokio::fs::create_dir(&workspace)
        .await
        .map_err(anyhow::Error::from)?;
    private_permissions(&workspace, 0o700).await?;
    let cleanup = Cleanup(workspace.clone());
    let mut result = execute_in(
        state,
        job,
        certificate_id,
        document.revision,
        plan,
        &domains,
        token,
        current.get("account_secret_ref"),
        &workspace,
        &binary,
    )
    .await;
    // This directory is unique to this job and contains only its transient private material.
    // Keep encrypted account/key references and the public certificate version in the database.
    if tokio::fs::remove_dir_all(&workspace).await.is_err() {
        return Err(ApiError::Conflict(
            "issuer_private_workspace_cleanup_failed".into(),
        ));
    }
    drop(cleanup);
    if let Ok(value) = &mut result {
        value["temporary_material_cleanup"] = json!("confirmed");
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn execute_in(
    state: &AppState,
    job: Uuid,
    certificate: Uuid,
    revision: i64,
    plan: &Plan,
    domains: &[String],
    token: &str,
    account: Option<Uuid>,
    workspace: &Path,
    binary: &[u8],
) -> ApiResult<Value> {
    let binary_path = workspace.join("lego");
    secure_write(&binary_path, binary, 0o700).await?;
    let storage = workspace.join("storage");
    secure_directory(&storage).await?;
    if let Some(id) = account {
        let value = crate::control_center::credentials::resolve_reference(
            state,
            id,
            "certificate",
            "acme-account",
        )
        .await?;
        let files: BTreeMap<String, String> =
            serde_json::from_value(value["lego_account_files"].clone())
                .map_err(anyhow::Error::from)?;
        for (path, content) in files {
            if !safe_account_path(&path) || content.len() > 65536 {
                return Err(ApiError::Conflict("issuer_account_material_invalid".into()));
            }
            let destination = storage.join(path);
            let parent = destination
                .parent()
                .ok_or_else(|| ApiError::Conflict("issuer_account_path_invalid".into()))?;
            secure_directory(parent).await?;
            secure_write(&destination, content.as_bytes(), 0o600).await?;
        }
    }
    let mut command = tokio::process::Command::new(&binary_path);
    command
        .arg(format!("--path={}", storage.display()))
        .arg(format!("--email={}", plan.email))
        .arg("--dns=cloudflare")
        .arg("--key-type=ec256")
        .arg("--accept-tos");
    if plan.staging {
        command.arg("--server=https://acme-staging-v02.api.letsencrypt.org/directory");
    } else {
        command.arg("--server=https://acme-v02.api.letsencrypt.org/directory");
    }
    for domain in domains {
        command.arg(format!("--domains={domain}"));
    }
    command
        .arg("run")
        .current_dir(workspace)
        .env_clear()
        .env("CF_DNS_API_TOKEN", token)
        .env("CLOUDFLARE_DNS_API_TOKEN", token)
        .env("CLOUDFLARE_POLLING_INTERVAL", "5")
        .env("CLOUDFLARE_PROPAGATION_TIMEOUT", "120")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut process = command
        .spawn()
        .map_err(|_| ApiError::Conflict("issuer_spawn_failed".into()))?;
    let status = match tokio::time::timeout(Duration::from_secs(600), process.wait()).await {
        Ok(status) => status.map_err(|_| ApiError::Conflict("issuer_wait_failed".into()))?,
        Err(_) => {
            process
                .kill()
                .await
                .map_err(|_| ApiError::Conflict("issuer_stop_unconfirmed".into()))?;
            process
                .wait()
                .await
                .map_err(|_| ApiError::Conflict("issuer_stop_unconfirmed".into()))?;
            return Err(ApiError::Conflict(
                "issuer_timed_out_dns_cleanup_required".into(),
            ));
        }
    };
    let account_files = pack_accounts(&storage)
        .await
        .map_err(|_| ApiError::Conflict("issuer_account_backup_failed".into()))?;
    if !account_files.is_empty() {
        let account_ref = crate::control_center::credentials::store_generated(
            &state.pool,
            &format!("ACME account {certificate}"),
            "certificate",
            json!({"lego_account_files":account_files}),
        )
        .await?;
        sqlx::query("UPDATE network_acme_plans SET account_secret_ref=$2 WHERE certificate_id=$1")
            .bind(certificate)
            .bind(account_ref)
            .execute(&state.pool)
            .await?;
    }
    if !status.success() {
        return Err(ApiError::Conflict(
            "issuer_failed_dns_or_acme_validation".into(),
        ));
    }
    let (pem, key) = result_files(&storage, domains)
        .await
        .map_err(|_| ApiError::Conflict("issued_certificate_material_invalid".into()))?;
    let parsed =
        x509::parse(&pem).map_err(|_| ApiError::Conflict("issued_certificate_invalid".into()))?;
    if parsed.not_after <= sinan_protocol::now_timestamp() {
        return Err(ApiError::Conflict("issued_certificate_expired".into()));
    }
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let chain = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::Conflict("issued_chain_invalid".into()))?;
    let private = PrivateKeyDer::from_pem_slice(key.as_bytes())
        .map_err(|_| ApiError::Conflict("issued_key_invalid".into()))?;
    rustls::sign::CertifiedKey::from_der(chain, private, &rustls::crypto::ring::default_provider())
        .map_err(|_| ApiError::Conflict("issued_certificate_key_mismatch".into()))?;
    let private_ref = crate::control_center::credentials::store_generated(
        &state.pool,
        &format!("Certificate key {certificate} {}", plan.tool_version),
        "certificate",
        json!({"private_key":key,"fingerprint":parsed.fingerprint}),
    )
    .await?;
    let version = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    let mut tx = state.pool.begin().await?;
    let actual: i64 =
        sqlx::query_scalar("SELECT revision FROM network_documents WHERE id=$1 FOR UPDATE")
            .bind(certificate)
            .fetch_one(&mut *tx)
            .await?;
    let version_revision:i64=sqlx::query_scalar("SELECT COALESCE(max(revision),0)+1 FROM network_certificate_versions WHERE certificate_id=$1").bind(certificate).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO network_certificate_versions(id,certificate_id,revision,public_chain,fingerprint,not_before,not_after,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(version).bind(certificate).bind(version_revision).bind(pem).bind(&parsed.fingerprint).bind(parsed.not_before).bind(parsed.not_after).bind(now).execute(&mut *tx).await?;
    let selected = actual == revision;
    if selected {
        sqlx::query("UPDATE network_documents SET active_version=$2,revision=revision+1,updated_at=$3 WHERE id=$1").bind(certificate).bind(version).bind(now).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE network_acme_jobs SET key_secret_ref=$2,version_id=$3 WHERE id=$1")
        .bind(job)
        .bind(private_ref)
        .bind(version)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(
        json!({"issued":true,"saved":true,"deployed":false,"handshake_verified":false,"version_id":version,"private_key_reference":private_ref,"fingerprint":parsed.fingerprint,"not_after":parsed.not_after,"active_version_selected":selected,"tool":"lego","tool_version":plan.tool_version,"staging":plan.staging,"temporary_material_cleanup":"required_before_completion"}),
    )
}

fn extract(
    bytes: &[u8],
    artifact: &sinan_protocol::release::VerifiedArtifact,
) -> anyhow::Result<Vec<u8>> {
    crate::releases::verify_payload(artifact, bytes)?;
    if artifact.metadata().format == "raw" {
        return Ok(bytes.to_vec());
    }
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path_bytes().as_ref() == artifact.metadata().binary_name.as_bytes() {
            let mut value = Vec::new();
            entry.read_to_end(&mut value)?;
            artifact.verify_binary(&value)?;
            return Ok(value);
        }
    }
    anyhow::bail!("binary missing")
}

async fn result_files(storage: &Path, domains: &[String]) -> anyhow::Result<(String, String)> {
    let mut files = tokio::fs::read_dir(storage.join("certificates")).await?;
    while let Some(file) = files.next_entry().await? {
        let path = file.path();
        if path.extension().and_then(|value| value.to_str()) != Some("crt") {
            continue;
        }
        let pem = ordinary_text(&path, 65536).await?;
        let cert = x509::parse(&pem)?;
        if domains
            .iter()
            .all(|domain| x509::covers(&cert.names, domain))
        {
            return Ok((
                pem,
                ordinary_text(&path.with_extension("key"), 16384).await?,
            ));
        }
    }
    anyhow::bail!("certificate chain not found")
}

async fn pack_accounts(storage: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut stack = vec![storage.join("accounts")];
    let mut total = 0usize;
    while let Some(directory) = stack.pop() {
        if !directory.try_exists()? {
            continue;
        }
        let mut entries = tokio::fs::read_dir(directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            ensure!(!metadata.is_symlink(), "account material cannot be symlink");
            if metadata.is_dir() {
                ensure!(stack.len() < 32, "account tree too deep");
                stack.push(path);
                continue;
            }
            let name = path
                .strip_prefix(storage)?
                .to_str()
                .context("account path is not UTF8")?
                .to_owned();
            ensure!(safe_account_path(&name), "unsafe account path");
            let content = ordinary_text(&path, 65536).await?;
            total += content.len();
            ensure!(
                total <= 48000 && result.len() < 64,
                "account material exceeds credential limit"
            );
            result.insert(name, content);
        }
    }
    ensure!(
        serde_json::to_vec(&json!({"lego_account_files":result}))?.len() <= 65536,
        "encoded account material exceeds credential limit"
    );
    Ok(result)
}
fn safe_account_path(path: &str) -> bool {
    path.starts_with("accounts/")
        && path.len() <= 1024
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !path.contains(['\\', '\0', '\n', '\r'])
}
async fn ordinary_text(path: &Path, max: u64) -> anyhow::Result<String> {
    let metadata = tokio::fs::symlink_metadata(path).await?;
    ensure!(
        metadata.is_file() && !metadata.is_symlink() && metadata.len() <= max,
        "material is not a bounded ordinary file"
    );
    Ok(tokio::fs::read_to_string(path).await?)
}
async fn secure_directory(path: &Path) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(path).await?;
    let metadata = tokio::fs::symlink_metadata(path).await?;
    ensure!(
        metadata.is_dir() && !metadata.is_symlink(),
        "private directory is not ordinary"
    );
    private_permissions(path, 0o700).await
}
async fn secure_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options.open(path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    Ok(())
}
async fn private_permissions(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    }
    Ok(())
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
