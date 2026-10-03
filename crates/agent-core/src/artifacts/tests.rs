use super::{preflight::verify_cache_with_keys, verification::verify_binary_with_keys};
use crate::release_test_support as release_support;
use crate::{Config, State, reconcile::ApplyIntent, state::IntentRecord};
use sinan_adapter_sdk::{Plan, Prepared, RuntimeSpec};
use std::{collections::BTreeMap, fs, path::PathBuf};
use uuid::Uuid;

#[tokio::test]
async fn update_negotiation_does_not_relax_artifact_download_urls() {
    let client = super::PanelClient::new("http://127.0.0.1:1", "fixture-session").unwrap();
    for path in [
        "/api/agent/v1/update?download_source=panel",
        "/api/agent/v1/update?download_source=github&extra=1",
        "/api/agent/v1/update?download_source=github#fragment",
        "/api/agent/v1/manifest?download_source=github",
        "//example.com/api/agent/v1/update?download_source=github",
    ] {
        let error = client
            .get_json::<serde_json::Value>(path)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("without credentials, query or fragment")
        );
    }
    assert!(
        client
            .validate_url(
                "http://127.0.0.1:1/api/agent/v1/artifacts/agent/0.9.0/amd64?download_source=github"
            )
            .is_err()
    );
}

struct Fixture {
    directory: PathBuf,
    config: Config,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("sinan-proof-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let config = Config {
            state_db: directory.join("state.db"),
            install_root: directory.join("install"),
            ..Config::default()
        };
        Self { directory, config }
    }
    fn runtime(&self, version: &str) -> Prepared {
        let directory = self.config.install_root.join("runtime").join(version);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("runtime"), b"fixture-runtime").unwrap();
        release_support::install_proof(
            &directory,
            &release_support::proof_for_archive(
                "runtime",
                version,
                "runtime",
                b"cached-archive",
                b"fixture-runtime",
            ),
        );
        Prepared {
            spec: RuntimeSpec {
                revision: 1,
                kernel_version: version.into(),
                binary_path: directory.join("runtime"),
                config_hash: "fixture".into(),
                revision_dir: self.directory.join("revisions/1"),
                stats_listen: String::new(),
                files: BTreeMap::new(),
            },
            listen_ports: vec![],
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn installed_proof_checks_file_identity_and_ordinary_paths() {
    let test = Fixture::new();
    let runtime = test.runtime("1");
    let keys = release_support::trusted_keys();
    verify_binary_with_keys(&runtime.spec.binary_path, "runtime", "tar.gz", &keys)
        .await
        .unwrap();
    let directory = runtime.spec.binary_path.parent().unwrap();
    fs::rename(directory, directory.with_file_name("2")).unwrap();
    assert!(
        verify_binary_with_keys(
            &directory.with_file_name("2").join("runtime"),
            "runtime",
            "tar.gz",
            &keys
        )
        .await
        .is_err()
    );
    fs::rename(directory.with_file_name("2"), directory).unwrap();
    fs::rename(
        directory.join("release.json"),
        directory.join("original.json"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            directory.join("original.json"),
            directory.join("release.json"),
        )
        .unwrap();
        assert!(
            verify_binary_with_keys(&runtime.spec.binary_path, "runtime", "tar.gz", &keys)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
#[cfg(unix)]
async fn current_link_can_only_select_a_signed_sibling_version() {
    let test = Fixture::new();
    let runtime = test.runtime("1");
    let plugin = test.config.install_root.join("runtime");
    let link = plugin.join("current");
    let keys = release_support::trusted_keys();
    std::os::unix::fs::symlink(runtime.spec.binary_path.parent().unwrap(), &link).unwrap();
    verify_binary_with_keys(&link.join("runtime"), "runtime", "tar.gz", &keys)
        .await
        .unwrap();
    fs::remove_file(&link).unwrap();
    let outside = Fixture::new();
    let outside_runtime = outside.runtime("1");
    std::os::unix::fs::symlink(outside_runtime.spec.binary_path.parent().unwrap(), &link).unwrap();
    assert!(
        verify_binary_with_keys(&link.join("runtime"), "runtime", "tar.gz", &keys)
            .await
            .is_err()
    );
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(
        runtime.spec.binary_path.parent().unwrap(),
        plugin.join("alias"),
    )
    .unwrap();
    assert!(
        verify_binary_with_keys(&plugin.join("alias/runtime"), "runtime", "tar.gz", &keys)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn migration_preflight_preserves_database_and_rejects_unsigned_pending_rollback() {
    let test = Fixture::new();
    let previous = test.runtime("1");
    let target = test.runtime("2");
    {
        let mut state = State::open(&test.config.state_db).unwrap();
        state.set_json("applied:runtime", &previous).unwrap();
        state
            .begin_intent(&IntentRecord {
                op_id: Uuid::new_v4(),
                module: "runtime".into(),
                payload: serde_json::to_value(ApplyIntent {
                    previous: Some(previous.clone()),
                    target: target.clone(),
                    plan: Plan::Restart,
                })
                .unwrap(),
            })
            .unwrap();
    }
    let before = fs::read(&test.config.state_db).unwrap();
    let keys = release_support::trusted_keys();
    verify_cache_with_keys(&test.config, &keys).await.unwrap();
    assert_eq!(before, fs::read(&test.config.state_db).unwrap());
    fs::remove_file(
        target
            .spec
            .binary_path
            .parent()
            .unwrap()
            .join("release.json"),
    )
    .unwrap();
    assert!(verify_cache_with_keys(&test.config, &keys).await.is_err());
    assert_eq!(before, fs::read(&test.config.state_db).unwrap());
    test.runtime("2");
    fs::write(&previous.spec.binary_path, b"untrusted-runtime").unwrap();
    assert!(verify_cache_with_keys(&test.config, &keys).await.is_err());
    assert_eq!(before, fs::read(&test.config.state_db).unwrap());
}

#[tokio::test]
#[cfg(unix)]
async fn migration_preflight_checks_current_even_without_a_database() {
    let test = Fixture::new();
    let runtime = test.runtime("1");
    std::os::unix::fs::symlink(
        runtime.spec.binary_path.parent().unwrap(),
        test.config.install_root.join("runtime/current"),
    )
    .unwrap();
    let keys = release_support::trusted_keys();
    verify_cache_with_keys(&test.config, &keys).await.unwrap();
    assert!(!test.config.state_db.exists());
    fs::write(&runtime.spec.binary_path, b"untrusted-runtime").unwrap();
    assert!(verify_cache_with_keys(&test.config, &keys).await.is_err());
    assert!(!test.config.state_db.exists());
    let plugin = test.config.install_root.join("runtime");
    let moved = test.directory.join("moved-runtime");
    fs::rename(&plugin, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &plugin).unwrap();
    assert!(verify_cache_with_keys(&test.config, &keys).await.is_err());
}

#[tokio::test]
async fn migration_preflight_reads_committed_wal_without_writing_it() {
    let test = Fixture::new();
    let runtime = test.runtime("1");
    let mut state = State::open(&test.config.state_db).unwrap();
    state.set_json("applied:runtime", &runtime).unwrap();
    let wal = PathBuf::from(format!("{}-wal", test.config.state_db.display()));
    let before = fs::read(&wal).unwrap();
    verify_cache_with_keys(&test.config, &release_support::trusted_keys())
        .await
        .unwrap();
    assert_eq!(before, fs::read(&wal).unwrap());
    assert_eq!(
        state
            .get_json::<Prepared>("applied:runtime")
            .unwrap()
            .unwrap()
            .spec
            .binary_path,
        runtime.spec.binary_path
    );
}

#[tokio::test]
async fn migration_preflight_checks_resumable_diagnostic_jobs() {
    let test = Fixture::new();
    let runtime = test.runtime("1");
    let mut state = State::open(&test.config.state_db).unwrap();
    let keys = release_support::trusted_keys();
    let proof = release_support::proof_for_archive(
        "runtime",
        "1",
        "runtime",
        b"cached-archive",
        b"fixture-runtime",
    );
    let mut job = sinan_protocol::DiagnosticJob {
        id: Uuid::new_v4(),
        plugin: "runtime".into(),
        version: "1".into(),
        artifact: sinan_protocol::Artifact {
            url: "http://127.0.0.1:1/unused".into(),
            sha256: release_support::hash(b"cached-archive"),
            proof: Some(proof),
        },
        timeout_secs: 30,
        resource_budget: None,
        expires_at: None,
        options: BTreeMap::new(),
    };
    state
        .set_json("diagnostics:active", &serde_json::json!({"Preparing":job}))
        .unwrap();
    verify_cache_with_keys(&test.config, &keys).await.unwrap();
    job.artifact.proof = None;
    state
        .set_json("diagnostics:active", &serde_json::json!({"Preparing":job}))
        .unwrap();
    assert!(verify_cache_with_keys(&test.config, &keys).await.is_err());
    let spec = sinan_adapter_sdk::DiagnosticSpec {
        id: job.id.to_string(),
        version: "1".into(),
        binary_path: runtime.spec.binary_path.clone(),
        job_dir: test.directory.join("diagnostic"),
        timeout_secs: 30,
        options: BTreeMap::new(),
    };
    let mut service = sinan_adapter_sdk::ServiceJob {
        unit: format!("sinan-diagnostic-{}.service", job.id),
        program: spec.binary_path.clone(),
        args: vec![],
        working_directory: spec.job_dir.clone(),
        timeout_secs: 30,
        memory_max: Default::default(),
        tasks_max: Default::default(),
        cpu_max_percent: Default::default(),
        cpu_weight: Default::default(),
        io_weight: Default::default(),
        oom_score_adjust: Default::default(),
    };
    state
        .set_json(
            "diagnostics:active",
            &serde_json::json!({"Started":{"spec":spec,"service":service,"plugin":"runtime"}}),
        )
        .unwrap();
    verify_cache_with_keys(&test.config, &keys).await.unwrap();
    service.program = PathBuf::from("/bin/false");
    state
        .set_json(
            "diagnostics:active",
            &serde_json::json!({"Started":{"spec":spec,"service":service,"plugin":"runtime"}}),
        )
        .unwrap();
    assert!(verify_cache_with_keys(&test.config, &keys).await.is_err());
}

#[tokio::test]
async fn installed_verification_rejects_a_signed_artifact_with_another_role_or_format() {
    let test = Fixture::new();
    let runtime = test.runtime("1");
    let directory = runtime.spec.binary_path.parent().unwrap();
    let keys = release_support::trusted_keys();
    release_support::install_proof(
        directory,
        &release_support::proof_for_archive(
            "diagnostic-fixture",
            "1",
            "runtime",
            b"cached-archive",
            b"fixture-runtime",
        ),
    );
    verify_binary_with_keys(
        &runtime.spec.binary_path,
        "diagnostic-fixture",
        "tar.gz",
        &keys,
    )
    .await
    .unwrap();
    assert!(
        verify_binary_with_keys(&runtime.spec.binary_path, "runtime", "tar.gz", &keys)
            .await
            .is_err()
    );
    let bytes = b"fixture-runtime";
    let proof = release_support::signed_release(vec![(
        release_support::entry("runtime", "1", "runtime", "raw", bytes, bytes),
        bytes.to_vec(),
    )]);
    release_support::install_proof(directory, &proof);
    verify_binary_with_keys(&runtime.spec.binary_path, "runtime", "raw", &keys)
        .await
        .unwrap();
    assert!(
        verify_binary_with_keys(&runtime.spec.binary_path, "runtime", "tar.gz", &keys)
            .await
            .is_err()
    );
}
