use super::*;
use sinan_protocol::{platform::ARTIFACT_TARGETS, platform::artifact_target};

pub(super) fn validate_targets(targets: &[String]) -> ApiResult<()> {
    if targets.is_empty()
        || targets.len() > ARTIFACT_TARGETS.len()
        || targets
            .iter()
            .any(|target| !ARTIFACT_TARGETS.contains(&target.as_str()))
        || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
    {
        return Err(ApiError::BadRequest(
            "请选择有效且不重复的服务器平台架构".into(),
        ));
    }
    Ok(())
}

pub(super) fn targets_from_info(info: &Value) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    let Some(arch) = info["arch"].as_str() else {
        return targets;
    };
    let os = info["os"].as_str().unwrap_or("linux");
    for libc in [
        info["libc"].as_str(),
        info["runtime_libc"].as_str().or(info["libc"].as_str()),
    ] {
        if let Some(target) = artifact_target(os, libc, arch) {
            targets.insert(target);
        }
    }
    if targets.is_empty() && os == "linux" && info["libc"].is_null() {
        // Older agents may report only the CPU architecture.
        match arch {
            "aarch64" | "arm64" => {
                targets.insert("arm64".into());
            }
            "x86_64" | "amd64" => {
                targets.insert("amd64".into());
            }
            _ => (),
        }
    }
    targets
}

pub(super) async fn default_targets(state: &AppState) -> ApiResult<Vec<String>> {
    let infos: Vec<Value> =
        sqlx::query_scalar("SELECT static_info FROM servers WHERE deleted_at IS NULL")
            .fetch_all(&state.pool)
            .await?;
    let mut targets: BTreeSet<_> = infos.iter().flat_map(targets_from_info).collect();
    if targets.is_empty() {
        targets.insert(sinan_protocol::release::native_target().map_err(invalid)?);
    }
    Ok(targets.into_iter().collect())
}

pub(super) fn candidates(target: &str, format: &str) -> Vec<String> {
    if matches!(target, "amd64" | "arm64") {
        // Architecture-only requests describe the original GNU host deployment.
        return if format == "raw" {
            vec![
                format!("linux-musl-{target}"),
                target.into(),
                format!("linux-gnu-{target}"),
            ]
        } else {
            vec![format!("linux-gnu-{target}"), target.into()]
        };
    }
    let mut candidates = vec![target.to_owned()];
    if let Some(arch) = target.strip_prefix("linux-gnu-") {
        if format == "raw" {
            candidates.push(format!("linux-musl-{arch}"));
        }
        candidates.push(arch.into());
    } else if let Some(arch) = target.strip_prefix("linux-musl-")
        && format == "raw"
    {
        // Original raw Linux artifacts are statically linked musl executables.
        candidates.push(arch.into());
    }
    candidates
}

pub(super) fn selected_paths(
    verified: &VerifiedRelease,
    targets: &[String],
) -> ApiResult<BTreeSet<String>> {
    validate_targets(targets)?;
    let mut components: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for entry in &verified.metadata().artifacts {
        components
            .entry((&entry.name, &entry.version))
            .or_default()
            .push(entry);
    }
    let mut paths = BTreeSet::new();
    for target in targets {
        let mut found = false;
        for entries in components.values() {
            let mut selected = None;
            for candidate in candidates(target, &entries[0].format) {
                if let Some(entry) = entries.iter().find(|entry| entry.arch == candidate) {
                    selected = Some(entry);
                    break;
                }
            }
            if let Some(entry) = selected {
                paths.insert(
                    canonical_path(&entry.name, &entry.version, &entry.arch).map_err(invalid)?,
                );
                found = true;
            }
        }
        if !found {
            return Err(ApiError::BadRequest(format!(
                "该发布不包含服务器平台架构 {target} 的兼容制品"
            )));
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_agent_and_runtime_abis_keep_one_cpu_architecture() {
        assert_eq!(
            targets_from_info(&json!({
                "os":"linux", "arch":"aarch64", "libc":"musl", "runtime_libc":"gnu"
            })),
            BTreeSet::from(["linux-gnu-arm64".into(), "linux-musl-arm64".into()])
        );
        assert!(targets_from_info(&json!({"arch":"riscv64"})).is_empty());
        assert_eq!(
            targets_from_info(&json!({"arch":"aarch64"})),
            BTreeSet::from(["arm64".into()])
        );
        assert!(targets_from_info(&json!({})).is_empty());
    }
}
