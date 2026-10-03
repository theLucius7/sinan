use crate::{Config, artifacts::PanelClient};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_adapter_sdk::{Descriptor, Privileged, ServiceManager};
use sinan_protocol::fleet::{AccessPolicy, Job, Operation};
use std::path::Path;

fn path_allowed(
    config: &Config,
    local: &AccessPolicy,
    remote: &AccessPolicy,
    path: &str,
    write: bool,
) -> Result<()> {
    let path = Path::new(path);
    ensure!(
        path.is_absolute()
            && !path.components().any(|part| matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
        "invalid file path"
    );
    let protected = [
        config.identity_dir.clone(),
        config.state_db.clone(),
        config.agent_root.clone(),
        config.install_root.clone(),
    ];
    ensure!(
        !protected
            .iter()
            .any(|protected| path.starts_with(protected))
            && !["/proc", "/sys", "/dev"]
                .iter()
                .any(|protected| path.starts_with(protected)),
        "protected file scope"
    );
    for part in path.components() {
        let value = part.as_os_str().to_string_lossy().to_ascii_lowercase();
        ensure!(
            ![
                ".ssh",
                "shadow",
                "gshadow",
                "identity",
                "fleet-policy.json",
                "agent.toml"
            ]
            .contains(&value.as_str())
                && !value.ends_with(".key")
                && !value.ends_with(".pem")
                && !value.contains("credential")
                && !value.contains("secret"),
            "sensitive file access denied"
        );
    }
    let (left, right) = if write {
        (&local.write_directories, &remote.write_directories)
    } else {
        (&local.read_directories, &remote.read_directories)
    };
    ensure!(
        [left, right]
            .iter()
            .all(|scopes| scopes.iter().any(|scope| scope != "/"
                && Path::new(scope).is_absolute()
                && path.starts_with(scope))),
        "file is outside permitted directories"
    );
    Ok(())
}
fn service_allowed(local: &AccessPolicy, remote: &AccessPolicy, unit: &str) -> Result<()> {
    ensure!(
        local.services.contains(&unit.to_owned()) && remote.services.contains(&unit.to_owned()),
        "service is outside permitted scope"
    );
    Ok(())
}
async fn command(ops: &dyn Privileged, program: &str, args: Vec<String>) -> Result<Value> {
    let result = ops
        .execute_bounded(Path::new(program), &args, 15, 128 * 1024)
        .await?;
    ensure!(
        !result.timed_out && result.output.success,
        "inspection command failed: {}",
        result.output.stderr
    );
    Ok(
        json!({"stdout":result.output.stdout,"stderr":result.output.stderr,"truncated":result.truncated}),
    )
}
pub(super) async fn execute(
    config: &Config,
    local: &AccessPolicy,
    job: &Job,
    ops: &dyn Privileged,
    services: &dyn ServiceManager,
    client: &PanelClient,
    descriptors: &[Descriptor],
) -> Result<Value> {
    let remote = &job.policy;
    match &job.operation {
        Operation::Snapshot {} => {
            let mut results = serde_json::Map::new();
            for (name, program, args) in [
                ("system", "uname", vec!["-a".into()]),
                ("uptime", "uptime", vec![]),
                ("disk", "df", vec!["-P".into()]),
                ("memory", "free", vec!["-b".into()]),
            ] {
                results.insert(name.into(), command(ops, program, args).await?);
            }
            Ok(Value::Object(results))
        }
        Operation::Services {} => {
            let mut result = Vec::new();
            for unit in remote
                .services
                .iter()
                .filter(|unit| local.services.contains(unit))
            {
                result.push(json!({"unit":unit,"details":services.status_details(unit).await?}));
            }
            Ok(json!({"services":result}))
        }
        Operation::Service { unit, action } => {
            service_allowed(local, remote, unit)?;
            match action.as_str() {
                "status" => {}
                "start" => services.start(unit).await?,
                "stop" => services.stop(unit).await?,
                "restart" => services.restart(unit).await?,
                "enable" => services.set_startup(unit, true).await?,
                "disable" => services.set_startup(unit, false).await?,
                _ => anyhow::bail!("unsupported service action"),
            };
            Ok(json!({"unit":unit,"action":action,"details":services.status_details(unit).await?}))
        }
        Operation::Logs {
            unit,
            since,
            priority,
            search,
        } => {
            service_allowed(local, remote, unit)?;
            let logs = services.recent_logs(unit).await?;
            let lines: Vec<_> = logs
                .lines
                .into_iter()
                .filter(|line| {
                    since.is_none_or(|since| line.timestamp.is_some_and(|at| at >= since))
                        && priority
                            .is_none_or(|priority| line.priority.is_some_and(|p| p <= priority))
                        && line.text.contains(search)
                })
                .map(|line| json!({"at":line.timestamp,"priority":line.priority,"text":line.text}))
                .collect();
            Ok(
                json!({"lines":lines,"truncated":logs.truncated,"sampled_at":sinan_protocol::now_timestamp(),"bounded_recent_window":true}),
            )
        }
        Operation::Ports {} => command(ops, "ss", vec!["-H".into(), "-lntup".into()]).await,
        Operation::RuntimePermissions { module } => {
            ensure!(
                local.runtime_inspection && remote.runtime_inspection,
                "runtime inspection is outside permitted scope"
            );
            let matches: Vec<_> = descriptors
                .iter()
                .filter(|descriptor| {
                    descriptor.plugin_name == *module || descriptor.module == *module
                })
                .collect();
            ensure!(
                matches.len() == 1,
                "runtime inspection requires one registered module descriptor"
            );
            super::runtime_permissions::inspect(config, matches[0], ops, services).await
        }
        Operation::FileRead { path } => {
            path_allowed(config, local, remote, path, false)?;
            let maximum = local
                .maximum_file_bytes
                .min(remote.maximum_file_bytes)
                .min(256 * 1024);
            ensure!(maximum > 0, "file access budget has not been granted");
            let bytes = ops.read_managed_file(Path::new(path), maximum).await?;
            Ok(
                json!({"path":path,"bytes":bytes.len(),"content":STANDARD.encode(&bytes),"sha256":format!("{:x}",Sha256::digest(&bytes))}),
            )
        }
        Operation::FileInspect { path } => {
            path_allowed(config, local, remote, path, false)?;
            let maximum = local
                .maximum_file_bytes
                .min(remote.maximum_file_bytes)
                .min(256 * 1024);
            ensure!(maximum > 0, "file inspection budget has not been granted");
            Ok(
                json!({"path":path,"observation":ops.inspect_managed_file(Path::new(path),maximum).await?,"sampled_at":sinan_protocol::now_timestamp()}),
            )
        }
        Operation::FileUpload {
            path,
            content,
            sha256,
            previous_sha256,
        } => {
            path_allowed(config, local, remote, path, true)?;
            let maximum = local
                .maximum_file_bytes
                .min(remote.maximum_file_bytes)
                .min(256 * 1024);
            let bytes = STANDARD.decode(content)?;
            ensure!(
                maximum > 0 && bytes.len() <= maximum,
                "upload exceeds granted file budget"
            );
            ensure!(
                format!("{:x}", Sha256::digest(&bytes)) == *sha256,
                "uploaded file checksum mismatch"
            );
            ensure!(
                previous_sha256
                    .as_ref()
                    .is_none_or(|hash| hash.len() == 64
                        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())),
                "old file checksum is invalid"
            );
            let created = ops
                .upload_managed_file(Path::new(path), &bytes, previous_sha256.as_deref())
                .await?;
            Ok(
                json!({"path":path,"bytes":bytes.len(),"sha256":sha256,"created":created,"saved":true,"applied":false}),
            )
        }
        Operation::FileWrite {
            path,
            content,
            sha256,
            previous_sha256,
            syntax,
        } => {
            path_allowed(config, local, remote, path, true)?;
            let bytes = STANDARD.decode(content)?;
            ensure!(
                bytes.len()
                    <= local
                        .maximum_file_bytes
                        .min(remote.maximum_file_bytes)
                        .min(256 * 1024),
                "file exceeds access budget"
            );
            ensure!(
                format!("{:x}", Sha256::digest(&bytes)) == *sha256,
                "file checksum mismatch"
            );
            match syntax.as_str() {
                "json" => {
                    serde_json::from_slice::<Value>(&bytes)?;
                }
                "toml" => {
                    toml::from_str::<toml::Value>(std::str::from_utf8(&bytes)?)?;
                }
                "text" => {
                    std::str::from_utf8(&bytes)?;
                }
                _ => anyhow::bail!("unsupported syntax mode"),
            };
            ops.replace_managed_file(Path::new(path), &bytes, previous_sha256)
                .await?;
            Ok(
                json!({"path":path,"sha256":sha256,"saved":true,"applied":false,"service_reload_required":true}),
            )
        }
        Operation::SystemNetwork { operation } => {
            let action = operation["action"].as_str().unwrap_or("");
            let granted = if action.starts_with("mesh_") {
                local.private_mesh && remote.private_mesh
            } else if action.starts_with("tunnel_") {
                local.reverse_tunnel && remote.reverse_tunnel
            } else if action.starts_with("firewall_") {
                local.firewall && remote.firewall
            } else {
                action == "inventory" || local.system_network && remote.system_network
            };
            ensure!(
                granted,
                "requested network capability is not granted on both sides"
            );
            crate::system_network::execute(
                ops,
                config
                    .state_db
                    .parent()
                    .unwrap_or(Path::new("/var/lib/sinan/core")),
                operation,
            )
            .await
        }
        Operation::PortForward { operation } => {
            ensure!(
                local.port_forward && remote.port_forward,
                "port forwarding not granted"
            );
            crate::system_forwarding::execute(ops, operation).await
        }
        Operation::CertificateDeploy { deployment_id } => {
            ensure!(
                local.certificate_deploy && remote.certificate_deploy,
                "certificate deployment not granted"
            );
            let material: Value = client
                .get_json(&format!(
                    "/api/agent/v1/network-certificates/{deployment_id}/material"
                ))
                .await
                .map_err(|_| {
                    anyhow::anyhow!("certificate material could not be authorized or fetched")
                })?;
            for name in ["certificate_path", "private_key_path"] {
                let target = Path::new(
                    material[name]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("certificate deployment path missing"))?,
                );
                ensure!(
                    ![
                        &config.identity_dir,
                        &config.state_db,
                        &config.agent_root,
                        &config.install_root
                    ]
                    .iter()
                    .any(|protected| target.starts_with(protected)),
                    "certificate deployment path overlaps protected Agent material"
                );
            }
            crate::system_network::deploy_certificate(ops,services,local,remote,&material).await.map_err(|_|anyhow::anyhow!("certificate deployment failed; material was not retained in the task result"))
        }
        Operation::CertificateInspect { deployment_id } => {
            ensure!(
                local.certificate_deploy && remote.certificate_deploy,
                "certificate inspection not granted"
            );
            let material: Value = client
                .get_json(&format!(
                    "/api/agent/v1/network-certificates/{deployment_id}/inspection"
                ))
                .await
                .map_err(|_| {
                    anyhow::anyhow!("certificate inspection metadata could not be fetched")
                })?;
            let target = Path::new(
                material["certificate_path"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("certificate inspection path missing"))?,
            );
            ensure!(
                ![
                    &config.identity_dir,
                    &config.state_db,
                    &config.agent_root,
                    &config.install_root
                ]
                .iter()
                .any(|protected| target.starts_with(protected)),
                "certificate inspection path overlaps protected Agent material"
            );
            crate::system_network::inspect_certificate(ops, services, local, remote, &material)
                .await
                .map_err(|_| {
                    anyhow::anyhow!("certificate inspection failed; no material was retained")
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_scope_requires_both_grants_and_protects_identity() {
        let config = Config::default();
        let allowed = AccessPolicy {
            read_directories: vec!["/srv/example".into(), "/etc/sinan".into()],
            write_directories: vec!["/srv/example".into()],
            maximum_file_bytes: 4096,
            ..AccessPolicy::default()
        };
        assert!(path_allowed(&config, &allowed, &allowed, "/srv/example/app.json", false).is_ok());
        assert!(
            path_allowed(
                &config,
                &allowed,
                &AccessPolicy::default(),
                "/srv/example/app.json",
                false
            )
            .is_err()
        );
        assert!(
            path_allowed(
                &config,
                &allowed,
                &allowed,
                "/srv/example-other/app.json",
                false
            )
            .is_err()
        );
        assert!(
            path_allowed(
                &config,
                &allowed,
                &allowed,
                "/etc/sinan/identity/device.key",
                false
            )
            .is_err()
        );
        assert!(
            path_allowed(
                &config,
                &allowed,
                &allowed,
                "/srv/example/../private/app.json",
                false
            )
            .is_err()
        );
        assert!(
            path_allowed(
                &config,
                &allowed,
                &allowed,
                "/srv/example/certificate.pem",
                false
            )
            .is_err()
        );
    }
    #[test]
    fn service_scope_is_an_intersection() {
        let local = AccessPolicy {
            services: vec!["example.service".into()],
            ..AccessPolicy::default()
        };
        assert!(service_allowed(&local, &local, "example.service").is_ok());
        assert!(service_allowed(&local, &AccessPolicy::default(), "example.service").is_err());
        assert!(service_allowed(&local, &local, "other.service").is_err());
    }
}
