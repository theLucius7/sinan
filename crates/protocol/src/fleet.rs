use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const OPERATIONS_CAPABILITY: &str = "fleet:operations:v1";
pub const TERMINAL_CAPABILITY: &str = "fleet:terminal:pty:v1";
pub const RUNTIME_PREFLIGHT_CAPABILITY: &str = "fleet:runtime-preflight:v1";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessPolicy {
    pub terminal_accounts: Vec<String>,
    pub services: Vec<String>,
    pub read_directories: Vec<String>,
    pub write_directories: Vec<String>,
    pub maximum_file_bytes: usize,
    pub system_network: bool,
    pub port_forward: bool,
    pub private_mesh: bool,
    pub reverse_tunnel: bool,
    pub firewall: bool,
    pub certificate_deploy: bool,
    #[serde(skip_serializing_if = "disabled")]
    pub runtime_inspection: bool,
}

fn disabled(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Snapshot {},
    Services {},
    Service {
        unit: String,
        action: String,
    },
    Logs {
        unit: String,
        since: Option<i64>,
        priority: Option<u8>,
        search: String,
    },
    Ports {},
    RuntimePermissions {
        module: String,
    },
    FileRead {
        path: String,
    },
    FileInspect {
        path: String,
    },
    FileUpload {
        path: String,
        content: String,
        sha256: String,
        previous_sha256: Option<String>,
    },
    FileWrite {
        path: String,
        content: String,
        sha256: String,
        previous_sha256: String,
        syntax: String,
    },
    SystemNetwork {
        operation: Value,
    },
    PortForward {
        operation: Value,
    },
    CertificateDeploy {
        deployment_id: Uuid,
    },
    CertificateInspect {
        deployment_id: Uuid,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub operation: Operation,
    pub policy: AccessPolicy,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobResult {
    pub id: Uuid,
    pub succeeded: bool,
    pub result: Value,
    pub error: Option<String>,
    pub completed_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminalControl {
    pub id: Uuid,
    pub account: String,
    pub policy: AccessPolicy,
    pub columns: u16,
    pub rows: u16,
    pub expires_at: i64,
    pub close_requested: bool,
    pub output_sequence: i64,
    pub inputs: Vec<TerminalInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminalInput {
    pub sequence: i64,
    pub data: String,
    pub columns: Option<u16>,
    pub rows: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminalEvent {
    pub id: Uuid,
    pub sequence: i64,
    pub input_sequence: i64,
    pub output: String,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Work {
    pub jobs: Vec<Job>,
    pub terminals: Vec<TerminalControl>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_policy_defaults_do_not_enable_remote_controls() {
        let policy: AccessPolicy = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(policy.terminal_accounts.is_empty());
        assert!(policy.services.is_empty());
        assert!(policy.write_directories.is_empty());
        assert_eq!(policy.maximum_file_bytes, 0);
        assert!(!policy.system_network);
        assert!(!policy.port_forward);
        assert!(!policy.runtime_inspection);
        assert!(
            serde_json::to_value(&policy)
                .unwrap()
                .get("runtime_inspection")
                .is_none()
        );
        let enabled: AccessPolicy =
            serde_json::from_value(serde_json::json!({"runtime_inspection":true})).unwrap();
        assert_eq!(
            serde_json::to_value(enabled).unwrap()["runtime_inspection"],
            true
        );
    }
    #[test]
    fn arbitrary_shell_and_unrecognized_operation_fields_are_rejected() {
        assert!(
            serde_json::from_value::<Operation>(
                serde_json::json!({"kind":"command","command":"id"})
            )
            .is_err()
        );
        for (kind, operation) in [
            ("snapshot", Operation::Snapshot {}),
            ("services", Operation::Services {}),
            ("ports", Operation::Ports {}),
        ] {
            let wire = serde_json::json!({"kind":kind});
            assert_eq!(serde_json::to_value(operation).unwrap(), wire);
            let decoded: Operation = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
            for field in ["command", "unexpected"] {
                let mut invalid = wire.clone();
                invalid[field] = serde_json::json!("id");
                assert!(
                    serde_json::from_value::<Operation>(invalid).is_err(),
                    "{kind} must reject the unrecognized {field} field"
                );
            }
        }
        assert!(
            serde_json::from_value::<Operation>(
                serde_json::json!({"kind":"service","unit":"example.service","action":"status"})
            )
            .is_ok()
        );
    }
}
