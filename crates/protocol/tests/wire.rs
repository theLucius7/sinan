#![forbid(unsafe_code)]

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sinan_protocol::*;
use std::{collections::BTreeMap, fmt::Debug};
use uuid::Uuid;

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T) {
    let encoded = serde_json::to_vec(&value).unwrap();
    let decoded: T = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, value);
}

fn known_messages() -> Vec<Message> {
    let applied = BTreeMap::from([("runtime".to_string(), 7)]);
    let epoch = Uuid::from_u128(42);
    vec![
        Message::AuthChallenge(AuthChallenge {
            nonce: "base64-nonce".into(),
            server_time: 1_790_000_000,
        }),
        Message::AuthResponse(AuthResponse {
            server_id: 3,
            signature: "base64-signature".into(),
        }),
        Message::HelloAck(HelloAck {
            server_time: 1_790_000_000,
            session_token: "test-only-session".into(),
            session_expires_at: 1_790_003_600,
        }),
        Message::Hello(Hello {
            agent_version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: vec!["usage".into()],
            applied: applied.clone(),
        }),
        Message::Heartbeat(Heartbeat {
            applied,
            uptime_secs: 123,
        }),
        Message::TelemetryStatic(StaticInfo {
            os: None,
            libc: None,
            runtime_libc: None,
            ip_addresses: vec!["192.0.2.10".into(), "2001:db8::10".into()],
            interface_addresses: BTreeMap::new(),
            discovered_public_ips: Vec::new(),
            system: Some("Debian GNU/Linux 12".into()),
            kernel: Some("6.1.0".into()),
            arch: Some("amd64".into()),
            cpu_model: Some("Example CPU".into()),
            cpu_cores: Some(2),
            memory_total: Some(4_000_000_000),
            disk_total: Some(40_000_000_000),
            virtualization: Some("kvm".into()),
            hostname: Some("example-host".into()),
            agent_version: Some("0.1.0".into()),
            runtime_version: Some("1.14.2".into()),
            extra: BTreeMap::new(),
        }),
        Message::TelemetryMetrics(Metrics {
            swap_used: None,
            swap_total: None,
            processes: None,
            disks: Vec::new(),
            gpus: Vec::new(),
            cpu_percent: Some(12.5),
            memory_used: Some(1_000_000_000),
            load_1: Some(0.5),
            load_5: Some(0.4),
            load_15: Some(0.3),
            disk_used: Some(2_000_000_000),
            network_interfaces: BTreeMap::from([(
                "eth0".into(),
                NetworkMetrics {
                    received_bytes: Some(4000),
                    transmitted_bytes: Some(5000),
                    receive_bytes_per_sec: Some(50.0),
                    transmit_bytes_per_sec: Some(100.0),
                },
            )]),
            tcp_connections: Some(4),
            udp_connections: Some(2),
            uptime_secs: Some(123),
            extra: BTreeMap::new(),
        }),
        Message::ApplyResult(ApplyResult {
            module: "runtime".into(),
            rev: 7,
            op_id: Uuid::from_u128(1),
            status: ApplyStatus::Applied,
            healthy: true,
            error: None,
        }),
        Message::UsageBatch(UsageBatch {
            epoch,
            seq: 1,
            period_start: 1_790_000_000,
            period_end: 1_790_000_030,
            records: vec![UsageRecord {
                stat_name: "u1_n3".into(),
                uplink: 123,
                downlink: 456,
            }],
        }),
        Message::ManifestChanged(ManifestChanged { rev: 12 }),
        Message::UsageAck(UsageAck { epoch, seq: 1 }),
        Message::RetirementRequest(RetirementRequest { request_id: epoch }),
        Message::RetirementResult(RetirementResult {
            request_id: epoch,
            success: true,
            error: None,
            receipt: Some(RetirementReceipt {
                server_id: 3,
                request_id: epoch,
                signature: "test-only-receipt".into(),
            }),
        }),
    ]
}

#[test]
fn all_websocket_payloads_roundtrip_through_envelopes() {
    let messages = known_messages();
    assert_eq!(messages.len(), 13);
    for message in messages {
        let envelope = message.clone().into_envelope().unwrap();
        assert_eq!(envelope.message_type, message.message_type());
        assert_eq!(envelope.v, PROTOCOL_VERSION);
        assert!(!envelope.id.is_nil());
        assert!(envelope.ts > 0);
        let wire = serde_json::to_vec(&envelope).unwrap();
        let decoded: Envelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.decode().unwrap(), message);
    }
}

#[test]
fn all_http_payloads_roundtrip() {
    let artifact = Artifact {
        proof: None,
        url: "https://panel.example.invalid/api/agent/v1/artifacts/runtime/1.14.2/amd64".into(),
        sha256: "a".repeat(64),
    };
    let module = ModuleManifest {
        kernel_version: "1.14.2".into(),
        artifact: artifact.clone(),
        config_rev: 7,
        bundle_url: "https://panel.example.invalid/api/agent/v1/bundles/7".into(),
        bundle_sha256: "b".repeat(64),
        stats_listen: "127.0.0.1:18085".into(),
    };
    roundtrip(artifact);
    roundtrip(module.clone());
    roundtrip(Manifest {
        rev: 12,
        modules: BTreeMap::from([("runtime".into(), module)]),
    });
    roundtrip(Bundle {
        files: BTreeMap::from([("config.json".into(), "{\"inbounds\":[]}".into())]),
    });
    roundtrip(EnrollRequest {
        token: "test-only-enrollment".into(),
        device_public_key: "base64-public-key".into(),
        static_info: StaticInfo::default(),
    });
    roundtrip(EnrollResponse { server_id: 3 });
    roundtrip(ApplyResult {
        module: "runtime".into(),
        rev: 8,
        op_id: Uuid::from_u128(2),
        status: ApplyStatus::Failed,
        healthy: false,
        error: Some("health check failed".into()),
    });
}

#[test]
fn all_known_messages_ignore_unknown_envelope_and_payload_fields() {
    for message in known_messages() {
        let envelope = message.clone().into_envelope().unwrap();
        let mut wire = serde_json::to_value(envelope).unwrap();
        wire["new_envelope_field"] = json!({"enabled": true});
        wire["payload"]["new_payload_field"] = json!(123);
        let decoded: Envelope = serde_json::from_value(wire).unwrap();
        match decoded.decode().unwrap() {
            Message::TelemetryStatic(mut value) => {
                assert_eq!(value.extra.remove("new_payload_field"), Some(json!(123)));
                assert_eq!(Message::TelemetryStatic(value), message);
            }
            Message::TelemetryMetrics(mut value) => {
                assert_eq!(value.extra.remove("new_payload_field"), Some(json!(123)));
                assert_eq!(Message::TelemetryMetrics(value), message);
            }
            value => assert_eq!(value, message),
        }
    }
}

#[test]
fn unknown_message_is_preserved_and_does_not_block_following_messages() {
    let payload = json!({"future": [1, 2, 3]});
    let unknown = Envelope::new("future.notification", &payload).unwrap();
    let heartbeat = Envelope::new(
        "heartbeat",
        Heartbeat {
            applied: BTreeMap::new(),
            uptime_secs: 100,
        },
    )
    .unwrap();
    let decoded: Vec<Message> = [unknown, heartbeat]
        .iter()
        .map(|envelope| envelope.decode().unwrap())
        .collect();
    assert_eq!(
        decoded[0],
        Message::Unknown {
            message_type: "future.notification".into(),
            payload
        }
    );
    assert!(matches!(decoded[1], Message::Heartbeat(_)));
    assert_eq!(
        decoded[0]
            .clone()
            .into_envelope()
            .unwrap()
            .decode()
            .unwrap(),
        decoded[0]
    );
}

#[test]
fn missing_or_invalid_required_fields_are_rejected() {
    let missing = Envelope::new("heartbeat", json!({"applied": {}})).unwrap();
    assert!(missing.decode().is_err());
    let invalid = Envelope::new(
        "usage.ack",
        json!({"epoch": "not-a-uuid", "seq": "invalid"}),
    )
    .unwrap();
    assert!(invalid.decode().is_err());
    assert!(serde_json::from_value::<Envelope>(json!({"v": 1})).is_err());
}

#[test]
fn missing_metrics_are_omitted_without_inventing_zero_values() {
    assert_eq!(serde_json::to_value(Metrics::default()).unwrap(), json!({}));
    assert_eq!(
        serde_json::to_value(NetworkMetrics::default()).unwrap(),
        json!({})
    );
    assert_eq!(
        serde_json::to_value(StaticInfo::default()).unwrap(),
        json!({})
    );
    let measured_zero = Metrics {
        cpu_percent: Some(0.0),
        ..Metrics::default()
    };
    assert_eq!(
        serde_json::to_value(measured_zero).unwrap(),
        json!({"cpu_percent": 0.0})
    );
    let decoded: Metrics = serde_json::from_value(json!({"memory_used": 100})).unwrap();
    assert_eq!(decoded.memory_used, Some(100));
    assert_eq!(decoded.cpu_percent, None);
}

#[test]
fn manifest_and_bundle_match_the_documented_wire_shape() {
    let wire = json!({ "rev": 12, "modules": { "singbox": {
        "kernel_version": "1.14.2", "artifact": { "url": "/artifact", "sha256": "a".repeat(64) },
        "config_rev": 7, "bundle_url": "/bundle", "bundle_sha256": "b".repeat(64), "stats_listen": "127.0.0.1:18085"
    } } });
    let manifest: Manifest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(manifest).unwrap(), wire);
    let bundle: Bundle = serde_json::from_value(json!({"files": {"config.json": "{}"}})).unwrap();
    assert_eq!(bundle.files["config.json"], "{}");
}

#[test]
fn typed_payload_helper_and_wire_field_names_are_stable() {
    let envelope = Envelope::new("manifest.changed", ManifestChanged { rev: 9 }).unwrap();
    assert_eq!(
        envelope.to_payload::<ManifestChanged>().unwrap(),
        ManifestChanged { rev: 9 }
    );
    let wire: Value = serde_json::to_value(envelope).unwrap();
    assert_eq!(wire["type"], "manifest.changed");
    assert!(wire.get("message_type").is_none());
    assert_eq!(
        serde_json::to_value(ApplyStatus::Applied).unwrap(),
        "applied"
    );
    assert_eq!(serde_json::to_value(ApplyStatus::Failed).unwrap(), "failed");
}

#[test]
fn http_payloads_accept_unknown_fields() {
    let enrollment: EnrollRequest = serde_json::from_value(json!({
        "token": "test-only-enrollment", "device_public_key": "test-public-key",
        "static_info": {"future_os_detail": "supported"}, "new_field": true
    }))
    .unwrap();
    assert_eq!(
        enrollment.static_info.extra["future_os_detail"],
        "supported"
    );
    let response: EnrollResponse =
        serde_json::from_value(json!({"server_id": 3, "new_field": true})).unwrap();
    assert_eq!(response.server_id, 3);
    let manifest: Manifest =
        serde_json::from_value(json!({"rev": 1, "modules": {}, "new_field": true})).unwrap();
    assert_eq!(manifest.rev, 1);
    let bundle: Bundle =
        serde_json::from_value(json!({"files": {"config.json": "{}"}, "new_field": true})).unwrap();
    assert_eq!(bundle.files.len(), 1);
}

#[test]
fn diagnostic_http_payloads_roundtrip_and_accept_additive_fields() {
    let job = DiagnosticJob {
        id: Uuid::from_u128(99),
        plugin: "nodequality".into(),
        version: "upstream-commit".into(),
        artifact: Artifact {
            proof: None,
            url: "https://panel.example.invalid/api/agent/v1/artifacts/nodequality/upstream-commit/amd64".into(),
            sha256: "a".repeat(64),
        },
        timeout_secs: 1800,
        resource_budget:None,
        expires_at: Some(1_790_003_600),
        options: BTreeMap::from([
            ("ip_version".into(), "both".into()),
            ("upload_report".into(), "false".into()),
        ]),
    };
    roundtrip(job.clone());
    assert!(
        serde_json::to_value(&job)
            .unwrap()
            .get("resource_budget")
            .is_none()
    );
    let mut budgeted = job.clone();
    budgeted.resource_budget = Some(sinan_protocol::DiagnosticResourceBudget {
        memory_max: 64 * 1024 * 1024,
        tasks_max: 32,
        cpu_max_percent: None,
        cpu_weight: 10,
        io_weight: 10,
        oom_score_adjust: 500,
    });
    let mut unsafe_budget = serde_json::to_value(&budgeted).unwrap();
    unsafe_budget["resource_budget"]["command"] = json!("arbitrary-command");
    assert!(serde_json::from_value::<DiagnosticJob>(unsafe_budget).is_err());
    let legacy_budget = serde_json::to_value(&budgeted).unwrap();
    assert!(
        legacy_budget["resource_budget"]
            .get("cpu_max_percent")
            .is_none()
    );
    assert_eq!(
        serde_json::from_value::<DiagnosticJob>(legacy_budget).unwrap(),
        budgeted
    );
    budgeted.resource_budget.as_mut().unwrap().cpu_max_percent = Some(20);
    assert!(budgeted.resource_budget.as_ref().unwrap().valid());
    for rejected in [0, 6401] {
        let mut invalid = budgeted.resource_budget.clone().unwrap();
        invalid.cpu_max_percent = Some(rejected);
        assert!(!invalid.valid());
    }
    roundtrip(budgeted);
    let mut wire = serde_json::to_value(&job).unwrap();
    wire["future_option"] = json!(true);
    assert_eq!(serde_json::from_value::<DiagnosticJob>(wire).unwrap(), job);
    for status in [
        DiagnosticStatus::Running,
        DiagnosticStatus::Cleaning,
        DiagnosticStatus::Succeeded,
        DiagnosticStatus::Failed,
    ] {
        roundtrip(DiagnosticUpdate {
            id: job.id,
            status,
            report: Some(DiagnosticReport {
                text: "Example diagnostic report".into(),
                report_url: Some("https://nodequality.com/r/EXAMPLE_REPORT".into()),
            }),
            error: None,
        });
    }
    let old_info: StaticInfo = serde_json::from_value(json!({"arch":"amd64"})).unwrap();
    assert!(old_info.ip_addresses.is_empty());
    assert!(
        serde_json::to_value(old_info)
            .unwrap()
            .get("ip_addresses")
            .is_none()
    );
    assert!(serde_json::from_value::<DiagnosticJob>(json!({"plugin":"nodequality"})).is_err());
    assert!(
        serde_json::from_value::<DiagnosticUpdate>(json!({"id":job.id,"status":"queued"})).is_err()
    );
}

#[test]
fn cleaning_wire_retains_report_and_reason_without_claiming_completion() {
    let update = DiagnosticUpdate {
        id: Uuid::from_u128(199),
        status: DiagnosticStatus::Cleaning,
        report: Some(DiagnosticReport {
            text: "saved partial output".into(),
            report_url: None,
        }),
        error: Some("cleanup is awaiting process and mount confirmation".into()),
    };
    let wire = serde_json::to_value(&update).unwrap();
    assert_eq!(wire["status"], "cleaning");
    assert_eq!(
        serde_json::from_value::<DiagnosticUpdate>(wire).unwrap(),
        update
    );
    assert!(!DiagnosticStatus::Running.is_terminal());
    assert!(!DiagnosticStatus::Cleaning.is_terminal());
    assert!(DiagnosticStatus::Succeeded.is_terminal());
    assert!(DiagnosticStatus::Failed.is_terminal());
    assert_eq!(
        sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY,
        "diagnostic:confirmed-completion"
    );
    for status in ["queued", "cancel_requested", "cancelled"] {
        assert!(
            serde_json::from_value::<DiagnosticUpdate>(json!({
                "id": update.id,
                "status": status,
            }))
            .is_err()
        );
    }
}

#[test]
fn runtime_libc_preserves_absence_and_rejects_explicit_non_string_values() {
    let old: StaticInfo = serde_json::from_value(json!({"libc": "musl"})).unwrap();
    assert!(old.runtime_libc.is_none());
    assert!(
        serde_json::to_value(old)
            .unwrap()
            .get("runtime_libc")
            .is_none()
    );
    for value in ["gnu", "musl", "unknown"] {
        let info: StaticInfo =
            serde_json::from_value(json!({"libc": "musl", "runtime_libc": value})).unwrap();
        assert_eq!(info.libc.as_deref(), Some("musl"));
        assert_eq!(info.runtime_libc.as_deref(), Some(value));
        assert_eq!(serde_json::to_value(info).unwrap()["runtime_libc"], value);
    }
    for value in [json!(null), json!(false), json!(1), json!([]), json!({})] {
        assert!(
            serde_json::from_value::<StaticInfo>(json!({"libc":"gnu","runtime_libc":value}))
                .is_err()
        );
    }
}

#[test]
fn cancellation_messages_bind_known_tasks_and_require_explicit_confirmation() {
    let job = DiagnosticJob {
        resource_budget: None,
        id: Uuid::from_u128(19),
        plugin: "nodequality".into(),
        version: "fixed-version".into(),
        artifact: Artifact {
            url: "https://panel.example.invalid/fixed-artifact".into(),
            sha256: "a".repeat(64),
            proof: None,
        },
        timeout_secs: 1800,
        expires_at: Some(1_790_003_600),
        options: BTreeMap::new(),
    };
    let request = DiagnosticCancelRequest {
        server_id: 3,
        job: job.clone(),
    };
    let result = DiagnosticCancelResult {
        server_id: 3,
        id: job.id,
        plugin: job.plugin,
        confirmed: true,
        report: None,
        error: None,
    };
    for message in [
        Message::DiagnosticCancelRequest(request.clone()),
        Message::DiagnosticCancelResult(result.clone()),
    ] {
        let envelope = message.clone().into_envelope().unwrap();
        assert_eq!(envelope.decode().unwrap(), message);
        assert_eq!(envelope.message_type, message.message_type());
    }
    let mut arbitrary_unit = serde_json::to_value(request).unwrap();
    arbitrary_unit["unit"] = json!("unrelated.service");
    assert!(serde_json::from_value::<DiagnosticCancelRequest>(arbitrary_unit).is_err());
    let mut missing_confirmation = serde_json::to_value(result).unwrap();
    missing_confirmation
        .as_object_mut()
        .unwrap()
        .remove("confirmed");
    assert!(serde_json::from_value::<DiagnosticCancelResult>(missing_confirmation).is_err());
    assert!(
        serde_json::from_value::<DiagnosticUpdate>(
            json!({"id":Uuid::from_u128(19),"status":"cancelled"})
        )
        .is_err()
    );
}
