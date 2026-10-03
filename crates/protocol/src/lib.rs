#![forbid(unsafe_code)]

pub mod platform;
pub mod runtime_operations;
pub use runtime_operations::*;
pub mod runtime_validations;
pub use runtime_validations::*;
pub mod tasks;
pub mod upgrade;
pub use upgrade::{AgentRelease, release_version};
pub mod fleet;
pub mod telemetry;
pub use tasks::*;
pub use telemetry::{
    AgentSettings, DiskMetrics, GpuMetrics, TelemetryAck, TelemetryBatch, TelemetrySample,
};

mod diagnostics;
mod retirement;
pub mod runtime_control;
pub use diagnostics::*;
pub use retirement::*;
pub use runtime_control::*;
pub mod release;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const PROTOCOL_MIN: u16 = 1;
pub const PROTOCOL_MAX: u16 = 1;
pub type ServerId = i64;
pub type Revision = u64;
pub type AppliedRevisions = BTreeMap<String, Revision>;

/// Returns the current Unix timestamp in whole seconds.
pub fn now_timestamp() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u16,
    #[serde(rename = "type")]
    pub message_type: String,
    pub id: Uuid,
    pub ts: i64,
    pub payload: Value,
}

impl Envelope {
    pub fn new<T: Serialize>(
        message_type: impl Into<String>,
        payload: T,
    ) -> serde_json::Result<Self> {
        Ok(Self {
            v: PROTOCOL_VERSION,
            message_type: message_type.into(),
            id: Uuid::new_v4(),
            ts: now_timestamp(),
            payload: serde_json::to_value(payload)?,
        })
    }

    pub fn to_payload<T: DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_value(self.payload.clone())
    }

    /// Unknown message types remain available to callers for logging and ignoring.
    pub fn decode(&self) -> serde_json::Result<Message> {
        match self.message_type.as_str() {
            "auth.challenge" => self.to_payload().map(Message::AuthChallenge),
            "auth.response" => self.to_payload().map(Message::AuthResponse),
            "hello.ack" => self.to_payload().map(Message::HelloAck),
            "hello" => self.to_payload().map(Message::Hello),
            "heartbeat" => self.to_payload().map(Message::Heartbeat),
            "telemetry.static" => self.to_payload().map(Message::TelemetryStatic),
            "telemetry.metrics" => self.to_payload().map(Message::TelemetryMetrics),
            "apply.result" => self.to_payload().map(Message::ApplyResult),
            "runtime.checkpoint.request" => {
                self.to_payload().map(Message::RuntimeCheckpointRequest)
            }
            "runtime.checkpoint.result" => self.to_payload().map(Message::RuntimeCheckpointResult),
            "runtime.checkpoint.ack" => self.to_payload().map(Message::RuntimeCheckpointAck),
            "runtime.barrier.request" => self
                .to_payload()
                .map(Message::RuntimeRecoveryBarrierRequest),
            "runtime.barrier.result" => {
                self.to_payload().map(Message::RuntimeRecoveryBarrierResult)
            }
            "runtime.barrier.ack" => self.to_payload().map(Message::RuntimeRecoveryBarrierAck),
            "runtime.path_probe.request" => self.to_payload().map(Message::RuntimePathProbeRequest),
            "runtime.path_probe.result" => self.to_payload().map(Message::RuntimePathProbeResult),
            "runtime.path_probe.ack" => self.to_payload().map(Message::RuntimePathProbeAck),
            "usage.batch" => self.to_payload().map(Message::UsageBatch),
            "manifest.changed" => self.to_payload().map(Message::ManifestChanged),
            "diagnostic.cancel.request" => self.to_payload().map(Message::DiagnosticCancelRequest),
            "diagnostic.cancel.result" => self.to_payload().map(Message::DiagnosticCancelResult),
            "retirement.request" => self.to_payload().map(Message::RetirementRequest),
            "retirement.result" => self.to_payload().map(Message::RetirementResult),
            "usage.ack" => self.to_payload().map(Message::UsageAck),
            _ => Ok(Message::Unknown {
                message_type: self.message_type.clone(),
                payload: self.payload.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    AuthChallenge(AuthChallenge),
    AuthResponse(AuthResponse),
    HelloAck(HelloAck),
    Hello(Hello),
    Heartbeat(Heartbeat),
    TelemetryStatic(StaticInfo),
    TelemetryMetrics(Metrics),
    ApplyResult(ApplyResult),
    RuntimeCheckpointRequest(RuntimeCheckpointRequest),
    RuntimeCheckpointResult(RuntimeCheckpointResult),
    RuntimeCheckpointAck(RuntimeControlAck),
    RuntimeRecoveryBarrierRequest(RuntimeRecoveryBarrierRequest),
    RuntimeRecoveryBarrierResult(RuntimeRecoveryBarrierResult),
    RuntimeRecoveryBarrierAck(RuntimeControlAck),
    RuntimePathProbeRequest(RuntimePathProbeRequest),
    RuntimePathProbeResult(RuntimePathProbeResult),
    RuntimePathProbeAck(RuntimeControlAck),
    UsageBatch(UsageBatch),
    ManifestChanged(ManifestChanged),
    DiagnosticCancelRequest(DiagnosticCancelRequest),
    DiagnosticCancelResult(DiagnosticCancelResult),
    RetirementRequest(RetirementRequest),
    RetirementResult(RetirementResult),
    UsageAck(UsageAck),
    Unknown {
        message_type: String,
        payload: Value,
    },
}

impl Message {
    pub fn message_type(&self) -> &str {
        match self {
            Self::AuthChallenge(_) => "auth.challenge",
            Self::AuthResponse(_) => "auth.response",
            Self::HelloAck(_) => "hello.ack",
            Self::Hello(_) => "hello",
            Self::Heartbeat(_) => "heartbeat",
            Self::TelemetryStatic(_) => "telemetry.static",
            Self::TelemetryMetrics(_) => "telemetry.metrics",
            Self::ApplyResult(_) => "apply.result",
            Self::RuntimeCheckpointRequest(_) => "runtime.checkpoint.request",
            Self::RuntimeCheckpointResult(_) => "runtime.checkpoint.result",
            Self::RuntimeCheckpointAck(_) => "runtime.checkpoint.ack",
            Self::RuntimeRecoveryBarrierRequest(_) => "runtime.barrier.request",
            Self::RuntimeRecoveryBarrierResult(_) => "runtime.barrier.result",
            Self::RuntimeRecoveryBarrierAck(_) => "runtime.barrier.ack",
            Self::RuntimePathProbeRequest(_) => "runtime.path_probe.request",
            Self::RuntimePathProbeResult(_) => "runtime.path_probe.result",
            Self::RuntimePathProbeAck(_) => "runtime.path_probe.ack",
            Self::UsageBatch(_) => "usage.batch",
            Self::ManifestChanged(_) => "manifest.changed",
            Self::DiagnosticCancelRequest(_) => "diagnostic.cancel.request",
            Self::DiagnosticCancelResult(_) => "diagnostic.cancel.result",
            Self::RetirementRequest(_) => "retirement.request",
            Self::RetirementResult(_) => "retirement.result",
            Self::UsageAck(_) => "usage.ack",
            Self::Unknown { message_type, .. } => message_type,
        }
    }

    pub fn into_envelope(self) -> serde_json::Result<Envelope> {
        let payload = match &self {
            Self::AuthChallenge(value) => serde_json::to_value(value)?,
            Self::AuthResponse(value) => serde_json::to_value(value)?,
            Self::HelloAck(value) => serde_json::to_value(value)?,
            Self::Hello(value) => serde_json::to_value(value)?,
            Self::Heartbeat(value) => serde_json::to_value(value)?,
            Self::TelemetryStatic(value) => serde_json::to_value(value)?,
            Self::TelemetryMetrics(value) => serde_json::to_value(value)?,
            Self::ApplyResult(value) => serde_json::to_value(value)?,
            Self::RuntimeCheckpointRequest(value) => serde_json::to_value(value)?,
            Self::RuntimeCheckpointResult(value) => serde_json::to_value(value)?,
            Self::RuntimeCheckpointAck(value) => serde_json::to_value(value)?,
            Self::RuntimeRecoveryBarrierRequest(value) => serde_json::to_value(value)?,
            Self::RuntimeRecoveryBarrierResult(value) => serde_json::to_value(value)?,
            Self::RuntimeRecoveryBarrierAck(value) => serde_json::to_value(value)?,
            Self::RuntimePathProbeRequest(value) => serde_json::to_value(value)?,
            Self::RuntimePathProbeResult(value) => serde_json::to_value(value)?,
            Self::RuntimePathProbeAck(value) => serde_json::to_value(value)?,
            Self::UsageBatch(value) => serde_json::to_value(value)?,
            Self::ManifestChanged(value) => serde_json::to_value(value)?,
            Self::DiagnosticCancelRequest(value) => serde_json::to_value(value)?,
            Self::DiagnosticCancelResult(value) => serde_json::to_value(value)?,
            Self::RetirementRequest(value) => serde_json::to_value(value)?,
            Self::RetirementResult(value) => serde_json::to_value(value)?,
            Self::UsageAck(value) => serde_json::to_value(value)?,
            Self::Unknown { payload, .. } => payload.clone(),
        };
        Envelope::new(self.message_type(), payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
    pub server_time: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub server_id: ServerId,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    pub server_time: i64,
    pub session_token: String,
    pub session_expires_at: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub agent_version: String,
    pub protocol_version: u16,
    pub capabilities: Vec<String>,
    pub applied: AppliedRevisions,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub applied: AppliedRevisions,
    pub uptime_secs: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc: Option<String>,
    /// Host ABI used by separately installed runtimes, independent of the Agent ABI.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_runtime_libc"
    )]
    pub runtime_libc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub interface_addresses: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovered_public_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtualization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

fn deserialize_runtime_libc<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    // Absence means an older Agent; an explicit null must not become absence
    // after a telemetry message is decoded and saved by the panel.
    String::deserialize(deserializer).map(Some)
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_used: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<DiskMetrics>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpus: Vec<GpuMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_used: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_1: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_5: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_15: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_used: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_interfaces: BTreeMap<String, NetworkMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_connections: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_connections: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkMetrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmitted_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_bytes_per_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmit_bytes_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    Applied,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyResult {
    pub module: String,
    pub rev: Revision,
    pub op_id: Uuid,
    pub status: ApplyStatus,
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub stat_name: String,
    pub uplink: u64,
    pub downlink: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageBatch {
    pub epoch: Uuid,
    pub seq: u64,
    pub period_start: i64,
    pub period_end: i64,
    pub records: Vec<UsageRecord>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageAck {
    pub epoch: Uuid,
    pub seq: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChanged {
    pub rev: Revision,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub url: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<release::ReleaseProof>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleManifest {
    pub kernel_version: String,
    pub artifact: Artifact,
    pub config_rev: Revision,
    pub bundle_url: String,
    pub bundle_sha256: String,
    pub stats_listen: String,
}
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub rev: Revision,
    pub modules: BTreeMap<String, ModuleManifest>,
}
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub files: BTreeMap<String, String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub device_public_key: String,
    pub static_info: StaticInfo,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub server_id: ServerId,
}
