use crate::Artifact;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// A fixed, registered diagnostic plugin task; never an arbitrary shell command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticJob {
    pub id: Uuid,
    pub plugin: String,
    pub version: String,
    pub artifact: Artifact,
    pub timeout_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_budget: Option<DiagnosticResourceBudget>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

/// A service-owned ceiling; an Agent may only tighten its adapter's local budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticResourceBudget {
    pub memory_max: u64,
    pub tasks_max: u32,
    /// Aggregate CPU ceiling: 100 is one logical CPU, independent of contention weight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_max_percent: Option<u32>,
    pub cpu_weight: u16,
    pub io_weight: u16,
    pub oom_score_adjust: i16,
}

impl DiagnosticResourceBudget {
    pub fn valid(&self) -> bool {
        (16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&self.memory_max)
            && (16..=256).contains(&self.tasks_max)
            && self
                .cpu_max_percent
                .is_none_or(|value| (1..=6400).contains(&value))
            && (1..=100).contains(&self.cpu_weight)
            && (1..=100).contains(&self.io_weight)
            && (500..=1000).contains(&self.oom_score_adjust)
    }
}

pub const DIAGNOSTIC_SERVICE_CAPABILITY: &str = "diagnostic:job-service";
pub const DIAGNOSTIC_CPU_CEILING_CAPABILITY: &str = "diagnostic:cpu-quota:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Running,
    Cleaning,
    Succeeded,
    Failed,
}

impl DiagnosticStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// Devices advertise this only when all execution outcomes await cleanup proof.
pub const DIAGNOSTIC_COMPLETION_CAPABILITY: &str = "diagnostic:confirmed-completion";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticUpdate {
    pub id: Uuid,
    pub status: DiagnosticStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<DiagnosticReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Devices advertise this only when diagnostic cleanup can be confirmed.
pub const DIAGNOSTIC_CANCEL_CAPABILITY: &str = "diagnostic:confirmed-cancel";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticCancelRequest {
    pub server_id: crate::ServerId,
    pub job: DiagnosticJob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticCancelResult {
    pub server_id: crate::ServerId,
    pub id: Uuid,
    pub plugin: String,
    pub confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<DiagnosticReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Chapters are uploaded independently of execution status and the legacy report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSectionUpdate {
    pub id: Uuid,
    pub name: String,
    pub text: String,
    pub complete: bool,
    pub revision: u64,
    pub collected_at: i64,
}

pub const DIAGNOSTIC_SECTIONS_CAPABILITY: &str = "diagnostic:report-sections";
pub const DIAGNOSTIC_SECTION_LIMIT: usize = 64 * 1024;
pub const DIAGNOSTIC_SECTION_COUNT: usize = 32;

impl DiagnosticSectionUpdate {
    pub fn valid(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= 64
            && self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            && !self.text.trim().is_empty()
            && self.text.len() <= DIAGNOSTIC_SECTION_LIMIT
            && (1..=i64::MAX as u64).contains(&self.revision)
            && self.collected_at > 0
    }
}
