use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sinan_protocol::fleet::Operation;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub kind: String,
    pub service: Option<String>,
    pub timeout_secs: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_schedule_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub name: String,
    pub steps: Vec<Step>,
    pub batch_size: usize,
    pub concurrency: usize,
    pub pause_between_batches: bool,
    pub max_duration_secs: i64,
}

impl Step {
    pub fn is_runtime(&self) -> bool {
        self.kind == "singbox_retry_deployment"
    }
    pub fn is_panel(&self) -> bool {
        self.kind == "panel_backup"
    }
    pub fn is_fleet(&self) -> bool {
        !self.is_runtime() && !self.is_panel()
    }

    pub fn validate(&self) -> ApiResult<()> {
        if self.is_panel() {
            if self.service.is_some()
                || self.runtime_version.is_some()
                || self.backup_schedule_id.is_none()
                || !(60..=1800).contains(&self.timeout_secs)
            {
                return Err(ApiError::BadRequest(
                    "完整面板备份须选择已登记备份计划、60–1800秒预算，且不能附加服务或运行时参数"
                        .into(),
                ));
            }
            return Ok(());
        }
        if self.is_runtime() {
            if self.service.is_some()
                || self.backup_schedule_id.is_some()
                || self.runtime_version.as_deref() != Some("1.14.2")
                || !(1..=600).contains(&self.timeout_secs)
            {
                return Err(ApiError::BadRequest("部署步骤仅支持重新应用已签名的失败部署1.14.2，须为1–600秒且不能附加服务或备份参数".into()));
            }
            return Ok(());
        }
        if self.runtime_version.is_some() || self.backup_schedule_id.is_some() {
            return Err(ApiError::BadRequest(
                "此服务或盘点步骤不能附加其他执行器参数".into(),
            ));
        }
        self.operation().map(|_| ())
    }

    pub fn operation(&self) -> ApiResult<Operation> {
        if !(1..=600).contains(&self.timeout_secs) {
            return Err(ApiError::BadRequest("步骤超时须为 1–600 秒".into()));
        }
        let action = match self.kind.as_str() {
            "system_snapshot" if self.service.is_none() => {
                return Ok(Operation::Snapshot {});
            }
            "service_status" => "status",
            "service_start" => "start",
            "service_stop" => "stop",
            "service_restart" => "restart",
            _ => return Err(ApiError::BadRequest("不支持的固定操作类型".into())),
        };
        let service = self.service.as_deref().unwrap_or("");
        if service.is_empty()
            || service.len() > 128
            || service.starts_with('-')
            || !service
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'@' | b'_' | b'.' | b'-'))
        {
            return Err(ApiError::BadRequest("服务名无效".into()));
        }
        Ok(Operation::Service {
            unit: service.into(),
            action: action.into(),
        })
    }

    pub fn permission(&self) -> &'static str {
        if self.is_panel() {
            "recovery:write"
        } else if self.is_runtime() {
            "proxy:write"
        } else if self.kind == "system_snapshot" {
            "operations:read"
        } else if self.kind == "service_status" {
            "services:read"
        } else {
            "services:write"
        }
    }
}

impl Plan {
    pub fn validate(&self, targets: &[i64]) -> ApiResult<()> {
        label(&self.name, 128)?;
        if !(1..=256).contains(&targets.len())
            || targets.iter().any(|v| *v <= 0)
            || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
            || !(1..=16).contains(&self.steps.len())
            || !(1..=32).contains(&self.batch_size)
            || !(1..=16).contains(&self.concurrency)
            || self.concurrency > self.batch_size
            || !(60..=86400).contains(&self.max_duration_secs)
        {
            return Err(ApiError::BadRequest(
                "目标、步骤、并发、批次或总时长无效".into(),
            ));
        }
        for step in &self.steps {
            step.validate()?;
        }
        if self
            .steps
            .iter()
            .enumerate()
            .any(|(position, step)| step.is_panel() && position != 0)
        {
            return Err(ApiError::BadRequest(
                "完整面板备份只可作为唯一首步，同一任务生成一次恢复点，随后再执行首台及后续批次"
                    .into(),
            ));
        }
        Ok(())
    }
}

pub fn label(value: &str, limit: usize) -> ApiResult<()> {
    if value.trim().is_empty()
        || value.chars().count() > limit
        || value.chars().any(char::is_control)
    {
        Err(ApiError::BadRequest("文字为空、过长或包含控制字符".into()))
    } else {
        Ok(())
    }
}

pub fn digest(value: &Value) -> ApiResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(anyhow::Error::from)?)
    ))
}

pub fn batch(index: usize, size: usize) -> i32 {
    if index == 0 {
        0
    } else {
        (1 + (index - 1) / size) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_parameters_cannot_introduce_shell_or_option_syntax() {
        for service in ["--help", "foo;id", "$(id)", "../foo", "foo\nbar", "foo'bar"] {
            assert!(
                Step {
                    kind: "service_restart".into(),
                    service: Some(service.into()),
                    timeout_secs: 30,
                    runtime_version: None,
                    backup_schedule_id: None
                }
                .operation()
                .is_err()
            );
        }
        assert!(
            matches!(Step { kind: "service_status".into(), service: Some("demo@node.service".into()), timeout_secs: 30,runtime_version:None,backup_schedule_id:None }.operation().unwrap(),Operation::Service{unit,action} if unit=="demo@node.service" && action=="status")
        );
    }

    #[test]
    fn canary_is_separate_from_fixed_following_batches() {
        assert_eq!(
            (0..8).map(|v| batch(v, 3)).collect::<Vec<_>>(),
            vec![0, 1, 1, 1, 2, 2, 2, 3]
        );
    }

    #[test]
    fn executor_parameters_and_backup_barrier_are_explicit() {
        let legacy: Step = serde_json::from_value(
            serde_json::json!({"kind":"system_snapshot","service":null,"timeout_secs":30}),
        )
        .unwrap();
        assert!(legacy.validate().is_ok());
        let backup = Step {
            kind: "panel_backup".into(),
            service: None,
            timeout_secs: 600,
            runtime_version: None,
            backup_schedule_id: Some(Uuid::new_v4()),
        };
        assert!(backup.validate().is_ok());
        assert!(backup.operation().is_err());
        let mut plan = Plan {
            name: "TEST_ONLY deployment recovery point".into(),
            steps: vec![backup.clone(), legacy.clone()],
            batch_size: 2,
            concurrency: 1,
            pause_between_batches: true,
            max_duration_secs: 1800,
        };
        assert!(plan.validate(&[1, 2]).is_ok());
        plan.steps = vec![legacy, backup];
        assert!(plan.validate(&[1, 2]).is_err());
        let mut runtime = Step {
            kind: "singbox_retry_deployment".into(),
            service: None,
            timeout_secs: 300,
            runtime_version: Some("1.14.2".into()),
            backup_schedule_id: None,
        };
        assert!(runtime.validate().is_ok());
        runtime.runtime_version = Some("latest".into());
        assert!(runtime.validate().is_err());
        runtime.runtime_version = Some("1.14.2".into());
        runtime.service = Some("other.service".into());
        assert!(runtime.validate().is_err());
    }
}
