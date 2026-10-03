use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::Json};
use uuid::Uuid;

#[derive(Clone, Serialize, FromRow)]
pub(super) struct Account {
    pub id: Uuid,
    pub name: String,
    pub site: String,
    #[serde(skip)]
    pub access_key_id: String,
    #[serde(skip)]
    pub access_key_secret: String,
    pub credential_id: Option<Uuid>,
    pub enabled: bool,
    pub auto_enabled: bool,
    pub limit_gb: i64,
    pub revision: i64,
    pub bill: Option<Json<super::billing::Bill>>,
    pub traffic: Option<Json<super::billing::Traffic>>,
    pub traffic_error: Option<String>,
    pub error_code: Option<String>,
    pub next_run_at: i64,
    pub balance: Option<Json<super::costs::Balance>>,
    pub balance_error: Option<String>,
    pub balance_next_at: i64,
}

#[derive(Serialize, FromRow)]
pub(super) struct Resource {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub kind: String,
    pub region: String,
    pub cloud_id: String,
    pub auto_enabled: bool,
    pub cap_mbps: i64,
    pub revision: i64,
    pub snapshot: Option<Json<Snapshot>>,
    pub checked_at: Option<i64>,
    pub error_code: Option<String>,
    pub instance_bill: Option<Json<super::costs::InstanceBill>>,
    pub bill_error: Option<String>,
    pub bill_next_at: i64,
    pub power_policy: Json<super::power::Policy>,
    pub power_state: Option<Json<super::power::State>>,
    pub power_checked_at: Option<i64>,
    pub power_error: Option<String>,
    pub next_power_at: i64,
    pub manual_hold: bool,
    pub threshold_hold: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub bandwidth_mbps: i64,
    pub charge_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub kind: String,
    pub cloud_id: String,
    pub region: String,
    pub public_ip: String,
    pub bandwidth_mbps: i64,
    pub charge_type: String,
    pub resource_charge_type: String,
    pub status: String,
}

impl Target {
    pub fn validate(&self, before: &Snapshot) -> ApiResult<()> {
        if !(1..=100).contains(&self.bandwidth_mbps)
            || !matches!(self.charge_type.as_str(), "PayByTraffic" | "PayByBandwidth")
        {
            return Err(ApiError::BadRequest(
                "带宽范围为 1–100 Mbps，请选择有效计费方式".into(),
            ));
        }
        if before.kind == "eip" && self.charge_type != before.charge_type {
            return Err(ApiError::BadRequest(
                "EIP 计费转换请前往阿里云控制台；此接口只调整带宽".into(),
            ));
        }
        Ok(())
    }
    pub fn matches(&self, snapshot: &Snapshot) -> bool {
        self.bandwidth_mbps == snapshot.bandwidth_mbps && self.charge_type == snapshot.charge_type
    }
}

#[derive(Serialize, FromRow)]
pub(super) struct Operation {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub account_revision: i64,
    pub resource_revision: i64,
    pub before_state: Json<Snapshot>,
    pub target: Json<Target>,
    pub source: String,
    pub billing_cycle: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub updated_at: i64,
    pub next_check_at: i64,
    pub error_code: Option<String>,
    pub request_id: Option<String>,
}

pub(super) fn label(value: &str) -> ApiResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        Err(ApiError::BadRequest("名称须为 1–128 个字符".into()))
    } else {
        Ok(value.into())
    }
}

pub(super) fn identifier(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && (3..=80).contains(&value.len())
        && value
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-')
}

pub(super) fn message(code: &str) -> &'static str {
    match code {
        "authentication_failed" => "访问密钥无效或缺少权限",
        "credential_unavailable" => "集中云凭据已停用、用途不符或解密密钥缺失，请在凭据中心核对",
        "credential_invalid" => {
            "集中云凭据字段或提供方不符，需要阿里云 access_key_id 与 access_key_secret"
        }
        "capacity_unavailable" => "实例库存或抢占价格条件不足，保活冷却后再尝试",
        "insufficient_balance" => "账号余额不足或资源欠费，请前往阿里云核对",
        "resource_locked" => "实例已被云端锁定，暂不能启停",
        "request_rejected" => "云端明确拒绝本次启停请求，请核对状态与权限",
        "stop_mode_unsupported" => "节省停机需要按量付费 VPC 实例",
        "stop_mode_mismatch" => "实例已停止，但实际停机模式与请求不符；请在云端核对收费",
        "stop_mode_unknown" => "实例已停止，但云端未提供可核实的停机模式",
        "rate_limited" => "云服务限流，请稍后重试",
        "resource_not_found" => "未找到指定地域和标识的资源",
        "unsupported_resource" => "仅支持 ECS 固定公网 IP 和按量付费的独立 EIP；不操作共享带宽包",
        "resource_busy" => "云资源正在变更或状态不支持调整",
        "billing_incomplete" => "账单分页、单位或响应不完整，自动控制暂停",
        "state_changed" => "云资源或本地配置已变化，请重新预览",
        "policy_inactive" => "策略已关闭或当月账单不可用于自动控制",
        "request_timeout" | "network_error" | "response_error" => {
            "云端响应未确认，请核对结果后再操作"
        }
        "invalid_response" => "云服务响应与预期不符",
        "provider_rejected" => "云服务未接受请求，请检查资源限制与权限",
        "awaiting_confirmation" => "请求结果尚未核实，系统只读回状态，不重复提交",
        _ => "云接口暂时不可用",
    }
}
