use super::super::{
    client::Cloud,
    model::{Account, Resource},
};
use crate::cloud_api::Failure;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in super::super) struct State {
    pub cloud_id: String,
    pub region: String,
    pub status: String,
    pub stopped_mode: Option<String>,
    pub charge_type: String,
    pub network_type: String,
    pub spot_strategy: String,
    pub interruption_behavior: Option<String>,
    pub public_ips: Vec<String>,
    pub locked: bool,
}
impl State {
    pub fn spot(&self) -> bool {
        matches!(
            self.spot_strategy.as_str(),
            "SpotWithPriceLimit" | "SpotAsPriceGo"
        )
    }
    pub fn validate(&self, action: &str, mode: &str) -> Result<(), Failure> {
        if self.locked {
            return Err("resource_locked".into());
        }
        if !matches!(self.status.as_str(), "Running" | "Stopped") {
            return Err("resource_busy".into());
        }
        if action == "stop"
            && mode == "StopCharging"
            && (self.charge_type != "PostPaid" || self.network_type != "vpc")
        {
            return Err("stop_mode_unsupported".into());
        }
        Ok(())
    }
}
impl Cloud {
    pub(in super::super) async fn power_state(
        &self,
        account: &Account,
        resource: &Resource,
    ) -> Result<State, Failure> {
        if resource.kind != "ecs" {
            return Err("unsupported_resource".into());
        }
        let value = self
            .ecs
            .call(
                &account.access_key_id,
                &account.access_key_secret,
                "DescribeInstances",
                &[
                    ("RegionId", resource.region.clone()),
                    ("InstanceIds", json!([resource.cloud_id]).to_string()),
                    ("MaxResults", "10".into()),
                ],
            )
            .await?;
        parse(&value, resource)
    }
    pub(in super::super) async fn power_control(
        &self,
        account: &Account,
        resource: &Resource,
        action: &str,
        mode: &str,
    ) -> Result<String, Failure> {
        let mut params = vec![
            ("RegionId", resource.region.clone()),
            ("InstanceId", resource.cloud_id.clone()),
        ];
        if action == "stop" {
            params.extend([("ForceStop", "false".into()), ("StoppedMode", mode.into())]);
        } else {
            params.push(("InitLocalDisk", "false".into()));
        }
        let value = self
            .ecs
            .power_call(
                &account.access_key_id,
                &account.access_key_secret,
                if action == "stop" {
                    "StopInstance"
                } else {
                    "StartInstance"
                },
                &params,
            )
            .await?;
        value["RequestId"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .map(str::to_owned)
            .ok_or("invalid_response".into())
    }
}
fn field(value: &Value, key: &str) -> Result<String, Failure> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or("invalid_response".into())
}
fn parse(value: &Value, resource: &Resource) -> Result<State, Failure> {
    let rows = value["Instances"]["Instance"]
        .as_array()
        .ok_or(Failure::from("invalid_response"))?;
    if rows.len() != 1
        || value.get("TotalCount").is_some_and(|v| v != 1)
        || value
            .get("NextToken")
            .is_some_and(|v| !v.is_null() && v != "")
    {
        return Err("resource_not_found".into());
    }
    let row = &rows[0];
    if row["InstanceId"] != resource.cloud_id || row["RegionId"] != resource.region {
        return Err("resource_not_found".into());
    }
    let status = field(row, "Status")?;
    if !matches!(
        status.as_str(),
        "Running" | "Stopped" | "Starting" | "Stopping" | "Pending"
    ) {
        return Err("resource_busy".into());
    }
    let stopped_mode = row["StoppedMode"]
        .as_str()
        .filter(|v| super::policy::valid_mode(v))
        .map(str::to_owned);
    let charge_type = field(row, "InstanceChargeType")?;
    let network_type = field(row, "InstanceNetworkType")?;
    let spot_strategy = field(row, "SpotStrategy")?;
    if !matches!(charge_type.as_str(), "PrePaid" | "PostPaid")
        || !matches!(network_type.as_str(), "vpc" | "classic")
        || !matches!(
            spot_strategy.as_str(),
            "NoSpot" | "SpotWithPriceLimit" | "SpotAsPriceGo"
        )
    {
        return Err("invalid_response".into());
    }
    let public_ips: Vec<String> =
        serde_json::from_value(row["PublicIpAddress"]["IpAddress"].clone())
            .map_err(|_| Failure::from("invalid_response"))?;
    if public_ips.len() > 16
        || public_ips
            .iter()
            .any(|ip| ip.parse::<std::net::IpAddr>().is_err())
    {
        return Err("invalid_response".into());
    }
    let locks = row["OperationLocks"]["LockReason"]
        .as_array()
        .ok_or(Failure::from("invalid_response"))?;
    Ok(State {
        cloud_id: resource.cloud_id.clone(),
        region: resource.region.clone(),
        status,
        stopped_mode,
        charge_type,
        network_type,
        spot_strategy,
        interruption_behavior: row["SpotInterruptionBehavior"]
            .as_str()
            .filter(|v| matches!(*v, "Stop" | "Terminate"))
            .map(str::to_owned),
        public_ips,
        locked: !locks.is_empty(),
    })
}
