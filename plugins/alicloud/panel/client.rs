use super::{
    billing,
    model::{Account, Resource, Snapshot, Target},
};
use crate::plugins::cloud_api::{Failure, aliyun::Aliyun};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) struct Cloud {
    pool: Option<sqlx::PgPool>,
    pub(super) ecs: Aliyun,
    vpc: Aliyun,
    pub(super) bss: Aliyun,
    pub(super) bss_international: Aliyun,
    cdt: Aliyun,
}
impl Cloud {
    pub fn new(pool: &sqlx::PgPool) -> Result<Self, Failure> {
        Ok(Self {
            pool: Some(pool.clone()),
            ecs: Aliyun::new("ecs")?,
            vpc: Aliyun::new("vpc")?,
            bss: Aliyun::new("bss")?,
            bss_international: Aliyun::new("bss_international")?,
            cdt: Aliyun::new("cdt")?,
        })
    }
    #[cfg(test)]
    pub fn local(endpoint: &str) -> Self {
        Self {
            pool: None,
            ecs: Aliyun::local("ecs", endpoint),
            vpc: Aliyun::local("vpc", endpoint),
            bss: Aliyun::local("bss", endpoint),
            bss_international: Aliyun::local("bss_international", endpoint),
            cdt: Aliyun::local("cdt", endpoint),
        }
    }
    pub(super) async fn resolved_account(&self, account: &Account) -> Result<Account, Failure> {
        let mut resolved = account.clone();
        if let Some(id) = account.credential_id {
            let pool = self
                .pool
                .as_ref()
                .ok_or(Failure::from("credential_unavailable"))?;
            let value = crate::control_center::credentials::resolve_reference_pool(
                pool,
                id,
                "cloud",
                &format!("alicloud:{}", account.id),
            )
            .await
            .map_err(|_| Failure::from("credential_unavailable"))?;
            if value
                .get("provider")
                .and_then(Value::as_str)
                .is_some_and(|v| !matches!(v, "alicloud" | "aliyun"))
            {
                return Err("credential_invalid".into());
            }
            let key = value["access_key_id"]
                .as_str()
                .filter(|v| crate::plugins::cloud_api::credential(v))
                .ok_or(Failure::from("credential_invalid"))?;
            let secret = value["access_key_secret"]
                .as_str()
                .filter(|v| crate::plugins::cloud_api::credential(v))
                .ok_or(Failure::from("credential_invalid"))?;
            resolved.access_key_id = key.into();
            resolved.access_key_secret = secret.into();
        } else if !crate::plugins::cloud_api::credential(&account.access_key_id)
            || !crate::plugins::cloud_api::credential(&account.access_key_secret)
        {
            return Err("credential_invalid".into());
        }
        Ok(resolved)
    }
    pub async fn bill(&self, account: &Account, now: i64) -> Result<billing::Bill, Failure> {
        let resolved = self.resolved_account(account).await?;
        let account = &resolved;
        let service = if account.site == "international" {
            &self.bss_international
        } else {
            &self.bss
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            billing::query(service, account, now),
        )
        .await
        .unwrap_or(Err("request_timeout".into()))
    }
    pub async fn traffic(&self, account: &Account, now: i64) -> Result<billing::Traffic, Failure> {
        let resolved = self.resolved_account(account).await?;
        let account = &resolved;
        let result = self
            .cdt
            .call(
                &account.access_key_id,
                &account.access_key_secret,
                "ListCdtInternetTraffic",
                &[("RegionId", "cn-hongkong".into())],
            )
            .await?;
        billing::traffic(&result, now)
    }
    pub async fn snapshot(
        &self,
        account: &Account,
        resource: &Resource,
    ) -> Result<Snapshot, Failure> {
        let resolved = self.resolved_account(account).await?;
        let account = &resolved;
        let (service, action, params) = if resource.kind == "ecs" {
            (
                &self.ecs,
                "DescribeInstances",
                vec![
                    ("RegionId", resource.region.clone()),
                    ("InstanceIds", json!([resource.cloud_id]).to_string()),
                    ("MaxResults", "10".into()),
                ],
            )
        } else {
            (
                &self.vpc,
                "DescribeEipAddresses",
                vec![
                    ("RegionId", resource.region.clone()),
                    ("AllocationId", resource.cloud_id.clone()),
                    ("PageNumber", "1".into()),
                    ("PageSize", "100".into()),
                ],
            )
        };
        let result = service
            .call(
                &account.access_key_id,
                &account.access_key_secret,
                action,
                &params,
            )
            .await?;
        parse_snapshot(&result, resource)
    }
    pub async fn modify(
        &self,
        account: &Account,
        resource: &Resource,
        before: &Snapshot,
        target: &Target,
        operation_id: Uuid,
    ) -> Result<String, Failure> {
        let resolved = self.resolved_account(account).await?;
        let account = &resolved;
        let (service, action, mut params) = if resource.kind == "ecs" {
            (
                &self.ecs,
                "ModifyInstanceNetworkSpec",
                vec![
                    ("InstanceId", resource.cloud_id.clone()),
                    ("InternetMaxBandwidthOut", target.bandwidth_mbps.to_string()),
                    ("AllocatePublicIp", "false".into()),
                    ("AutoPay", "true".into()),
                    ("ClientToken", operation_id.to_string()),
                ],
            )
        } else {
            (
                &self.vpc,
                "ModifyEipAddressAttribute",
                vec![
                    ("AllocationId", resource.cloud_id.clone()),
                    ("Bandwidth", target.bandwidth_mbps.to_string()),
                ],
            )
        };
        params.push(("RegionId", resource.region.clone()));
        if resource.kind == "ecs" && target.charge_type != before.charge_type {
            params.push(("NetworkChargeType", target.charge_type.clone()));
        }
        let result = service
            .call(
                &account.access_key_id,
                &account.access_key_secret,
                action,
                &params,
            )
            .await?;
        text(&result, "RequestId")
    }
}

fn text(value: &Value, field: &str) -> Result<String, Failure> {
    value[field]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(Failure::from("invalid_response"))
}
fn blank(value: &Value) -> bool {
    value.is_null() || value == ""
}

fn parse_snapshot(result: &Value, resource: &Resource) -> Result<Snapshot, Failure> {
    let ecs = resource.kind == "ecs";
    let entries = if ecs {
        &result["Instances"]["Instance"]
    } else {
        &result["EipAddresses"]["EipAddress"]
    };
    let entries = entries
        .as_array()
        .ok_or(Failure::from("invalid_response"))?;
    if entries.len() != 1
        || result.get("TotalCount").is_some_and(|v| v != 1)
        || result.get("NextToken").is_some_and(|v| !blank(v))
    {
        return Err("resource_not_found".into());
    }
    let row = &entries[0];
    if row[if ecs { "InstanceId" } else { "AllocationId" }] != resource.cloud_id
        || row["RegionId"] != resource.region
    {
        return Err("resource_not_found".into());
    }
    let charge_type = text(row, "InternetChargeType")?;
    if !matches!(charge_type.as_str(), "PayByTraffic" | "PayByBandwidth") {
        return Err("unsupported_resource".into());
    }
    let status = text(row, "Status")?;
    if (ecs && !matches!(status.as_str(), "Running" | "Stopped"))
        || (!ecs && !matches!(status.as_str(), "Available" | "InUse"))
    {
        return Err("resource_busy".into());
    }
    let resource_charge_type = text(
        row,
        if ecs {
            "InstanceChargeType"
        } else {
            "ChargeType"
        },
    )?;
    let (public_ip, bandwidth_mbps) = if ecs {
        if !blank(&row["EipAddress"]["AllocationId"])
            || !matches!(resource_charge_type.as_str(), "PrePaid" | "PostPaid")
        {
            return Err("unsupported_resource".into());
        }
        let ips = row["PublicIpAddress"]["IpAddress"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or(Failure::from("unsupported_resource"))?;
        (
            ips[0]
                .as_str()
                .ok_or(Failure::from("invalid_response"))?
                .to_owned(),
            row["InternetMaxBandwidthOut"].as_i64(),
        )
    } else {
        if resource_charge_type != "PostPaid"
            || !blank(&row["BandwidthPackageId"])
            || (!blank(&row["Netmode"]) && row["Netmode"] != "public")
        {
            return Err("unsupported_resource".into());
        }
        (
            text(row, "IpAddress")?,
            row["Bandwidth"]
                .as_str()
                .and_then(|v| v.parse::<i64>().ok()),
        )
    };
    if public_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err("invalid_response".into());
    }
    let bandwidth_mbps = bandwidth_mbps
        .filter(|v| (0..=100000).contains(v))
        .ok_or(Failure::from("invalid_response"))?;
    Ok(Snapshot {
        kind: resource.kind.clone(),
        cloud_id: resource.cloud_id.clone(),
        region: resource.region.clone(),
        public_ip,
        bandwidth_mbps,
        charge_type,
        resource_charge_type,
        status,
    })
}
