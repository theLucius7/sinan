use super::{Account, Cloud, Group, Resource, Snapshot};
use crate::plugins::cloud_api::Failure;
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

fn ids(value: &Value) -> Result<Vec<String>, Failure> {
    let values = value
        .as_array()
        .filter(|values| (1..=16).contains(&values.len()))
        .ok_or(Failure::from("invalid_response"))?;
    let mut ids = BTreeSet::new();
    for value in values {
        let id = value
            .as_str()
            .filter(|id| super::super::model::identifier(id, "sg-"))
            .ok_or(Failure::from("invalid_response"))?;
        if !ids.insert(id.to_owned()) {
            return Err("invalid_response".into());
        }
    }
    Ok(ids.into_iter().collect())
}
pub(super) async fn instance(
    cloud: &Cloud,
    account: &Account,
    resource: &Resource,
) -> Result<(String, Vec<String>), Failure> {
    let account = cloud.resolved_account(account).await?;
    let value = cloud
        .ecs
        .call(
            &account.access_key_id,
            &account.access_key_secret,
            "DescribeInstances",
            &[
                ("RegionId", resource.region.clone()),
                ("InstanceIds", json!([resource.cloud_id]).to_string()),
                ("PageSize", "10".into()),
            ],
        )
        .await?;
    let entries = value["Instances"]["Instance"]
        .as_array()
        .filter(|entries| entries.len() == 1)
        .ok_or(Failure::from("resource_not_found"))?;
    if value["TotalCount"] != 1
        || entries[0]["InstanceId"] != resource.cloud_id
        || entries[0]["RegionId"] != resource.region
        || value
            .get("NextToken")
            .is_some_and(|value| !value.is_null() && value != "")
    {
        return Err("resource_not_found".into());
    }
    let vpc = entries[0]["VpcAttributes"]["VpcId"]
        .as_str()
        .filter(|id| super::super::model::identifier(id, "vpc-"))
        .ok_or(Failure::from("unsupported_resource"))?;
    Ok((
        vpc.to_owned(),
        ids(&entries[0]["SecurityGroupIds"]["SecurityGroupId"])?,
    ))
}
pub(super) async fn group(
    cloud: &Cloud,
    account: &Account,
    resource: &Resource,
    id: &str,
    vpc: &str,
) -> Result<Group, Failure> {
    let resolved = cloud.resolved_account(account).await?;
    let value = cloud
        .ecs
        .call(
            &resolved.access_key_id,
            &resolved.access_key_secret,
            "DescribeSecurityGroupAttribute",
            &[
                ("RegionId", resource.region.clone()),
                ("SecurityGroupId", id.into()),
                ("Direction", "all".into()),
            ],
        )
        .await?;
    let permissions = value["Permissions"]["Permission"]
        .as_array()
        .filter(|rules| rules.len() <= 1024)
        .ok_or(Failure::from("invalid_response"))?;
    if value["SecurityGroupId"] != id
        || value["VpcId"] != vpc
        || value
            .get("NextToken")
            .is_some_and(|value| !value.is_null() && value != "")
        || serde_json::to_vec(permissions)
            .map_err(|_| Failure::from("invalid_response"))?
            .len()
            > 32768
    {
        return Err("unsupported_resource".into());
    }
    let kind = value["SecurityGroupType"]
        .as_str()
        .filter(|kind| matches!(*kind, "normal" | "enterprise"))
        .ok_or(Failure::from("unsupported_resource"))?;
    let inner_access_policy = value["InnerAccessPolicy"]
        .as_str()
        .filter(|policy| matches!(*policy, "Accept" | "Drop"))
        .ok_or(Failure::from("unsupported_resource"))?;
    // Canonical rule ordering makes snapshots stable without dropping provider evidence.
    let mut permissions = permissions.clone();
    permissions.sort_by_key(Value::to_string);
    Ok(Group {
        id: id.into(),
        vpc_id: vpc.into(),
        kind: kind.into(),
        inner_access_policy: inner_access_policy.into(),
        permissions: json!(permissions),
    })
}
pub(super) async fn snapshot(
    cloud: &Cloud,
    account: &Account,
    resource: &Resource,
    target: &[String],
) -> Result<(Snapshot, i64), Failure> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (vpc, current) = instance(cloud, account, resource).await?;
        let observed_at = sinan_protocol::now_timestamp();
        let union: BTreeSet<_> = current.iter().chain(target).cloned().collect();
        let mut groups = Vec::new();
        for id in union {
            groups.push(group(cloud, account, resource, &id, &vpc).await?);
        }
        Ok((
            Snapshot {
                resource_id: resource.id,
                account_id: account.id,
                account_revision: account.revision,
                resource_revision: resource.revision,
                instance_id: resource.cloud_id.clone(),
                region: resource.region.clone(),
                vpc_id: vpc,
                server_ids: Vec::new(),
                link_updated_at: None,
                current_groups: current,
                managed_groups: Vec::new(),
                protected_groups: Vec::new(),
                groups,
            },
            observed_at,
        ))
    })
    .await
    .unwrap_or(Err(Failure::from("request_timeout")))
}
pub(super) async fn change(
    cloud: &Cloud,
    account: &Account,
    resource: &Resource,
    action: &str,
    group: &str,
) -> Result<String, Failure> {
    let account = cloud.resolved_account(account).await?;
    let action = match action {
        "join" => "JoinSecurityGroup",
        "leave" => "LeaveSecurityGroup",
        _ => return Err("invalid_configuration".into()),
    };
    let value = cloud
        .ecs
        .call(
            &account.access_key_id,
            &account.access_key_secret,
            action,
            &[
                ("RegionId", resource.region.clone()),
                ("InstanceId", resource.cloud_id.clone()),
                ("SecurityGroupId", group.into()),
            ],
        )
        .await?;
    value["RequestId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(Failure::from("invalid_response"))
}
