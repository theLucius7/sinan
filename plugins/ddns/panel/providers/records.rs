use super::{aliyun::AliDns, huawei::Huawei, tencent::Tencent};
use crate::plugins::ddns::{
    cloudflare::{Cloudflare, Failure},
    dns_records::Request,
    model::{Provider, domain, identifier, token},
};
use reqwest::Method;
use serde_json::{Value, json};

pub(crate) struct RecordClient {
    pub provider: Provider,
    cloudflare: Cloudflare,
    aliyun: AliDns,
    tencent: Tencent,
    huawei: Huawei,
    key: String,
    secret: String,
}

impl RecordClient {
    pub(crate) fn new(provider: Provider, value: &Value) -> Result<Self, Failure> {
        let expected = match provider {
            Provider::Cloudflare => "cloudflare",
            Provider::Aliyun => "aliyun",
            Provider::Tencent => "tencent",
            Provider::Huawei => "huawei",
        };
        if value.get("provider").is_some_and(|value| value != expected) {
            return Err("invalid_configuration".into());
        }
        let (key, secret) = if provider == Provider::Cloudflare {
            (
                token(value["api_token"].as_str().unwrap_or_default())
                    .map_err(|_| Failure::from("authentication_failed"))?,
                String::new(),
            )
        } else {
            let key = value["access_key_id"].as_str().unwrap_or_default();
            let secret = value["access_key_secret"].as_str().unwrap_or_default();
            if !crate::plugins::cloud_api::credential(key)
                || !crate::plugins::cloud_api::credential(secret)
            {
                return Err("authentication_failed".into());
            }
            (key.into(), secret.into())
        };
        Ok(Self {
            provider,
            cloudflare: Cloudflare::new()?,
            aliyun: AliDns::new()?,
            tencent: Tencent::new()?,
            huawei: Huawei::new()?,
            key,
            secret,
        })
    }
    #[cfg(test)]
    pub(crate) fn local(provider: Provider, endpoint: &str) -> Self {
        Self {
            provider,
            cloudflare: Cloudflare::local(endpoint),
            aliyun: AliDns::local(endpoint),
            tencent: Tencent::local(endpoint),
            huawei: Huawei::local(endpoint),
            key: if provider == Provider::Cloudflare {
                "TEST_ONLY_TOKEN_VALUE"
            } else {
                "TEST_ONLY_ACCESS_ID"
            }
            .into(),
            secret: "TEST_ONLY_ACCESS_SECRET".into(),
        }
    }
    pub(super) async fn cf(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, Failure> {
        self.cloudflare
            .call(method, path, &self.key, query, body)
            .await
    }
    pub(super) async fn ali(
        &self,
        action: &str,
        params: &[(&str, String)],
    ) -> Result<Value, Failure> {
        self.aliyun
            .call_credentials(&self.key, &self.secret, action, params)
            .await
    }
    pub(super) async fn tc(&self, action: &str, body: Value) -> Result<Value, Failure> {
        self.tencent
            .call_credentials(&self.key, &self.secret, action, body)
            .await
    }
    pub(super) async fn hw(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, Failure> {
        self.huawei
            .call_credentials((&self.key, &self.secret), method, path, query, body)
            .await
    }
    pub(crate) async fn zone(&self, id: &str) -> Result<String, Failure> {
        match self.provider {
            Provider::Cloudflare => {
                if !identifier(id) {
                    return Err("invalid_configuration".into());
                }
                let result = self
                    .cf(Method::GET, &format!("zones/{id}"), &[], None)
                    .await?;
                if result["result"]["id"] != id || result["result"]["status"] != "active" {
                    return Err("zone_inactive".into());
                }
                result["result"]["name"]
                    .as_str()
                    .and_then(domain)
                    .ok_or("invalid_response".into())
            }
            Provider::Aliyun => {
                let result = self
                    .ali(
                        "DescribeDomainInfo",
                        &[
                            ("DomainName", id.into()),
                            ("NeedDetailAttributes", "true".into()),
                        ],
                    )
                    .await?;
                if result["DomainName"] != id {
                    return Err("zone_mismatch".into());
                }
                domain(id).ok_or("invalid_configuration".into())
            }
            Provider::Tencent => {
                let result = self.tc("DescribeDomain", json!({"Domain":id})).await?;
                if result["DomainInfo"]["Domain"] != id
                    || result["DomainInfo"]["Status"] != "ENABLE"
                {
                    return Err("zone_inactive".into());
                }
                domain(id).ok_or("invalid_configuration".into())
            }
            Provider::Huawei => {
                if !identifier(id) {
                    return Err("invalid_configuration".into());
                }
                let result = self
                    .hw(Method::GET, &format!("v2/zones/{id}"), &[], None)
                    .await?;
                if result["id"] != id
                    || result["zone_type"] != "public"
                    || result["status"] != "ACTIVE"
                {
                    return Err("zone_inactive".into());
                }
                result["name"]
                    .as_str()
                    .and_then(domain)
                    .ok_or("invalid_response".into())
            }
        }
    }
    pub(crate) async fn list(&self, zone: &str, owner: &str, page: u32) -> Result<Value, Failure> {
        super::record_reads::list(self, zone, owner, page).await
    }
    pub(crate) async fn find(
        &self,
        zone: &str,
        name: &str,
        owner: &str,
    ) -> Result<Vec<Value>, Failure> {
        super::record_reads::find(self, zone, name, owner).await
    }
    pub(crate) async fn get(&self, zone: &str, id: &str, owner: &str) -> Result<Value, Failure> {
        super::record_reads::get(self, zone, id, owner).await
    }
    pub(crate) async fn write(&self, request: &Request, zone_name: &str) -> Result<Value, Failure> {
        super::record_writes::write(self, request, zone_name).await
    }
}

pub(super) fn relative(name: &str, zone: &str) -> Result<String, Failure> {
    if name == zone {
        Ok("@".into())
    } else {
        name.strip_suffix(&format!(".{zone}"))
            .map(str::to_owned)
            .ok_or("zone_mismatch".into())
    }
}
pub(super) fn full(name: &str, zone: &str) -> String {
    if name == "@" {
        zone.into()
    } else {
        format!("{name}.{zone}")
    }
}
pub(super) fn canonical(
    value: &Value,
    provider: Provider,
    zone_name: &str,
) -> Result<Value, Failure> {
    let mut result = match provider {
        Provider::Cloudflare => crate::plugins::ddns::dns_record_spec::snapshot(value),
        Provider::Aliyun => {
            json!({"id":super::id(&value["RecordId"])? ,"name":full(value["RR"].as_str().ok_or(Failure::from("invalid_response"))?,zone_name),"type":value["Type"],"content":value["Value"],"ttl":value["TTL"],"line":value["Line"],"proxied":false,"provider_state":if value["Status"].as_str().is_some_and(|value|value.eq_ignore_ascii_case("enable")){"active"}else{"disabled"}})
        }
        Provider::Tencent => {
            let detail = value.get("SubDomain").is_some();
            json!({"id":super::id(&value[if detail{"Id"}else{"RecordId"}])?,"name":full(value[if detail{"SubDomain"}else{"Name"}].as_str().ok_or(Failure::from("invalid_response"))?,zone_name),"type":value[if detail{"RecordType"}else{"Type"}],"content":value["Value"],"ttl":value["TTL"],"line":value[if detail{"RecordLineId"}else{"LineId"}],"proxied":false,"provider_state":if value["Enabled"]==1||value["Status"]=="ENABLE"{"active"}else{"disabled"}})
        }
        Provider::Huawei => {
            let records = value["records"]
                .as_array()
                .ok_or(Failure::from("invalid_response"))?;
            let mut result = json!({"id":super::id(&value["id"])? ,"name":value["name"].as_str().map(|name|name.trim_end_matches('.').to_ascii_lowercase()),"type":value["type"],"ttl":value["ttl"],"proxied":false,"provider_state":if value["status"]=="ACTIVE"{"active"}else{"pending"}});
            if records.len() == 1 {
                result["content"] = records[0].clone();
                if result["type"] == "MX" {
                    let content = records[0]
                        .as_str()
                        .ok_or(Failure::from("invalid_response"))?;
                    let (priority, target) = content
                        .split_once(' ')
                        .ok_or(Failure::from("invalid_response"))?;
                    result["priority"] = priority
                        .parse::<u64>()
                        .map_err(|_| Failure::from("invalid_response"))?
                        .into();
                    result["content"] = target.trim().into();
                }
            } else {
                result["data"] = json!({"records":records});
            }
            if let Some(comment) = value["description"].as_str() {
                result["comment"] = comment.into();
            }
            result
        }
    };
    if matches!(provider, Provider::Aliyun | Provider::Tencent)
        && let Some(comment) = value["Remark"].as_str()
    {
        result["comment"] = comment.into();
    }
    if result["comment"].is_null() {
        result["comment"] = "".into();
    }
    if provider == Provider::Aliyun
        && let Some(locked) = value.get("Locked")
    {
        result["locked"] = locked.clone();
    }
    if provider == Provider::Tencent
        && let Some(weight) = value.get("Weight")
    {
        result["weight"] = weight.clone();
    }
    result["name"] =
        crate::plugins::ddns::dns_record_spec::name(result["name"].as_str().unwrap_or_default())
            .ok_or(Failure::from("invalid_response"))?
            .into();
    if result["id"].as_str().is_none_or(|id| {
        id.is_empty()
            || id.len() > 128
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || (matches!(provider, Provider::Cloudflare | Provider::Huawei) && !identifier(id))
            || (provider == Provider::Tencent && id.parse::<u64>().is_err())
    }) {
        return Err("invalid_response".into());
    }
    if result["name"]
        .as_str()
        .is_none_or(|name| name != zone_name && !name.ends_with(&format!(".{zone_name}")))
        || result["type"].as_str().is_none()
        || result["ttl"].as_u64().is_none()
    {
        return Err("invalid_response".into());
    }
    if matches!(provider, Provider::Aliyun | Provider::Tencent) && result["type"] == "MX" {
        if value[if provider == Provider::Aliyun {
            "Priority"
        } else {
            "MX"
        }]
        .as_u64()
        .is_none()
        {
            return Err("invalid_response".into());
        }
        result["priority"] = value[if provider == Provider::Aliyun {
            "Priority"
        } else {
            "MX"
        }]
        .clone();
    }
    if matches!(provider, Provider::Aliyun | Provider::Tencent) && result["line"].as_str().is_none()
    {
        return Err("invalid_response".into());
    }
    Ok(result)
}

#[cfg(test)]
#[path = "../tests/dns_records_multicloud.rs"]
mod tests;
