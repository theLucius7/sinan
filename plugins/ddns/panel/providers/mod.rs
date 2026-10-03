mod aliyun;
mod huawei;
mod tencent;

use super::{
    cloudflare::{Cloudflare, Failure, Outcome},
    lifecycle::{Snapshot, expected_matches},
    model::{Provider, Rule, domain},
};
use serde_json::Value;
use std::{future::Future, net::IpAddr};

pub(super) struct Providers {
    cloudflare: Cloudflare,
    aliyun: aliyun::AliDns,
    tencent: tencent::Tencent,
    huawei: huawei::Huawei,
}

impl Providers {
    pub(super) fn new() -> Result<Self, Failure> {
        Ok(Self {
            cloudflare: Cloudflare::new()?,
            aliyun: aliyun::AliDns::new()?,
            tencent: tencent::Tencent::new()?,
            huawei: huawei::Huawei::new()?,
        })
    }

    #[cfg(test)]
    pub(super) async fn reconcile(&self, rule: &Rule, ip: IpAddr) -> Result<Outcome, Failure> {
        self.reconcile_guarded(rule, ip, || async { Ok(()) }).await
    }

    #[cfg(test)]
    pub(super) fn local(endpoint: &str) -> Self {
        Self {
            cloudflare: Cloudflare::local(endpoint),
            aliyun: aliyun::AliDns::local(endpoint),
            tencent: tencent::Tencent::local(endpoint),
            huawei: huawei::Huawei::local(endpoint),
        }
    }
}

impl Providers {
    #[cfg(test)]
    pub(super) async fn reconcile_guarded<G, Check, Checked>(
        &self,
        rule: &Rule,
        ip: IpAddr,
        check: Check,
    ) -> Result<Outcome, Failure>
    where
        Check: FnMut() -> Checked,
        Checked: Future<Output = Result<G, Failure>>,
    {
        self.reconcile_expected_guarded(rule, ip, None, check).await
    }

    pub(super) async fn inspect(&self, rule: &Rule) -> Result<Option<Snapshot>, Failure> {
        match rule.config.provider {
            Provider::Cloudflare => self.cloudflare.inspect(rule).await,
            Provider::Aliyun => self.aliyun.inspect(rule).await,
            Provider::Tencent => self.tencent.inspect(rule).await,
            Provider::Huawei => self.huawei.inspect(rule).await,
        }
    }

    pub(super) async fn reconcile_expected_guarded<G, Check, Checked>(
        &self,
        rule: &Rule,
        ip: IpAddr,
        expected: Option<&Snapshot>,
        check: Check,
    ) -> Result<Outcome, Failure>
    where
        Check: FnMut() -> Checked,
        Checked: Future<Output = Result<G, Failure>>,
    {
        match rule.config.provider {
            Provider::Cloudflare => {
                self.cloudflare
                    .reconcile_expected_guarded(rule, ip, expected, check)
                    .await
            }
            Provider::Aliyun => {
                self.aliyun
                    .reconcile_expected_guarded(rule, ip, expected, check)
                    .await
            }
            Provider::Tencent => {
                self.tencent
                    .reconcile_expected_guarded(rule, ip, expected, check)
                    .await
            }
            Provider::Huawei => {
                self.huawei
                    .reconcile_expected_guarded(rule, ip, expected, check)
                    .await
            }
        }
    }
}

#[derive(Clone)]
struct Record {
    id: String,
    name: String,
    kind: String,
    line: String,
    values: Vec<String>,
    ttl: u64,
    active: bool,
    marker: Option<String>,
}

impl Record {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind.clone(),
            line: self.line.clone(),
            values: self.values.clone(),
            ttl: self.ttl,
            proxied: false,
            active: self.active,
            marker: self.marker.clone(),
        }
    }
}

fn text(value: &Value, key: &str) -> Result<String, Failure> {
    value[key]
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or("invalid_response".into())
}

fn id(value: &Value) -> Result<String, Failure> {
    let id = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|v| v.to_string()))
        .ok_or(Failure::from("invalid_response"))?;
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid_response".into());
    }
    Ok(id)
}

fn relative(rule: &Rule) -> String {
    rule.config
        .record_name
        .strip_suffix(&format!(".{}", rule.config.zone_id))
        .unwrap_or("@")
        .into()
}

fn full_name(rr: &str, zone: &str) -> Option<String> {
    domain(&if rr == "@" {
        zone.into()
    } else {
        format!("{rr}.{zone}")
    })
}

fn choose<'a>(
    rule: &Rule,
    records: &'a [Record],
    zone: &str,
) -> Result<Option<&'a Record>, Failure> {
    if records.iter().any(|r| r.name != rule.config.record_name) {
        return Err("invalid_response".into());
    }
    if records
        .iter()
        .any(|r| r.kind == "CNAME" || (r.kind == "NS" && r.name != zone))
    {
        return Err("record_conflict".into());
    }
    let matching: Vec<_> = records
        .iter()
        .filter(|r| r.kind == rule.config.record_type && r.line == rule.config.line)
        .collect();
    if matching.len() > 1 {
        return Err("record_conflict".into());
    }
    let Some(record) = matching.first() else {
        return Ok(None);
    };
    if !record.active || record.values.len() != 1 {
        return Err("record_conflict".into());
    }
    let marker = format!("sinan-ddns:{}", rule.id);
    if rule.record_id.as_deref() != Some(&record.id)
        && record.marker.as_deref() != Some(&marker)
        && !rule.config.adopt_existing
    {
        return Err("record_not_owned".into());
    }
    Ok(Some(record))
}

fn same(record: &Record, rule: &Rule, ip: IpAddr) -> bool {
    record.values.len() == 1
        && record.values[0].parse::<IpAddr>().ok() == Some(ip)
        && record.ttl == u64::from(rule.config.ttl)
}

fn verify(record: Record, rule: &Rule, record_id: &str, ip: IpAddr) -> Result<Outcome, Failure> {
    if record.id != record_id
        || record.name != rule.config.record_name
        || record.kind != rule.config.record_type
        || record.line != rule.config.line
        || !same(&record, rule, ip)
    {
        return Err("invalid_response".into());
    }
    if !record.active {
        return Err("provider_pending".into());
    }
    Ok(Outcome {
        record_id: record.id,
        status: "updated",
    })
}

mod record_reads;
mod record_writes;
mod records;
pub(super) use records::RecordClient;
