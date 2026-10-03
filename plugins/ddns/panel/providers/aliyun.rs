use super::*;
use crate::cloud_api::aliyun::Aliyun;

pub(super) struct AliDns(Aliyun);
impl AliDns {
    pub(super) fn new() -> Result<Self, Failure> {
        Ok(Self(Aliyun::new("alidns")?))
    }
    #[cfg(test)]
    pub(super) fn local(endpoint: &str) -> Self {
        Self(Aliyun::local("alidns", endpoint))
    }
    async fn call(
        &self,
        rule: &Rule,
        action: &str,
        params: &[(&str, String)],
    ) -> Result<Value, Failure> {
        self.0
            .call(&rule.access_key_id, &rule.access_key_secret, action, params)
            .await
    }
}

fn record(value: &Value) -> Result<Record, Failure> {
    let zone = text(value, "DomainName")?;
    let locked = value["Locked"]
        .as_bool()
        .ok_or(Failure::from("invalid_response"))?;
    Ok(Record {
        id: id(&value["RecordId"])?,
        name: full_name(&text(value, "RR")?, &zone).ok_or(Failure::from("invalid_response"))?,
        kind: text(value, "Type")?,
        line: text(value, "Line")?,
        values: vec![text(value, "Value")?],
        ttl: value["TTL"]
            .as_u64()
            .ok_or(Failure::from("invalid_response"))?,
        active: value["Status"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("enable"))
            && !locked,
        marker: None,
    })
}

impl AliDns {
    pub(super) async fn reconcile_guarded<G, Check, Checked>(
        &self,
        rule: &Rule,
        ip: IpAddr,
        mut check: Check,
    ) -> Result<Outcome, Failure>
    where
        Check: FnMut() -> Checked,
        Checked: Future<Output = Result<G, Failure>>,
    {
        let spec = &rule.config;
        let zone = self
            .call(
                rule,
                "DescribeDomainInfo",
                &[
                    ("DomainName", spec.zone_id.clone()),
                    ("NeedDetailAttributes", "true".into()),
                ],
            )
            .await?;
        if domain(&text(&zone, "DomainName")?).as_deref() != Some(spec.zone_id.as_str()) {
            return Err("zone_mismatch".into());
        }
        if zone["MinTtl"]
            .as_u64()
            .is_some_and(|ttl| u64::from(spec.ttl) < ttl)
        {
            return Err("ttl_not_supported".into());
        }
        let list = self
            .call(
                rule,
                "DescribeSubDomainRecords",
                &[
                    ("DomainName", spec.zone_id.clone()),
                    ("SubDomain", spec.record_name.clone()),
                    ("PageNumber", "1".into()),
                    ("PageSize", "100".into()),
                ],
            )
            .await?;
        let entries = list["DomainRecords"]["Record"]
            .as_array()
            .ok_or(Failure::from("invalid_response"))?;
        if list["TotalCount"].as_u64() != Some(entries.len() as u64)
            || entries.len() > 100
            || list["PageNumber"] != 1
        {
            return Err("record_conflict".into());
        }
        let records = entries.iter().map(record).collect::<Result<Vec<_>, _>>()?;
        let existing = choose(rule, &records, &spec.zone_id)?;
        if let Some(record) = existing.filter(|r| same(r, rule, ip)) {
            let _guard = check().await?;
            return Ok(Outcome {
                record_id: record.id.clone(),
                status: "unchanged",
            });
        }
        let mut params = vec![
            ("RR", relative(rule)),
            ("Type", spec.record_type.clone()),
            ("Value", ip.to_string()),
            ("TTL", spec.ttl.to_string()),
            ("Line", spec.line.clone()),
        ];
        let action = if let Some(record) = existing {
            params.push(("RecordId", record.id.clone()));
            "UpdateDomainRecord"
        } else {
            params.push(("DomainName", spec.zone_id.clone()));
            "AddDomainRecord"
        };
        let _guard = check().await?;
        let result = self.call(rule, action, &params).await?;
        let record_id = id(&result["RecordId"])?;
        if existing.is_some_and(|r| r.id != record_id) {
            return Err("invalid_response".into());
        }
        let result = self
            .call(
                rule,
                "DescribeDomainRecordInfo",
                &[("RecordId", record_id.clone())],
            )
            .await?;
        verify(record(&result)?, rule, &record_id, ip)
    }
}
