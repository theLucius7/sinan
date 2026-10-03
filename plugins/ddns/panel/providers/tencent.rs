use super::*;
use crate::cloud_api::{signing, transport};
use serde_json::json;

pub(super) struct Tencent {
    client: reqwest::Client,
    endpoint: String,
}
impl Tencent {
    pub(super) fn new() -> Result<Self, Failure> {
        Ok(Self {
            client: transport::client()?,
            endpoint: "https://dnspod.tencentcloudapi.com/".into(),
        })
    }
    #[cfg(test)]
    pub(super) fn local(endpoint: &str) -> Self {
        assert_eq!(
            reqwest::Url::parse(endpoint).unwrap().host_str(),
            Some("127.0.0.1")
        );
        let mut result = Self::new().unwrap();
        result.endpoint = endpoint.into();
        result
    }
    async fn call(&self, rule: &Rule, action: &str, body: Value) -> Result<Value, Failure> {
        let body = body.to_string();
        let timestamp = sinan_protocol::now_timestamp();
        let auth = signing::tencent(
            &rule.access_key_id,
            &rule.access_key_secret,
            "dnspod.tencentcloudapi.com",
            action,
            &body,
            timestamp,
        );
        let value = transport::json(
            self.client
                .post(&self.endpoint)
                .header("content-type", "application/json")
                .header("x-tc-action", action)
                .header("x-tc-version", "2021-03-23")
                .header("x-tc-timestamp", timestamp)
                .header("authorization", auth)
                .body(body),
        )
        .await?;
        let result = &value["Response"];
        if !result["Error"].is_null() {
            let code = result["Error"]["Code"].as_str().unwrap_or_default();
            return Err(if code.starts_with("RequestLimitExceeded") {
                "rate_limited"
            } else if code.starts_with("AuthFailure") || code.starts_with("Unauthorized") {
                "authentication_failed"
            } else {
                "provider_rejected"
            }
            .into());
        }
        text(result, "RequestId")?;
        Ok(result.clone())
    }
}

fn record(value: &Value, zone: &str, detail: bool) -> Result<Record, Failure> {
    if !value["Weight"].is_null() && value["Weight"].as_u64().is_none() {
        return Err("invalid_response".into());
    }
    Ok(Record {
        id: id(&value[if detail { "Id" } else { "RecordId" }])?,
        name: full_name(
            &text(value, if detail { "SubDomain" } else { "Name" })?,
            zone,
        )
        .ok_or(Failure::from("invalid_response"))?,
        kind: text(value, if detail { "RecordType" } else { "Type" })?,
        line: text(value, if detail { "RecordLineId" } else { "LineId" })?,
        values: vec![text(value, "Value")?],
        ttl: value["TTL"]
            .as_u64()
            .ok_or(Failure::from("invalid_response"))?,
        active: (if detail {
            value["Enabled"] == 1
        } else {
            value["Status"] == "ENABLE"
        }) && value["Weight"].as_u64().is_none_or(|weight| weight == 0),
        marker: None,
    })
}

impl Tencent {
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
            .call(rule, "DescribeDomain", json!({"Domain":spec.zone_id}))
            .await?;
        if domain(&text(&zone["DomainInfo"], "Domain")?).as_deref() != Some(spec.zone_id.as_str()) {
            return Err("zone_mismatch".into());
        }
        if zone["DomainInfo"]["Status"] != "ENABLE" {
            return Err("zone_inactive".into());
        }
        let list=self.call(rule,"DescribeRecordList",json!({"Domain":spec.zone_id,"SubDomain":relative(rule),"Limit":100,"Offset":0,"ErrorOnEmpty":"no"})).await?;
        let entries = list["RecordList"]
            .as_array()
            .ok_or(Failure::from("invalid_response"))?;
        if list["RecordCountInfo"]["TotalCount"].as_u64() != Some(entries.len() as u64)
            || entries.len() > 100
        {
            return Err("record_conflict".into());
        }
        let records = entries
            .iter()
            .map(|v| record(v, &spec.zone_id, false))
            .collect::<Result<Vec<_>, _>>()?;
        let existing = choose(rule, &records, &spec.zone_id)?;
        if let Some(record) = existing.filter(|r| same(r, rule, ip)) {
            let _guard = check().await?;
            return Ok(Outcome {
                record_id: record.id.clone(),
                status: "unchanged",
            });
        }
        let mut body = json!({"Domain":spec.zone_id,"SubDomain":relative(rule),"RecordType":spec.record_type,"RecordLine":"默认","RecordLineId":spec.line,"Value":ip.to_string(),"TTL":spec.ttl});
        let action = if let Some(record) = existing {
            body["RecordId"] = record
                .id
                .parse::<u64>()
                .map_err(|_| Failure::from("invalid_response"))?
                .into();
            "ModifyRecord"
        } else {
            "CreateRecord"
        };
        let _guard = check().await?;
        let result = self.call(rule, action, body).await?;
        let record_id = id(&result["RecordId"])?;
        if existing.is_some_and(|r| r.id != record_id) {
            return Err("invalid_response".into());
        }
        let result=self.call(rule,"DescribeRecord",json!({"Domain":spec.zone_id,"RecordId":record_id.parse::<u64>().map_err(|_|Failure::from("invalid_response"))?})).await?;
        verify(
            record(&result["RecordInfo"], &spec.zone_id, true)?,
            rule,
            &record_id,
            ip,
        )
    }
}
