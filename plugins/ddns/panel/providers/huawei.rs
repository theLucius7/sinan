use super::*;
use crate::plugins::cloud_api::{signing, transport};
use serde_json::json;

pub(super) struct Huawei {
    client: reqwest::Client,
    endpoint: reqwest::Url,
}
impl Huawei {
    pub(super) fn new() -> Result<Self, Failure> {
        Ok(Self {
            client: transport::client()?,
            endpoint: reqwest::Url::parse("https://dns.myhuaweicloud.com/")
                .map_err(|_| Failure::from("client_error"))?,
        })
    }
    #[cfg(test)]
    pub(super) fn local(endpoint: &str) -> Self {
        let mut result = Self::new().unwrap();
        result.endpoint = reqwest::Url::parse(endpoint).unwrap();
        assert_eq!(result.endpoint.host_str(), Some("127.0.0.1"));
        result
    }
    async fn call(
        &self,
        rule: &Rule,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, Failure> {
        self.call_credentials(
            (&rule.access_key_id, &rule.access_key_secret),
            method,
            path,
            query,
            body,
        )
        .await
    }
    pub(super) async fn call_credentials(
        &self,
        credentials: (&str, &str),
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, Failure> {
        let (key, secret) = credentials;
        let mut url = self
            .endpoint
            .join(path)
            .map_err(|_| Failure::from("invalid_configuration"))?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v)));
        }
        let date = signing::iso_time(sinan_protocol::now_timestamp()).replace(['-', ':'], "");
        let body = body.map(|v| v.to_string()).unwrap_or_default();
        let auth = signing::huawei(key, secret, method.as_str(), &url, &body, &date);
        let response = transport::json(
            self.client
                .request(method, url)
                .header("content-type", "application/json")
                .header("x-sdk-date", date)
                .header("authorization", auth)
                .body(body),
        )
        .await?;
        if response.get("error_code").is_some() {
            return Err("provider_rejected".into());
        }
        Ok(response)
    }
}

fn record(value: &Value, zone: &str) -> Result<Record, Failure> {
    if text(value, "zone_id")? != zone {
        return Err("invalid_response".into());
    }
    Ok(Record {
        id: id(&value["id"])?,
        name: domain(&text(value, "name")?).ok_or(Failure::from("invalid_response"))?,
        kind: text(value, "type")?,
        line: String::new(),
        values: value["records"]
            .as_array()
            .ok_or(Failure::from("invalid_response"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(Failure::from("invalid_response"))
            })
            .collect::<Result<_, _>>()?,
        ttl: value["ttl"]
            .as_u64()
            .ok_or(Failure::from("invalid_response"))?,
        active: value["status"] == "ACTIVE",
        marker: value["description"].as_str().map(str::to_owned),
    })
}

impl Huawei {
    async fn read_records(&self, rule: &Rule) -> Result<(Vec<Record>, String), Failure> {
        use reqwest::Method;
        let spec = &rule.config;
        let zone_path = format!("v2/zones/{}", spec.zone_id);
        let zone = self.call(rule, Method::GET, &zone_path, &[], None).await?;
        let zone_name = domain(&text(&zone, "name")?).ok_or(Failure::from("invalid_response"))?;
        if zone["id"] != spec.zone_id || zone["zone_type"] != "public" || zone["status"] != "ACTIVE"
        {
            return Err("zone_inactive".into());
        }
        if spec.record_name != zone_name && !spec.record_name.ends_with(&format!(".{zone_name}")) {
            return Err("zone_mismatch".into());
        }
        let path = format!("{zone_path}/recordsets");
        let list = self
            .call(
                rule,
                Method::GET,
                &path,
                &[
                    ("name", format!("{}.", spec.record_name)),
                    ("search_mode", "equal".into()),
                    ("limit", "100".into()),
                    ("offset", "0".into()),
                ],
                None,
            )
            .await?;
        let entries = list["recordsets"]
            .as_array()
            .ok_or(Failure::from("invalid_response"))?;
        if list.get("links").is_some_and(|links| !links.is_object())
            || list["links"]
                .get("next")
                .is_some_and(|next| !next.is_string())
        {
            return Err("invalid_response".into());
        }
        if list["metadata"]["total_count"].as_u64() != Some(entries.len() as u64)
            || entries.len() > 100
            || list["links"]["next"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
        {
            return Err("record_conflict".into());
        }
        if entries.iter().any(|r| {
            matches!(
                r["status"].as_str(),
                Some("PENDING_CREATE" | "PENDING_UPDATE" | "PENDING_DELETE")
            )
        }) {
            return Err("provider_pending".into());
        }
        let records = entries
            .iter()
            .map(|v| record(v, &spec.zone_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((records, zone_name))
    }

    pub(super) async fn inspect(&self, rule: &Rule) -> Result<Option<Snapshot>, Failure> {
        let (records, zone) = self.read_records(rule).await?;
        let existing = choose(rule, &records, &zone)?;
        Ok(existing.map(Record::snapshot))
    }

    pub(super) async fn reconcile_expected_guarded<G, Check, Checked>(
        &self,
        rule: &Rule,
        ip: IpAddr,
        expected: Option<&Snapshot>,
        mut check: Check,
    ) -> Result<Outcome, Failure>
    where
        Check: FnMut() -> Checked,
        Checked: Future<Output = Result<G, Failure>>,
    {
        use reqwest::Method;
        let spec = &rule.config;
        let (records, zone) = self.read_records(rule).await?;
        let existing = choose(rule, &records, &zone)?;
        let current = existing.map(Record::snapshot);
        expected_matches(current.as_ref(), expected)?;
        if let Some(record) = existing.filter(|r| same(r, rule, ip)) {
            let _guard = check().await?;
            return Ok(Outcome {
                record_id: record.id.clone(),
                status: "unchanged",
            });
        }
        let path = format!("v2/zones/{}/recordsets", spec.zone_id);
        let mut body = json!({"name":format!("{}.",spec.record_name),"type":spec.record_type,"records":[ip.to_string()],"ttl":spec.ttl});
        let (method, path) = if let Some(record) = existing {
            // Omit unrelated metadata: a read-time description must not overwrite
            // an administrator's later change while DDNS updates the address.
            (Method::PUT, format!("{path}/{}", record.id))
        } else {
            body["description"] = format!("sinan-ddns:{}", rule.id).into();
            (Method::POST, path)
        };
        let _guard = check().await?;
        let result = self.call(rule, method, &path, &[], Some(body)).await?;
        let record_id = id(&result["id"])?;
        if existing.is_some_and(|r| r.id != record_id) {
            return Err("invalid_response".into());
        }
        let written = record(&result, &spec.zone_id)?;
        if existing.is_none()
            && written.marker.as_deref() != Some(format!("sinan-ddns:{}", rule.id).as_str())
        {
            return Err("invalid_response".into());
        }
        // Huawei acknowledges asynchronous changes. The next round confirms ACTIVE.
        if written.values.len() == 1
            && same(&written, rule, ip)
            && written.name == spec.record_name
            && written.kind == spec.record_type
            && matches!(
                result["status"].as_str(),
                Some("PENDING_CREATE" | "PENDING_UPDATE")
            )
        {
            return Ok(Outcome {
                record_id,
                status: "submitted",
            });
        }
        verify(written, rule, &record_id, ip)
    }
}
