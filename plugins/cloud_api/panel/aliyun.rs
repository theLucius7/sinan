use super::{Failure, signing, transport};
use serde_json::Value;
use std::collections::BTreeMap;

pub struct Aliyun {
    client: reqwest::Client,
    endpoint: String,
    version: &'static str,
}

impl Aliyun {
    pub fn new(service: &str) -> Result<Self, Failure> {
        let (host, version) = match service {
            "alidns" => ("alidns.aliyuncs.com", "2015-01-09"),
            "ecs" => ("ecs.aliyuncs.com", "2014-05-26"),
            "vpc" => ("vpc.aliyuncs.com", "2016-04-28"),
            "bss" => ("business.aliyuncs.com", "2017-12-14"),
            "bss_international" => ("business.ap-southeast-1.aliyuncs.com", "2017-12-14"),
            "cdt" => ("cdt.aliyuncs.com", "2021-08-13"),
            _ => return Err("invalid_configuration".into()),
        };
        Ok(Self {
            client: transport::client()?,
            endpoint: format!("https://{host}/"),
            version,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn local(service: &str, endpoint: &str) -> Self {
        assert_eq!(
            reqwest::Url::parse(endpoint).unwrap().host_str(),
            Some("127.0.0.1")
        );
        let mut result = Self::new(service).unwrap();
        result.endpoint = endpoint.into();
        result
    }

    pub async fn call(
        &self,
        id: &str,
        secret: &str,
        action: &str,
        parameters: &[(&str, String)],
    ) -> Result<Value, Failure> {
        self.request(id, secret, action, parameters, false).await
    }
    pub async fn power_call(
        &self,
        id: &str,
        secret: &str,
        action: &str,
        parameters: &[(&str, String)],
    ) -> Result<Value, Failure> {
        self.request(id, secret, action, parameters, true).await
    }
    async fn request(
        &self,
        id: &str,
        secret: &str,
        action: &str,
        parameters: &[(&str, String)],
        power: bool,
    ) -> Result<Value, Failure> {
        let mut values: BTreeMap<String, String> = parameters
            .iter()
            .map(|(k, v)| ((*k).into(), v.clone()))
            .collect();
        values.extend([
            ("Action".into(), action.into()),
            ("Version".into(), self.version.into()),
            ("Format".into(), "JSON".into()),
            ("AccessKeyId".into(), id.into()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureVersion".into(), "1.0".into()),
            ("SignatureNonce".into(), uuid::Uuid::new_v4().to_string()),
            (
                "Timestamp".into(),
                signing::iso_time(sinan_protocol::now_timestamp()),
            ),
        ]);
        let signature = signing::aliyun(secret, &values);
        values.insert("Signature".into(), signature);
        let request = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(signing::query(&values));
        let response = if power {
            transport::power_json(request).await?
        } else {
            transport::json(request).await?
        };
        if response
            .get("Code")
            .is_some_and(|code| code != "Success" && code != "200" && code != 200)
            || response.get("Success").is_some_and(|v| v != true)
        {
            let code = response["Code"].as_str().unwrap_or_default();
            return Err(if code.starts_with("Throttling") {
                "rate_limited"
            } else if code.contains("AccessKey")
                || code.contains("Signature")
                || code.contains("Forbidden")
            {
                "authentication_failed"
            } else {
                "provider_rejected"
            }
            .into());
        }
        if response["RequestId"].as_str().is_none_or(str::is_empty) {
            return Err("invalid_response".into());
        }
        Ok(response)
    }
}
