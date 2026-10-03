use super::QualityField;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityFieldKind {
    Text,
    CountryCode,
    Boolean,
    Score,
    Asn,
    Latitude,
    Longitude,
}

fn definitions(database: &str) -> &'static [(&'static str, &'static str, QualityFieldKind)] {
    match database {
        "ipregistry-v1" => &[
            ("/connection/asn", "ASN", QualityFieldKind::Asn),
            (
                "/connection/organization",
                "网络组织",
                QualityFieldKind::Text,
            ),
            ("/connection/type", "连接类型", QualityFieldKind::Text),
            (
                "/location/country/code",
                "国家代码",
                QualityFieldKind::CountryCode,
            ),
            ("/security/is_proxy", "代理", QualityFieldKind::Boolean),
            ("/security/is_tor", "Tor", QualityFieldKind::Boolean),
            ("/security/is_vpn", "VPN", QualityFieldKind::Boolean),
            ("/security/is_abuser", "滥用", QualityFieldKind::Boolean),
            (
                "/security/is_attacker",
                "攻击来源",
                QualityFieldKind::Boolean,
            ),
            (
                "/security/is_cloud_provider",
                "云服务商",
                QualityFieldKind::Boolean,
            ),
        ],
        "dbip-v2" => &[
            ("/countryCode", "国家代码", QualityFieldKind::CountryCode),
            ("/countryName", "国家或地区", QualityFieldKind::Text),
            ("/asNumber", "ASN", QualityFieldKind::Asn),
            ("/asName", "网络组织", QualityFieldKind::Text),
            ("/isp", "ISP", QualityFieldKind::Text),
            ("/usageType", "用途类型", QualityFieldKind::Text),
            ("/isProxy", "代理", QualityFieldKind::Boolean),
            ("/isCrawler", "爬虫", QualityFieldKind::Boolean),
            ("/latitude", "纬度", QualityFieldKind::Latitude),
            ("/longitude", "经度", QualityFieldKind::Longitude),
        ],
        "maxmind" => &[
            ("/ASN/AutonomousSystemNumber", "ASN", QualityFieldKind::Asn),
            (
                "/ASN/AutonomousSystemOrganization",
                "网络组织",
                QualityFieldKind::Text,
            ),
            ("/Country/Name", "国家或地区", QualityFieldKind::Text),
            (
                "/Country/IsoCode",
                "国家代码",
                QualityFieldKind::CountryCode,
            ),
            ("/City/Name", "城市", QualityFieldKind::Text),
            ("/City/Latitude", "纬度", QualityFieldKind::Latitude),
            ("/City/Longitude", "经度", QualityFieldKind::Longitude),
            ("/City/Location/TimeZone", "时区", QualityFieldKind::Text),
        ],
        "ipapi" => &[
            ("/asn/type", "ASN 类型", QualityFieldKind::Text),
            ("/company/type", "组织类型", QualityFieldKind::Text),
            (
                "/company/abuser_score",
                "滥用评分（上游原值）",
                QualityFieldKind::Score,
            ),
            (
                "/location/country_code",
                "国家代码",
                QualityFieldKind::CountryCode,
            ),
            ("/is_proxy", "代理", QualityFieldKind::Boolean),
            ("/is_tor", "Tor", QualityFieldKind::Boolean),
            ("/is_vpn", "VPN", QualityFieldKind::Boolean),
            ("/is_datacenter", "数据中心", QualityFieldKind::Boolean),
            ("/is_abuser", "滥用", QualityFieldKind::Boolean),
            ("/is_crawler", "爬虫", QualityFieldKind::Boolean),
        ],
        "scamalytics" => &[
            (
                "/scamalytics/scamalytics_score",
                "风险评分（上游原值）",
                QualityFieldKind::Score,
            ),
            (
                "/scamalytics/scamalytics_proxy/is_vpn",
                "VPN",
                QualityFieldKind::Boolean,
            ),
            (
                "/scamalytics/scamalytics_proxy/is_datacenter",
                "数据中心",
                QualityFieldKind::Boolean,
            ),
            (
                "/scamalytics/is_blacklisted_external",
                "外部黑名单",
                QualityFieldKind::Boolean,
            ),
            (
                "/external_datasources/firehol/is_proxy",
                "FireHOL 代理",
                QualityFieldKind::Boolean,
            ),
            (
                "/external_datasources/x4bnet/is_tor",
                "X4B Tor",
                QualityFieldKind::Boolean,
            ),
            (
                "/external_datasources/maxmind_geolite2/ip_country_code",
                "国家代码",
                QualityFieldKind::CountryCode,
            ),
        ],
        "abuseipdb" => &[
            ("/data/usageType", "用途类型", QualityFieldKind::Text),
            (
                "/data/abuseConfidenceScore",
                "滥用置信度（上游原值）",
                QualityFieldKind::Score,
            ),
        ],
        "abuseipdb-v2" => &[
            ("/data/usageType", "用途类型", QualityFieldKind::Text),
            (
                "/data/countryCode",
                "国家代码",
                QualityFieldKind::CountryCode,
            ),
            ("/data/isp", "ISP", QualityFieldKind::Text),
            ("/data/isTor", "Tor", QualityFieldKind::Boolean),
            (
                "/data/abuseConfidenceScore",
                "滥用置信度（0–100 原值）",
                QualityFieldKind::Score,
            ),
        ],
        "ip2location" => &[
            (
                "/fraud_score",
                "欺诈评分（上游原值）",
                QualityFieldKind::Score,
            ),
            ("/country_code", "国家代码", QualityFieldKind::CountryCode),
            ("/usage_type", "用途类型", QualityFieldKind::Text),
            ("/as_info/as_usage_type", "ASN 用途", QualityFieldKind::Text),
            ("/is_proxy", "代理", QualityFieldKind::Boolean),
            (
                "/proxy/is_public_proxy",
                "公共代理",
                QualityFieldKind::Boolean,
            ),
            ("/proxy/is_web_proxy", "网页代理", QualityFieldKind::Boolean),
            ("/proxy/is_tor", "Tor", QualityFieldKind::Boolean),
            ("/proxy/is_vpn", "VPN", QualityFieldKind::Boolean),
            (
                "/proxy/is_data_center",
                "数据中心",
                QualityFieldKind::Boolean,
            ),
            ("/proxy/is_spammer", "垃圾邮件", QualityFieldKind::Boolean),
            ("/proxy/is_web_crawler", "爬虫", QualityFieldKind::Boolean),
            ("/proxy/is_scanner", "扫描器", QualityFieldKind::Boolean),
            ("/proxy/is_botnet", "僵尸网络", QualityFieldKind::Boolean),
        ],
        "ipdata" => &[
            ("/country_code", "国家代码", QualityFieldKind::CountryCode),
            ("/threat/is_proxy", "代理", QualityFieldKind::Boolean),
            ("/threat/is_tor", "Tor", QualityFieldKind::Boolean),
            (
                "/threat/is_datacenter",
                "数据中心",
                QualityFieldKind::Boolean,
            ),
            ("/threat/is_threat", "威胁", QualityFieldKind::Boolean),
            (
                "/threat/is_known_abuser",
                "已知滥用",
                QualityFieldKind::Boolean,
            ),
            (
                "/threat/is_known_attacker",
                "已知攻击者",
                QualityFieldKind::Boolean,
            ),
        ],
        "ipqualityscore" => &[
            (
                "/fraud_score",
                "欺诈评分（上游原值）",
                QualityFieldKind::Score,
            ),
            ("/country_code", "国家代码", QualityFieldKind::CountryCode),
            ("/proxy", "代理", QualityFieldKind::Boolean),
            ("/tor", "Tor", QualityFieldKind::Boolean),
            ("/vpn", "VPN", QualityFieldKind::Boolean),
            ("/recent_abuse", "近期滥用", QualityFieldKind::Boolean),
            ("/bot_status", "机器人", QualityFieldKind::Boolean),
        ],
        _ => &[],
    }
}

fn meaningful_text(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && !matches!(
            text.to_ascii_lowercase().as_str(),
            "null" | "undefined" | "unknown" | "n/a" | "none" | "nan" | "-" | "未知"
        )
}

fn numeric(value: &Value) -> Option<f64> {
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => text.trim().parse().ok()?,
        _ => return None,
    };
    number.is_finite().then_some(number)
}

fn score(value: &Value) -> Option<f64> {
    numeric(value)
        .or_else(|| {
            // IPAPI also returns a numeric score followed by a parenthesized rating.
            let text = value.as_str()?.trim();
            let (number, rating) = text.split_once(' ')?;
            let rating = rating.trim().strip_prefix('(')?.strip_suffix(')')?;
            if !meaningful_text(rating) {
                return None;
            }
            numeric(&Value::String(number.into()))
        })
        .filter(|number| *number >= 0.0)
}

fn valid_field(database: &str, kind: QualityFieldKind, value: &Value) -> bool {
    if database == "abuseipdb-v2" && matches!(kind, QualityFieldKind::Score) {
        return value.as_u64().is_some_and(|number| number <= 100);
    }
    match kind {
        QualityFieldKind::Text => value.as_str().is_some_and(meaningful_text),
        QualityFieldKind::CountryCode => value.as_str().is_some_and(|text| {
            text.len() == 2 && text.bytes().all(|byte| byte.is_ascii_alphabetic())
        }),
        QualityFieldKind::Boolean => value.is_boolean(),
        QualityFieldKind::Score => score(value).is_some(),
        QualityFieldKind::Asn => numeric(value).is_some_and(|number| {
            number > 0.0 && number <= u32::MAX as f64 && number.fract() == 0.0
        }),
        QualityFieldKind::Latitude => {
            numeric(value).is_some_and(|number| (-90.0..=90.0).contains(&number))
        }
        QualityFieldKind::Longitude => {
            numeric(value).is_some_and(|number| (-180.0..=180.0).contains(&number))
        }
    }
}

pub(super) fn confirmed_response(value: &Value) -> bool {
    if !value.is_object() {
        return false;
    }
    if value
        .get("success")
        .is_some_and(|success| success != &Value::Bool(true))
    {
        return false;
    }
    if value.get("status").is_some_and(|status| {
        !status.as_str().is_some_and(|status| {
            matches!(
                status.to_ascii_lowercase().as_str(),
                "success" | "succeeded" | "ok"
            )
        })
    }) {
        return false;
    }
    if value
        .get("error")
        .is_some_and(|error| !error.is_null() && error != &Value::Bool(false))
    {
        return false;
    }
    if value.get("errors").is_some_and(|errors| match errors {
        Value::Null => false,
        Value::Array(errors) => !errors.is_empty(),
        Value::Object(errors) => !errors.is_empty(),
        _ => true,
    }) {
        return false;
    }
    true
}

pub(super) fn parse_fields(database: &str, value: &Value) -> Vec<QualityField> {
    // Only documented response envelopes have query status semantics.
    let confirmed_data = !matches!(database, "abuseipdb" | "abuseipdb-v2")
        || value.get("data").is_some_and(confirmed_response);
    if !confirmed_response(value) || !confirmed_data {
        return Vec::new();
    }
    definitions(database)
        .iter()
        .filter_map(|(path, label, kind)| {
            let value = value.pointer(path)?;
            if !valid_field(database, *kind, value) {
                return None;
            }
            let value = match value {
                Value::String(text) => Value::String(text.chars().take(512).collect()),
                value => value.clone(),
            };
            Some(QualityField {
                label: (*label).into(),
                value,
                kind: Some(*kind),
            })
        })
        .collect()
}

pub(super) fn confirmed_cached_fields(
    database: &str,
    fields: Vec<QualityField>,
) -> Vec<QualityField> {
    fields
        .into_iter()
        .filter_map(|mut field| {
            if let Some((_, _, kind)) = definitions(database)
                .iter()
                .find(|(_, label, _)| *label == field.label)
            {
                field.kind = Some(*kind);
                valid_field(database, *kind, &field.value).then_some(field)
            } else {
                // Legacy/custom labels retain valid scalars without guessing their semantics.
                let valid = match &field.value {
                    Value::String(text) => meaningful_text(text),
                    Value::Number(number) => number.as_f64().is_some_and(f64::is_finite),
                    Value::Bool(_) => true,
                    _ => false,
                };
                field.kind = None;
                valid.then_some(field)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
