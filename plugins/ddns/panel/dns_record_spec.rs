use super::dns_records::Request;
use super::model::{Provider, identifier};
use crate::error::{ApiError, ApiResult};
use serde_json::Value;

pub(super) fn name(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    let (prefix, host) = value
        .strip_prefix("*.")
        .map_or(("", value), |host| ("*.", host));
    if host
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || ":/%?#@\\[]*".contains(c))
    {
        return None;
    }
    let parsed = reqwest::Url::parse(&format!("https://{host}/")).ok()?;
    let host = parsed.host_str()?;
    if host.len() > 251
        || !host.contains('.')
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
    {
        return None;
    }
    Some(format!("{prefix}{host}"))
}

pub(super) fn normalize(request: &mut Request, zone: &str) -> ApiResult<()> {
    if !matches!(request.operation.as_str(), "create" | "update" | "delete") {
        return Err(ApiError::BadRequest("请选择新建、修改或删除记录".into()));
    }
    if request.operation != "create"
        && request.record_id.as_deref().is_none_or(|id| {
            id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ApiError::BadRequest("请明确选择已有记录标识".into()));
    }
    if request.operation == "create" && request.record_id.is_some() {
        return Err(ApiError::BadRequest("新建记录不能指定已有标识".into()));
    }
    if request.operation == "delete" {
        request.record = Value::Null;
        return Ok(());
    }
    let record = request
        .record
        .as_object_mut()
        .ok_or_else(|| ApiError::BadRequest("DNS 记录参数必须为对象".into()))?;
    if record.keys().any(|key| {
        ![
            "name", "type", "content", "ttl", "proxied", "priority", "data", "comment", "line",
        ]
        .contains(&key.as_str())
    }) {
        return Err(ApiError::BadRequest(
            "包含未支持的记录字段，不会静默丢弃参数".into(),
        ));
    }
    let owner = record
        .get("name")
        .and_then(Value::as_str)
        .and_then(name)
        .ok_or_else(|| ApiError::BadRequest("记录名称无效".into()))?;
    if owner != zone && !owner.ends_with(&format!(".{zone}")) {
        return Err(ApiError::BadRequest("记录不属于此区域".into()));
    }
    record.insert("name".into(), owner.into());
    let kind = record
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if ![
        "A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "HTTPS", "SVCB", "PTR",
    ]
    .contains(&kind.as_str())
    {
        return Err(ApiError::BadRequest("此记录类型当前不可用".into()));
    }
    if record
        .get("ttl")
        .and_then(Value::as_u64)
        .is_none_or(|ttl| ttl != 1 && !(60..=86400).contains(&ttl))
    {
        return Err(ApiError::BadRequest("TTL 必须为自动或 60–86400 秒".into()));
    }
    if record.get("content").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|content| content.len() > 4096 || content.contains('\0'))
    }) || record.get("comment").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|comment| comment.len() > 256 || comment.chars().any(char::is_control))
    }) || record
        .get("data")
        .is_some_and(|value| !value.is_object() || value.to_string().len() > 8192)
        || record.get("line").is_some_and(|value| {
            value.as_str().is_none_or(|line| {
                line.is_empty() || line.len() > 128 || line.chars().any(char::is_control)
            })
        })
        || record
            .get("proxied")
            .is_some_and(|value| !value.is_boolean())
        || record
            .get("priority")
            .is_some_and(|value| value.as_u64().is_none_or(|priority| priority > 65535))
    {
        return Err(ApiError::BadRequest(
            "记录内容、结构参数或优先级无效".into(),
        ));
    }
    if !record.contains_key("content") && !record.contains_key("data") {
        return Err(ApiError::BadRequest("请填写记录内容或结构参数".into()));
    }
    if ["A", "AAAA"].contains(&kind.as_str()) {
        let contents = if let Some(content) = record.get("content") {
            vec![content.clone()]
        } else {
            record
                .get("data")
                .and_then(|data| data.get("records"))
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| ApiError::BadRequest("地址记录必须包含地址内容或地址数组".into()))?
        };
        if contents.is_empty()
            || contents.iter().any(|value| {
                value
                    .as_str()
                    .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                    .is_none_or(|ip| ip.is_ipv4() != (kind == "A"))
            })
        {
            return Err(ApiError::BadRequest("地址与记录类型不匹配".into()));
        }
    }
    Ok(())
}

pub(super) fn normalize_for(
    request: &mut Request,
    zone: &str,
    provider: Provider,
) -> ApiResult<()> {
    normalize(request, zone)?;
    if request
        .record_id
        .as_deref()
        .is_some_and(|id| match provider {
            Provider::Cloudflare | Provider::Huawei => !identifier(id),
            Provider::Tencent => id.parse::<u64>().is_err(),
            Provider::Aliyun => false,
        })
    {
        return Err(ApiError::BadRequest("记录标识不符合所选提供方格式".into()));
    }
    if request.operation == "delete" {
        return Ok(());
    }
    let record = request
        .record
        .as_object_mut()
        .ok_or_else(|| ApiError::BadRequest("记录参数无效".into()))?;
    let kind = record["type"].as_str().unwrap_or_default().to_owned();
    if provider == Provider::Cloudflare {
        if record.contains_key("line") {
            return Err(ApiError::BadRequest("Cloudflare 不支持线路参数".into()));
        }
        return Ok(());
    }
    if !["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"].contains(&kind.as_str())
        || record.get("proxied").is_some_and(|value| value != false)
    {
        return Err(ApiError::BadRequest(
            "所选提供方未支持此记录类型或代理参数".into(),
        ));
    }
    if record["ttl"] == 1 {
        return Err(ApiError::BadRequest(
            "此提供方需明确 TTL 秒数，不能使用 Cloudflare 自动 TTL".into(),
        ));
    }
    if kind == "MX"
        && !record.contains_key("data")
        && record.get("priority").and_then(Value::as_u64).is_none()
    {
        return Err(ApiError::BadRequest("MX 记录必须提供优先级".into()));
    }
    if kind != "MX" && record.contains_key("priority") {
        return Err(ApiError::BadRequest("仅 MX 记录支持独立优先级".into()));
    }
    if provider == Provider::Huawei {
        if record.contains_key("line") {
            return Err(ApiError::BadRequest("华为云此接口未启用线路参数".into()));
        }
        if let Some(data) = record.get("data") {
            let values = data
                .get("records")
                .and_then(Value::as_array)
                .ok_or_else(|| ApiError::BadRequest("华为云结构参数仅支持 records 数组".into()))?;
            if data.as_object().is_none_or(|fields| fields.len() != 1)
                || values.is_empty()
                || values.len() > 100
                || values.iter().any(|value| {
                    value.as_str().is_none_or(|value| {
                        value.is_empty() || value.len() > 4096 || value.contains('\0')
                    })
                })
                || record.contains_key("content")
                || record.contains_key("priority")
            {
                return Err(ApiError::BadRequest(
                    "华为云记录数组无效或与单条内容冲突".into(),
                ));
            }
        }
        if let Some(values) = record
            .get("data")
            .and_then(|data| data.get("records"))
            .and_then(Value::as_array)
            .filter(|values| values.len() == 1)
        {
            let value = values[0].as_str().unwrap_or_default().to_owned();
            record.remove("data");
            if kind == "MX" {
                let (priority, target) = value
                    .split_once(' ')
                    .ok_or_else(|| ApiError::BadRequest("MX 文本必须为优先级与目标".into()))?;
                record.insert(
                    "priority".into(),
                    priority
                        .parse::<u64>()
                        .map_err(|_| ApiError::BadRequest("MX 优先级无效".into()))?
                        .into(),
                );
                record.insert("content".into(), target.trim().into());
            } else {
                record.insert("content".into(), value.into());
            }
        }
    } else {
        if record.contains_key("data") {
            return Err(ApiError::BadRequest(
                "此提供方结构记录使用官方文本内容，不支持结构参数对象".into(),
            ));
        }
        record.entry("line").or_insert_with(|| {
            if provider == Provider::Aliyun {
                "default".into()
            } else {
                "0".into()
            }
        });
    }
    Ok(())
}

pub(super) fn capabilities(provider: Provider) -> Value {
    serde_json::json!({"record_types":if provider==Provider::Cloudflare{vec!["A","AAAA","CNAME","TXT","MX","NS","SRV","CAA","PTR","HTTPS","SVCB"]}else{vec!["A","AAAA","CNAME","TXT","MX","NS","SRV","CAA"]},"proxy":provider==Provider::Cloudflare,"line":matches!(provider,Provider::Aliyun|Provider::Tencent),"structured_data":matches!(provider,Provider::Cloudflare|Provider::Huawei),"asynchronous_confirmation":provider==Provider::Huawei})
}

pub(super) fn snapshot(record: &Value) -> Value {
    let mut result = serde_json::Map::new();
    for key in [
        "id", "name", "type", "content", "ttl", "proxied", "priority", "data", "comment",
    ] {
        if let Some(value) = record.get(key) {
            result.insert(key.into(), value.clone());
        }
    }
    Value::Object(result)
}

#[cfg(test)]
#[path = "tests/dns_record_spec.rs"]
mod tests;
