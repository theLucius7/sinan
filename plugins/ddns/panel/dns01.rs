use super::{
    cloudflare::Cloudflare,
    load,
    model::{Provider, domain},
};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

/// DNS credentials remain inside the plugin and are never included in results.
pub(crate) async fn present(
    state: &AppState,
    rule_id: Uuid,
    challenge_id: Uuid,
    name: &str,
    value: &str,
    credential_id: Option<Uuid>,
) -> ApiResult<String> {
    let (client, path, token) = context(state, rule_id, name, credential_id).await?;
    let marker = format!("sinan-acme:{challenge_id}");
    let records = records(&client, &path, &token, name).await?;
    let owned: Vec<_> = records
        .iter()
        .filter(|record| record["comment"] == marker)
        .collect();
    if owned.len() > 1 {
        return Err(ApiError::Conflict(
            "验证记录存在多个受管副本，请人工核对".into(),
        ));
    }
    if let Some(record) = owned.first() {
        if record["type"] != "TXT" || record["content"] != value {
            return Err(ApiError::Conflict("现有验证记录与挑战内容不同".into()));
        }
        return record["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Conflict("提供方记录标识无效".into()));
    }
    // Existing TXT records are preserved. An ambiguous timeout is handled by a later read.
    let result = client
        .call(
            Method::POST,
            &path,
            &token,
            &[],
            Some(json!({"name":name,"type":"TXT","content":value,"ttl":120,"comment":marker})),
        )
        .await
        .map_err(failure)?;
    let record = &result["result"];
    if record["name"] != name
        || record["type"] != "TXT"
        || record["content"] != value
        || record["comment"] != marker
    {
        return Err(ApiError::Conflict(
            "提供方返回的验证记录不匹配；请核对远端".into(),
        ));
    }
    record["id"]
        .as_str()
        .filter(|id| super::model::identifier(id))
        .map(str::to_owned)
        .ok_or_else(|| ApiError::Conflict("提供方验证记录标识无效".into()))
}

pub(crate) async fn cleanup(
    state: &AppState,
    rule_id: Uuid,
    challenge_id: Uuid,
    name: &str,
    value: &str,
    record_id: Option<&str>,
    credential_id: Option<Uuid>,
) -> ApiResult<()> {
    let (client, path, token) = context(state, rule_id, name, credential_id).await?;
    let marker = format!("sinan-acme:{challenge_id}");
    let records = records(&client, &path, &token, name).await?;
    for record in records.iter().filter(|record| record["comment"] == marker) {
        let id = record["id"]
            .as_str()
            .filter(|id| super::model::identifier(id))
            .ok_or_else(|| ApiError::Conflict("提供方验证记录标识无效".into()))?;
        if record_id.is_some_and(|expected| expected != id)
            || record["type"] != "TXT"
            || record["content"] != value
        {
            return Err(ApiError::Conflict("远端验证记录已被修改，拒绝清理".into()));
        }
        client
            .call(Method::DELETE, &format!("{path}/{id}"), &token, &[], None)
            .await
            .map_err(failure)?;
    }
    Ok(())
}

async fn context(
    state: &AppState,
    rule_id: Uuid,
    name: &str,
    credential_id: Option<Uuid>,
) -> ApiResult<(Cloudflare, String, String)> {
    let mut rule = load(&state.pool, rule_id).await?;
    if rule.config.provider != Provider::Cloudflare {
        return Err(ApiError::Conflict(
            "DNS-01 TXT执行器目前仅支持Cloudflare；其他提供方需维护方执行".into(),
        ));
    }
    super::credentials::hydrate(&state.pool, &mut rule).await?;
    let challenge_domain = name
        .strip_prefix("_acme-challenge.")
        .and_then(domain)
        .ok_or_else(|| ApiError::BadRequest("DNS-01记录名称无效".into()))?;
    let owned_domain = rule.config.record_name.trim_start_matches("*.");
    if challenge_domain != owned_domain {
        return Err(ApiError::BadRequest(
            "验证名称必须与所选DDNS凭据规则域名相同".into(),
        ));
    }
    let token = if let Some(id) = credential_id {
        let secret =
            crate::control_center::credentials::resolve_reference(state, id, "dns", "dns01")
                .await?;
        secret["api_token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or_else(|| ApiError::Conflict("DNS凭据不含API Token".into()))?
            .to_owned()
    } else {
        rule.api_token
    };
    let client = Cloudflare::new().map_err(failure)?;
    let zone_path = format!("zones/{}", rule.config.zone_id);
    let zone = client
        .call(Method::GET, &zone_path, &token, &[], None)
        .await
        .map_err(failure)?;
    let zone_name = zone["result"]["name"]
        .as_str()
        .and_then(domain)
        .ok_or_else(|| ApiError::Conflict("提供方Zone资料无效".into()))?;
    if zone["result"]["id"] != rule.config.zone_id
        || zone["result"]["status"] != "active"
        || (challenge_domain != zone_name && !challenge_domain.ends_with(&format!(".{zone_name}")))
    {
        return Err(ApiError::Conflict("Zone不匹配或未激活".into()));
    }
    Ok((client, format!("{zone_path}/dns_records"), token))
}

async fn records(
    client: &Cloudflare,
    path: &str,
    token: &str,
    name: &str,
) -> ApiResult<Vec<Value>> {
    let result = client
        .call(
            Method::GET,
            path,
            token,
            &[("name.exact", name), ("per_page", "100"), ("page", "1")],
            None,
        )
        .await
        .map_err(failure)?;
    let records = result["result"]
        .as_array()
        .ok_or_else(|| ApiError::Conflict("提供方验证记录列表无效".into()))?;
    if result["result_info"]["total_count"].as_u64() != Some(records.len() as u64)
        || result["result_info"]["total_pages"]
            .as_u64()
            .is_none_or(|pages| pages > 1)
        || records
            .iter()
            .any(|record| record["name"] != name || record["type"] == "CNAME")
    {
        return Err(ApiError::Conflict(
            "验证记录列表不完整或存在CNAME冲突".into(),
        ));
    }
    Ok(records.clone())
}

fn failure(error: super::cloudflare::Failure) -> ApiError {
    ApiError::Conflict(format!("DNS提供方操作未确认：{}", error.code))
}
