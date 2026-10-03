use super::model::{Config, Provider, Rule};
use crate::error::{ApiError, ApiResult};
use serde_json::Value;
use sqlx::PgPool;

pub(super) async fn validate_reference(pool: &PgPool, config: &Config) -> ApiResult<()> {
    if let Some(id) = config.account_id {
        if config.credential_id.is_some() {
            return Err(ApiError::BadRequest(
                "账号引用与独立凭据引用不能混用".into(),
            ));
        }
        let account = super::dns_accounts::load(pool, id).await?;
        validate_binding(config, &account.config)?;
        return validate_id(pool, account.config.credential_id).await;
    }
    if let Some(id) = config.credential_id {
        validate_id(pool, id).await?;
    }
    Ok(())
}

async fn validate_id(pool: &PgPool, id: uuid::Uuid) -> ApiResult<()> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credential_entries WHERE id=$1 AND kind='dns' AND enabled)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    if !present {
        return Err(ApiError::Conflict(
            "所选 DNS 凭据不存在、已停用或用途不匹配".into(),
        ));
    }
    Ok(())
}

fn validate_binding(config: &Config, account: &super::dns_accounts::Config) -> ApiResult<()> {
    if !account.enabled
        || account.provider != config.provider
        || !account.zone_ids.contains(&config.zone_id)
        || (!account.server_ids.is_empty() && !account.server_ids.contains(&config.server_id))
    {
        return Err(ApiError::Conflict(
            "DNS 账号已停用或未授权此提供方、区域及服务器".into(),
        ));
    }
    Ok(())
}

pub(super) async fn authorize_reference(
    state: &crate::AppState,
    headers: &axum::http::HeaderMap,
    config: &Config,
) -> ApiResult<()> {
    if let Some(id) = config.account_id {
        let account = super::dns_accounts::load(&state.pool, id).await?;
        super::dns_accounts::authorize(state, headers, &account.config, "dns:write").await?;
    }
    Ok(())
}

pub(super) fn populate(rule: &mut Rule, value: &Value) -> ApiResult<()> {
    let provider = match rule.config.provider {
        Provider::Cloudflare => "cloudflare",
        Provider::Tencent => "tencent",
        Provider::Aliyun => "aliyun",
        Provider::Huawei => "huawei",
    };
    if value
        .get("provider")
        .is_some_and(|value| value.as_str() != Some(provider))
    {
        return Err(ApiError::Conflict("凭据的 DNS 提供方与规则不匹配".into()));
    }
    if rule.config.provider == Provider::Cloudflare {
        rule.api_token = super::model::token(value["api_token"].as_str().unwrap_or_default())?;
        rule.access_key_id.clear();
        rule.access_key_secret.clear();
    } else {
        let key = value["access_key_id"].as_str().unwrap_or_default();
        let secret = value["access_key_secret"].as_str().unwrap_or_default();
        if !crate::plugins::cloud_api::credential(key)
            || !crate::plugins::cloud_api::credential(secret)
        {
            return Err(ApiError::Conflict("DNS 凭据不含有效的访问密钥对".into()));
        }
        rule.api_token.clear();
        rule.access_key_id = key.into();
        rule.access_key_secret = secret.into();
    }
    Ok(())
}

pub(super) async fn hydrate(pool: &PgPool, rule: &mut Rule) -> ApiResult<()> {
    if let Some(id) = rule.config.account_id {
        let account = super::dns_accounts::load(pool, id).await?;
        validate_binding(&rule.config, &account.config)?;
        rule.config.credential_id = Some(account.config.credential_id);
    }
    if let Some(id) = rule.config.credential_id {
        let value = crate::control_center::credentials::resolve_reference_pool(
            pool,
            id,
            "dns",
            &format!("ddns:{}", rule.id),
        )
        .await?;
        populate(rule, &value)?;
    }
    Ok(())
}

pub(super) async fn guard_reference(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    rule: &Rule,
) -> Result<(), super::cloudflare::Failure> {
    if let Some(id) = rule.config.account_id {
        let config: Option<sqlx::types::Json<super::dns_accounts::Config>> =
            sqlx::query_scalar("SELECT config FROM dns_accounts WHERE id=$1 FOR SHARE")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|_| super::cloudflare::Failure::from("storage_error"))?;
        let config = config
            .ok_or(super::cloudflare::Failure::from("credential_unavailable"))?
            .0;
        validate_binding(&rule.config, &config)
            .map_err(|_| super::cloudflare::Failure::from("credential_unavailable"))?;
        if rule.config.credential_id != Some(config.credential_id) {
            return Err("credential_unavailable".into());
        }
    }
    if let Some(id) = rule.config.credential_id {
        let found: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM credential_entries WHERE id=$1 AND enabled AND kind='dns' FOR SHARE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| super::cloudflare::Failure::from("storage_error"))?;
        if found.is_none() {
            return Err("credential_unavailable".into());
        }
    }
    Ok(())
}
