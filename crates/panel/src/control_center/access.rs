use crate::{
    AppState,
    auth::hash_token,
    error::{ApiError, ApiResult},
};
use axum::http::{HeaderMap, header};
use serde::{Deserialize, Serialize};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

pub const FEATURES: &[&str] = &[
    "servers",
    "monitoring",
    "terminal",
    "files",
    "services",
    "diagnostics",
    "network",
    "dns",
    "proxy",
    "operations",
    "recovery",
    "cloud",
    "security",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    pub admin_id: i64,
    pub login_name: String,
    pub display_name: String,
    pub role: String,
    pub all_servers: bool,
    pub capabilities: Vec<String>,
    pub server_ids: Vec<i64>,
    #[serde(skip)]
    pub token_id: Option<Uuid>,
    #[serde(skip)]
    pub token_capabilities: Option<Vec<String>>,
    #[serde(skip)]
    pub token_servers: Option<Vec<i64>>,
}

pub fn valid_capability(value: &str) -> bool {
    value.split_once(':').is_some_and(|(feature, action)| {
        FEATURES.contains(&feature) && matches!(action, "read" | "write")
    })
}

pub(crate) fn session_hash(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    let values: Vec<_> = cookie
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("sinan_session="))
        .collect();
    (values.len() == 1 && !values[0].is_empty() && values[0].len() <= 512)
        .then(|| hash_token(values[0]))
}

fn management_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| token.starts_with("sinan_api_") && token.len() <= 512)
}

pub async fn authenticate(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    let now = now_timestamp();
    let token = if let Some(token) = management_token(headers) {
        Some(sqlx::query("SELECT id,admin_id,capabilities,server_ids,all_servers FROM management_api_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>$2")
            .bind(hash_token(token)).bind(now).fetch_optional(&state.pool).await?.ok_or(ApiError::Unauthorized)?)
    } else {
        None
    };
    let admin_id = if let Some(ref token) = token {
        token.try_get::<i64, _>("admin_id")?
    } else {
        sqlx::query_scalar::<_,i64>("SELECT admin_id FROM sessions WHERE token_hash=$1 AND admin_id IS NOT NULL AND expires_at>$2")
            .bind(session_hash(headers).ok_or(ApiError::Unauthorized)?).bind(now).fetch_optional(&state.pool).await?.ok_or(ApiError::Unauthorized)?
    };
    let profile = sqlx::query("SELECT * FROM administrator_profiles WHERE admin_id=$1 AND enabled")
        .bind(admin_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let server_ids = sqlx::query_scalar(
        "SELECT server_id FROM administrator_server_grants WHERE admin_id=$1 ORDER BY server_id",
    )
    .bind(admin_id)
    .fetch_all(&state.pool)
    .await?;
    let mut principal = Principal {
        admin_id,
        login_name: profile.try_get("login_name")?,
        display_name: profile.try_get("display_name")?,
        role: profile.try_get("role")?,
        all_servers: profile.try_get("all_servers")?,
        capabilities: serde_json::from_value(profile.try_get("capabilities")?)
            .map_err(anyhow::Error::from)?,
        server_ids,
        token_id: None,
        token_capabilities: None,
        token_servers: None,
    };
    if let Some(token) = token {
        let id: Uuid = token.try_get("id")?;
        principal.token_id = Some(id);
        principal.token_capabilities = Some(
            serde_json::from_value(token.try_get("capabilities")?).map_err(anyhow::Error::from)?,
        );
        if !token.try_get::<bool, _>("all_servers")? {
            principal.token_servers = Some(
                serde_json::from_value(token.try_get("server_ids")?)
                    .map_err(anyhow::Error::from)?,
            );
        }
        sqlx::query("UPDATE management_api_tokens SET last_used_at=$2 WHERE id=$1")
            .bind(id)
            .bind(now)
            .execute(&state.pool)
            .await?;
    }
    Ok(principal)
}

impl Principal {
    pub fn allows(&self, capability: &str) -> bool {
        valid_capability(capability)
            && (self.role == "owner" || self.capabilities.iter().any(|item| item == capability))
            && !(self.role == "viewer" && capability.ends_with(":write"))
            && self
                .token_capabilities
                .as_ref()
                .is_none_or(|items| items.iter().any(|item| item == capability))
    }
    pub fn allows_server(&self, id: i64) -> bool {
        (self.all_servers || self.server_ids.contains(&id))
            && self
                .token_servers
                .as_ref()
                .is_none_or(|ids| ids.contains(&id))
    }
    pub fn global_servers(&self) -> bool {
        self.all_servers && self.token_servers.is_none()
    }
}

pub async fn require_capability(
    state: &AppState,
    headers: &HeaderMap,
    capability: &str,
) -> ApiResult<i64> {
    let actor = authenticate(state, headers).await?;
    if !actor.allows(capability) {
        return Err(ApiError::Forbidden(
            "当前管理员或 API 令牌没有此操作权限".into(),
        ));
    }
    Ok(actor.admin_id)
}

pub async fn require_server(
    state: &AppState,
    headers: &HeaderMap,
    server_id: i64,
    capability: &str,
) -> ApiResult<i64> {
    let actor = authenticate(state, headers).await?;
    if !actor.allows(capability) || !actor.allows_server(server_id) {
        return Err(ApiError::Forbidden(
            "当前管理员或 API 令牌没有此服务器的操作权限".into(),
        ));
    }
    Ok(actor.admin_id)
}

pub async fn require_owner(state: &AppState, headers: &HeaderMap) -> ApiResult<i64> {
    let actor = authenticate(state, headers).await?;
    if actor.role != "owner" || actor.token_id.is_some() {
        return Err(ApiError::Forbidden("此操作需要所有者会话".into()));
    }
    Ok(actor.admin_id)
}

pub async fn require_recent_proof(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let actor = authenticate(state, headers).await?;
    if actor.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "高风险操作需要管理员会话再次验证".into(),
        ));
    }
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM administrator_reauth WHERE session_hash=$1 AND expires_at>$2)",
    )
    .bind(session_hash(headers).ok_or(ApiError::Unauthorized)?)
    .bind(now_timestamp())
    .fetch_one(&state.pool)
    .await?;
    if !valid {
        return Err(ApiError::Forbidden(
            "请先再次验证管理员密码及二步验证码，证明有效期为五分钟".into(),
        ));
    }
    Ok(())
}

pub async fn actor_server_allowed(
    pool: &sqlx::PgPool,
    actor: i64,
    server: i64,
    capability: &str,
) -> Result<bool, sqlx::Error> {
    if !valid_capability(capability) {
        return Ok(false);
    }
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM administrator_profiles p WHERE p.admin_id=$1 AND p.enabled AND (p.role='owner' OR p.capabilities ? $3) AND (p.role<>'viewer' OR $3 NOT LIKE '%:write') AND (p.all_servers OR EXISTS(SELECT 1 FROM administrator_server_grants g WHERE g.admin_id=p.admin_id AND g.server_id=$2)))")
        .bind(actor).bind(server).bind(capability).fetch_one(pool).await
}

pub async fn require_actor_server(
    state: &AppState,
    actor: i64,
    server: i64,
    capability: &str,
) -> ApiResult<()> {
    if !actor_server_allowed(&state.pool, actor, server, capability).await? {
        return Err(ApiError::Forbidden(
            "管理员已失去此服务器操作权限，任务已停止派发".into(),
        ));
    }
    Ok(())
}

pub async fn require_actor_capability(
    state: &AppState,
    actor: i64,
    capability: &str,
) -> ApiResult<()> {
    if !valid_capability(capability) {
        return Err(ApiError::Forbidden("能力标识无效".into()));
    }
    let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM administrator_profiles WHERE admin_id=$1 AND enabled AND (role='owner' OR capabilities ? $2) AND (role<>'viewer' OR $2 NOT LIKE '%:write'))")
        .bind(actor).bind(capability).fetch_one(&state.pool).await?;
    if !allowed {
        return Err(ApiError::Forbidden(
            "管理员已失去此功能权限，任务已停止派发".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn actor() -> Principal {
        Principal {
            admin_id: 1,
            login_name: "admin".into(),
            display_name: "所有者".into(),
            role: "owner".into(),
            all_servers: true,
            capabilities: vec![],
            server_ids: vec![],
            token_id: None,
            token_capabilities: None,
            token_servers: None,
        }
    }
    #[test]
    fn token_and_actor_permissions_intersect() {
        let mut principal = actor();
        principal.token_capabilities = Some(vec!["servers:read".into()]);
        principal.token_servers = Some(vec![2]);
        assert!(principal.allows("servers:read"));
        assert!(!principal.allows("servers:write"));
        assert!(principal.allows_server(2));
        assert!(!principal.allows_server(3));
        principal.role = "viewer".into();
        principal.capabilities = vec!["servers:write".into()];
        principal.token_capabilities = None;
        assert!(!principal.allows("servers:write"));
    }
    #[test]
    fn duplicate_cookie_cannot_choose_a_session() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "sinan_session=a; sinan_session=b".parse().unwrap(),
        );
        assert!(session_hash(&headers).is_none());
    }
}
