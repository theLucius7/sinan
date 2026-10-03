use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::http::HeaderMap;

pub(super) const REASON: &str = "连接凭据与订阅地址需要 proxy:write 权限及五分钟内的交互式管理员再次验证；只读接口只提供授权与状态";

pub(super) async fn may_reveal(state: &AppState, headers: &HeaderMap) -> ApiResult<bool> {
    let actor = crate::control_center::authenticate(state, headers).await?;
    if !actor.allows("proxy:write") || actor.token_id.is_some() {
        return Ok(false);
    }
    match crate::control_center::require_recent_proof(state, headers).await {
        Ok(()) => Ok(true),
        Err(ApiError::Forbidden(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) async fn require_reveal(state: &AppState, headers: &HeaderMap) -> ApiResult<i64> {
    let actor = crate::control_center::require_capability(state, headers, "proxy:write").await?;
    crate::control_center::require_recent_proof(state, headers).await?;
    Ok(actor)
}

pub(super) async fn audit_read(
    state: &AppState,
    headers: &HeaderMap,
    user: Option<i64>,
    action: &str,
    detail: serde_json::Value,
) -> ApiResult<()> {
    let actor = crate::control_center::require_capability(state, headers, "proxy:write").await?;
    let mut tx = state.pool.begin().await?;
    super::operations_workflows::event(&mut tx, Some(actor), user, action, detail).await?;
    tx.commit().await?;
    Ok(())
}
