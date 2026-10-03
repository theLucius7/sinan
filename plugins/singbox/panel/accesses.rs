use crate::{
    AppState,
    auth::require_admin,
    error::{ApiError, ApiResult},
    plugins::singbox::business,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Serialize, FromRow)]
pub struct AccessView {
    pub user_id: i64,
    pub node_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Uuid>,
    pub stat_name: String,
    pub direct_grant: bool,
}
impl AccessView {
    fn visibility(mut self, reveal: bool) -> Self {
        if !reveal {
            self.uuid = None;
        }
        self
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub node_id: i64,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<AccessView>>> {
    require_admin(&state, &headers).await?;
    let reveal = super::secret_access::may_reveal(&state, &headers).await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND deleted_at IS NULL)")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let accesses = sqlx::query_as::<_, AccessView>("SELECT a.user_id,a.node_id,a.uuid,a.stat_name,a.direct_grant FROM accesses a JOIN nodes n ON n.id=a.node_id JOIN servers s ON s.id=n.server_id WHERE a.user_id=$1 AND n.deleted_at IS NULL AND s.deleted_at IS NULL ORDER BY a.node_id").bind(id).fetch_all(&state.pool).await?;
    if reveal {
        super::secret_access::audit_read(&state,&headers,Some(id),"security_node_credentials_read",serde_json::json!({"source":"access_list","node_ids":accesses.iter().map(|access|access.node_id).collect::<Vec<_>>(),"credential_values_recorded":false})).await?;
    }
    Ok(Json(
        accesses
            .into_iter()
            .map(|access| access.visibility(reveal))
            .collect(),
    ))
}

pub async fn grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<GrantRequest>,
) -> ApiResult<Json<AccessView>> {
    require_admin(&state, &headers).await?;
    let reveal = super::secret_access::may_reveal(&state, &headers).await?;
    let mut transaction = state.pool.begin().await?;
    super::entitlements::lock(&mut transaction).await?;
    business::lock_user(&mut transaction, id).await?;
    super::chains::ensure_direct(&mut transaction, request.node_id).await?;
    let server_id: i64 =
        sqlx::query_scalar("SELECT server_id FROM nodes WHERE id=$1 AND deleted_at IS NULL")
            .bind(request.node_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApiError::NotFound)?;
    business::lock_server(&mut transaction, server_id).await?;
    let config: serde_json::Value =
        sqlx::query_scalar("SELECT protocol_config FROM nodes WHERE id=$1 AND deleted_at IS NULL")
            .bind(request.node_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApiError::NotFound)?;
    let config: sinan_compiler::ProtocolConfig =
        serde_json::from_value(config).map_err(anyhow::Error::from)?;
    if let Some(access) = sqlx::query_as::<_, AccessView>(
        "UPDATE accesses SET direct_grant=TRUE WHERE user_id=$1 AND node_id=$2 RETURNING user_id,node_id,uuid,stat_name,direct_grant",
    )
    .bind(id)
    .bind(request.node_id)
    .fetch_optional(&mut *transaction)
    .await?
    {
        transaction.commit().await?;
        if reveal {super::secret_access::audit_read(&state,&headers,Some(id),"security_node_credentials_read",serde_json::json!({"source":"access_grant_response","node_ids":[request.node_id],"credential_values_recorded":false})).await?;}
        return Ok(Json(access.visibility(reveal)));
    }
    let access = sqlx::query_as::<_, AccessView>("INSERT INTO accesses(user_id,node_id,uuid,stat_name,credential) VALUES($1,$2,$3,$4,$5) RETURNING user_id,node_id,uuid,stat_name,direct_grant").bind(id).bind(request.node_id).bind(Uuid::new_v4()).bind(sinan_compiler::stat_name(id, request.node_id)).bind(super::node_protocol::credential(config.credential_size())).fetch_one(&mut *transaction).await?;
    business::mark_dirty(&mut transaction, &[server_id]).await?;
    transaction.commit().await?;
    if reveal {
        super::secret_access::audit_read(&state,&headers,Some(id),"security_node_credentials_read",serde_json::json!({"source":"access_grant_response","node_ids":[request.node_id],"credential_values_recorded":false})).await?;
    }
    Ok(Json(access.visibility(reveal)))
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, node_id)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &headers).await?;
    let mut transaction = state.pool.begin().await?;
    super::entitlements::lock(&mut transaction).await?;
    business::lock_user(&mut transaction, user_id).await?;
    let server_id: i64 =
        sqlx::query_scalar("SELECT server_id FROM nodes WHERE id=$1 AND deleted_at IS NULL")
            .bind(node_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(ApiError::NotFound)?;
    business::lock_server(&mut transaction, server_id).await?;
    let removed = sqlx::query(
        "UPDATE accesses SET direct_grant=FALSE WHERE user_id=$1 AND node_id=$2 AND direct_grant",
    )
    .bind(user_id)
    .bind(node_id)
    .execute(&mut *transaction)
    .await?;
    if removed.rows_affected() > 0 {
        super::policies::sync_users(&mut transaction, &[user_id]).await?;
    }
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
