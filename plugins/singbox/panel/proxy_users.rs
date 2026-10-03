use crate::{
    AppState,
    auth::{random_token, require_admin},
    business,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use sinan_protocol::now_timestamp;
use sqlx::FromRow;

#[derive(FromRow)]
struct ProxyUserRow {
    id: i64,
    name: String,
    subscription_token: String,
}

#[derive(Serialize)]
pub struct ProxyUserView {
    pub id: i64,
    pub name: String,
    pub subscription_token: String,
    pub subscription_url: String,
}
impl ProxyUserRow {
    fn view(self, public_url: &str) -> ProxyUserView {
        ProxyUserView {
            id: self.id,
            name: self.name,
            subscription_url: format!("{public_url}/sub/{}", self.subscription_token),
            subscription_token: self.subscription_token,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyUserRequest {
    pub name: String,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ProxyUserView>>> {
    require_admin(&state, &headers).await?;
    let users = sqlx::query_as::<_, ProxyUserRow>(
        "SELECT id,name,subscription_token FROM users WHERE deleted_at IS NULL ORDER BY id",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        users
            .into_iter()
            .map(|user| user.view(&state.config.public_url))
            .collect(),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<ProxyUserView>> {
    require_admin(&state, &headers).await?;
    let user = sqlx::query_as::<_, ProxyUserRow>(
        "SELECT id,name,subscription_token FROM users WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(user.view(&state.config.public_url)))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProxyUserRequest>,
) -> ApiResult<(StatusCode, Json<ProxyUserView>)> {
    require_admin(&state, &headers).await?;
    let name = business::name(&request.name)?;
    let user = sqlx::query_as::<_, ProxyUserRow>("INSERT INTO users(name,subscription_token) VALUES($1,$2) RETURNING id,name,subscription_token").bind(name).bind(random_token()).fetch_one(&state.pool).await?;
    Ok((
        StatusCode::CREATED,
        Json(user.view(&state.config.public_url)),
    ))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<ProxyUserRequest>,
) -> ApiResult<Json<ProxyUserView>> {
    require_admin(&state, &headers).await?;
    let name = business::name(&request.name)?;
    let mut transaction = state.pool.begin().await?;
    super::entitlements::lock(&mut transaction).await?;
    business::lock_user(&mut transaction, id).await?;
    let servers = business::lock_user_servers(&mut transaction, id).await?;
    let user = sqlx::query_as::<_, ProxyUserRow>(
        "UPDATE users SET name=$2 WHERE id=$1 RETURNING id,name,subscription_token",
    )
    .bind(id)
    .bind(name)
    .fetch_one(&mut *transaction)
    .await?;
    business::mark_dirty(&mut transaction, &servers).await?;
    transaction.commit().await?;
    Ok(Json(user.view(&state.config.public_url)))
}

pub async fn reset_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<ProxyUserView>> {
    require_admin(&state, &headers).await?;
    let user = sqlx::query_as::<_, ProxyUserRow>(
        "UPDATE users SET subscription_token=$2 WHERE id=$1 AND deleted_at IS NULL RETURNING id,name,subscription_token",
    )
    .bind(id)
    .bind(random_token())
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(user.view(&state.config.public_url)))
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &headers).await?;
    let mut transaction = state.pool.begin().await?;
    super::entitlements::lock(&mut transaction).await?;
    business::lock_user(&mut transaction, id).await?;
    let servers = business::lock_user_servers(&mut transaction, id).await?;
    sqlx::query("UPDATE users SET deleted_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now_timestamp())
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM passkey_accounts WHERE id IN (SELECT account_id FROM singbox_portal_accounts WHERE user_id=$1)")
        .bind(id).execute(&mut *transaction).await?;
    sqlx::query("DELETE FROM accesses WHERE user_id=$1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM singbox_user_policies WHERE user_id=$1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    business::mark_dirty(&mut transaction, &servers).await?;
    transaction.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
