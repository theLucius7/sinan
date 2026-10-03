use super::{
    account_on,
    client::Cloud,
    failure, lock,
    model::{self, Account, Operation, Resource, Target},
    operations, resource,
};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(super::power::routes())
        .route("/api/plugins/alicloud", get(list))
        .route("/api/plugins/alicloud/accounts", post(create_account))
        .route(
            "/api/plugins/alicloud/accounts/{id}",
            patch(update_account).delete(remove_account),
        )
        .route(
            "/api/plugins/alicloud/accounts/{id}/refresh",
            post(refresh_account),
        )
        .route("/api/plugins/alicloud/resources", post(create_resource))
        .route(
            "/api/plugins/alicloud/resources/{id}",
            patch(update_resource).delete(remove_resource),
        )
        .route(
            "/api/plugins/alicloud/resources/{id}/refresh",
            post(refresh_resource),
        )
        .route(
            "/api/plugins/alicloud/resources/{id}/preview",
            post(preview),
        )
        .route(
            "/api/plugins/alicloud/operations/{id}/confirm",
            post(confirm),
        )
        .route("/api/plugins/alicloud/operations/{id}/cancel", post(cancel))
        .route(
            "/api/plugins/alicloud/operations/{id}/dismiss",
            post(dismiss),
        )
}
async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let accounts: Vec<Account> =
        sqlx::query_as("SELECT * FROM alicloud_accounts WHERE NOT archived ORDER BY name,id")
            .fetch_all(&state.pool)
            .await?;
    let resources: Vec<Resource> =
        sqlx::query_as("SELECT * FROM alicloud_resources WHERE NOT archived ORDER BY name,id")
            .fetch_all(&state.pool)
            .await?;
    let operations: Vec<Operation> = sqlx::query_as("SELECT * FROM alicloud_operations ORDER BY (status IN ('queued','running','uncertain')) DESC,created_at DESC,id LIMIT 100").fetch_all(&state.pool).await?;
    let power_jobs: Vec<super::power::Job> = sqlx::query_as("SELECT * FROM alicloud_power_jobs ORDER BY (status IN ('queued','running','uncertain')) DESC,created_at DESC,id LIMIT 100").fetch_all(&state.pool).await?;
    let events: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',e.id,'resource_id',e.resource_id,'title',e.title,'message',e.message,'created_at',e.created_at,'deliveries',COALESCE((SELECT jsonb_agg(jsonb_build_object('channel',d.channel,'status',d.status,'attempts',d.attempts,'last_error',d.last_error,'next_attempt_at',d.next_attempt_at,'delivered_at',d.delivered_at) ORDER BY d.id) FROM alicloud_deliveries d WHERE d.event_id=e.id),'[]'::jsonb)) FROM alicloud_events e ORDER BY e.id DESC LIMIT 100").fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"accounts":accounts,"resources":resources,"operations":operations,"power_jobs":power_jobs,"events":events}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountWrite {
    name: String,
    site: String,
    enabled: bool,
    auto_enabled: bool,
    limit_gb: i64,
    access_key_id: Option<String>,
    access_key_secret: Option<String>,
    credential_id: Option<Uuid>,
    #[serde(default)]
    legacy_credentials: bool,
    revision: Option<i64>,
}
impl AccountWrite {
    fn validate(&self) -> ApiResult<()> {
        model::label(&self.name)?;
        if !matches!(self.site.as_str(), "china" | "international")
            || !(1..=1_000_000_000).contains(&self.limit_gb)
        {
            return Err(ApiError::BadRequest(
                "请选择账号站点，并填写 1–1000000000 GB 的自动降速阈值".into(),
            ));
        }
        Ok(())
    }
    fn credentials(&self, previous: Option<&Account>) -> ApiResult<(String, String, Option<Uuid>)> {
        let key = self.access_key_id.as_deref().unwrap_or("").trim();
        let secret = self.access_key_secret.as_deref().unwrap_or("").trim();
        if let Some(id) = self.credential_id {
            if !key.is_empty() || !secret.is_empty() {
                return Err(ApiError::BadRequest(
                    "集中引用与旧明文密钥不能同时提交".into(),
                ));
            }
            return Ok((String::new(), String::new(), Some(id)));
        }
        if key.is_empty() && secret.is_empty() {
            if let Some(account) = previous {
                if account.credential_id.is_some() && self.legacy_credentials {
                    return Err(ApiError::BadRequest(
                        "切换旧兼容模式必须明确提供独立密钥对".into(),
                    ));
                }
                return Ok((
                    account.access_key_id.clone(),
                    account.access_key_secret.clone(),
                    account.credential_id,
                ));
            }
        } else if self.legacy_credentials
            && crate::plugins::cloud_api::credential(key)
            && crate::plugins::cloud_api::credential(secret)
        {
            return Ok((key.into(), secret.into(), None));
        }
        Err(ApiError::BadRequest(
            "请引用集中云凭据；只有明确选择旧兼容模式时才接收独立密钥对".into(),
        ))
    }
}
async fn validate_reference(state: &AppState, id: Option<Uuid>) -> ApiResult<()> {
    if let Some(id) = id {
        let available:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM credential_entries WHERE id=$1 AND kind='cloud' AND enabled)").bind(id).fetch_one(&state.pool).await?;
        if !available {
            return Err(ApiError::BadRequest(
                "集中云凭据不存在、已停用或用途不符".into(),
            ));
        }
    }
    Ok(())
}
async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AccountWrite>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    auth::require_admin(&state, &headers).await?;
    input.validate()?;
    let (key, secret, credential) = input.credentials(None)?;
    validate_reference(&state, credential).await?;
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104831)")
        .execute(&mut *tx)
        .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM alicloud_accounts WHERE NOT archived")
            .fetch_one(&mut *tx)
            .await?;
    if count >= 8 {
        return Err(ApiError::Conflict("最多登记 8 个云账号".into()));
    }
    sqlx::query("INSERT INTO alicloud_accounts(id,name,site,access_key_id,access_key_secret,enabled,auto_enabled,limit_gb,credential_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(id).bind(input.name.trim()).bind(input.site).bind(key).bind(secret).bind(input.enabled).bind(input.auto_enabled).bind(input.limit_gb).bind(credential).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"id":id}))))
}
async fn update_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<AccountWrite>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    input.validate()?;
    let mut tx = lock(&state.pool, id).await?;
    let previous = account_on(&mut tx, id).await?;
    if input.revision != Some(previous.revision) {
        return Err(ApiError::Conflict("账号配置已变化，请刷新后重试".into()));
    }
    let (key, secret, credential) = input.credentials(Some(&previous))?;
    if credential != previous.credential_id {
        validate_reference(&state, credential).await?;
    }
    if input.site != previous.site
        || key != previous.access_key_id
        || secret != previous.access_key_secret
        || credential != previous.credential_id
    {
        let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM alicloud_operations o JOIN alicloud_resources r ON r.id=o.resource_id WHERE r.account_id=$1 AND o.status IN ('running','uncertain')) OR EXISTS(SELECT 1 FROM alicloud_power_jobs j JOIN alicloud_resources r ON r.id=j.resource_id WHERE r.account_id=$1 AND j.status IN ('running','uncertain')) OR EXISTS(SELECT 1 FROM alicloud_security_group_operations o JOIN alicloud_resources r ON r.id=o.resource_id WHERE r.account_id=$1 AND o.status IN ('running','unknown'))")
            .bind(id).fetch_one(&mut *tx).await?;
        if unresolved {
            return Err(ApiError::Conflict(
                "此账号仍有已发送或结果待核对的云操作，请先核对或结束跟踪，再更换站点及访问密钥"
                    .into(),
            ));
        }
    }
    // Any edit invalidates queued authorization and cached billing evidence.
    sqlx::query("UPDATE alicloud_accounts SET name=$2,site=$3,access_key_id=$4,access_key_secret=$5,enabled=$6,auto_enabled=$7,limit_gb=$8,credential_id=$9,revision=revision+1,bill=NULL,traffic=NULL,traffic_error=NULL,error_code=NULL,next_run_at=0,balance=NULL,balance_error=NULL,balance_next_at=0 WHERE id=$1")
        .bind(id).bind(input.name.trim()).bind(input.site).bind(key).bind(secret).bind(input.enabled).bind(input.auto_enabled).bind(input.limit_gb).bind(credential).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_operations SET status='cancelled',updated_at=$2 WHERE resource_id IN (SELECT id FROM alicloud_resources WHERE account_id=$1) AND status IN ('preview','queued')")
        .bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_power_jobs SET status='cancelled',updated_at=$2 WHERE resource_id IN (SELECT id FROM alicloud_resources WHERE account_id=$1) AND status IN ('preview','queued')").bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_resources SET instance_bill=NULL,bill_error=NULL,bill_next_at=0,next_power_at=0 WHERE account_id=$1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Option<Json<Revision>>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = lock(&state.pool, id).await?;
    let current = account_on(&mut tx, id).await?;
    if input.is_some_and(|Json(input)| input.revision != current.revision) {
        return Err(ApiError::Conflict("账号配置已变化，请刷新后重试".into()));
    }
    let has_resources: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM alicloud_resources WHERE account_id=$1 AND NOT archived)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if has_resources {
        return Err(ApiError::Conflict("请先移除该账号登记的云资源".into()));
    }
    sqlx::query("UPDATE alicloud_accounts SET archived=true,enabled=false,auto_enabled=false,access_key_id='',access_key_secret='',credential_id=NULL,bill=NULL,traffic=NULL,balance=NULL WHERE id=$1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn refresh_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = lock(&state.pool, id).await?;
    let account = account_on(&mut tx, id).await?;
    if !account.enabled {
        return Err(ApiError::Conflict("请先启用云账号".into()));
    }
    let last: i64 = sqlx::query_scalar("SELECT last_attempt_at FROM alicloud_accounts WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let now = sinan_protocol::now_timestamp();
    if last + 60 > now
        || (account.error_code.as_deref() == Some("rate_limited") && account.next_run_at > now)
    {
        return Err(ApiError::Busy);
    }
    sqlx::query("UPDATE alicloud_accounts SET next_run_at=0,balance_next_at=CASE WHEN balance_error IS NULL THEN 0 ELSE balance_next_at END WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE alicloud_resources SET bill_next_at=CASE WHEN bill_error IS NULL THEN 0 ELSE bill_next_at END,next_power_at=0 WHERE account_id=$1 AND NOT archived").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceWrite {
    account_id: Uuid,
    name: String,
    kind: String,
    region: String,
    cloud_id: String,
    auto_enabled: bool,
    cap_mbps: i64,
    revision: Option<i64>,
}
impl ResourceWrite {
    fn validate(&self) -> ApiResult<()> {
        model::label(&self.name)?;
        if !matches!(self.kind.as_str(), "ecs" | "eip")
            || !model::identifier(&self.region, "")
            || !model::identifier(
                &self.cloud_id,
                if self.kind == "ecs" { "i-" } else { "eip-" },
            )
            || !(1..=100).contains(&self.cap_mbps)
        {
            return Err(ApiError::BadRequest(
                "请填写有效的资源类型、地域、资源标识，以及 1–100 Mbps 的自动降速目标".into(),
            ));
        }
        Ok(())
    }
}
async fn create_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ResourceWrite>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    auth::require_admin(&state, &headers).await?;
    input.validate()?;
    let mut tx = lock(&state.pool, input.account_id).await?;
    account_on(&mut tx, input.account_id).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(739104832)")
        .execute(&mut *tx)
        .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM alicloud_resources WHERE NOT archived")
            .fetch_one(&mut *tx)
            .await?;
    if count >= 32 {
        return Err(ApiError::Conflict("最多登记 32 个云资源".into()));
    }
    let id = Uuid::new_v4();
    let result=sqlx::query("INSERT INTO alicloud_resources(id,account_id,name,kind,region,cloud_id,auto_enabled,cap_mbps) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(input.account_id).bind(input.name.trim()).bind(input.kind).bind(input.region).bind(input.cloud_id).bind(input.auto_enabled).bind(input.cap_mbps).execute(&mut *tx).await;
    if result.as_ref().is_err_and(|e| {
        e.as_database_error()
            .is_some_and(|e| e.is_unique_violation())
    }) {
        return Err(ApiError::Conflict(
            "该地域和资源已登记，请勿用多个账号重复管理".into(),
        ));
    }
    result?;
    sqlx::query("UPDATE alicloud_accounts SET next_run_at=0 WHERE id=$1")
        .bind(input.account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"id":id}))))
}
async fn update_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ResourceWrite>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    input.validate()?;
    let initial = resource(&state.pool, id).await?;
    let mut tx = lock(&state.pool, initial.account_id).await?;
    let current: Resource =
        sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    if Some(current.revision) != input.revision
        || input.account_id != current.account_id
        || input.kind != current.kind
        || input.region != current.region
        || input.cloud_id != current.cloud_id
    {
        return Err(ApiError::Conflict(
            "配置已变化，或尝试修改固定的账号、类型、地域和资源标识；请刷新或另行登记".into(),
        ));
    }
    sqlx::query("UPDATE alicloud_resources SET name=$2,auto_enabled=$3,cap_mbps=$4,revision=revision+1 WHERE id=$1").bind(id).bind(input.name.trim()).bind(input.auto_enabled).bind(input.cap_mbps).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_operations SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status IN ('preview','queued')").bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_power_jobs SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status IN ('preview','queued')").bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Option<Json<Revision>>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let resource = resource(&state.pool, id).await?;
    let mut tx = lock(&state.pool, resource.account_id).await?;
    let current: Resource =
        sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    if input.is_some_and(|Json(input)| input.revision != current.revision) {
        return Err(ApiError::Conflict("资源配置已变化，请刷新后重试".into()));
    }
    operations::idle(&mut tx, id).await?;
    sqlx::query("UPDATE alicloud_resources SET archived=true,auto_enabled=false,revision=revision+1 WHERE id=$1").bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_operations SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status='preview'").bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE alicloud_power_jobs SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status='preview'").bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn refresh_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<model::Snapshot>> {
    auth::require_admin(&state, &headers).await?;
    let initial = resource(&state.pool, id).await?;
    let mut tx = lock(&state.pool, initial.account_id).await?;
    let account = account_on(&mut tx, initial.account_id).await?;
    let resource: Resource =
        sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    if !account.enabled {
        return Err(ApiError::Conflict("请先启用云账号".into()));
    }
    let snapshot = Cloud::new(&state.pool)
        .map_err(failure)?
        .snapshot(&account, &resource)
        .await
        .map_err(failure)?;
    operations::snapshot_on(&mut tx, id, &snapshot).await?;
    tx.commit().await?;
    Ok(Json(snapshot))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    target: Target,
    revision: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    revision: i64,
}
async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Preview>,
) -> ApiResult<Json<Operation>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(
        operations::preview(
            &state.pool,
            id,
            input.target,
            input.revision,
            &Cloud::new(&state.pool).map_err(failure)?,
        )
        .await?,
    ))
}
async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Operation>)> {
    auth::require_admin(&state, &headers).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(operations::confirm(&state.pool, id).await?),
    ))
}
async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    operations::cancel(&state.pool, id, false).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn dismiss(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    operations::cancel(&state.pool, id, true).await?;
    Ok(StatusCode::NO_CONTENT)
}
