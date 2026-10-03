mod client;
mod store;

use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

const STALE_AFTER_SECS: i64 = 21600;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/operations/cloud/hetzner/accounts",
            get(accounts).post(save_account),
        )
        .route(
            "/api/operations/cloud/hetzner/accounts/{id}",
            delete(archive_account),
        )
        .route(
            "/api/operations/cloud/hetzner/accounts/{id}/refresh",
            post(refresh),
        )
        .route("/api/operations/cloud/hetzner/resources", get(resources))
        .route(
            "/api/operations/cloud/hetzner/resources/{id}",
            get(resource),
        )
        .route(
            "/api/operations/cloud/hetzner/resources/{id}/link",
            post(link),
        )
        .route(
            "/api/operations/cloud/hetzner/resources/{id}/history",
            get(history),
        )
}

pub(super) fn provider() -> Value {
    json!({"id":"hetzner","name":"Hetzner Cloud","inventory_read":true,"resource_linking":true,"history":true,"billing":false,"balance":false,"remote_writes":false,"official_source":"Hetzner Cloud v1 /servers","supported_resources":["cloud_server"],"unsupported":["dedicated_robot_server","billing","balance","power_changes","bandwidth_changes","security_group_changes"],"refresh":"仅显式读取官方服务器清单；不发起云资源变更","credential_shape":{"provider":"hetzner","api_token":"凭据中心中的受限 API 令牌"}})
}

async fn accounts(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    super::require_global(&state, &headers, "cloud:read").await?;
    let mut rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'credential_id',credential_id,'archived',archived,'revision',revision,'last_attempt_at',last_attempt_at,'last_read_at',last_read_at,'last_error',last_error,'refreshing',refresh_id IS NOT NULL AND refresh_started_at>$1-180) FROM operations_hetzner_accounts ORDER BY archived,name,id LIMIT 101")
        .bind(now_timestamp()).fetch_all(&state.pool).await?;
    let truncated = rows.len() > 100;
    rows.truncate(100);
    Ok(Json(
        json!({"accounts":rows,"provider":provider(),"truncated":truncated,"limit":100}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountInput {
    id: Option<Uuid>,
    name: String,
    credential_id: Uuid,
    expected_revision: Option<i64>,
}

async fn save_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AccountInput>,
) -> ApiResult<Json<Value>> {
    let actor = super::require_global(&state, &headers, "cloud:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    super::model::label(&input.name, 200)?;
    let mut tx = state.pool.begin().await?;
    let credential: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM credential_entries WHERE id=$1 AND kind='cloud' AND enabled)",
    )
    .bind(input.credential_id)
    .fetch_one(&mut *tx)
    .await?;
    if !credential {
        return Err(ApiError::BadRequest(
            "请选择已启用的云用途凭据中心条目".into(),
        ));
    }
    let now = now_timestamp();
    let id = input.id.unwrap_or_else(Uuid::new_v4);
    let revision = if input.id.is_some() {
        let previous = sqlx::query("SELECT credential_id,revision,archived FROM operations_hetzner_accounts WHERE id=$1 FOR UPDATE")
            .bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
        let revision: i64 = previous.try_get("revision")?;
        if previous.try_get::<bool, _>("archived")? || input.expected_revision != Some(revision) {
            return Err(ApiError::Conflict(
                "账户已停用或被其他管理员修改，请刷新后重新确认".into(),
            ));
        }
        let previous_credential: Uuid = previous.try_get("credential_id")?;
        if previous_credential != input.credential_id {
            let populated: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM operations_hetzner_resources WHERE account_id=$1)",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if populated {
                return Err(ApiError::Conflict("已有资源的账户请在原凭据条目中轮换令牌；其他项目须新建账户，避免将同号资源或关联误迁".into()));
            }
        }
        let next = revision
            .checked_add(1)
            .ok_or_else(|| ApiError::Conflict("账户版本已达上限".into()))?;
        sqlx::query("UPDATE operations_hetzner_accounts SET name=$2,credential_id=$3,revision=$4,updated_at=$5,updated_by=$6,refresh_id=NULL,refresh_started_at=NULL WHERE id=$1")
            .bind(id).bind(input.name.trim()).bind(input.credential_id).bind(next).bind(now).bind(actor).execute(&mut *tx).await?;
        next
    } else {
        sqlx::query("SELECT pg_advisory_xact_lock(530119)")
            .execute(&mut *tx)
            .await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM operations_hetzner_accounts WHERE NOT archived",
        )
        .fetch_one(&mut *tx)
        .await?;
        if count >= 100 {
            return Err(ApiError::Conflict(
                "最多保留一百个启用的 Hetzner 账户；历史停用账户仍保留".into(),
            ));
        }
        sqlx::query("INSERT INTO operations_hetzner_accounts(id,name,credential_id,created_at,updated_at,updated_by) VALUES($1,$2,$3,$4,$4,$5)")
            .bind(id).bind(input.name.trim()).bind(input.credential_id).bind(now).bind(actor).execute(&mut *tx).await?;
        1
    };
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"revision":revision,"remote_action_executed":false}),
    ))
}

async fn archive_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let actor = super::require_global(&state, &headers, "cloud:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let result = sqlx::query("UPDATE operations_hetzner_accounts SET archived=true,revision=revision+1,updated_at=$2,updated_by=$3,refresh_id=NULL,refresh_started_at=NULL WHERE id=$1")
        .bind(id).bind(now_timestamp()).bind(actor).execute(&state.pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(
        json!({"id":id,"archived":true,"remote_action_executed":false,"history_retained":true}),
    ))
}

async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    super::require_global(&state, &headers, "cloud:read").await?;
    let refresh_id = Uuid::new_v4();
    let started = now_timestamp();
    let account = sqlx::query("UPDATE operations_hetzner_accounts SET refresh_id=$2,refresh_started_at=$3,last_attempt_at=$3 WHERE id=$1 AND NOT archived AND (refresh_id IS NULL OR refresh_started_at<$3-180) RETURNING credential_id")
        .bind(id).bind(refresh_id).bind(started).fetch_optional(&state.pool).await?;
    let Some(account) = account else {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM operations_hetzner_accounts WHERE id=$1 AND NOT archived)",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
        return Err(if exists {
            ApiError::Busy
        } else {
            ApiError::NotFound
        });
    };
    let credential: Uuid = account.try_get("credential_id")?;
    let value = control_center::credentials::resolve_reference_pool(
        &state.pool,
        credential,
        "cloud",
        &format!("hetzner:{id}"),
    )
    .await;
    let inventory = match value {
        Ok(value) => match token(&value) {
            Some(token) => client::fetch(token).await,
            None => client::Inventory {
                servers: Vec::new(),
                complete: false,
                pages: 0,
                error_code: Some("credential_invalid".into()),
            },
        },
        Err(_) => client::Inventory {
            servers: Vec::new(),
            complete: false,
            pages: 0,
            error_code: Some("credential_unavailable".into()),
        },
    };
    store::persist(&state.pool, id, refresh_id, started, &inventory)
        .await
        .map(Json)
}

fn token(value: &Value) -> Option<&str> {
    if value.get("provider").and_then(Value::as_str) != Some("hetzner") {
        return None;
    }
    value
        .get("api_token")
        .and_then(Value::as_str)
        .filter(|value| {
            (20..=512).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
}

async fn resources(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = control_center::authenticate(&state, &headers).await?;
    if !actor.allows("cloud:read") {
        return Err(ApiError::Forbidden("没有云资源读取授权".into()));
    }
    let permitted: Vec<i64> = actor
        .token_servers
        .as_ref()
        .unwrap_or(&actor.server_ids)
        .iter()
        .copied()
        .filter(|id| actor.allows_server(*id))
        .collect();
    let statement = format!(
        "{} WHERE ($2 OR r.server_id=ANY($3)) ORDER BY a.archived,a.name,r.name,r.id LIMIT 501",
        store::RESOURCE_SELECT
    );
    let mut rows: Vec<Value> = sqlx::query(&statement)
        .bind(now_timestamp())
        .bind(actor.global_servers())
        .bind(permitted)
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(|row| row.get("value"))
        .collect();
    let truncated = rows.len() > 500;
    rows.truncate(500);
    Ok(Json(
        json!({"resources":rows,"provider":provider(),"served_at":now_timestamp(),"inventory_stale_after_secs":STALE_AFTER_SECS,"limits":{"page_size":50,"max_pages":10,"max_resources":500,"list_limit":500,"list_truncated":truncated}}),
    ))
}

async fn resource_value(state: &AppState, headers: &HeaderMap, id: Uuid) -> ApiResult<Value> {
    let statement = format!("{} WHERE r.id=$2", store::RESOURCE_SELECT);
    let row = sqlx::query(&statement)
        .bind(now_timestamp())
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    if let Some(server) = row.try_get::<Option<i64>, _>("server_id")? {
        control_center::require_server(state, headers, server, "cloud:read").await?;
    } else {
        super::require_global(state, headers, "cloud:read").await?;
    }
    Ok(row.try_get("value")?)
}

async fn resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    resource_value(&state, &headers, id).await.map(Json)
}

async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    resource_value(&state, &headers, id).await?;
    Ok(Json(sqlx::query_scalar("SELECT to_jsonb(o) FROM operations_hetzner_observations o WHERE resource_id=$1 ORDER BY observed_at DESC,id DESC LIMIT 200")
        .bind(id).fetch_all(&state.pool).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkInput {
    server_id: Option<i64>,
    notes: String,
}

async fn link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<LinkInput>,
) -> ApiResult<Json<Value>> {
    let actor = control_center::require_capability(&state, &headers, "cloud:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    if !input.notes.is_empty() {
        super::model::label(&input.notes, 4096)?;
    }
    let mut tx = state.pool.begin().await?;
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT server_id FROM operations_hetzner_resources WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if let Some(server) = previous {
        control_center::require_server(&state, &headers, server, "cloud:write").await?;
    } else {
        super::require_global(&state, &headers, "cloud:write").await?;
    }
    if let Some(server) = input.server_id {
        control_center::require_server(&state, &headers, server, "cloud:write").await?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1 AND deleted_at IS NULL)",
        )
        .bind(server)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }
    sqlx::query("UPDATE operations_hetzner_resources SET server_id=$2,notes=$3,updated_at=$4,updated_by=$5 WHERE id=$1")
        .bind(id).bind(input.server_id).bind(input.notes).bind(now_timestamp()).bind(actor).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"resource_id":id,"server_id":input.server_id,"remote_action_executed":false}),
    ))
}

#[cfg(test)]
mod tests;
