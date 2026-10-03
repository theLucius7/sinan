use crate::{
    AppState,
    auth::{hash_token, random_token, require_admin},
    error::{ApiError, ApiResult},
    server_assets::AssetSettings,
    server_traffic::{self, TrafficSummary},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sinan_protocol::{AgentSettings, EnrollRequest, EnrollResponse, ProbeSpec, now_timestamp};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

pub(crate) const SERVER_COLUMNS: &str = "id, name, device_public_key, static_info, last_seen, last_contact_at, last_heartbeat_at, NULLIF(metrics_sampled_at,0) AS metrics_sampled_at, latest_metrics, agent_settings, asset_settings, manifest_rev, capabilities";

#[derive(Serialize, FromRow)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub device_public_key: Option<String>,
    pub static_info: Value,
    pub last_seen: Option<i64>,
    /// Real time of the last message; `last_seen` is backdated on a clean disconnect.
    #[serde(skip)]
    #[sqlx(default)]
    pub last_contact_at: Option<i64>,
    pub last_heartbeat_at: Option<i64>,
    pub metrics_sampled_at: Option<i64>,
    #[sqlx(skip)]
    pub metrics_received_at: Option<i64>,
    #[sqlx(skip)]
    pub metrics_persisted_at: Option<i64>,
    #[sqlx(skip)]
    pub served_at: i64,
    #[sqlx(skip)]
    pub telemetry_settings: Option<sinan_protocol::telemetry::TelemetrySettings>,
    pub agent_settings: Value,
    #[sqlx(json)]
    pub asset_settings: AssetSettings,
    #[sqlx(skip)]
    pub traffic: Option<TrafficSummary>,
    pub latest_metrics: Value,
    pub manifest_rev: i64,
    pub capabilities: Value,
    #[sqlx(default)]
    pub online: bool,
    #[sqlx(default)]
    pub metrics_stale: bool,
}

impl Server {
    pub(crate) fn with_online(mut self) -> Self {
        let now = now_timestamp();
        self.asset_settings.renew(now);
        self.online = self
            .last_seen
            .is_some_and(|seen| now.saturating_sub(seen) <= 60);
        let settings =
            serde_json::from_value::<sinan_protocol::AgentSettings>(self.agent_settings.clone())
                .unwrap_or_default();
        let allowance = settings
            .sample_interval_secs
            .saturating_mul(3)
            .saturating_add(settings.upload_interval_secs.saturating_mul(2))
            .max(15);
        self.metrics_stale = self.metrics_sampled_at.is_some_and(|sampled| {
            sinan_protocol::telemetry::now_millis().saturating_sub(sampled)
                > (allowance as i64).saturating_mul(1000)
        });
        self
    }
}

#[derive(Deserialize)]
pub struct ServerRequest {
    pub name: String,
    pub asset_settings: Option<AssetSettings>,
    pub auto_update: Option<bool>,
}

#[derive(Deserialize)]
pub struct CreateServerRequest {
    pub name: String,
    #[serde(default)]
    pub agent_settings: AgentSettings,
    #[serde(default)]
    pub telemetry_settings: sinan_protocol::telemetry::TelemetrySettings,
    #[serde(default)]
    pub probes: Vec<ProbeSpec>,
    #[serde(default)]
    pub asset_settings: AssetSettings,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Server>>> {
    require_admin(&state, &headers).await?;
    let query =
        format!("SELECT {SERVER_COLUMNS} FROM servers WHERE deleted_at IS NULL ORDER BY id");
    let servers = sqlx::query_as::<_, Server>(&query)
        .fetch_all(&state.pool)
        .await?;
    let mut servers: Vec<_> = servers.into_iter().map(Server::with_online).collect();
    server_traffic::attach(&state.pool, &mut servers, now_timestamp()).await?;
    crate::telemetry::attach_live(&state, &mut servers).await?;
    Ok(Json(servers))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<CreateServerRequest>,
) -> ApiResult<(StatusCode, Json<Server>)> {
    require_admin(&state, &headers).await?;
    let name = valid_name(&request.name)?;
    let mut asset = request.asset_settings.normalized()?;
    validate_mirror(&asset, &state.config.public_url)?;
    asset.renew(now_timestamp());
    if !request.agent_settings.valid() {
        return Err(ApiError::BadRequest(
            "采样与上传间隔必须在 1–60 秒内，上传间隔不能小于采样间隔".into(),
        ));
    }
    if !request.telemetry_settings.valid() {
        return Err(ApiError::BadRequest("历史写入间隔须为 15–3600 秒".into()));
    }
    if request.probes.len() > 32 {
        return Err(ApiError::BadRequest("每台服务器最多配置 32 个拨测".into()));
    }
    for spec in &mut request.probes {
        spec.normalize();
        spec.id = Uuid::new_v4();
        crate::probes::prepare_write(spec)?;
    }
    let mut transaction = state.pool.begin().await?;
    crate::latency_tasks::lock(&mut transaction).await?;
    let query = format!(
        "INSERT INTO servers (name, agent_settings, asset_settings, telemetry_settings) VALUES ($1, $2, $3, $4) RETURNING {SERVER_COLUMNS}"
    );
    let server = sqlx::query_as::<_, Server>(&query)
        .bind(name)
        .bind(json!(request.agent_settings))
        .bind(json!(asset))
        .bind(json!(request.telemetry_settings))
        .fetch_one(&mut *transaction)
        .await?;
    for spec in request.probes {
        sqlx::query("INSERT INTO network_probes (id, server_id, spec) VALUES ($1, $2, $3)")
            .bind(spec.id)
            .bind(server.id)
            .bind(json!(spec))
            .execute(&mut *transaction)
            .await?;
    }
    crate::latency_tasks::assign_defaults(&mut transaction, server.id).await?;
    transaction.commit().await?;
    let mut server = server.with_online();
    crate::telemetry::attach_live(&state, std::slice::from_mut(&mut server)).await?;
    Ok((StatusCode::CREATED, Json(server)))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Server>> {
    require_admin(&state, &headers).await?;
    let query =
        format!("SELECT {SERVER_COLUMNS} FROM servers WHERE id = $1 AND deleted_at IS NULL");
    let server = sqlx::query_as::<_, Server>(&query)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut server = server.with_online();
    server_traffic::attach(
        &state.pool,
        std::slice::from_mut(&mut server),
        now_timestamp(),
    )
    .await?;
    crate::telemetry::attach_live(&state, std::slice::from_mut(&mut server)).await?;
    Ok(Json(server))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<ServerRequest>,
) -> ApiResult<Json<Server>> {
    require_admin(&state, &headers).await?;
    let name = valid_name(&request.name)?;
    let asset = request
        .asset_settings
        .map(|asset| {
            let mut asset = asset.normalized()?;
            validate_mirror(&asset, &state.config.public_url)?;
            asset.renew(now_timestamp());
            Ok::<_, ApiError>(json!(asset))
        })
        .transpose()?;
    let mut transaction = state.pool.begin().await?;
    let previous: Value = sqlx::query_scalar(
        "SELECT asset_settings FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    if let Some(asset) = &asset {
        let previous: AssetSettings =
            serde_json::from_value(previous).map_err(anyhow::Error::from)?;
        if asset["reset_day"] != json!(previous.reset_day)
            || asset["network_interface"] != json!(previous.network_interface)
        {
            sqlx::query("UPDATE server_traffic_corrections SET invalidated_at=$2 WHERE server_id=$1 AND invalidated_at IS NULL")
                .bind(id).bind(now_timestamp()).execute(&mut *transaction).await?;
        }
    }
    let query = format!(
        "UPDATE servers SET name = $2, asset_settings=COALESCE($3,asset_settings),
         agent_settings=CASE WHEN $4::boolean IS NULL THEN agent_settings ELSE agent_settings || jsonb_build_object('auto_update',$4::boolean) END
         WHERE id = $1 AND deleted_at IS NULL RETURNING {SERVER_COLUMNS}"
    );
    let server = sqlx::query_as::<_, Server>(&query)
        .bind(id)
        .bind(name)
        .bind(asset)
        .bind(request.auto_update)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ApiError::NotFound)?;
    transaction.commit().await?;
    let mut server = server.with_online();
    server_traffic::attach(
        &state.pool,
        std::slice::from_mut(&mut server),
        now_timestamp(),
    )
    .await?;
    crate::telemetry::attach_live(&state, std::slice::from_mut(&mut server)).await?;
    Ok(Json(server))
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    require_admin(&state, &headers).await?;
    crate::retirement::remove(&state, id).await
}

#[derive(Deserialize, Default)]
pub struct EnrollmentQuery {
    pub agent_version: Option<String>,
    pub agent_target: Option<String>,
    pub platform: Option<String>,
}

pub async fn issue_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(query): Query<EnrollmentQuery>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers).await?;
    let token = random_token();
    let expires_at = now_timestamp() + 86_400;
    let mut transaction = state.pool.begin().await?;
    let exists = sqlx::query(
        "SELECT id, asset_settings FROM servers WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let asset: AssetSettings = serde_json::from_value(exists.unwrap().get("asset_settings"))
        .map_err(anyhow::Error::from)?;
    let selection = crate::installation::select_with_mirror(
        &state,
        query.agent_version.as_deref(),
        &token,
        query.platform.as_deref(),
        query.agent_target.as_deref(),
        &asset.agent_mirror,
    )
    .await;
    let (install_command, installation, warning) = match selection {
        Ok(installation) => (
            Some(installation.install_command.clone()),
            Some(json!(installation)),
            None,
        ),
        Err(ApiError::Conflict(message)) => (None, None, Some(message)),
        Err(error) => return Err(error),
    };
    sqlx::query(
        "INSERT INTO enrollment_tokens (token_hash, server_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(hash_token(&token))
    .bind(id)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(
        json!({"token": token, "expires_at": expires_at, "install_command": install_command,
        "installation": installation, "warning": warning}),
    ))
}

/// Expired enrollment tokens can never validate again; keep a short grace period
/// for troubleshooting and then remove them in bounded batches (ADR 0077).
pub(crate) async fn purge_expired_enrollments(pool: &PgPool, now: i64) -> anyhow::Result<u64> {
    Ok(sqlx::query("DELETE FROM enrollment_tokens WHERE token_hash IN (SELECT token_hash FROM enrollment_tokens WHERE expires_at < $1 ORDER BY expires_at LIMIT 500)")
        .bind(now - 7 * 86_400)
        .execute(pool)
        .await?
        .rows_affected())
}

pub async fn validate_enrollment(pool: &PgPool, token: &str) -> ApiResult<i64> {
    if token.is_empty() || token.len() > 512 {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query_scalar::<_, i64>("SELECT enrollment_tokens.server_id FROM enrollment_tokens JOIN servers ON servers.id = enrollment_tokens.server_id WHERE enrollment_tokens.token_hash = $1 AND enrollment_tokens.expires_at > $2 AND enrollment_tokens.consumed_at IS NULL AND servers.deleted_at IS NULL")
        .bind(hash_token(token)).bind(now_timestamp()).fetch_optional(pool).await?.ok_or(ApiError::Unauthorized)
}

pub async fn enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    validate_public_key(&request.device_public_key)?;
    if request.token.is_empty() || request.token.len() > 512 {
        return Err(ApiError::Unauthorized);
    }
    let now = now_timestamp();
    let token_hash = hash_token(&request.token);
    let mut transaction = state.pool.begin().await?;
    let row = sqlx::query("SELECT e.server_id, s.device_public_key FROM enrollment_tokens e JOIN servers s ON s.id = e.server_id WHERE e.token_hash = $1 AND e.expires_at > $2 AND e.consumed_at IS NULL AND s.deleted_at IS NULL FOR UPDATE OF e, s")
        .bind(&token_hash).bind(now).fetch_optional(&mut *transaction).await?.ok_or(ApiError::Unauthorized)?;
    let id: i64 = row.try_get("server_id")?;
    let previous_key: Option<String> = row.try_get("device_public_key")?;
    if previous_key
        .as_ref()
        .is_some_and(|key| key != &request.device_public_key)
    {
        return Err(ApiError::Conflict(
            "服务器已经注册，设备公钥不能更换".into(),
        ));
    }
    sqlx::query("UPDATE servers SET device_public_key = $2, static_info = $3 WHERE id = $1")
        .bind(id)
        .bind(&request.device_public_key)
        .bind(json!(request.static_info))
        .execute(&mut *transaction)
        .await?;
    sqlx::query("UPDATE enrollment_tokens SET consumed_at = $2 WHERE token_hash = $1")
        .bind(token_hash)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(Json(EnrollResponse { server_id: id }))
}

fn valid_name(value: &str) -> ApiResult<&str> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 128 || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "服务器名称需为 1 至 128 个字符，且不能包含控制字符".into(),
        ));
    }
    Ok(value)
}

fn validate_public_key(value: &str) -> ApiResult<()> {
    let error =
        || ApiError::BadRequest("设备公钥必须是 URL-safe 无填充 base64 编码的 ed25519 公钥".into());
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| error())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| error())?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| error())?;
    if key.is_weak() {
        return Err(error());
    }
    Ok(())
}

fn validate_mirror(asset: &AssetSettings, panel: &str) -> ApiResult<()> {
    if let (Ok(mirror), Ok(panel)) = (
        reqwest::Url::parse(&asset.agent_mirror),
        reqwest::Url::parse(panel),
    ) && mirror.origin() == panel.origin()
    {
        return Err(ApiError::BadRequest(
            "Agent 下载加速不能使用面板地址，请填写独立的 GitHub 镜像".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../panel/migrations")]
    async fn only_long_expired_enrollment_tokens_are_purged(pool: PgPool) -> anyhow::Result<()> {
        let server: i64 =
            sqlx::query_scalar("INSERT INTO servers(name) VALUES('TEST_ONLY') RETURNING id")
                .fetch_one(&pool)
                .await?;
        let now = 10_000_000;
        for (token, expires_at, consumed_at) in [
            ("expired-unused", now - 8 * 86_400, None),
            ("expired-consumed", now - 8 * 86_400, Some(now - 9 * 86_400)),
            ("recently-expired", now - 86_400, None),
            ("valid", now + 3_600, None),
        ] {
            sqlx::query("INSERT INTO enrollment_tokens(token_hash,server_id,expires_at,consumed_at) VALUES($1,$2,$3,$4)")
                .bind(token).bind(server).bind(expires_at).bind(consumed_at).execute(&pool).await?;
        }
        assert_eq!(purge_expired_enrollments(&pool, now).await?, 2);
        let mut remaining: Vec<String> =
            sqlx::query_scalar("SELECT token_hash FROM enrollment_tokens")
                .fetch_all(&pool)
                .await?;
        remaining.sort();
        assert_eq!(remaining, ["recently-expired", "valid"]);
        Ok(())
    }
}
