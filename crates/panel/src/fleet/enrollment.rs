use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
    server_assets::AssetSettings,
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sinan_protocol::{AgentSettings, ProbeSpec, now_timestamp, telemetry::TelemetrySettings};
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TemplateConfig {
    pub agent_settings: AgentSettings,
    pub telemetry_settings: TelemetrySettings,
    pub asset_settings: AssetSettings,
    pub probes: Vec<ProbeSpec>,
    pub alerts: Vec<Value>,
    pub asset: Value,
}
impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            agent_settings: AgentSettings::default(),
            telemetry_settings: TelemetrySettings::default(),
            asset_settings: AssetSettings::default(),
            probes: Vec::new(),
            alerts: Vec::new(),
            asset: json!({}),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInput {
    id: Option<Uuid>,
    name: String,
    config: TemplateConfig,
}

fn normalize(mut config: TemplateConfig) -> ApiResult<TemplateConfig> {
    config.asset_settings = config.asset_settings.normalized()?;
    if !config.agent_settings.valid()
        || !config.telemetry_settings.valid()
        || config.probes.len() > 32
        || config.alerts.len() > 32
    {
        return Err(ApiError::BadRequest(
            "模板采集参数、拨测或告警数量无效".into(),
        ));
    }
    for spec in &mut config.probes {
        spec.normalize();
        crate::probes::prepare_write(spec)?;
    }
    for alert in &config.alerts {
        let spec: crate::notifications::rules::Spec = serde_json::from_value(alert.clone())
            .map_err(|_| ApiError::BadRequest("告警模板必须符合资源告警字段".into()))?;
        if spec.name.trim().is_empty()
            || !spec.threshold.is_finite()
            || spec.threshold <= 0.0
            || !(1..=1440).contains(&spec.duration_minutes)
        {
            return Err(ApiError::BadRequest("告警名称、阈值或持续时间无效".into()));
        }
    }
    if !config.asset.is_object()
        || serde_json::to_vec(&config.asset)
            .map_err(anyhow::Error::from)?
            .len()
            > 16 * 1024
    {
        return Err(ApiError::BadRequest("采购关系必须是有界 JSON 对象".into()));
    }
    Ok(config)
}

pub async fn templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    crate::control_center::require_capability(&state, &headers, "servers:read").await?;
    let rows =
        sqlx::query("SELECT id,name,config,updated_at FROM fleet_templates ORDER BY name,id")
            .fetch_all(&state.pool)
            .await?;
    Ok(Json(rows.into_iter().map(|r| json!({"id":r.get::<Uuid,_>("id"),"name":r.get::<String,_>("name"),"config":r.get::<Value,_>("config"),"updated_at":r.get::<i64,_>("updated_at")})).collect()))
}

pub async fn save_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<TemplateInput>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "servers:write").await?;
    let name = super::text(&input.name, 128)?;
    if name.is_empty() {
        return Err(ApiError::BadRequest("模板名称不能为空".into()));
    }
    let config = normalize(input.config)?;
    validate_mirror(&config, &state)?;
    let id = input.id.unwrap_or_else(Uuid::new_v4);
    sqlx::query("INSERT INTO fleet_templates(id,name,config,created_at,updated_at) VALUES($1,$2,$3,$4,$4) ON CONFLICT(id) DO UPDATE SET name=$2,config=$3,updated_at=$4")
        .bind(id).bind(&name).bind(json!(config)).bind(now_timestamp()).execute(&state.pool).await?;
    Ok(Json(json!({"id":id,"name":name,"config":config})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchInput {
    template_id: Option<Uuid>,
    names: Vec<String>,
}

pub async fn batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BatchInput>,
) -> ApiResult<Json<Vec<Value>>> {
    crate::control_center::require_capability(&state, &headers, "servers:write").await?;
    if input.names.is_empty() || input.names.len() > 100 {
        return Err(ApiError::BadRequest("一次登记需要 1–100 台服务器".into()));
    }
    let config = if let Some(id) = input.template_id {
        let value: Value = sqlx::query_scalar("SELECT config FROM fleet_templates WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
        normalize(serde_json::from_value(value).map_err(anyhow::Error::from)?)?
    } else {
        TemplateConfig::default()
    };
    validate_mirror(&config, &state)?;
    let mut results = Vec::new();
    for (index, name) in input.names.into_iter().enumerate() {
        let result = register(&state, &config, &name).await;
        results.push(match result {
            Ok(value) => {
                json!({"index":index,"name":name,"status":"registered","registration":value})
            }
            Err(error) => {
                json!({"index":index,"name":name,"status":"failed","error":error.to_string()})
            }
        });
    }
    Ok(Json(results))
}

async fn register(state: &AppState, config: &TemplateConfig, name: &str) -> ApiResult<Value> {
    let name = super::text(name, 128)?;
    if name.is_empty() {
        return Err(ApiError::BadRequest("服务器名称不能为空".into()));
    }
    let token = auth::random_token();
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    crate::latency_tasks::lock(&mut tx).await?;
    let id: i64=sqlx::query_scalar("INSERT INTO servers(name,agent_settings,telemetry_settings,asset_settings) VALUES($1,$2,$3,$4) RETURNING id")
        .bind(name).bind(json!(config.agent_settings)).bind(json!(config.telemetry_settings)).bind(json!(config.asset_settings)).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO fleet_profiles(server_id,asset,updated_at) VALUES($1,$2,$3)")
        .bind(id)
        .bind(&config.asset)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    for spec in &config.probes {
        let mut spec = spec.clone();
        spec.id = Uuid::new_v4();
        sqlx::query("INSERT INTO network_probes(id,server_id,spec) VALUES($1,$2,$3)")
            .bind(spec.id)
            .bind(id)
            .bind(json!(spec))
            .execute(&mut *tx)
            .await?;
    }
    for alert in &config.alerts {
        let mut spec = alert.clone();
        spec["all_servers"] = json!(false);
        spec["server_ids"] = json!([id]);
        sqlx::query("INSERT INTO alert_rules(id,spec,revision) VALUES($1,$2,1)")
            .bind(Uuid::new_v4())
            .bind(spec)
            .execute(&mut *tx)
            .await?;
    }
    crate::latency_tasks::assign_defaults(&mut tx, id).await?;
    sqlx::query("INSERT INTO enrollment_tokens(token_hash,server_id,expires_at) VALUES($1,$2,$3)")
        .bind(auth::hash_token(&token))
        .bind(id)
        .bind(now + 86400)
        .execute(&mut *tx)
        .await?;
    super::record(&mut tx, id, "registered", json!({"template":true})).await?;
    tx.commit().await?;
    Ok(json!({"server_id":id,"token":token,"expires_at":now+86400,"enrolled":false}))
}

fn validate_mirror(config: &TemplateConfig, state: &AppState) -> ApiResult<()> {
    if !config.asset_settings.agent_mirror.is_empty()
        && let (Ok(mirror), Ok(panel)) = (
            reqwest::Url::parse(&config.asset_settings.agent_mirror),
            reqwest::Url::parse(&state.config.public_url),
        )
        && mirror.origin() == panel.origin()
    {
        return Err(ApiError::BadRequest(
            "Agent 下载镜像必须独立于面板，保留 GitHub 来源与验签".into(),
        ));
    }
    Ok(())
}
