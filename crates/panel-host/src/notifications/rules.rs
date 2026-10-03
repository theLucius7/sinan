use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    Cpu,
    Memory,
    Disk,
    NetIn,
    NetOut,
}

impl Metric {
    pub fn unit(self) -> &'static str {
        if matches!(self, Self::NetIn | Self::NetOut) {
            "MiB/s"
        } else {
            "%"
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Aggregation {
    Average,
    Continuous,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub name: String,
    pub metric: Metric,
    pub threshold: f64,
    pub duration_minutes: u16,
    pub aggregation: Aggregation,
    pub all_servers: bool,
    pub enabled: bool,
    pub server_ids: Vec<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    spec: Spec,
    revision: Option<i64>,
}

#[derive(Serialize)]
pub struct Rule {
    pub id: Uuid,
    pub spec: Spec,
    pub revision: i64,
}

pub(super) async fn read(tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<Vec<Rule>> {
    let rows: Vec<(Uuid, Value, i64)> =
        sqlx::query_as("SELECT id,spec,revision FROM alert_rules ORDER BY id")
            .fetch_all(&mut **tx)
            .await?;
    rows.into_iter()
        .map(|(id, spec, revision)| {
            Ok(Rule {
                id,
                spec: serde_json::from_value(spec)?,
                revision,
            })
        })
        .collect()
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Rule>>> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let mut rules = read(&mut tx).await?;
    let live: std::collections::HashSet<i64> =
        sqlx::query_scalar("SELECT id FROM servers WHERE deleted_at IS NULL")
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
    for rule in &mut rules {
        rule.spec.server_ids.retain(|id| live.contains(id));
    }
    Ok(Json(rules))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> ApiResult<(StatusCode, Json<Rule>)> {
    auth::require_admin(&state, &headers).await?;
    Ok((
        StatusCode::CREATED,
        Json(save(&state, Uuid::new_v4(), input, false).await?),
    ))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Input>,
) -> ApiResult<Json<Rule>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(save(&state, id, input, true).await?))
}

async fn save(state: &AppState, id: Uuid, mut input: Input, editing: bool) -> ApiResult<Rule> {
    let spec = &mut input.spec;
    spec.name = spec.name.trim().into();
    spec.server_ids.sort_unstable();
    if spec.name.is_empty()
        || spec.name.chars().count() > 80
        || spec.name.chars().any(char::is_control)
        || !spec.threshold.is_finite()
        || spec.threshold < 0.01
        || spec.threshold
            > if spec.metric.unit() == "%" {
                100.0
            } else {
                1_000_000.0
            }
        || !(1..=1440).contains(&spec.duration_minutes)
        || spec.server_ids.len() > 4096
        || (spec.enabled && !spec.all_servers && spec.server_ids.is_empty())
        || spec.server_ids.iter().any(|id| *id <= 0)
        || spec.server_ids.windows(2).any(|v| v[0] == v[1])
    {
        return Err(ApiError::BadRequest(
            "资源规则无效，请检查名称、阈值、1–1440 分钟窗口及服务器选择".into(),
        ));
    }
    if spec.all_servers {
        spec.server_ids.clear();
    }
    let mut tx = state.pool.begin().await?;
    super::lock_settings(&mut tx).await?;
    let revision = if editing {
        let previous: i64 = sqlx::query_scalar("SELECT revision FROM alert_rules WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
        if input.revision != Some(previous) {
            return Err(ApiError::Conflict("规则已被修改，请刷新后重试".into()));
        }
        previous + 1
    } else {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules")
            .fetch_one(&mut *tx)
            .await?;
        if count >= 20 {
            return Err(ApiError::Conflict("最多配置 20 条资源告警规则".into()));
        }
        1
    };
    let existing: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM servers WHERE id=ANY($1) AND deleted_at IS NULL ORDER BY id FOR SHARE",
    )
    .bind(&spec.server_ids)
    .fetch_all(&mut *tx)
    .await?;
    if existing != spec.server_ids {
        return Err(ApiError::BadRequest("选择的服务器不存在或已删除".into()));
    }
    close_previous(&mut tx, id).await?;
    sqlx::query("INSERT INTO alert_rules(id,spec,revision) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET spec=EXCLUDED.spec,revision=EXCLUDED.revision")
        .bind(id).bind(json!(spec)).bind(revision).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Rule {
        id,
        spec: input.spec,
        revision,
    })
}

async fn close_previous(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("UPDATE server_alert_events SET resolved_at=$2,resolution='changed' WHERE category='resource' AND details->>'rule_id'=$1 AND resolved_at IS NULL")
        .bind(id.to_string()).bind(sinan_protocol::now_timestamp()).execute(&mut **tx).await?;
    sqlx::query("UPDATE notification_outbox o SET status='cancelled' FROM server_alert_events e WHERE o.event_id=e.id AND e.category='resource' AND e.details->>'rule_id'=$1 AND o.status='pending'")
        .bind(id.to_string()).execute(&mut **tx).await?;
    Ok(())
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    super::lock_settings(&mut tx).await?;
    if sqlx::query("DELETE FROM alert_rules WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 0
    {
        return Err(ApiError::NotFound);
    }
    close_previous(&mut tx, id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
