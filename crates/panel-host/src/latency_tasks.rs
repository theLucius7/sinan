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
use sinan_protocol::ProbeSpec;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    spec: ProbeSpec,
    default_enabled: bool,
    server_ids: Vec<i64>,
    revision: Option<i64>,
}

#[derive(Serialize)]
pub struct Task {
    id: Uuid,
    spec: ProbeSpec,
    default_enabled: bool,
    server_ids: Vec<i64>,
    revision: i64,
}

// Serialize default assignment and group edits before taking server row locks.
pub(crate) async fn lock(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(1936289389, 1)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Vec<Task>>> {
    auth::require_admin(&state, &headers).await?;
    let rows: Vec<(Uuid, Value, bool, i64, Vec<i64>)> = sqlx::query_as(
        "SELECT t.id,t.spec,t.default_enabled,t.revision,ARRAY(SELECT p.server_id FROM network_probes p
         JOIN servers s ON s.id=p.server_id AND s.deleted_at IS NULL WHERE p.task_id=t.id ORDER BY p.server_id)
         FROM latency_tasks t ORDER BY t.spec->>'name',t.id")
        .fetch_all(&state.pool).await?;
    let tasks = rows
        .into_iter()
        .map(|(id, spec, default_enabled, revision, server_ids)| {
            Ok(Task {
                id,
                spec: crate::probes::presentation(serde_json::from_value(spec)?),
                default_enabled,
                server_ids,
                revision,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()
        .map_err(anyhow::Error::from)?;
    Ok(Json(tasks))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> ApiResult<(StatusCode, Json<Task>)> {
    auth::require_admin(&state, &headers).await?;
    let task = save(&state, Uuid::new_v4(), input, false).await?;
    Ok((StatusCode::CREATED, Json(task)))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Input>,
) -> ApiResult<Json<Task>> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(save(&state, id, input, true).await?))
}

async fn save(state: &AppState, id: Uuid, mut input: Input, editing: bool) -> ApiResult<Task> {
    input.spec.id = id;
    input.server_ids.sort_unstable();
    if input.server_ids.len() > 4096
        || input.server_ids.iter().any(|id| *id <= 0)
        || input.server_ids.windows(2).any(|ids| ids[0] == ids[1])
    {
        return Err(ApiError::BadRequest(
            "延迟任务配置无效，请检查目标、间隔及服务器选择".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    lock(&mut tx).await?;
    let revision = if editing {
        let (previous, revision): (Value, i64) =
            sqlx::query_as("SELECT spec,revision FROM latency_tasks WHERE id=$1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(ApiError::NotFound)?;
        if input.revision != Some(revision) {
            return Err(ApiError::Conflict("任务已被修改，请刷新后重试".into()));
        }
        let previous: ProbeSpec = serde_json::from_value(previous).map_err(anyhow::Error::from)?;
        if !input.spec.same_measurement_identity(&previous) {
            return Err(ApiError::Conflict(
                "检测方式、目标、端口、网络版本、运营商和地区创建后不可修改，请新建任务以保留历史归属".into(),
            ));
        }
        revision
            .checked_add(1)
            .ok_or_else(|| ApiError::Conflict("任务修订号已到上限，请保留历史并新建任务".into()))?
    } else {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM latency_tasks")
            .fetch_one(&mut *tx)
            .await?;
        if count >= 32 {
            return Err(ApiError::Conflict("最多配置 32 个统一延迟任务".into()));
        }
        1
    };
    crate::probes::prepare_write(&mut input.spec)?;
    let mut affected: Vec<i64> =
        sqlx::query_scalar("SELECT server_id FROM network_probes WHERE task_id=$1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    affected.extend(&input.server_ids);
    affected.sort_unstable();
    affected.dedup();
    sqlx::query("SELECT id FROM servers WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(&affected)
        .fetch_all(&mut *tx)
        .await?;
    let servers: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM servers WHERE id=ANY($1) AND deleted_at IS NULL ORDER BY id",
    )
    .bind(&input.server_ids)
    .fetch_all(&mut *tx)
    .await?;
    if servers != input.server_ids {
        return Err(ApiError::BadRequest(
            "选择的服务器不存在或已删除，请刷新后重试".into(),
        ));
    }
    for server in &servers {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM network_probes WHERE server_id=$1 AND (task_id IS NULL OR task_id<>$2)")
            .bind(server).bind(id).fetch_one(&mut *tx).await?;
        if count >= 32 {
            return Err(ApiError::Conflict(format!(
                "服务器 #{server} 已有 32 个拨测，未保存任何更改"
            )));
        }
    }
    sqlx::query("INSERT INTO latency_tasks(id,spec,default_enabled,revision) VALUES($1,$2,$3,$4)
        ON CONFLICT(id) DO UPDATE SET spec=EXCLUDED.spec,default_enabled=EXCLUDED.default_enabled,revision=EXCLUDED.revision")
        .bind(id).bind(json!(input.spec)).bind(input.default_enabled).bind(revision).execute(&mut *tx).await?;
    // Removing an assignment never reuses its measurement ID if assigned again later.
    sqlx::query("DELETE FROM network_probes WHERE task_id=$1 AND NOT(server_id=ANY($2))")
        .bind(id)
        .bind(&servers)
        .execute(&mut *tx)
        .await?;
    for server in &servers {
        let previous: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM network_probes WHERE task_id=$1 AND server_id=$2")
                .bind(id)
                .bind(server)
                .fetch_optional(&mut *tx)
                .await?;
        let mut spec = input.spec.clone();
        spec.id = previous.unwrap_or_else(Uuid::new_v4);
        sqlx::query("INSERT INTO network_probes(id,server_id,spec,task_id) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET spec=EXCLUDED.spec,revision=network_probes.revision+1")
            .bind(spec.id).bind(server).bind(json!(spec)).bind(id).execute(&mut *tx).await?;
    }
    for server in affected {
        crate::probes::bump_revision(&mut tx, server).await?;
    }
    tx.commit().await?;
    Ok(Task {
        id,
        spec: crate::probes::presentation(input.spec),
        default_enabled: input.default_enabled,
        server_ids: servers,
        revision,
    })
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    input: Option<Json<crate::probes::DeleteProbe>>,
) -> ApiResult<StatusCode> {
    auth::require_admin(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    lock(&mut tx).await?;
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM latency_tasks WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    if input.and_then(|Json(input)| input.revision) != Some(revision) {
        return Err(ApiError::Conflict("任务已被修改，请刷新后重试".into()));
    }
    let servers: Vec<i64> = sqlx::query_scalar(
        "SELECT server_id FROM network_probes WHERE task_id=$1 ORDER BY server_id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("SELECT id FROM servers WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(&servers)
        .fetch_all(&mut *tx)
        .await?;
    if sqlx::query("DELETE FROM latency_tasks WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 0
    {
        return Err(ApiError::NotFound);
    }
    for server in servers {
        crate::probes::bump_revision(&mut tx, server).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// The caller acquires the group lock before inserting the server and explicit probes.
pub(crate) async fn assign_defaults(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
) -> ApiResult<()> {
    let defaults: Vec<(Uuid, Value)> =
        sqlx::query_as("SELECT id,spec FROM latency_tasks WHERE default_enabled ORDER BY id")
            .fetch_all(&mut **tx)
            .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM network_probes WHERE server_id=$1")
        .bind(server)
        .fetch_one(&mut **tx)
        .await?;
    if count + defaults.len() as i64 > 32 {
        return Err(ApiError::Conflict(
            "初始拨测与默认延迟任务合计超过 32 个，请减少目标后重试".into(),
        ));
    }
    for (id, spec) in defaults {
        let mut spec: ProbeSpec = serde_json::from_value(spec).map_err(anyhow::Error::from)?;
        spec.id = Uuid::new_v4();
        sqlx::query("INSERT INTO network_probes(id,server_id,spec,task_id) VALUES($1,$2,$3,$4)")
            .bind(spec.id)
            .bind(server)
            .bind(json!(spec))
            .bind(id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("UPDATE latency_tasks SET revision=revision+1 WHERE id=$1")
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    crate::probes::bump_revision(tx, server).await?;
    Ok(())
}
