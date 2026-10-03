use super::model::label;
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    name: String,
    interval_secs: i64,
    next_run_at: i64,
    recipient: String,
    retention_count: i32,
    retention_days: i32,
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    super::require_global(&state, &headers, "recovery:read").await?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(s) FROM operations_backup_schedules s ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        json!({"schedules":rows,"executor":"面板本机 pg_dump 与 age；数据库导出快照和签名制品写锁","storage_configured":std::env::var_os("SINAN_BACKUP_DIR").is_some(),"immutable_images_configured":std::env::var_os("SINAN_BACKUP_PANEL_IMAGE").is_some()&&std::env::var_os("SINAN_BACKUP_POSTGRES_IMAGE").is_some(),"keyring_material":"仅备份外部保管位置和所需密钥ID，不打包解密主密钥"}),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Schedule>,
) -> ApiResult<Json<Value>> {
    let actor = super::require_global(&state, &headers, "recovery:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    label(&request.name, 128)?;
    let now = now_timestamp();
    if !(3600..=31536000).contains(&request.interval_secs)
        || request.next_run_at < now
        || request.next_run_at > now + 31536000
        || !(1..=1000).contains(&request.retention_count)
        || !(1..=3650).contains(&request.retention_days)
        || request.recipient.len() != 62
        || !request.recipient.starts_with("age1")
        || !request
            .recipient
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit())
    {
        return Err(ApiError::BadRequest(
            "备份周期、首次时间、age公钥或保留策略无效".into(),
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_backup_schedules(id,name,requested_by,interval_secs,next_run_at,recipient,retention_count,retention_days,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)").bind(id).bind(request.name).bind(actor).bind(request.interval_secs).bind(request.next_run_at).bind(request.recipient).bind(request.retention_count).bind(request.retention_days).bind(now).execute(&state.pool).await?;
    Ok(Json(
        json!({"id":id,"status":"scheduled","storage":"进程配置的SINAN_BACKUP_DIR；未配置时使用私有本机目录，不宣称异地存储"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pause {
    paused: bool,
}

pub async fn pause(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Pause>,
) -> ApiResult<Json<Value>> {
    super::require_global(&state, &headers, "recovery:write").await?;
    if !request.paused {
        control_center::require_recent_proof(&state, &headers).await?;
    }
    let changed=sqlx::query("UPDATE operations_backup_schedules SET paused=$2,updated_at=$3 WHERE id=$1 AND claimed_id IS NULL").bind(id).bind(request.paused).bind(now_timestamp()).execute(&state.pool).await?.rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict(
            "备份仍在执行或计划不存在，请先等待执行记录".into(),
        ));
    }
    Ok(Json(json!({"id":id,"paused":request.paused})))
}

pub(super) async fn tick(state: &AppState) -> ApiResult<()> {
    let now = now_timestamp();
    sqlx::query("UPDATE operations_backup_schedules SET paused=true,claimed_id=NULL,last_error='面板重启时备份尚未确认完成；已暂停，检查私有暂存材料后人工恢复',updated_at=$1 WHERE claimed_id IS NOT NULL AND last_started_at<$2")
        .bind(now).bind(state.started_at).execute(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    let row=sqlx::query("SELECT * FROM operations_backup_schedules WHERE NOT paused AND claimed_id IS NULL AND next_run_at<=$1 ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED").bind(now).fetch_optional(&mut *tx).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let id: Uuid = row.get("id");
    let actor: i64 = row.get("requested_by");
    let global:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM administrator_profiles WHERE admin_id=$1 AND enabled AND all_servers)").bind(actor).fetch_one(&mut *tx).await?;
    if !global
        || control_center::require_actor_capability(state, actor, "recovery:write")
            .await
            .is_err()
    {
        sqlx::query("UPDATE operations_backup_schedules SET paused=true,last_error='提交者备份权限已撤销',updated_at=$2 WHERE id=$1").bind(id).bind(now).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(());
    }
    let execution = Uuid::new_v4();
    let due: i64 = row.get("next_run_at");
    let interval: i64 = row.get("interval_secs");
    sqlx::query("UPDATE operations_backup_schedules SET claimed_id=$2,last_started_at=$3,next_run_at=$4,updated_at=$3 WHERE id=$1").bind(id).bind(execution).bind(now).bind(due+((now-due)/interval+1)*interval).execute(&mut *tx).await?;
    tx.commit().await?;
    let result = super::backup_executor::execute(
        state,
        execution,
        id,
        &row.get::<String, _>("recipient"),
        actor,
        &row.get::<String, _>("name"),
    )
    .await;
    let error = result.as_ref().err().map(|error| match error {
        ApiError::Conflict(message) | ApiError::BadRequest(message) => message.clone(),
        _ => "备份执行失败，请检查工具、数据库或受限存储".into(),
    });
    sqlx::query("UPDATE operations_backup_schedules SET claimed_id=NULL,last_finished_at=$2,last_error=$3,updated_at=$2 WHERE id=$1 AND claimed_id=$4").bind(id).bind(now_timestamp()).bind(&error).bind(execution).execute(&state.pool).await?;
    if let Some(error) = error {
        let mut tx = state.pool.begin().await?;
        super::incidents::open(
            &mut tx,
            &format!("backup:{id}"),
            None,
            &format!("定时完整备份失败：{error}"),
            "critical",
            json!({"schedule_id":id,"execution_id":execution,"observed_at":now_timestamp()}),
            now_timestamp(),
            None,
        )
        .await?;
        tx.commit().await?;
        return result.map(|_| ());
    } else {
        let mut tx = state.pool.begin().await?;
        super::incidents::recover(&mut tx,&format!("backup:{id}"),json!({"backup_id":execution,"database_dump":"实际完成","encryption":"实际完成","observed_at":now_timestamp()}),now_timestamp(),true).await?;
        tx.commit().await?;
        super::backup_executor::retention(
            state,
            id,
            row.get("retention_count"),
            row.get("retention_days"),
        )
        .await?;
    }
    Ok(())
}
