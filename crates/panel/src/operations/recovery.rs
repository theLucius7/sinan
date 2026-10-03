use super::model::{digest, label};
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

pub async fn backups(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    super::require_global(&state, &headers, "recovery:read").await?;
    let records:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(b)||jsonb_build_object('drills',COALESCE((SELECT jsonb_agg(to_jsonb(d) ORDER BY d.recorded_at DESC) FROM operations_restore_drills d WHERE d.backup_id=b.id),'[]'::jsonb)) FROM operations_backup_records b ORDER BY b.created_at DESC LIMIT 100").fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"records":records,"execution":"定时计划由面板本机执行 pg_dump 与 age；独立 scripts/recovery.py 执行完整性核对和隔离恢复；外部报告保留其来源，面板不读取备份私钥","recovery_manual":"docs/operations-recovery.md"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    name: String,
    manifest: Value,
    location: String,
    encrypted: bool,
    retain_until: Option<i64>,
    dependency_ids: Vec<Uuid>,
}

fn manifest_valid(manifest: &Value) -> bool {
    manifest["complete"] == true
        && matches!(manifest["format"].as_i64(), Some(1 | 2))
        && manifest["sha256"].as_object().is_some_and(|hashes| {
            ["environment", "database.dump", "panel-data.tar.gz"]
                .iter()
                .all(|name| {
                    hashes
                        .get(*name)
                        .and_then(Value::as_str)
                        .is_some_and(hash_valid)
                })
        })
        && manifest["image"]
            .as_str()
            .is_some_and(|v| !v.trim().is_empty())
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|v| v.is_ascii_hexdigit())
}

pub async fn import_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Backup>,
) -> ApiResult<Json<Value>> {
    let actor = super::require_global(&state, &headers, "recovery:write").await?;
    label(&request.name, 128)?;
    label(&request.location, 2048)?;
    if !manifest_valid(&request.manifest) || request.dependency_ids.len() > 32 {
        return Err(ApiError::BadRequest(
            "备份清单不完整或依赖过多；不得登记为可恢复备份".into(),
        ));
    }
    let hash = digest(&request.manifest)?;
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(530018)")
        .execute(&mut *tx)
        .await?;
    for dependency in &request.dependency_ids {
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_backup_records WHERE id=$1 AND retired_at IS NULL)").bind(dependency).fetch_one(&mut *tx).await?;
        if !exists {
            return Err(ApiError::Conflict("恢复依赖不存在或已退役".into()));
        }
    }
    sqlx::query("INSERT INTO operations_backup_records(id,name,manifest,manifest_sha256,location,encrypted,verification,created_at,imported_at,imported_by,retain_until,dependency_ids) VALUES($1,$2,$3,$4,$5,$6,'declared',$7,$7,$8,$9,$10)")
        .bind(id).bind(request.name).bind(request.manifest).bind(&hash).bind(request.location).bind(request.encrypted).bind(now_timestamp()).bind(actor).bind(request.retain_until).bind(request.dependency_ids).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"manifest_sha256":hash,"verification":"declared","message":"仅登记清单；完整性与恢复必须由独立工具实际执行并导入报告"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Drill {
    report: Value,
}

pub async fn import_drill(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Drill>,
) -> ApiResult<Json<Value>> {
    let actor = super::require_global(&state, &headers, "recovery:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let report = &request.report;
    if report["tool"] != "sinan-recovery"
        || report["format"] != 1
        || report["manifest_sha256"]
            .as_str()
            .is_none_or(|v| !hash_valid(v))
        || report["completed_at"]
            .as_i64()
            .is_none_or(|v| v <= 0 || v > now_timestamp())
        || !matches!(
            report["action"].as_str(),
            Some("verify" | "drill" | "restore")
        )
    {
        return Err(ApiError::BadRequest(
            "报告必须来自独立恢复工具并包含清单身份与完成时间".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(530018)")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT manifest_sha256,manifest,retired_at FROM operations_backup_records WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if report["manifest_sha256"] != row.get::<String, _>("manifest_sha256")
        || row.get::<Option<i64>, _>("retired_at").is_some()
    {
        return Err(ApiError::Conflict(
            "报告对应的备份身份不一致或备份已退役".into(),
        ));
    }
    let restored = matches!(report["action"].as_str(), Some("drill" | "restore"));
    let requires_key_authentication = row.get::<Value, _>("manifest")["required_key_ids"]
        .as_array()
        .is_some_and(|versions| !versions.is_empty());
    let passed = report["passed"] == true
        && report["checks"]["integrity"] == true
        && (!restored
            || (report["checks"]["database_restore"] == true
                && report["checks"]["panel_health"] == true
                && (!requires_key_authentication
                    || report["checks"]["keyring_authenticated"] == true)
                && report["isolated"] == true));
    let drill = Uuid::new_v4();
    sqlx::query("INSERT INTO operations_restore_drills(id,backup_id,report,report_sha256,passed,recorded_at,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(drill).bind(id).bind(report).bind(digest(report)?).bind(passed).bind(now_timestamp()).bind(actor).execute(&mut *tx).await?;
    if passed {
        sqlx::query("UPDATE operations_backup_records SET verification=CASE WHEN $2 THEN 'restored' WHEN verification='restored' THEN verification ELSE 'integrity_verified' END WHERE id=$1").bind(id).bind(restored).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"id":drill,"passed":passed,"evidence_origin":"外部工具报告，面板未重新执行恢复"}),
    ))
}

pub async fn retire(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    super::require_global(&state, &headers, "recovery:write").await?;
    control_center::require_recent_proof(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(530018)")
        .execute(&mut *tx)
        .await?;
    let _: Uuid =
        sqlx::query_scalar("SELECT id FROM operations_backup_records WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let dependencies:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM operations_backup_records WHERE $1=ANY(dependency_ids) AND retired_at IS NULL").bind(id).fetch_all(&mut *tx).await?;
    let jobs:Vec<Uuid>=sqlx::query_scalar("SELECT p.job_id FROM operations_panel_steps p JOIN operations_jobs j ON j.id=p.job_id WHERE (p.backup_id=$1 OR p.execution_id=$1) AND (j.status IN ('queued','running','paused','cancel_requested','uncertain') OR p.state IN ('running','uncertain'))").bind(id).fetch_all(&mut *tx).await?;
    let held:bool=sqlx::query_scalar("SELECT retain_until IS NOT NULL AND retain_until>$2 FROM operations_backup_records WHERE id=$1").bind(id).bind(now_timestamp()).fetch_one(&mut *tx).await?;
    if !dependencies.is_empty() || !jobs.is_empty() || held {
        return Err(ApiError::ConflictReferences {
            message: "仍被恢复点或运维任务依赖，或处于保留期限，不能退役".into(),
            references: json!({"dependencies":dependencies,"operation_jobs":jobs,"retention_hold":held}),
        });
    }
    sqlx::query("UPDATE operations_backup_records SET retired_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"retired":true,"storage_deleted":false,"message":"台账退役不会删除存储；使用独立工具的精确路径保留清理流程"}),
    ))
}
