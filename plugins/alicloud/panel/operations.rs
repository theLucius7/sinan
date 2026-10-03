use super::{
    account_on, billing,
    client::Cloud,
    failure, lock,
    model::{Account, Operation, Resource, Snapshot, Target},
    resource,
};
use crate::error::{ApiError, ApiResult};
use sqlx::{PgPool, Postgres, Transaction, types::Json};
use uuid::Uuid;

pub(super) async fn load(pool: &PgPool, id: Uuid) -> ApiResult<Operation> {
    sqlx::query_as("SELECT * FROM alicloud_operations WHERE id=$1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}
async fn fresh_resource(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<Resource> {
    sqlx::query_as("SELECT * FROM alicloud_resources WHERE id=$1 AND NOT archived")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ApiError::NotFound)
}
pub(super) async fn idle(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> ApiResult<()> {
    super::power::idle(tx, id).await?;
    let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM alicloud_operations WHERE resource_id=$1 AND status IN ('queued','running','uncertain')) OR EXISTS(SELECT 1 FROM alicloud_security_group_operations WHERE resource_id=$1 AND status IN ('running','unknown'))")
        .bind(id).fetch_one(&mut **tx).await?;
    if active {
        return Err(ApiError::Conflict(
            "此资源仍有待处理或结果不确定的操作，请先核对操作记录".into(),
        ));
    }
    Ok(())
}

pub(super) async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    account: &Account,
    resource: &Resource,
    before: &Snapshot,
    target: &Target,
    cycle: Option<&str>,
) -> ApiResult<Uuid> {
    target.validate(before)?;
    idle(tx, resource.id).await?;
    let id = Uuid::new_v4();
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE alicloud_operations SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status='preview'")
        .bind(resource.id).bind(now).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO alicloud_operations(id,resource_id,account_revision,resource_revision,before_state,target,source,billing_cycle,status,created_at,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10)")
        .bind(id).bind(resource.id).bind(account.revision).bind(resource.revision).bind(Json(before)).bind(Json(target))
        .bind(if cycle.is_some(){"automatic"}else{"manual"}).bind(cycle).bind(if cycle.is_some(){"queued"}else{"preview"}).bind(now).bind(now+300).execute(&mut **tx).await?;
    Ok(id)
}

pub(super) async fn snapshot_on(
    tx: &mut Transaction<'_, Postgres>,
    resource: Uuid,
    snapshot: &Snapshot,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE alicloud_resources SET snapshot=$2,checked_at=$3,error_code=NULL WHERE id=$1",
    )
    .bind(resource)
    .bind(Json(snapshot))
    .bind(sinan_protocol::now_timestamp())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn preview(
    pool: &PgPool,
    id: Uuid,
    target: Target,
    revision: i64,
    cloud: &Cloud,
) -> ApiResult<Operation> {
    let initial = resource(pool, id).await?;
    let mut tx = lock(pool, initial.account_id).await?;
    let account = account_on(&mut tx, initial.account_id).await?;
    let resource = fresh_resource(&mut tx, id).await?;
    if !account.enabled {
        return Err(ApiError::Conflict("请先启用云账号".into()));
    }
    if resource.revision != revision {
        return Err(ApiError::Conflict("资源配置已变化，请刷新后重试".into()));
    }
    idle(&mut tx, id).await?;
    let before = cloud.snapshot(&account, &resource).await.map_err(failure)?;
    target.validate(&before)?;
    if target.matches(&before) {
        return Err(ApiError::Conflict("资源已是目标配置，无需调整".into()));
    }
    snapshot_on(&mut tx, id, &before).await?;
    let operation = prepare(&mut tx, &account, &resource, &before, &target, None).await?;
    tx.commit().await?;
    load(pool, operation).await
}

pub(super) async fn confirm(pool: &PgPool, id: Uuid) -> ApiResult<Operation> {
    let initial = load(pool, id).await?;
    let resource = resource(pool, initial.resource_id).await?;
    let mut tx = lock(pool, resource.account_id).await?;
    let current: Operation = sqlx::query_as("SELECT * FROM alicloud_operations WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if matches!(
        current.status.as_str(),
        "queued" | "running" | "uncertain" | "succeeded"
    ) {
        return Ok(current);
    }
    let account = account_on(&mut tx, resource.account_id).await?;
    let resource = fresh_resource(&mut tx, resource.id).await?;
    if current.status != "preview"
        || current.expires_at <= sinan_protocol::now_timestamp()
        || !account.enabled
        || account.revision != current.account_revision
        || resource.revision != current.resource_revision
    {
        return Err(ApiError::Conflict(
            "预览已过期或配置发生变化，请重新预览".into(),
        ));
    }
    idle(&mut tx, resource.id).await?;
    sqlx::query("UPDATE alicloud_operations SET status='queued',updated_at=$2 WHERE id=$1")
        .bind(id)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    load(pool, id).await
}

pub(super) async fn cancel(pool: &PgPool, id: Uuid, dismiss: bool) -> ApiResult<()> {
    let initial = load(pool, id).await?;
    let resource = resource(pool, initial.resource_id).await?;
    let mut tx = lock(pool, resource.account_id).await?;
    let current: Operation = sqlx::query_as("SELECT * FROM alicloud_operations WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let status = if dismiss && current.status == "uncertain" {
        // Closing uncertain tracking never undoes a cloud action. Pause automation.
        sqlx::query(
            "UPDATE alicloud_resources SET auto_enabled=false,power_policy=jsonb_set(power_policy,'{enabled}','false'),manual_hold=true,revision=revision+1 WHERE id=$1",
        )
        .bind(resource.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE alicloud_operations SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status IN ('preview','queued')")
            .bind(resource.id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
        sqlx::query("UPDATE alicloud_power_jobs SET status='cancelled',updated_at=$2 WHERE resource_id=$1 AND status IN ('preview','queued')")
            .bind(resource.id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
        "dismissed"
    } else if !dismiss && matches!(current.status.as_str(), "preview" | "queued") {
        "cancelled"
    } else {
        return Err(ApiError::Conflict(
            "此操作已经开始，请先核对云端结果".into(),
        ));
    };
    sqlx::query("UPDATE alicloud_operations SET status=$2,updated_at=$3 WHERE id=$1")
        .bind(id)
        .bind(status)
        .bind(sinan_protocol::now_timestamp())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

fn eligible(operation: &Operation, account: &Account, resource: &Resource, now: i64) -> bool {
    account.enabled
        && account.revision == operation.account_revision
        && resource.revision == operation.resource_revision
        && operation.expires_at > now
        && (operation.source == "manual"
            || (resource.auto_enabled
                && billing::exceeded(account, now)
                && operation.billing_cycle.as_deref() == Some(billing::month(now).as_str())
                && operation.target.charge_type == "PayByTraffic"
                && operation.before_state.charge_type == "PayByTraffic"
                && operation.target.bandwidth_mbps == resource.cap_mbps
                && resource.cap_mbps < operation.before_state.bandwidth_mbps))
}
async fn finish(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    status: &str,
    error: Option<&str>,
) -> ApiResult<()> {
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE alicloud_operations SET status=$2,error_code=$3,updated_at=$4,next_check_at=$5 WHERE id=$1")
        .bind(id).bind(status).bind(error).bind(now).bind(now+60).execute(&mut **tx).await?;
    Ok(())
}
async fn readback(
    tx: &mut Transaction<'_, Postgres>,
    operation: &Operation,
    account: &Account,
    resource: &Resource,
    cloud: &Cloud,
) -> ApiResult<()> {
    match cloud.snapshot(account, resource).await {
        Ok(snapshot) => {
            let matches = operation.target.matches(&snapshot)
                && snapshot.public_ip == operation.before_state.public_ip;
            snapshot_on(tx, resource.id, &snapshot).await?;
            finish(
                tx,
                operation.id,
                if matches { "succeeded" } else { "uncertain" },
                if matches {
                    None
                } else {
                    Some("awaiting_confirmation")
                },
            )
            .await?;
        }
        Err(error) => finish(tx, operation.id, "uncertain", Some(error.code)).await?,
    }
    Ok(())
}

pub(super) async fn process(pool: &PgPool, id: Uuid, cloud: &Cloud) -> ApiResult<()> {
    let initial = load(pool, id).await?;
    let resource = resource(pool, initial.resource_id).await?;
    let mut tx = lock(pool, resource.account_id).await?;
    let operation: Operation = sqlx::query_as("SELECT * FROM alicloud_operations WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let account = account_on(&mut tx, resource.account_id).await?;
    let resource = fresh_resource(&mut tx, resource.id).await?;
    let now = sinan_protocol::now_timestamp();
    if operation.next_check_at > now {
        return Ok(());
    }
    if matches!(operation.status.as_str(), "running" | "uncertain") {
        readback(&mut tx, &operation, &account, &resource, cloud).await?;
        tx.commit().await?;
        return Ok(());
    }
    if operation.status != "queued" {
        return Ok(());
    }
    if !eligible(&operation, &account, &resource, now) {
        finish(&mut tx, id, "cancelled", Some("policy_inactive")).await?;
        tx.commit().await?;
        return Ok(());
    }
    let current = match cloud.snapshot(&account, &resource).await {
        Ok(value) => value,
        Err(error) => {
            finish(&mut tx, id, "failed", Some(error.code)).await?;
            tx.commit().await?;
            return Ok(());
        }
    };
    snapshot_on(&mut tx, resource.id, &current).await?;
    if current != operation.before_state.0 {
        finish(&mut tx, id, "failed", Some("state_changed")).await?;
        tx.commit().await?;
        return Ok(());
    }
    // Commit intent before the external side effect. Recovery only reads state.
    sqlx::query("UPDATE alicloud_operations SET status='running',updated_at=$2 WHERE id=$1")
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut tx = lock(pool, resource.account_id).await?;
    let account = account_on(&mut tx, resource.account_id).await?;
    let resource = fresh_resource(&mut tx, resource.id).await?;
    let operation: Operation = sqlx::query_as("SELECT * FROM alicloud_operations WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if operation.status != "running" {
        return Ok(());
    }
    if !eligible(
        &operation,
        &account,
        &resource,
        sinan_protocol::now_timestamp(),
    ) {
        finish(&mut tx, id, "cancelled", Some("policy_inactive")).await?;
    } else {
        match cloud
            .modify(
                &account,
                &resource,
                &operation.before_state,
                &operation.target,
                id,
            )
            .await
        {
            Ok(request_id) => {
                sqlx::query("UPDATE alicloud_operations SET request_id=$2 WHERE id=$1")
                    .bind(id)
                    .bind(request_id)
                    .execute(&mut *tx)
                    .await?;
                readback(&mut tx, &operation, &account, &resource, cloud).await?;
            }
            Err(error) => finish(&mut tx, id, "uncertain", Some(error.code)).await?,
        }
    }
    tx.commit().await?;
    Ok(())
}
