use super::client::Inventory;
use crate::error::{ApiError, ApiResult};
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub(super) const RESOURCE_SELECT: &str = "SELECT r.server_id,jsonb_build_object('id',r.id,'account_id',r.account_id,'account_name',a.name,'account_archived',a.archived,'cloud_id',r.cloud_id,'name',r.name,'snapshot',r.snapshot,'presence',r.presence,'last_seen_at',r.last_seen_at,'verified_at',r.verified_at,'last_attempt_at',r.last_attempt_at,'error_code',r.error_code,'stale',a.archived OR r.presence='unknown' OR r.error_code IS NOT NULL OR r.verified_at IS NULL OR r.verified_at<$1-21600,'link',CASE WHEN r.server_id IS NULL AND r.notes='' THEN NULL ELSE jsonb_build_object('server_id',r.server_id,'notes',r.notes,'updated_at',r.updated_at,'updated_by',r.updated_by) END) AS value FROM operations_hetzner_resources r JOIN operations_hetzner_accounts a ON a.id=r.account_id";

pub(super) async fn persist(
    pool: &PgPool,
    account_id: Uuid,
    refresh_id: Uuid,
    started: i64,
    inventory: &Inventory,
) -> ApiResult<Value> {
    let now = now_timestamp();
    let mut tx = pool.begin().await?;
    let account = sqlx::query("SELECT last_read_at FROM operations_hetzner_accounts WHERE id=$1 AND NOT archived AND refresh_id=$2 FOR UPDATE")
        .bind(account_id).bind(refresh_id).fetch_optional(&mut *tx).await?.ok_or_else(|| {
            ApiError::Conflict("账户在读取期间已被修改或停用，本次读取结果未覆盖当前配置".into())
        })?;
    let previous_read: Option<i64> = account.try_get("last_read_at")?;
    sqlx::query("INSERT INTO operations_hetzner_refreshes(id,account_id,started_at,completed_at,complete,pages,observed,error_code) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(refresh_id).bind(account_id).bind(started).bind(now).bind(inventory.complete).bind(inventory.pages as i32)
        .bind(inventory.servers.len() as i32).bind(&inventory.error_code).execute(&mut *tx).await?;
    let presence = if inventory.complete {
        "observed"
    } else {
        "unknown"
    };
    let mut seen = Vec::with_capacity(inventory.servers.len());
    for remote in &inventory.servers {
        seen.push(remote.cloud_id.clone());
        let previous = sqlx::query("SELECT id,name,snapshot,presence FROM operations_hetzner_resources WHERE account_id=$1 AND cloud_id=$2 FOR UPDATE")
            .bind(account_id).bind(&remote.cloud_id).fetch_optional(&mut *tx).await?;
        let id = previous
            .as_ref()
            .map(|row| row.get("id"))
            .unwrap_or_else(Uuid::new_v4);
        let previous_snapshot: Option<Value> = previous.as_ref().map(|row| row.get("snapshot"));
        let previous_presence: Option<String> = previous.as_ref().map(|row| row.get("presence"));
        let previous_name: Option<String> = previous.as_ref().map(|row| row.get("name"));
        let changes = changes(
            previous_snapshot.as_ref(),
            previous_presence.as_deref(),
            previous_name.as_deref(),
            &remote.snapshot,
            presence,
            &remote.name,
        );
        sqlx::query("INSERT INTO operations_hetzner_resources(id,account_id,cloud_id,name,snapshot,presence,last_seen_at,verified_at,last_attempt_at,error_code,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$7,$9,$7) ON CONFLICT(account_id,cloud_id) DO UPDATE SET name=EXCLUDED.name,snapshot=EXCLUDED.snapshot,presence=EXCLUDED.presence,last_seen_at=EXCLUDED.last_seen_at,verified_at=CASE WHEN $10 THEN EXCLUDED.verified_at ELSE operations_hetzner_resources.verified_at END,last_attempt_at=EXCLUDED.last_attempt_at,error_code=EXCLUDED.error_code")
            .bind(id).bind(account_id).bind(&remote.cloud_id).bind(&remote.name).bind(&remote.snapshot).bind(presence).bind(now)
            .bind(inventory.complete.then_some(now)).bind(&inventory.error_code).bind(inventory.complete).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO operations_hetzner_observations(resource_id,refresh_id,observed_at,source,presence,snapshot,changes) VALUES($1,$2,$3,'hetzner_cloud_v1_servers',$4,$5,$6)")
            .bind(id).bind(refresh_id).bind(now).bind(presence).bind(&remote.snapshot).bind(changes).execute(&mut *tx).await?;
    }
    let unseen_presence = if inventory.complete {
        "absent"
    } else {
        "unknown"
    };
    // A failed or capped inventory cannot establish absence. Keep the last
    // observed snapshot and record uncertainty instead of retiring resources.
    sqlx::query("WITH previous AS MATERIALIZED (SELECT id,snapshot,presence,error_code FROM operations_hetzner_resources WHERE account_id=$1 AND NOT(cloud_id=ANY($2)) AND (presence<>$3 OR error_code IS DISTINCT FROM $4) FOR UPDATE), changed AS (UPDATE operations_hetzner_resources r SET presence=$3,last_attempt_at=$5,error_code=$4,verified_at=CASE WHEN $6 THEN $5 ELSE r.verified_at END FROM previous p WHERE r.id=p.id RETURNING r.id) INSERT INTO operations_hetzner_observations(resource_id,refresh_id,observed_at,source,presence,snapshot,changes) SELECT p.id,$7,$5,'hetzner_cloud_v1_servers',$3,p.snapshot,jsonb_build_array(jsonb_build_object('field','presence','before',p.presence,'after',$3),jsonb_build_object('field','provider_error','before',p.error_code,'after',$4)) FROM previous p JOIN changed c ON c.id=p.id")
        .bind(account_id).bind(&seen).bind(unseen_presence).bind(&inventory.error_code).bind(now).bind(inventory.complete).bind(refresh_id)
        .execute(&mut *tx).await?;
    sqlx::query("UPDATE operations_hetzner_resources SET last_attempt_at=$3,error_code=$4,verified_at=CASE WHEN $5 THEN $3 ELSE verified_at END WHERE account_id=$1 AND NOT(cloud_id=ANY($2))")
        .bind(account_id).bind(&seen).bind(now).bind(&inventory.error_code).bind(inventory.complete).execute(&mut *tx).await?;
    let last_read = if inventory.complete {
        Some(now)
    } else {
        previous_read
    };
    sqlx::query("UPDATE operations_hetzner_accounts SET last_read_at=$2,last_error=$3,refresh_id=NULL,refresh_started_at=NULL WHERE id=$1")
        .bind(account_id).bind(last_read).bind(&inventory.error_code).execute(&mut *tx).await?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM operations_hetzner_resources WHERE account_id=$1")
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(
        json!({"account_id":account_id,"refresh_id":refresh_id,"complete":inventory.complete,"pages":inventory.pages,"observed":inventory.servers.len(),"total_cached":total,"error_code":inventory.error_code,"last_read_at":last_read,"remote_action_executed":false}),
    )
}

fn changes(
    previous: Option<&Value>,
    previous_presence: Option<&str>,
    previous_name: Option<&str>,
    current: &Value,
    presence: &str,
    name: &str,
) -> Value {
    let mut changes = Vec::new();
    if previous_presence != Some(presence) {
        changes.push(json!({"field":"presence","before":previous_presence,"after":presence}));
    }
    if previous_name != Some(name) {
        changes.push(json!({"field":"name","before":previous_name,"after":name}));
    }
    for key in [
        "status",
        "ipv4",
        "ipv6",
        "server_type",
        "location",
        "datacenter",
        "protection",
        "traffic",
    ] {
        let before = previous.and_then(|value| value.get(key));
        let after = current.get(key);
        if before != after {
            changes.push(json!({"field":key,"before":before,"after":after}));
        }
    }
    json!(changes)
}
