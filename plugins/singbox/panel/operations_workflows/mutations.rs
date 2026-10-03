use super::{Operation, digest};
use crate::error::ApiResult;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) fn user_id(operation: &Operation) -> Option<i64> {
    match operation {
        Operation::ReplacePackage { user_id, .. }
        | Operation::ExtendValidity { user_id, .. }
        | Operation::ResetQuota { user_id }
        | Operation::RotateNodeCredentials { user_id, .. } => Some(*user_id),
        _ => None,
    }
}

pub(super) async fn execute(
    tx: &mut Transaction<'_, Postgres>,
    administrator: i64,
    preview_id: Uuid,
    operation: &Operation,
) -> ApiResult<Value> {
    let now = sinan_protocol::now_timestamp();
    let receipt = match operation {
        Operation::PolicyBatch {
            user_ids,
            group_ids,
        } => {
            sqlx::query("DELETE FROM singbox_user_policies WHERE user_id=ANY($1)")
                .bind(user_ids)
                .execute(&mut **tx)
                .await?;
            sqlx::query("INSERT INTO singbox_user_policies SELECT u,g FROM unnest($1::bigint[]) u CROSS JOIN unnest($2::bigint[]) g").bind(user_ids).bind(group_ids).execute(&mut **tx).await?;
            super::super::policies::sync_users(tx, user_ids).await?;
            json!({"status":"queued","user_ids":user_ids,"group_ids":group_ids,"deployment_confirmation_required":true})
        }
        Operation::ReplacePackage {
            user_id,
            package_group_id,
        } => {
            let servers = super::super::business::lock_user_servers(tx, *user_id).await?;
            let assignment:i64=sqlx::query_scalar("INSERT INTO singbox_package_assignments(user_id,request_id,package_group_id,package_name,monthly_bytes,reset_day,reset_hour,reset_minute,timezone,starts_at,expires_at) SELECT $1,$2,id,name,monthly_bytes,reset_day,reset_hour,reset_minute,timezone,$4,$4+duration_days::bigint*86400 FROM singbox_package_groups WHERE id=$3 AND deleted_at IS NULL RETURNING id")
                .bind(user_id).bind(preview_id).bind(package_group_id).bind(now).fetch_one(&mut **tx).await?;
            sqlx::query("INSERT INTO singbox_user_packages(user_id,assignment_id) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET assignment_id=EXCLUDED.assignment_id").bind(user_id).bind(assignment).execute(&mut **tx).await?;
            super::super::business::mark_dirty(tx, &servers).await?;
            json!({"status":"saved","assignment_id":assignment,"effective_at":now,"ledger_preserved":true})
        }
        Operation::ExtendValidity { user_id, days } => {
            let servers = super::super::business::lock_user_servers(tx, *user_id).await?;
            let row=sqlx::query("INSERT INTO singbox_package_assignments(user_id,request_id,package_group_id,package_name,monthly_bytes,reset_day,reset_hour,reset_minute,timezone,starts_at,expires_at) SELECT a.user_id,$2,a.package_group_id,a.package_name,a.monthly_bytes,a.reset_day,a.reset_hour,a.reset_minute,a.timezone,a.starts_at,a.expires_at+$3::bigint*86400 FROM singbox_user_packages p JOIN singbox_package_assignments a ON a.id=p.assignment_id WHERE p.user_id=$1 RETURNING id,expires_at")
                .bind(user_id).bind(preview_id).bind(days).fetch_one(&mut **tx).await?;
            let assignment: i64 = row.get("id");
            sqlx::query("UPDATE singbox_user_packages SET assignment_id=$2 WHERE user_id=$1")
                .bind(user_id)
                .bind(assignment)
                .execute(&mut **tx)
                .await?;
            super::super::business::mark_dirty(tx, &servers).await?;
            json!({"status":"saved","assignment_id":assignment,"expires_at":row.get::<i64,_>("expires_at"),"quota_reset":false})
        }
        Operation::ResetQuota { user_id } => {
            let servers = super::super::business::lock_user_servers(tx, *user_id).await?;
            let credit:String=sqlx::query_scalar("INSERT INTO singbox_quota_credits(id,user_id,cycle_start,next_reset,bytes,created_at,administrator_id) SELECT $1,user_id,cycle_start,next_reset,used_bytes::numeric,$3,$4 FROM singbox_entitlements($3) WHERE user_id=$2 RETURNING bytes::text")
                .bind(preview_id).bind(user_id).bind(now).bind(administrator).fetch_one(&mut **tx).await?;
            super::super::business::mark_dirty(tx, &servers).await?;
            json!({"status":"saved","credit_bytes":credit,"validity_extended":false,"ledger_preserved":true})
        }
        Operation::RotateNodeCredentials { user_id, node_ids } => {
            let servers = super::super::business::lock_user_servers(tx, *user_id).await?;
            let configs: Vec<(i64, Value)> =
                sqlx::query_as("SELECT id,protocol_config FROM nodes WHERE id=ANY($1) ORDER BY id")
                    .bind(node_ids)
                    .fetch_all(&mut **tx)
                    .await?;
            for (node, config) in configs {
                let config: sinan_compiler::ProtocolConfig =
                    serde_json::from_value(config).map_err(anyhow::Error::from)?;
                sqlx::query(
                    "UPDATE accesses SET uuid=$3,credential=$4 WHERE user_id=$1 AND node_id=$2",
                )
                .bind(user_id)
                .bind(node)
                .bind(Uuid::new_v4())
                .bind(super::super::node_protocol::credential(
                    config.credential_size(),
                ))
                .execute(&mut **tx)
                .await?;
            }
            let mut rotations = Vec::new();
            for server in &servers {
                let accesses:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('node_id',a.node_id,'uuid',a.uuid,'credential',a.credential) FROM accesses a JOIN nodes n ON n.id=a.node_id WHERE a.user_id=$1 AND a.node_id=ANY($2) AND n.server_id=$3 ORDER BY a.node_id").bind(user_id).bind(node_ids).bind(server).fetch_all(&mut **tx).await?;
                if accesses.is_empty() {
                    continue;
                }
                let baseline:i64=sqlx::query_scalar("SELECT COALESCE(MAX(target_rev),0) FROM server_module_status WHERE server_id=$1 AND module='singbox'").bind(server).fetch_one(&mut **tx).await?;
                let nodes: Vec<i64> = accesses
                    .iter()
                    .filter_map(|v| v["node_id"].as_i64())
                    .collect();
                let id = Uuid::new_v4();
                sqlx::query("INSERT INTO singbox_credential_rotations(id,user_id,server_id,baseline_revision,node_ids,credential_fingerprint,requested_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(id).bind(user_id).bind(server).bind(baseline).bind(&nodes).bind(digest(&json!(accesses))?).bind(now).execute(&mut **tx).await?;
                rotations.push(json!({"id":id,"server_id":server,"node_ids":nodes,"state":"pending_device_confirmation"}));
            }
            super::super::business::mark_dirty(tx, &servers).await?;
            json!({"status":"queued","rotations":rotations,"subscription_url_reset":false,"old_downloaded_credentials_revoked":false})
        }
        Operation::MigrateNode {
            source_node_id,
            candidate_node_id,
        } => {
            let users:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT user_id FROM singbox_desired_accesses WHERE node_id=$1 ORDER BY user_id").bind(source_node_id).fetch_all(&mut **tx).await?;
            let servers: Vec<i64> = sqlx::query_scalar(
                "SELECT DISTINCT server_id FROM nodes WHERE id=ANY($1) ORDER BY server_id",
            )
            .bind(vec![*source_node_id, *candidate_node_id])
            .fetch_all(&mut **tx)
            .await?;
            sqlx::query("INSERT INTO singbox_policy_nodes(group_id,node_id) SELECT group_id,$2 FROM singbox_policy_nodes WHERE node_id=$1 ON CONFLICT DO NOTHING").bind(source_node_id).bind(candidate_node_id).execute(&mut **tx).await?;
            sqlx::query("DELETE FROM singbox_policy_nodes WHERE node_id=$1")
                .bind(source_node_id)
                .execute(&mut **tx)
                .await?;
            let directs: Vec<i64> = sqlx::query_scalar(
                "SELECT user_id FROM accesses WHERE node_id=$1 AND direct_grant ORDER BY user_id",
            )
            .bind(source_node_id)
            .fetch_all(&mut **tx)
            .await?;
            let config: Value = sqlx::query_scalar("SELECT protocol_config FROM nodes WHERE id=$1")
                .bind(candidate_node_id)
                .fetch_one(&mut **tx)
                .await?;
            let config: sinan_compiler::ProtocolConfig =
                serde_json::from_value(config).map_err(anyhow::Error::from)?;
            for user in directs {
                sqlx::query("INSERT INTO accesses(user_id,node_id,uuid,stat_name,direct_grant,credential) VALUES($1,$2,$3,$4,TRUE,$5) ON CONFLICT(user_id,node_id) DO UPDATE SET direct_grant=TRUE")
                    .bind(user).bind(candidate_node_id).bind(Uuid::new_v4()).bind(sinan_compiler::stat_name(user,*candidate_node_id)).bind(super::super::node_protocol::credential(config.credential_size())).execute(&mut **tx).await?;
            }
            sqlx::query("UPDATE accesses SET direct_grant=FALSE WHERE node_id=$1")
                .bind(source_node_id)
                .execute(&mut **tx)
                .await?;
            super::super::policies::sync_users(tx, &users).await?;
            super::super::business::mark_dirty(tx, &servers).await?;
            json!({"status":"queued","source_node_id":source_node_id,"candidate_node_id":candidate_node_id,"server_ids":servers,"source_retained":true,"agent_identity_copied":false,"device_confirmation_required":true,"historical_node_usage_retained":true})
        }
        Operation::Failover {
            source_chain_id,
            alternate_chain_id,
            group_ids,
            reason,
        } => {
            let users:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT user_id FROM singbox_user_policies WHERE group_id=ANY($1) ORDER BY user_id").bind(group_ids).fetch_all(&mut **tx).await?;
            sqlx::query("INSERT INTO singbox_policy_chains SELECT unnest($1::bigint[]),$2 ON CONFLICT DO NOTHING").bind(group_ids).bind(alternate_chain_id).execute(&mut **tx).await?;
            sqlx::query("DELETE FROM singbox_policy_chains WHERE group_id=ANY($1) AND chain_id=$2")
                .bind(group_ids)
                .bind(source_chain_id)
                .execute(&mut **tx)
                .await?;
            super::super::policies::sync_users(tx, &users).await?;
            json!({"status":"queued","source_chain_id":source_chain_id,"alternate_chain_id":alternate_chain_id,"group_ids":group_ids,"reason":reason,"automatic_failover":false,"direct_fallback":false,"old_chain_retained":true})
        }
    };
    Ok(receipt)
}
