use super::{Operation, digest, ids};
use crate::error::{ApiError, ApiResult};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};

pub(super) async fn user_state(
    tx: &mut Transaction<'_, Postgres>,
    users: &[i64],
) -> ApiResult<Value> {
    for id in users {
        super::super::business::lock_user(tx, *id).await?;
    }
    let state: Value = sqlx::query_scalar("SELECT COALESCE(jsonb_agg(jsonb_build_object('id',u.id,'name',u.name,'token',u.subscription_token,'entitlement',to_jsonb(e),'assignment',to_jsonb(a),'groups',COALESCE((SELECT jsonb_agg(group_id ORDER BY group_id) FROM singbox_user_policies WHERE user_id=u.id),'[]'),'accesses',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY node_id) FROM accesses x WHERE x.user_id=u.id),'[]')) ORDER BY u.id),'[]') FROM users u LEFT JOIN singbox_entitlements($2) e ON e.user_id=u.id LEFT JOIN singbox_user_packages p ON p.user_id=u.id LEFT JOIN singbox_package_assignments a ON a.id=p.assignment_id WHERE u.id=ANY($1)")
        .bind(users).bind(sinan_protocol::now_timestamp()).fetch_one(&mut **tx).await?;
    Ok(state)
}

async fn groups(tx: &mut Transaction<'_, Postgres>, groups: &[i64]) -> ApiResult<Value> {
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',g.id,'name',g.name,'nodes',COALESCE((SELECT jsonb_agg(node_id ORDER BY node_id) FROM singbox_policy_nodes WHERE group_id=g.id),'[]'),'chains',COALESCE((SELECT jsonb_agg(chain_id ORDER BY chain_id) FROM singbox_policy_chains WHERE group_id=g.id),'[]')) FROM singbox_policy_groups g WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(groups).fetch_all(&mut **tx).await?;
    if rows.len() != groups.len() {
        return Err(ApiError::BadRequest("所选策略组不存在".into()));
    }
    Ok(json!(rows))
}

async fn node(tx: &mut Transaction<'_, Postgres>, id: i64) -> ApiResult<Value> {
    let server: i64 =
        sqlx::query_scalar("SELECT server_id FROM nodes WHERE id=$1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    super::super::business::lock_server(tx, server).await?;
    super::super::settings::require_enabled(tx, server).await?;
    sqlx::query_scalar("SELECT jsonb_build_object('node',to_jsonb(n),'status',to_jsonb(m)-'updated_at','online',s.last_seen IS NOT NULL AND s.last_seen>=$2-60,'recent_observation',m.updated_at IS NOT NULL AND m.updated_at>=$2-300,'dirty',s.dirty_at,'retiring',EXISTS(SELECT 1 FROM server_retirements WHERE server_id=n.server_id)) FROM nodes n JOIN servers s ON s.id=n.server_id LEFT JOIN server_module_status m ON m.server_id=n.server_id AND m.module='singbox' WHERE n.id=$1 AND n.deleted_at IS NULL FOR UPDATE OF n")
        .bind(id).bind(sinan_protocol::now_timestamp()).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)
}

fn installed(value: &Value) -> bool {
    let status = &value["status"];
    value["dirty"].is_null()
        && value["retiring"] == false
        && value["online"] == true
        && value["recent_observation"] == true
        && status["healthy"] == true
        && status["target_rev"]
            .as_i64()
            .is_some_and(|rev| rev > 0 && status["applied_rev"] == rev)
        && status["last_error"].is_null()
}

fn safe_user(value: &Value) -> Value {
    json!({"id":value["id"],"name":value["name"],"entitlement":value["entitlement"]})
}

pub(super) async fn snapshot(
    tx: &mut Transaction<'_, Postgres>,
    operation: &Operation,
) -> ApiResult<(String, Value)> {
    let (state, summary) = match operation {
        Operation::PolicyBatch {
            user_ids,
            group_ids,
        } => {
            let users = ids(user_ids, false)?;
            let group_ids = ids(group_ids, true)?;
            let users_state = user_state(tx, &users).await?;
            let group_state = groups(tx, &group_ids).await?;
            let mut differences = Vec::new();
            for user in &users {
                let current: Vec<i64> = sqlx::query_scalar("SELECT node_id FROM singbox_desired_accesses WHERE user_id=$1 ORDER BY node_id").bind(user).fetch_all(&mut **tx).await?;
                let desired: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT node_id FROM (SELECT node_id FROM accesses WHERE user_id=$1 AND direct_grant UNION SELECT node_id FROM singbox_policy_nodes WHERE group_id=ANY($2) UNION SELECT c.entry_node_id FROM singbox_policy_chains p JOIN singbox_chains c ON c.id=p.chain_id WHERE p.group_id=ANY($2)) n ORDER BY node_id")
                    .bind(user).bind(&group_ids).fetch_all(&mut **tx).await?;
                differences.push(json!({"user_id":user,"added_nodes":desired.iter().filter(|n|!current.contains(n)).collect::<Vec<_>>(),"removed_nodes":current.iter().filter(|n|!desired.contains(n)).collect::<Vec<_>>(),"effective_nodes":desired}));
            }
            (
                json!({"users":users_state,"groups":group_state}),
                json!({"operation":"policy_batch","users":users_state.as_array().into_iter().flatten().map(safe_user).collect::<Vec<_>>(),"groups":group_state,"differences":differences,"effect":"替换所选用户的策略组集合；单独授权保留，重叠授权保留原凭据，设备确认应用后撤销最终移除的权限"}),
            )
        }
        Operation::ReplacePackage {
            user_id,
            package_group_id,
        } => {
            let state = user_state(tx, &[*user_id]).await?;
            let plan: Value = sqlx::query_scalar("SELECT to_jsonb(p)||jsonb_build_object('monthly_bytes',p.monthly_bytes::text) FROM singbox_package_groups p WHERE id=$1 AND deleted_at IS NULL FOR UPDATE").bind(package_group_id).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)?;
            let at = sinan_protocol::now_timestamp();
            let cycle: Value = sqlx::query_scalar("SELECT jsonb_build_object('cycle_start',b.cycle_start,'next_reset',b.next_reset,'used_bytes',GREATEST(COALESCE((SELECT SUM(uplink+downlink) FROM usage_records WHERE user_id=$1 AND period_end>b.cycle_start AND period_end<=b.next_reset),0)-COALESCE((SELECT SUM(bytes) FROM singbox_quota_credits WHERE user_id=$1 AND cycle_start=b.cycle_start AND next_reset=b.next_reset),0),0)::text) FROM singbox_package_groups p CROSS JOIN LATERAL singbox_cycle_bounds($3,p.reset_day,p.reset_hour,p.reset_minute,p.timezone) b WHERE p.id=$2")
                .bind(user_id).bind(package_group_id).bind(at).fetch_one(&mut **tx).await?;
            (
                json!({"user":state,"plan":plan,"cycle":cycle}),
                json!({"operation":"replace_package","user":safe_user(&state[0]),"plan":plan,"new_cycle":cycle,"effective_at":"确认时立即生效","duration_days":plan["duration_days"],"effect":"更换不可变套餐快照；有效期从确认时重新计算，历史账本保留，按新周期重新归集，不自动延长原到期日"}),
            )
        }
        Operation::ExtendValidity { user_id, days } => {
            if !(1..=36500).contains(days) {
                return Err(ApiError::BadRequest("延期天数应为 1 至 36500".into()));
            }
            let state = user_state(tx, &[*user_id]).await?;
            let expiry = state[0]["entitlement"]["expires_at"]
                .as_i64()
                .ok_or_else(|| ApiError::Conflict("用户未分配套餐，不能延期".into()))?;
            let new_expiry = expiry
                .checked_add(i64::from(*days) * 86400)
                .ok_or_else(|| ApiError::BadRequest("到期时间超出范围".into()))?;
            (
                state.clone(),
                json!({"operation":"extend_validity","user":safe_user(&state[0]),"previous_expires_at":expiry,"new_expires_at":new_expiry,"effect":"只延长原到期日，原套餐、开始时间、月度周期及本期用量保留；已到期用户不会自动获得从今天起完整的新期限"}),
            )
        }
        Operation::ResetQuota { user_id } => {
            let state = user_state(tx, &[*user_id]).await?;
            if state[0]["entitlement"]["monthly_bytes"].is_null()
                || state[0]["entitlement"]["cycle_start"].is_null()
            {
                return Err(ApiError::Conflict(
                    "用户没有有限月度额度，不能重置额度".into(),
                ));
            }
            (
                state.clone(),
                json!({"operation":"reset_quota","user":safe_user(&state[0]),"credit_bytes":state[0]["entitlement"]["used_bytes"],"effect":"为当前账期增加与当前已用量相等的补偿额度；不延长有效期，不删除历史批次，不重置设备 epoch；迟到批次仍按原账期计入"}),
            )
        }
        Operation::RotateNodeCredentials { user_id, node_ids } => {
            let nodes = ids(node_ids, false)?;
            let state = user_state(tx, &[*user_id]).await?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accesses a JOIN nodes n ON n.id=a.node_id WHERE a.user_id=$1 AND a.node_id=ANY($2) AND n.deleted_at IS NULL").bind(user_id).bind(&nodes).fetch_one(&mut **tx).await?;
            if count != nodes.len() as i64 {
                return Err(ApiError::BadRequest(
                    "只能轮换此用户已授权的受管节点；外部凭据需由提供方撤销".into(),
                ));
            }
            let mut node_states = Vec::new();
            for id in &nodes {
                node_states.push(node(tx, *id).await?);
            }
            if node_states.iter().any(|n| n["retiring"] == true) {
                return Err(ApiError::Conflict("服务器正在退役，不能轮换凭据".into()));
            }
            (
                json!({"user":state,"nodes":node_states}),
                json!({"operation":"rotate_node_credentials","user":safe_user(&state[0]),"node_ids":nodes,"effect":"重新生成所选节点连接身份，订阅地址保留；旧凭据只有在设备确认应用新配置后才可确认已撤销；无法保证强制断开现存连接"}),
            )
        }
        Operation::MigrateNode {
            source_node_id,
            candidate_node_id,
        } => {
            if source_node_id == candidate_node_id {
                return Err(ApiError::BadRequest("迁移候选必须是独立节点".into()));
            }
            let source = node(tx, *source_node_id).await?;
            let candidate = node(tx, *candidate_node_id).await?;
            let referenced: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM singbox_chains c WHERE (c.entry_node_id=ANY($1) OR c.exit_node_id=ANY($1)) AND (c.deleted_at IS NULL OR c.phase<>'retired')) OR EXISTS(SELECT 1 FROM singbox_ordered_chain_hops h JOIN singbox_chains c ON c.id=h.chain_id WHERE h.managed_node_id=ANY($1) AND (c.deleted_at IS NULL OR c.phase<>'retired'))")
                .bind(vec![*source_node_id,*candidate_node_id]).fetch_one(&mut **tx).await?;
            if referenced {
                return Err(ApiError::Conflict(
                    "链路中的节点需使用链路候选、验证和恢复流程，不能按普通节点迁移".into(),
                ));
            }
            if source["node"]["server_id"] == candidate["node"]["server_id"]
                || source["node"]["protocol"] != candidate["node"]["protocol"]
                || candidate["node"]["enabled"] != true
                || !installed(&candidate)
            {
                return Err(ApiError::Conflict(
                    "候选必须位于不同服务器，协议相同且启用；候选服务器需已成功应用当前目标配置"
                        .into(),
                ));
            }
            let users: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT user_id FROM singbox_desired_accesses WHERE node_id=$1 ORDER BY user_id").bind(source_node_id).fetch_all(&mut **tx).await?;
            let users_state = user_state(tx, &users).await?;
            let policy_groups: Vec<i64> = sqlx::query_scalar(
                "SELECT group_id FROM singbox_policy_nodes WHERE node_id=$1 ORDER BY group_id",
            )
            .bind(source_node_id)
            .fetch_all(&mut **tx)
            .await?;
            let groups_state = groups(tx, &policy_groups).await?;
            (
                json!({"source":source,"candidate":candidate,"users":users_state,"groups":groups_state}),
                json!({"operation":"migrate_node","source_node_id":source_node_id,"candidate_node_id":candidate_node_id,"source_server_id":source["node"]["server_id"],"candidate_server_id":candidate["node"]["server_id"],"candidate_endpoint":{"host":candidate["node"]["public_host"],"port":candidate["node"]["port"],"sni":candidate["node"]["sni"]},"affected_users":users_state.as_array().into_iter().flatten().map(safe_user).collect::<Vec<_>>(),"affected_groups":policy_groups,"effect":"迁移单独授权与策略组关系，候选使用独立凭据；保留旧节点与历史用量，发布两端配置后等待设备应用，入口公网可达仍需单独检测"}),
            )
        }
        Operation::Failover {
            source_chain_id,
            alternate_chain_id,
            group_ids,
            reason,
        } => {
            let reason = super::super::business::name(reason)?;
            if source_chain_id == alternate_chain_id {
                return Err(ApiError::BadRequest("备选链路必须与当前链路不同".into()));
            }
            let selected = ids(group_ids, false)?;
            let group_state = groups(tx, &selected).await?;
            let rows: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(c) FROM singbox_chains c WHERE id=ANY($1) AND deleted_at IS NULL ORDER BY id FOR UPDATE").bind(vec![*source_chain_id,*alternate_chain_id]).fetch_all(&mut **tx).await?;
            if rows.len() != 2 {
                return Err(ApiError::NotFound);
            }
            let alternate = rows
                .iter()
                .find(|c| c["id"] == *alternate_chain_id)
                .ok_or(ApiError::NotFound)?;
            let qualified = if alternate["path_kind"] == "ordered" {
                super::super::ordered_paths::lifecycle::qualified(tx, *alternate_chain_id).await?
            } else {
                sqlx::query_scalar("SELECT singbox_path_ready($1)")
                    .bind(alternate_chain_id)
                    .fetch_one(&mut **tx)
                    .await?
            };
            if !qualified {
                return Err(ApiError::Conflict(
                    "明确选择的备选链路尚未完成部署及路径验证，不能切换".into(),
                ));
            }
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM singbox_policy_chains WHERE group_id=ANY($1) AND chain_id=$2",
            )
            .bind(&selected)
            .bind(source_chain_id)
            .fetch_one(&mut **tx)
            .await?;
            if count != selected.len() as i64 {
                return Err(ApiError::Conflict(
                    "部分策略组已不包含原链路，请重新选择".into(),
                ));
            }
            let users:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT user_id FROM singbox_user_policies WHERE group_id=ANY($1) ORDER BY user_id").bind(&selected).fetch_all(&mut **tx).await?;
            let users_state = user_state(tx, &users).await?;
            (
                json!({"chains":rows,"groups":group_state,"users":users_state,"qualified":qualified}),
                json!({"operation":"failover","source_chain_id":source_chain_id,"source_chain_name":rows.iter().find(|c|c["id"]==*source_chain_id).map(|c|c["name"].clone()),"alternate_chain_id":alternate_chain_id,"alternate_chain_name":alternate["name"],"reason":reason,"group_ids":selected,"affected_users":users,"effect":"仅将显式选中的策略组转到已验证备选链路；不会创建自动出口池或绕过链路直连，旧链路保留，可另行确认恢复与清理"}),
            )
        }
    };
    Ok((digest(&state)?, summary))
}
