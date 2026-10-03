use super::{digest, event, prune};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "proxy:read").await?;
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    super::super::business::lock_user(&mut tx, id).await?;
    let account:Value=sqlx::query_scalar("SELECT jsonb_build_object('user_id',u.id,'name',u.name,'portal_created',p.account_id IS NOT NULL,'keys',(SELECT COUNT(*) FROM passkey_credentials WHERE account_id=p.account_id),'active_sessions',(SELECT COUNT(*) FROM singbox_portal_sessions WHERE account_id=p.account_id AND expires_at>$2),'activation_expires_at',p.activation_expires_at) FROM users u LEFT JOIN singbox_portal_accounts p ON p.user_id=u.id WHERE u.id=$1").bind(id).bind(sinan_protocol::now_timestamp()).fetch_one(&mut *tx).await?;
    let subscription = super::super::subscriptions::diagnostic_on(&mut tx, id).await?;
    let permissions:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('node_id',n.id,'name',n.name,'server_id',n.server_id,'protocol',n.protocol,'enabled',n.enabled,'direct_grant',COALESCE(a.direct_grant,FALSE),'policy_groups',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',src.id,'name',src.name,'chain_id',src.chain_id) ORDER BY src.id,src.chain_id) FROM (SELECT g.id,g.name,NULL::bigint AS chain_id FROM singbox_user_policies up JOIN singbox_policy_groups g ON g.id=up.group_id JOIN singbox_policy_nodes pn ON pn.group_id=g.id AND pn.node_id=n.id WHERE up.user_id=$1 UNION SELECT g.id,g.name,c.id AS chain_id FROM singbox_user_policies up JOIN singbox_policy_groups g ON g.id=up.group_id JOIN singbox_policy_chains pc ON pc.group_id=g.id JOIN singbox_chains c ON c.id=pc.chain_id AND c.entry_node_id=n.id WHERE up.user_id=$1) src),'[]'),'deployment',jsonb_build_object('target_revision',m.target_rev,'applied_revision',m.applied_rev,'healthy',m.healthy,'last_error',m.last_error,'last_observed_at',m.updated_at,'pending',s.dirty_at IS NOT NULL),'effective',EXISTS(SELECT 1 FROM singbox_eligible_accesses($2) e WHERE e.user_id=$1 AND e.node_id=n.id)) FROM singbox_desired_accesses d JOIN nodes n ON n.id=d.node_id JOIN servers s ON s.id=n.server_id LEFT JOIN accesses a ON a.user_id=d.user_id AND a.node_id=d.node_id LEFT JOIN server_module_status m ON m.server_id=n.server_id AND m.module='singbox' WHERE d.user_id=$1 ORDER BY n.id")
        .bind(id).bind(sinan_protocol::now_timestamp()).fetch_all(&mut *tx).await?;
    let ledger:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('server_id',r.server_id,'epoch',r.epoch,'sequence',r.seq::text,'node_id',r.node_id,'period_start',r.period_start,'period_end',r.period_end,'uplink',r.uplink::text,'downlink',r.downlink::text,'batch_payload_hash',b.payload_hash,'received_at',b.received_at,'last_replayed_at',b.last_replayed_at,'replay_count',b.replay_count::text,'delivery_delay_seconds',CASE WHEN b.received_at IS NULL THEN NULL ELSE GREATEST(b.received_at-r.period_end,0) END,'package_cycle_start',e.cycle_start,'package_next_reset',e.next_reset,'in_current_cycle',r.period_end>e.cycle_start AND r.period_end<=e.next_reset) FROM usage_records r JOIN usage_batches b USING(server_id,epoch,seq) LEFT JOIN singbox_entitlements($2) e ON e.user_id=r.user_id WHERE r.user_id=$1 ORDER BY r.period_end DESC,r.server_id,r.seq DESC LIMIT 200")
        .bind(id).bind(sinan_protocol::now_timestamp()).fetch_all(&mut *tx).await?;
    let credits:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'cycle_start',cycle_start,'next_reset',next_reset,'bytes',bytes::text,'created_at',created_at,'administrator_id',administrator_id) FROM singbox_quota_credits WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100").bind(id).fetch_all(&mut *tx).await?;
    let history:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'package_group_id',package_group_id,'package_name',package_name,'monthly_bytes',monthly_bytes::text,'starts_at',starts_at,'expires_at',expires_at,'reset_day',reset_day,'reset_hour',reset_hour,'reset_minute',reset_minute,'timezone',timezone) FROM singbox_package_assignments WHERE user_id=$1 ORDER BY id DESC LIMIT 100").bind(id).fetch_all(&mut *tx).await?;
    let events:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'administrator_id',administrator_id,'action',action,'detail',detail,'created_at',created_at) FROM singbox_operation_events WHERE user_id=$1 ORDER BY id DESC LIMIT 100").bind(id).fetch_all(&mut *tx).await?;
    let rotations = rotations(&mut tx, id).await?;
    let external = super::super::external_access::subscription_nodes(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"user_id":id,"account":account,"subscription":subscription,"permissions":permissions,"external_authorizations":external.entries,"ledger":ledger,"quota_credits":credits,"package_history":history,"rotations":rotations,"events":events,"limitations":{"user_speed_limit":{"available":false,"reason":"当前单运行时尚未提供可验证的逐用户限速能力"},"connection_limit":{"available":false,"reason":"当前协议与运行时没有统一逐用户连接数控制能力"},"external_revocation":{"available":false,"reason":"外部节点凭据由提供方控制，移除订阅授权不会撤销已下载凭据"},"credentials_read":{"available":false,"reason":super::super::secret_access::REASON},"ledger_receipt_time":{"available":true,"legacy_unknown":true,"reason":"新批次保存首次接收、重放次数与最近重放时间；旧批次接收时间未知。延迟依据设备时钟，需考虑时钟偏差"}}}),
    ))
}

pub(super) async fn rotations(
    tx: &mut Transaction<'_, Postgres>,
    user: i64,
) -> ApiResult<Vec<Value>> {
    let rows=sqlx::query("SELECT r.*,m.applied_rev,m.target_rev,m.healthy,m.updated_at,s.last_seen,s.dirty_at,s.capabilities,d.source_json FROM singbox_credential_rotations r JOIN servers s ON s.id=r.server_id LEFT JOIN server_module_status m ON m.server_id=r.server_id AND m.module='singbox' LEFT JOIN deployments d ON d.server_id=r.server_id AND d.module='singbox' AND d.rev=m.applied_rev WHERE r.user_id=$1 ORDER BY r.requested_at DESC,r.id LIMIT 100").bind(user).fetch_all(&mut **tx).await?;
    let mut result = Vec::new();
    for row in rows {
        let nodes: Vec<i64> = row.get("node_ids");
        let current:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('node_id',node_id,'uuid',uuid,'credential',credential) FROM accesses WHERE user_id=$1 AND node_id=ANY($2) ORDER BY node_id").bind(user).bind(&nodes).fetch_all(&mut **tx).await?;
        let expected: String = row.get("credential_fingerprint");
        let same_current = digest(&json!(current))? == expected;
        let mut applied = Vec::new();
        if let Some(source) = row.get::<Option<Value>, _>("source_json") {
            let models = super::super::ordered_paths::models::public_nodes(source)
                .map_err(anyhow::Error::from)?;
            for node in models {
                if nodes.contains(&node.id) {
                    for access in node.users.iter().filter(|a| a.user_id == user) {
                        applied.push(json!({"node_id":node.id,"uuid":access.uuid,"credential":access.credential}));
                    }
                }
            }
            applied.sort_by_key(|v| v["node_id"].as_i64());
        }
        let capabilities: Value = row.get("capabilities");
        let exact_required = capabilities.as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value == sinan_protocol::RUNTIME_CHECKPOINT_CAPABILITY)
        });
        let exact_confirmed: bool = if exact_required {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_module_checkpoints c JOIN runtime_control_receipts f ON f.request_id=c.checkpoint_request_id JOIN runtime_deployment_bindings b ON b.server_id=c.server_id AND b.module=c.module AND b.rev=$2 WHERE c.server_id=$1 AND c.module='singbox' AND c.verified_at>=$3 AND c.verified_at>$4-300 AND f.outcome='verified' AND c.checkpoint_json->'healthy'='true' AND c.checkpoint_json->'binding'->>'binding_digest'=b.binding_digest AND c.checkpoint_json->'binding'->>'bundle_sha256'=b.bundle_sha256 AND c.checkpoint_json->'binding'->>'deployment_id'=b.deployment_id::text)").bind(row.get::<i64,_>("server_id")).bind(row.get::<Option<i64>,_>("applied_rev")).bind(row.get::<i64,_>("requested_at")).bind(sinan_protocol::now_timestamp()).fetch_one(&mut **tx).await?
        } else {
            true
        };
        let confirmed = same_current
            && exact_confirmed
            && row
                .get::<Option<i64>, _>("last_seen")
                .is_some_and(|at| sinan_protocol::now_timestamp().saturating_sub(at) <= 60)
            && row.get::<Option<i64>, _>("dirty_at").is_none()
            && row
                .get::<Option<i64>, _>("updated_at")
                .is_some_and(|at| at >= row.get::<i64, _>("requested_at"))
            && row.get::<Option<bool>, _>("healthy") == Some(true)
            && row
                .get::<Option<i64>, _>("applied_rev")
                .is_some_and(|rev| rev > row.get::<i64, _>("baseline_revision"))
            && digest(&json!(applied))? == expected;
        if confirmed {
            sqlx::query("UPDATE singbox_credential_rotations SET confirmed_at=$2,confirmed_revision=$3 WHERE id=$1").bind(row.get::<Uuid,_>("id")).bind(row.get::<Option<i64>,_>("updated_at")).bind(row.get::<Option<i64>,_>("applied_rev")).execute(&mut **tx).await?;
        }
        result.push(json!({"id":row.get::<Uuid,_>("id"),"server_id":row.get::<i64,_>("server_id"),"node_ids":nodes,"requested_at":row.get::<i64,_>("requested_at"),"applied_revision":row.get::<Option<i64>,_>("applied_rev"),"last_device_observation":row.get::<Option<i64>,_>("updated_at"),"state":if !same_current {"superseded"} else if confirmed {"device_confirmed"} else if row.get::<Option<i64>,_>("confirmed_at").is_some() {"confirmation_stale"} else {"pending_device_confirmation"},"last_confirmed_at":if confirmed {row.get::<Option<i64>,_>("updated_at")} else {row.get::<Option<i64>,_>("confirmed_at")},"old_downloaded_credentials_revoked":confirmed,"existing_connections_disconnected":false}));
    }
    Ok(result)
}

pub(super) async fn privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "proxy:read").await?;
    let mut tx = state.pool.begin().await?;
    prune(&mut tx).await?;
    let policy: Value =
        sqlx::query_scalar("SELECT to_jsonb(p)-'singleton' FROM singbox_operation_privacy p")
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"policy":policy,"captured_fields":["主体编号","对象编号","动作","脱敏影响与结果","时间"],"not_captured":["订阅令牌","连接密钥","原始客户端地址","完整终端正文"],"usage_ledger_retention":"历史计量账本保留，审计清理不删除账本","central_policy_rule":"实际保留时间取插件分类策略与系统 audit/proxy-access 分类策略较短值，后台每三十秒执行清理；中心 proxy-access=0 停记订阅访问"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Privacy {
    administrator_days: i32,
    subscription_days: i32,
    security_days: i32,
}

pub(super) async fn save_privacy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Privacy>,
) -> ApiResult<Json<Value>> {
    let administrator =
        crate::control_center::require_capability(&state, &headers, "proxy:write").await?;
    if !(1..=3650).contains(&request.administrator_days)
        || !(0..=365).contains(&request.subscription_days)
        || !(1..=3650).contains(&request.security_days)
    {
        return Err(ApiError::BadRequest(
            "管理员/安全事件保留 1–3650 天，订阅获取记录保留 0–365 天；0 表示不记录订阅获取".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE singbox_operation_privacy SET administrator_days=$1,subscription_days=$2,security_days=$3 WHERE singleton").bind(request.administrator_days).bind(request.subscription_days).bind(request.security_days).execute(&mut *tx).await?;
    event(&mut tx,Some(administrator),None,"privacy_update",json!({"administrator_days":request.administrator_days,"subscription_days":request.subscription_days,"security_days":request.security_days})).await?;
    prune(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"saved":true})))
}
