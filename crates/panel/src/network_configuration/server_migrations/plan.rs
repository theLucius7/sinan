use super::super::{
    documents,
    models::{Configuration, Document},
    x509,
};
use super::{Request, compatibility, transform};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::http::HeaderMap;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) async fn build(
    state: &AppState,
    headers: &HeaderMap,
    tx: &mut Transaction<'_, Postgres>,
    request: &Request,
    identity_map: &BTreeMap<Uuid, Uuid>,
) -> ApiResult<Value> {
    let mut server_ids = vec![request.source_server_id, request.target_server_id];
    server_ids.sort_unstable();
    let mut servers = BTreeMap::new();
    for id in server_ids {
        servers.insert(id, server(tx, id).await?);
    }
    let target = servers
        .get(&request.target_server_id)
        .ok_or(ApiError::NotFound)?;
    let ids: Vec<_> = request
        .selections
        .iter()
        .map(|selection| selection.document_id)
        .collect();
    let rows: Vec<Document> =
        sqlx::query_as("SELECT * FROM network_documents WHERE id=ANY($1) ORDER BY id FOR UPDATE")
            .bind(&ids)
            .fetch_all(&mut **tx)
            .await?;
    if rows.len() != ids.len() {
        return Err(ApiError::NotFound);
    }
    let mut changes = Vec::new();
    let mut blockers = Vec::new();
    let mut references = BTreeMap::new();
    let mut dns_references = BTreeMap::new();
    let mut desired = BTreeMap::new();
    let mut credential_ids = BTreeSet::new();
    for document in rows {
        let config = documents::configuration(&document)?;
        documents::access(state, headers, &config, true).await?;
        documents::reference_access(state, headers, &config).await?;
        let selection = request
            .selections
            .iter()
            .find(|selection| selection.document_id == document.id)
            .ok_or(ApiError::NotFound)?;
        let after = transform::selected(
            &config,
            selection.target_config.as_ref(),
            request.source_server_id,
            request.target_server_id,
            identity_map,
        )?;
        documents::access(state, headers, &after, true).await?;
        // Fresh-identity dependencies are not yet inserted. Check existing source references;
        // the destination references are checked again inside the application transaction.
        let destination = identity_map
            .get(&document.id)
            .copied()
            .unwrap_or(document.id);
        let independent_identity = matches!(
            config,
            Configuration::Mesh { .. } | Configuration::Tunnel { .. }
        );
        if independent_identity != (destination != document.id) {
            return Err(ApiError::Conflict("独立网络身份映射已变化".into()));
        }
        for issue in compatibility::checks(&after, target) {
            blockers.push(json!({"document_id":document.id,"issue":issue}));
        }
        let mut notes = vec![
            "仅迁移目标配置；部署与真实可达性另行确认",
            "原服务器上的运行服务不会因此停止",
        ];
        if independent_identity {
            notes.extend([
                "使用新的业务对象标识，在目标本机另行生成密钥",
                "原配置与原密钥留在原服务器；旧身份不复制",
                "对端成员或中转需明确授权新的公钥后再连接",
            ]);
        }
        if let Configuration::Mesh { .. } = config {
            notes.push("新旧私有地址不能同时占用；启用候选前安排源接口停止和对端公钥更新");
        }
        if let Configuration::Tunnel { .. } = config {
            notes.push("候选隧道默认禁用；旧中转监听仍可能占用，需要单独清理或改发布端口");
        }
        if matches!(
            config,
            Configuration::Domain { .. } | Configuration::Certificate { .. }
        ) {
            notes.push("DDNS规则、DNS账号和签发凭据保持原引用；DNS地址同步另用插件迁移预览");
        }
        if let Configuration::Endpoint {
            public_address: Some(_),
            ..
        } = config
        {
            notes.push("公网地址不会根据服务器替换自动改写；请核对新入口及外部NAT维护方");
        }
        for related in transform::relation_ids(&config) {
            if references.contains_key(&related) {
                continue;
            }
            let linked: Document =
                sqlx::query_as("SELECT * FROM network_documents WHERE id=$1 FOR SHARE")
                    .bind(related)
                    .fetch_optional(&mut **tx)
                    .await?
                    .ok_or(ApiError::NotFound)?;
            documents::access(state, headers, &documents::configuration(&linked)?, false).await?;
            references.insert(related,json!({"id":linked.id,"kind":linked.kind,"revision":linked.revision,"config":linked.config,"active_version":linked.active_version}));
        }
        for rule in transform::rules(&config) {
            if dns_references.contains_key(&rule) {
                continue;
            }
            let row = sqlx::query(
                "SELECT id,server_id,revision,config FROM ddns_rules WHERE id=$1 FOR SHARE",
            )
            .bind(rule)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(ApiError::NotFound)?;
            let linked_server: i64 = row.get("server_id");
            control_center::require_server(state, headers, linked_server, "dns:read").await?;
            let rule_config: Value = row.get("config");
            let credential: Option<Uuid> = rule_config["credential_id"]
                .as_str()
                .and_then(|value| value.parse().ok());
            if let Some(id) = credential {
                credential_ids.insert(id);
            }
            let account = if let Some(account_id) = rule_config["account_id"]
                .as_str()
                .and_then(|value| value.parse::<Uuid>().ok())
            {
                let account =
                    sqlx::query("SELECT config,revision FROM dns_accounts WHERE id=$1 FOR SHARE")
                        .bind(account_id)
                        .fetch_optional(&mut **tx)
                        .await?
                        .ok_or(ApiError::NotFound)?;
                let account_config: Value = account.get("config");
                let actor = control_center::authenticate(state, headers).await?;
                let scope = account_config["server_ids"]
                    .as_array()
                    .ok_or(ApiError::NotFound)?;
                if (scope.is_empty() && !actor.global_servers())
                    || scope.iter().any(|server| {
                        server
                            .as_i64()
                            .is_none_or(|server| !actor.allows_server(server))
                    })
                {
                    return Err(ApiError::Forbidden(
                        "关联DNS账号不在当前管理员的完整范围内".into(),
                    ));
                }
                if let Some(id) = account_config["credential_id"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                {
                    credential_ids.insert(id);
                }
                json!({"id":account_id,"revision":account.get::<i64,_>("revision"),"config":account_config})
            } else {
                Value::Null
            };
            dns_references.insert(rule,json!({"id":rule,"server_id":linked_server,"revision":row.get::<i64,_>("revision"),"config":rule_config,"credential_id":credential,"account":account,"migration":"separate_ddns_preview"}));
        }
        let active = if let Some(version) = document.active_version {
            let row=sqlx::query("SELECT id,revision,fingerprint,not_before,not_after,public_chain FROM network_certificate_versions WHERE id=$1 AND certificate_id=$2 FOR SHARE")
                .bind(version).bind(document.id).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)?;
            if let Configuration::Certificate { targets, .. } = &after {
                let parsed = x509::parse(&row.get::<String, _>("public_chain"))?;
                for target in targets {
                    if !x509::covers(&parsed.names, &target.domain) {
                        blockers.push(json!({"document_id":document.id,"issue":{"code":"certificate_san_mismatch","domain":target.domain}}));
                    }
                }
                if parsed.not_after <= sinan_protocol::now_timestamp() {
                    blockers.push(
                        json!({"document_id":document.id,"issue":{"code":"certificate_expired"}}),
                    );
                }
            }
            json!({"id":version,"revision":row.get::<i64,_>("revision"),"fingerprint":row.get::<String,_>("fingerprint"),"not_before":row.get::<i64,_>("not_before"),"not_after":row.get::<i64,_>("not_after")})
        } else {
            Value::Null
        };
        let acme=sqlx::query("SELECT revision,config,account_secret_ref FROM network_acme_plans WHERE certificate_id=$1 FOR SHARE")
            .bind(document.id).fetch_optional(&mut **tx).await?;
        let acme = if let Some(row) = acme {
            let config: Value = row.get("config");
            if let Some(id) = row.get::<Option<Uuid>, _>("account_secret_ref") {
                credential_ids.insert(id);
            }
            if let Some(id) = config["credential_id"]
                .as_str()
                .and_then(|value| value.parse().ok())
            {
                credential_ids.insert(id);
            }
            json!({"revision":row.get::<i64,_>("revision"),"config":config,"account_secret_ref":row.get::<Option<Uuid>,_>("account_secret_ref")})
        } else {
            Value::Null
        };
        let key_refs:Vec<Uuid>=sqlx::query_scalar("SELECT DISTINCT key_secret_ref FROM network_acme_jobs WHERE certificate_id=$1 AND key_secret_ref IS NOT NULL ORDER BY key_secret_ref")
            .bind(document.id).fetch_all(&mut **tx).await?;
        credential_ids.extend(key_refs);
        desired.insert(destination, after.clone());
        changes.push(json!({"document_id":document.id,"destination_document_id":destination,"kind":document.kind,"revision":document.revision,"old_expected_digest":super::digest(&document.config)?,"before":config,"after":after,"changes":transform::values_differ(&config,&after)?,"active_version":document.active_version,"certificate_version":active,"acme_plan":acme,"independent_identity":independent_identity,"source_retained":independent_identity,"notes":notes,"deployment":"not_started","reachability":"not_verified","actual_listener_check":"requires_separate_agent_observation"}));
    }
    let outstanding:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',pending.id,'document_id',pending.document_id,'status',pending.status) FROM (SELECT o.id,l.document_id,o.status FROM network_operation_links l JOIN fleet_operations o ON o.id=l.operation_id WHERE l.document_id=ANY($1) AND ((o.status='queued' AND o.expires_at>$2) OR (o.status IN ('dispatched','unknown') AND o.reconciled_at IS NULL)) UNION SELECT o.id,d.certificate_id AS document_id,o.status FROM network_certificate_deployments d JOIN fleet_operations o ON o.id=d.operation_id WHERE d.certificate_id=ANY($1) AND ((o.status='queued' AND o.expires_at>$2) OR (o.status IN ('dispatched','unknown') AND o.reconciled_at IS NULL))) pending ORDER BY pending.id")
        .bind(&ids).bind(sinan_protocol::now_timestamp()).fetch_all(&mut **tx).await?;
    if !outstanding.is_empty() {
        blockers.push(json!({"code":"source_operations_outstanding","operations":outstanding}));
    }
    let issuance:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM network_acme_jobs WHERE certificate_id=ANY($1) AND status IN ('queued','running','unknown') ORDER BY id")
        .bind(&ids).fetch_all(&mut **tx).await?;
    if !issuance.is_empty() {
        blockers.push(json!({"code":"certificate_issuance_outstanding","jobs":issuance}));
    }
    let mut listener_locks = BTreeSet::new();
    for after in desired.values() {
        if let Configuration::Forwarding {
            server_id,
            protocol,
            listen_port,
            ..
        } = after
        {
            listener_locks.insert(format!(
                "sinan-forward:{server_id}:{protocol}:{listen_port}"
            ));
        }
    }
    for listener in listener_locks {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(listener)
            .execute(&mut **tx)
            .await?;
    }
    let existing:Vec<Document>=sqlx::query_as("SELECT * FROM network_documents WHERE config->>'server_id'=$1 OR config->'server_ids' @> $2::JSONB OR EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(config->'targets','[]'::JSONB)) AS target WHERE target->>'server_id'=$1) ORDER BY id LIMIT 1001 FOR SHARE")
        .bind(request.target_server_id.to_string()).bind(json!([request.target_server_id])).fetch_all(&mut **tx).await?;
    if existing.len() > 1000 {
        blockers.push(json!({"code":"conflict_inventory_limit","limit":1000}));
    }
    let mut conflict_inventory = Vec::new();
    for document in existing {
        if desired.contains_key(&document.id) {
            continue;
        }
        let config = documents::configuration(&document)?;
        if !config.servers().contains(&request.target_server_id) {
            continue;
        }
        conflict_inventory.push(json!({"id":document.id,"revision":document.revision,"digest":super::digest(&document.config)?}));
        for (selected_id, after) in &desired {
            if compatibility::listener_conflict(after, &config)
                && !compatibility::represented_by(*selected_id, after, document.id, &config)
            {
                blockers.push(json!({"document_id":selected_id,"issue":{"code":"target_configured_listener_conflict","server_id":request.target_server_id}}));
            }
        }
    }
    let desired: Vec<_> = desired.iter().collect();
    for left in 0..desired.len() {
        for right in left + 1..desired.len() {
            if compatibility::listener_conflict(desired[left].1, desired[right].1)
                && !compatibility::represented_by(
                    *desired[left].0,
                    desired[left].1,
                    *desired[right].0,
                    desired[right].1,
                )
            {
                blockers.push(json!({"code":"selected_listener_collision"}));
            }
        }
    }
    let mut credentials = Vec::new();
    for id in credential_ids {
        let entry:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'kind',kind,'version',version,'enabled',enabled,'key_id',key_id) FROM credential_entries WHERE id=$1 FOR SHARE")
            .bind(id).fetch_optional(&mut **tx).await?;
        if entry.as_ref().is_none_or(|entry| entry["enabled"] != true) {
            blockers.push(json!({"code":"credential_reference_unavailable","credential_id":id}));
        }
        credentials.push(entry.unwrap_or_else(|| json!({"id":id,"status":"missing"})));
    }
    let conflict_digest = super::digest(&json!(conflict_inventory))?;
    Ok(
        json!({"source":servers[&request.source_server_id],"target":target,"changes":changes,"related_documents":references.values().collect::<Vec<_>>(),"dns_references":dns_references.values().collect::<Vec<_>>(),"credential_metadata":credentials,"target_conflict_inventory_digest":conflict_digest,"blockers":blockers,"scope":"network_business_configuration_only","agent_identity_copied":false,"deployment":"not_started","reachability":"not_verified"}),
    )
}

async fn server(tx: &mut Transaction<'_, Postgres>, id: i64) -> ApiResult<Value> {
    let row=sqlx::query("SELECT id,name,capabilities,static_info,device_public_key FROM servers WHERE id=$1 AND deleted_at IS NULL FOR SHARE")
        .bind(id).fetch_optional(&mut **tx).await?.ok_or(ApiError::NotFound)?;
    let profile=sqlx::query("SELECT policy,lifecycle,maintenance_from,maintenance_until FROM fleet_profiles WHERE server_id=$1 FOR SHARE")
        .bind(id).fetch_optional(&mut **tx).await?;
    let retired: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM server_retirements WHERE server_id=$1)")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    if retired {
        return Err(ApiError::Conflict(
            "原服务器或替换服务器正在退役，先完成生命周期核对".into(),
        ));
    }
    let info: Value = row.get("static_info");
    let mut addresses = BTreeSet::new();
    for key in ["ip_addresses", "discovered_public_ips"] {
        if let Some(values) = info[key].as_array() {
            for address in values.iter().filter_map(Value::as_str) {
                addresses.insert(address.to_owned());
            }
        }
    }
    let (policy, lifecycle, from, until) = if let Some(profile) = profile {
        (
            profile.get::<Value, _>("policy"),
            profile.get::<String, _>("lifecycle"),
            profile.get::<Option<i64>, _>("maintenance_from"),
            profile.get::<Option<i64>, _>("maintenance_until"),
        )
    } else {
        (
            json!(sinan_protocol::fleet::AccessPolicy::default()),
            "active".into(),
            None,
            None,
        )
    };
    let identity: Option<String> = row.get("device_public_key");
    Ok(
        json!({"id":id,"name":row.get::<String,_>("name"),"capabilities":row.get::<Value,_>("capabilities"),"policy":policy,"lifecycle":lifecycle,"maintenance_from":from,"maintenance_until":until,"platform":{"os":info["os"],"arch":info["arch"]},"addresses":addresses,"agent_identity_digest":identity.map(|identity|format!("{:x}",Sha256::digest(identity.as_bytes()))),"identity_copied":false}),
    )
}
