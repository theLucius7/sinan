use super::super::{digest, event};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use sinan_compiler::{Access, Node};
use sinan_protocol::{fleet::Operation, now_timestamp};
use sqlx::{Postgres, Row, Transaction};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;
mod bootstrap;
pub(in super::super) use bootstrap::install as bootstrap_install;

const PERMISSIONS_MODULE: &str = "sing-box";
const PREFLIGHT_CAPABILITY: &str = sinan_protocol::fleet::RUNTIME_PREFLIGHT_CAPABILITY;

pub(super) fn check(
    key: &str,
    name: &str,
    state: &str,
    observed_at: Option<i64>,
    source: &str,
    evidence: Value,
    detail: &str,
) -> Value {
    json!({"key":key,"name":name,"state":state,"blocking":matches!(state,"failed"|"unknown"),"observed_at":observed_at,"source":source,"evidence":evidence,"detail":detail})
}

pub(super) async fn nodes(tx: &mut Transaction<'_, Postgres>, server: i64) -> ApiResult<Vec<Node>> {
    let query = format!(
        "SELECT {} FROM nodes n JOIN servers s ON s.id=n.server_id WHERE n.server_id=$1 AND n.deleted_at IS NULL ORDER BY n.id",
        super::super::super::business::NODE_COLUMNS
    );
    let rows: Vec<super::super::super::business::NodeRow> = sqlx::query_as(&query)
        .bind(server)
        .fetch_all(&mut **tx)
        .await?;
    let mut nodes = Vec::new();
    for row in rows {
        let users:Vec<(i64,Uuid,String)>=sqlx::query_as("SELECT user_id,uuid,credential FROM singbox_eligible_accesses($2) WHERE node_id=$1 ORDER BY user_id").bind(row.id).bind(now_timestamp()).fetch_all(&mut **tx).await?;
        nodes.push(
            row.model(
                users
                    .into_iter()
                    .map(|(user_id, uuid, credential)| Access {
                        user_id,
                        uuid,
                        credential,
                    })
                    .collect(),
            )?,
        );
    }
    Ok(nodes)
}

struct Context {
    nodes: Vec<Node>,
    info: Value,
    capabilities: Value,
    policy: Value,
    network_references: Vec<Value>,
    last_seen: Option<i64>,
    blocked: bool,
    target: Option<i64>,
}

async fn context(tx: &mut Transaction<'_, Postgres>, server: i64) -> ApiResult<Context> {
    super::super::super::business::lock_server(tx, server).await?;
    super::super::super::settings::require_enabled(tx, server).await?;
    let row=sqlx::query("SELECT s.static_info,s.capabilities,s.last_seen,COALESCE(p.policy,'{}'::jsonb) AS policy,m.target_rev,EXISTS(SELECT 1 FROM server_retirements WHERE server_id=s.id) OR COALESCE(p.lifecycle IN('draining','retired'),FALSE) OR COALESCE(p.lifecycle='maintenance' AND COALESCE(p.maintenance_from,0)<=$2 AND (p.maintenance_until IS NULL OR p.maintenance_until>$2),FALSE) OR EXISTS(SELECT 1 FROM operations_maintenance w WHERE s.id=ANY(w.targets) AND w.block_new_tasks AND w.starts_at<=$2 AND w.ends_at>$2) AS blocked FROM servers s LEFT JOIN fleet_profiles p ON p.server_id=s.id LEFT JOIN server_module_status m ON m.server_id=s.id AND m.module='singbox' WHERE s.id=$1").bind(server).bind(now_timestamp()).fetch_one(&mut **tx).await?;
    let network_references=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'revision',revision,'active_version',active_version,'config',config) FROM network_documents WHERE (kind='endpoint' AND (config->>'server_id')::bigint=$1) OR (kind='certificate' AND EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(config->'targets','[]'::jsonb)) target WHERE (target->>'server_id')::bigint=$1)) ORDER BY id")
        .bind(server).fetch_all(&mut **tx).await?;
    Ok(Context {
        network_references,
        nodes: nodes(tx, server).await?,
        info: row.get("static_info"),
        capabilities: row.get("capabilities"),
        policy: row.get("policy"),
        last_seen: row.get("last_seen"),
        blocked: row.get("blocked"),
        target: row.get("target_rev"),
    })
}

fn has(context: &Context, capability: &str) -> bool {
    context
        .capabilities
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value == capability))
}

fn fingerprint(
    state: &AppState,
    context: &Context,
) -> impl std::future::Future<Output = ApiResult<String>> + Send + use<> {
    let state = state.clone();
    let info = context.info.clone();
    let mut snapshot = json!({"nodes":context.nodes,"platform":context.info,"capabilities":context.capabilities,"policy":context.policy,"network_references":context.network_references,"runtime_version":"1.14.2"});
    async move {
        let artifact = match super::super::super::agent::runtime_artifact(&state, &info).await {
            Ok(value) => Some(value.sha256),
            Err(ApiError::BadRequest(_) | ApiError::NotFound) => None,
            Err(error) => return Err(error),
        };
        snapshot["artifact_sha256"] = json!(artifact);
        digest(&snapshot)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Listener {
    protocol: String,
    address: String,
    port: u16,
    purpose: String,
}

fn listeners(nodes: &[Node]) -> Vec<Listener> {
    let mut entries: BTreeSet<(String, String, u16, String)> = BTreeSet::new();
    entries.insert((
        "tcp".into(),
        "127.0.0.1".into(),
        18085,
        "运行时计量接口".into(),
    ));
    for node in nodes
        .iter()
        .filter(|node| node.enabled && !node.users.is_empty())
    {
        entries.insert((
            if node.protocol_config.uses_tcp() {
                "tcp"
            } else {
                "udp"
            }
            .into(),
            node.settings.listen.clone(),
            node.port,
            format!("节点 #{}", node.id),
        ));
        if node.protocol_config.kind() == "shadowsocks2022" {
            entries.insert((
                "udp".into(),
                node.settings.listen.clone(),
                node.port,
                format!("节点 #{} UDP", node.id),
            ));
        }
        if let Some(sinan_compiler::TlsConfig::Acme { challenge, .. }) = node.protocol_config.tls()
        {
            entries.insert((
                "tcp".into(),
                "::".into(),
                challenge.port(),
                "自动证书验证监听".into(),
            ));
        }
    }
    entries
        .into_iter()
        .map(|(protocol, address, port, purpose)| Listener {
            protocol,
            address,
            port,
            purpose,
        })
        .collect()
}

fn panel_checks(
    state: &AppState,
    context: &Context,
) -> impl std::future::Future<Output = ApiResult<Vec<Value>>> + Send + use<> {
    let now = now_timestamp();
    let online = context
        .last_seen
        .is_some_and(|at| (now - 60..=now).contains(&at));
    let mut checks = vec![
        check(
            "online",
            "设备连接",
            if online { "passed" } else { "failed" },
            context.last_seen,
            "authenticated_agent_message",
            json!({"maximum_age_secs":60}),
            "按最近经过设备身份验证的消息判断；离线时不使用旧设备结果确认。",
        ),
        check(
            "lifecycle",
            "生命周期",
            if context.blocked { "failed" } else { "passed" },
            Some(now),
            "current_server_lifecycle",
            json!({"accepts_new_tasks":!context.blocked}),
            "维护、停止接收新任务或退役状态阻塞预检请求与确认。",
        ),
        check(
            "policy",
            "受限本机预检授权",
            if context.policy["runtime_inspection"] == true {
                "passed"
            } else {
                "failed"
            },
            Some(now),
            "current_panel_policy",
            json!({"runtime_inspection":context.policy["runtime_inspection"],"agent_rechecks_local_policy":true}),
            "必须同时在面板策略与 Agent 本机配置开启只读运行时预检。",
        ),
    ];
    for capability in [
        "singbox",
        sinan_protocol::fleet::OPERATIONS_CAPABILITY,
        PREFLIGHT_CAPABILITY,
        sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY,
    ] {
        checks.push(check(
            &format!("capability:{capability}"),
            "设备能力",
            if has(context, capability) {
                "passed"
            } else {
                "failed"
            },
            context.last_seen,
            "authenticated_agent_capabilities",
            json!({"capability":capability}),
            "使用设备实际声明的独立能力；旧 Agent 不自动开放新权限。",
        ));
    }
    let compiled = sinan_compiler::compile_server(&context.nodes);
    checks.push(check("configuration","普通节点配置",if compiled.is_ok(){"passed"}else{"failed"},Some(now),"fixed_compiler_1.14.2",json!({"node_ids":context.nodes.iter().map(|node|node.id).collect::<Vec<_>>(),"compiled":compiled.is_ok(),"configuration_sha256":compiled.ok().map(|value|format!("{:x}",sha2::Sha256::digest(value.as_bytes()))),"secret_values_returned":false}),"确定性编译当前有效授权与普通节点；预检不复制凭据，也不替代 Agent 的原生配置检查。"));
    let state = state.clone();
    let info = context.info.clone();
    async move {
        let artifact = match super::super::super::agent::runtime_artifact(&state, &info).await {
            Ok(value) => check(
                "artifact",
                "运行时制品",
                "passed",
                Some(now),
                "verified_local_release_inventory",
                json!({"version":"1.14.2","sha256":value.sha256,"signature_verified":true,"payload_verified":true}),
                "核对目标平台与当前真正可用的签名制品，确认时重新核对摘要。",
            ),
            Err(ApiError::BadRequest(_) | ApiError::NotFound) => check(
                "artifact",
                "运行时制品",
                "failed",
                Some(now),
                "verified_local_release_inventory",
                json!({"version":"1.14.2","artifact_available":false}),
                "没有目标平台匹配且验签完整的固定版本制品。",
            ),
            Err(error) => return Err(error),
        };
        checks.push(artifact);
        Ok(checks)
    }
}

async fn evidence_permission(
    state: &AppState,
    headers: &HeaderMap,
    server: i64,
) -> ApiResult<bool> {
    for permission in ["operations:read", "monitoring:read"] {
        match crate::control_center::require_server(state, headers, server, permission).await {
            Ok(_) => {}
            Err(ApiError::Forbidden(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

pub(in super::super) async fn request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Value>> {
    let actor =
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    let principal = crate::control_center::authenticate(&state, &headers).await?;
    if principal.token_id.is_some() {
        return Err(ApiError::Forbidden(
            "异步目标设备预检要求管理员会话；API 令牌不能转为后台会话权限".into(),
        ));
    }
    for permission in ["operations:read", "monitoring:read", "diagnostics:write"] {
        crate::control_center::require_server(&state, &headers, server, permission).await?;
    }
    let mut tx = state.pool.begin().await?;
    super::super::super::entitlements::lock(&mut tx).await?;
    let initial = context(&mut tx, server).await?;
    let expected = fingerprint(&state, &initial).await?;
    let checks = panel_checks(&state, &initial).await?;
    if checks.iter().any(|check| check["blocking"] == true) {
        return Err(ApiError::Conflict(
            "设备、能力、授权、制品或配置条件未满足；请在完整预检逐项结果中处理后重试".into(),
        ));
    }
    tx.commit().await?;
    let network =
        super::preflight_network::refresh(&state, &headers, server, &initial.nodes, &initial.info)
            .await?;
    let mut tx = state.pool.begin().await?;
    super::super::super::entitlements::lock(&mut tx).await?;
    let current = context(&mut tx, server).await?;
    if fingerprint(&state, &current).await? != expected {
        return Err(ApiError::Conflict(
            "业务、授权、入口或制品在采集期间发生变化，请重新预检".into(),
        ));
    }
    let permissions = crate::fleet::enqueue_readonly_for_actor_tx(
        &mut tx,
        server,
        actor,
        Operation::RuntimePermissions {
            module: PERMISSIONS_MODULE.into(),
        },
    )
    .await?;
    let ports =
        crate::fleet::enqueue_readonly_for_actor_tx(&mut tx, server, actor, Operation::Ports {})
            .await?;
    let id = Uuid::new_v4();
    let now = now_timestamp();
    let snapshot = json!({"listeners":listeners(&current.nodes),"node_ids":current.nodes.iter().map(|node|node.id).collect::<Vec<_>>(),"runtime_module":PERMISSIONS_MODULE,"server_id":server});
    sqlx::query("INSERT INTO singbox_deployment_preflights(id,server_id,administrator_id,expected_digest,snapshot,panel_checks,ports_operation_id,permissions_operation_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(id).bind(server).bind(actor).bind(expected).bind(snapshot).bind(json!(network)).bind(ports).bind(permissions).bind(now).bind(now+300).execute(&mut *tx).await?;
    event(&mut tx,Some(actor),None,"runtime_preflight_requested",json!({"id":id,"server_id":server,"ports_operation_id":ports,"permissions_operation_id":permissions,"secret_values_recorded":false})).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"status":"queued","ports_operation_id":ports,"permissions_operation_id":permissions,"expires_at":now+300,"deployment_requested":false}),
    ))
}

fn fresh(result: &Value, requested_at: i64, now: i64) -> bool {
    result["completed_at"]
        .as_i64()
        .is_some_and(|at| at >= requested_at && (now - 300..=now).contains(&at))
}

fn permission_checks(receipt: &Value, requested_at: i64, now: i64) -> Vec<Value> {
    let result = &receipt["result"];
    let at = result["sampled_at"].as_i64();
    if receipt["succeeded"] != true
        || !fresh(receipt, requested_at, now)
        || at.is_none_or(|at| at < requested_at || at > now || now - at > 300)
        || result["module"] != PERMISSIONS_MODULE
    {
        return [
            ("directories", "目标目录与执行权限"),
            ("service_manager", "系统服务管理权限"),
        ]
        .into_iter()
        .map(|(key, name)| {
            check(
                key,
                name,
                "unknown",
                at,
                "agent_runtime_permissions",
                json!({"receipt_complete":receipt["succeeded"],"secret_values_returned":false}),
                "目标权限尚未取得有效新回执、读取失败或证据已过期；不能以排队成功代替权限检查。",
            )
        })
        .collect();
    }
    let directory = &result["runtime_directory"];
    let states = [
        directory["symlink_free"].as_bool(),
        directory["readable"].as_bool(),
        directory["writable"].as_bool(),
        directory["executable"].as_bool(),
        directory["runtime_readable"].as_bool(),
        directory["runtime_executable"].as_bool(),
    ];
    let path_matches = directory["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("/sing-box@main"));
    let state = if result["runtime_account"]["known"] != true {
        "unknown"
    } else if states.iter().all(|state| *state == Some(true))
        && path_matches
        && directory["error"].is_null()
        && directory["runtime_error"].is_null()
    {
        "passed"
    } else if states.contains(&Some(false))
        || !path_matches
        || !directory["error"].is_null()
        || !directory["runtime_error"].is_null()
    {
        "failed"
    } else {
        "unknown"
    };
    let manager = &result["service_manager"];
    let manager_state = if manager["available"] == true
        && manager["management_authorized"] == true
        && manager["privileged_effective_uid"] == 0
    {
        "passed"
    } else if manager["available"] == false || manager["management_authorized"] == false {
        "failed"
    } else {
        "unknown"
    };
    vec![
        check(
            "directories",
            "目标目录与执行权限",
            state,
            at,
            "agent_runtime_permissions",
            json!({"privileged_effective_uid":result["privileged_effective_uid"],"runtime_account":result["runtime_account"],"runtime_directory":directory,"secret_values_returned":false}),
            "实际核对已安装服务的原生 User/Group、NSS 账号及降权后读/遍历目录，另核特权安装访问与无符号链接；未安装或账号未知不回退成 root，不创建测试文件。",
        ),
        check(
            "service_manager",
            "系统服务管理权限",
            manager_state,
            at,
            "agent_service_manager_probe",
            manager.clone(),
            "实际只读连接系统服务后端并核对特权执行账号；非 root 或外部授权未知时阻塞，不推断能够重启服务。",
        ),
    ]
}

fn storage_check(receipt: &Value, requested_at: i64, now: i64) -> Value {
    let result = &receipt["result"];
    let at = result["sampled_at"].as_i64();
    let valid = receipt["succeeded"] == true
        && fresh(receipt, requested_at, now)
        && at.is_some_and(|at| at >= requested_at && at <= now && now - at <= 300)
        && result["module"] == PERMISSIONS_MODULE;
    let root = result["runtime_directory"]["path"].as_str();
    let directories = [
        ("data_directory", "data"),
        ("certificate_directory", "data/certificates"),
    ];
    let states: Vec<&str> = directories
        .iter()
        .map(|(field, suffix)| {
            let directory = &result[*field];
            let Some(root) = root else {
                return "unknown";
            };
            if !valid || directory.is_null() || result["runtime_account"]["known"] != true {
                return "unknown";
            }
            let expected = format!("{root}/{suffix}");
            let booleans = [
                directory["symlink_free"].as_bool(),
                directory["readable"].as_bool(),
                directory["writable"].as_bool(),
                directory["executable"].as_bool(),
                directory["runtime_readable"].as_bool(),
                directory["runtime_writable"].as_bool(),
                directory["runtime_executable"].as_bool(),
            ];
            if directory["path"] != expected
                || booleans.contains(&Some(false))
                || !directory["error"].is_null()
                || !directory["runtime_error"].is_null()
            {
                "failed"
            } else if booleans.iter().all(|value| *value == Some(true)) {
                "passed"
            } else {
                "unknown"
            }
        })
        .collect();
    let state = if states.contains(&"failed") {
        "failed"
    } else if states.iter().all(|state| *state == "passed") {
        "passed"
    } else {
        "unknown"
    };
    check(
        "acme_storage",
        "自动证书持久目录",
        state,
        at,
        "agent_runtime_permissions",
        json!({"runtime_account":result["runtime_account"],"data_directory":result["data_directory"],"certificate_directory":result["certificate_directory"],"secret_values_returned":false}),
        "目标设备逐级以目录描述符并降权到已安装服务真实账号，只读核对数据与证书目录或最近已存在父目录的读写遍历；root 可写不能代替运行时可写。符号链接、不可写、账号未知或过期回执均阻塞，不创建目录或读取私钥。",
    )
}

#[derive(Debug)]
struct ObservedListener {
    protocol: String,
    address: String,
    port: u16,
    pids: Vec<u32>,
}

fn parse_ports(stdout: &str) -> Option<Vec<ObservedListener>> {
    if stdout.len() > 64 * 1024 {
        return None;
    }
    let mut result = Vec::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || !matches!(fields[0], "tcp" | "udp" | "tcp6" | "udp6") {
            return None;
        }
        let (address, port) = fields[4].rsplit_once(':')?;
        let port = port.parse().ok()?;
        let pids = line
            .split("pid=")
            .skip(1)
            .map(|part| {
                part.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .ok()
            })
            .collect::<Option<Vec<_>>>()?;
        result.push(ObservedListener {
            protocol: fields[0].trim_end_matches('6').into(),
            address: address.trim_matches(['[', ']']).into(),
            port,
            pids,
        });
        if result.len() > 4096 {
            return None;
        }
    }
    Some(result)
}

fn overlaps(left: &str, right: &str) -> bool {
    left == right
        || ["*", "::", "0.0.0.0"].contains(&left)
        || ["*", "::", "0.0.0.0"].contains(&right)
        || left
            .parse::<IpAddr>()
            .ok()
            .zip(right.parse::<IpAddr>().ok())
            .is_some_and(|(left, right)| left == right)
}

fn ports_check(
    receipt: &Value,
    permissions: &Value,
    required: &[Listener],
    requested_at: i64,
    now: i64,
    checkpoint_verified: bool,
) -> Value {
    let at = receipt["completed_at"].as_i64();
    let result = &receipt["result"];
    let observed = if receipt["succeeded"] == true
        && fresh(receipt, requested_at, now)
        && result["truncated"] == false
    {
        result["stdout"].as_str().and_then(parse_ports)
    } else {
        None
    };
    let Some(observed) = observed else {
        return check(
            "ports",
            "实际监听冲突",
            "unknown",
            at,
            "agent_ss_lntup",
            json!({"operation_complete":receipt["succeeded"],"truncated":result["truncated"]}),
            "尚无完整、可解析且五分钟内的新监听证据；未知与截断均阻塞。",
        );
    };
    let manager = &permissions["result"]["service_manager"];
    let owned = if fresh(permissions, requested_at, now)
        && permissions["succeeded"] == true
        && manager["managed_unit"] == "sinan-singbox@main.service"
        && checkpoint_verified
    {
        manager["managed_pid"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u32::MAX as u64)
            .map(|pid| pid as u32)
    } else {
        None
    };
    let mut conflicts = Vec::new();
    let mut occupied = Vec::new();
    for target in required {
        for existing in observed.iter().filter(|existing| {
            existing.protocol == target.protocol
                && existing.port == target.port
                && overlaps(&existing.address, &target.address)
        }) {
            let managed = owned.is_some_and(|pid| {
                !existing.pids.is_empty() && existing.pids.iter().all(|actual| *actual == pid)
            });
            let evidence = json!({"required":target,"observed_address":existing.address,"observed_protocol":existing.protocol,"observed_port":existing.port,"observed_pids":existing.pids,"owned_by_verified_runtime":managed});
            if managed {
                occupied.push(evidence);
            } else {
                conflicts.push(evidence);
            }
        }
    }
    check(
        "ports",
        "实际监听冲突",
        if conflicts.is_empty() {
            "passed"
        } else {
            "failed"
        },
        at,
        "agent_ss_lntup",
        json!({"required":required,"conflicts":conflicts,"existing_managed_listeners":occupied,"verified_managed_pid":owned,"actual_source":"target_agent","process_name_used_for_ownership":false}),
        "核对 TCP/UDP、监听地址与端口；只有实际受管 unit MainPID 与近期配置 checkpoint 都匹配才允许已有监听，不凭进程名推断归属。",
    )
}

async fn aggregate_tx(
    state: &AppState,
    server: i64,
    tx: &mut Transaction<'_, Postgres>,
    context: &Context,
    access: bool,
) -> ApiResult<Value> {
    let mut checks = panel_checks(state, context).await?;
    let latest=sqlx::query("SELECT * FROM singbox_deployment_preflights WHERE server_id=$1 ORDER BY sequence DESC LIMIT 1").bind(server).fetch_optional(&mut **tx).await?;
    let Some(latest) = latest else {
        for (key, name) in [
            ("ports", "实际监听冲突"),
            ("directories", "目标目录与执行权限"),
            ("service_manager", "系统服务管理权限"),
            ("dns", "公开入口 DNS"),
            ("certificate", "证书材料与实际观测"),
        ] {
            checks.push(check(key,name,"unknown",None,"not_requested",json!({"required_permissions":["proxy:write","operations:read","monitoring:read","diagnostics:write"]}),"尚未执行完整预检；请求后等待目标 Agent 的只读回执与面板实际 DNS/证书核对。"));
        }
        return Ok(
            json!({"id":null,"panel_ready":false,"ready":false,"confirmed":false,"device_checks_pending":true,"bootstrap":{"available":context.target.is_none(),"ready":false,"reason":"首次安装需要先采集五分钟内的实际目录、管理权限和端口证据。"},"checks":checks}),
        );
    };
    let now = now_timestamp();
    let started: i64 = latest.get("created_at");
    let current = fingerprint(state, context).await? == latest.get::<String, _>("expected_digest");
    let unexpired = latest.get::<i64, _>("expires_at") > now;
    let network: Value = latest.get("panel_checks");
    for mut item in network.as_array().into_iter().flatten().cloned() {
        if item["state"] != "not_applicable"
            && item["observed_at"]
                .as_i64()
                .is_none_or(|at| at > now || now - at > 300)
        {
            item["state"] = json!("unknown");
            if item["blocking"] != false {
                item["blocking"] = json!(true);
            }
            item["detail"] = json!("网络或证书证据缺失、已过期或时间异常，请重新执行预检。");
        }
        checks.push(item);
    }
    let permissions_operation = sqlx::query(
        "SELECT status,result,expires_at FROM fleet_operations WHERE id=$1 AND server_id=$2",
    )
    .bind(latest.get::<Uuid, _>("permissions_operation_id"))
    .bind(server)
    .fetch_optional(&mut **tx)
    .await?;
    let ports_operation = sqlx::query(
        "SELECT status,result,expires_at FROM fleet_operations WHERE id=$1 AND server_id=$2",
    )
    .bind(latest.get::<Uuid, _>("ports_operation_id"))
    .bind(server)
    .fetch_optional(&mut **tx)
    .await?;
    let permissions: Option<Value> = permissions_operation
        .as_ref()
        .and_then(|row| row.get("result"));
    let ports: Option<Value> = ports_operation.as_ref().and_then(|row| row.get("result"));
    let operations = if access {
        vec![(latest.get::<Uuid,_>("permissions_operation_id"),permissions_operation.as_ref()),(latest.get::<Uuid,_>("ports_operation_id"),ports_operation.as_ref())].into_iter().map(|(id,row)|json!({"id":id,"status":row.map(|row|if row.get::<Option<Value>,_>("result").is_none()&&row.get::<i64,_>("expires_at")<=now{"unknown".to_string()}else{row.get::<String,_>("status")}).unwrap_or("unknown".into()),"agent_completed":row.is_some_and(|row|row.get::<Option<Value>,_>("result").is_some())})).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let pending = permissions.is_none() || ports.is_none();
    let bootstrap = if access {
        bootstrap::status(
            state,
            server,
            tx,
            context,
            bootstrap::Evidence {
                requested: started,
                current: current && unexpired,
                permissions: permissions.as_ref().unwrap_or(&Value::Null),
                ports: ports.as_ref().unwrap_or(&Value::Null),
            },
        )
        .await?
    } else {
        json!({"available":false,"ready":false,"reason":"当前管理员没有读取首次安装设备证据的权限。"})
    };
    if access {
        let permissions = permissions.unwrap_or(Value::Null);
        let ports = ports.unwrap_or(Value::Null);
        checks.extend(permission_checks(&permissions, started, now));
        if context.nodes.iter().any(|node| {
            node.enabled
                && !node.users.is_empty()
                && matches!(
                    node.protocol_config.tls(),
                    Some(sinan_compiler::TlsConfig::Acme { .. })
                )
        }) {
            checks.push(storage_check(&permissions, started, now));
        }
        let checkpoint = super::configuration_observation(tx, server, context.target).await?;
        checks.push(ports_check(
            &ports,
            &permissions,
            &listeners(&context.nodes),
            started,
            now,
            checkpoint["state"] == "verified",
        ));
    } else {
        checks.push(check(
            "evidence_access",
            "预检证据访问",
            "unknown",
            None,
            "current_authorization",
            json!({"required_permissions":["operations:read","monitoring:read"]}),
            "当前管理员没有读取目标设备运维或监听证据的权限，证据已隐藏。",
        ));
    }
    checks.push(check("snapshot","固定业务与证据时效",if current&&unexpired{"passed"}else{"unknown"},Some(started),"current_configuration_fingerprint",json!({"configuration_matches":current,"unexpired":unexpired,"expires_at":latest.get::<i64,_>("expires_at")}),"任何节点、有效授权、Agent 平台/能力、策略、登记入口、关联证书版本或制品变化都会使旧预检失效；五分钟到期后必须重新采样。"));
    super::preflight_network::resolve_dependencies(&mut checks);
    let ready = access && checks.iter().all(|check| check["blocking"] != true);
    Ok(
        json!({"id":latest.get::<Uuid,_>("id"),"created_at":started,"expires_at":latest.get::<i64,_>("expires_at"),"ready":ready,"panel_ready":ready,"confirmed":ready&&latest.get::<Option<i64>,_>("confirmed_at").is_some(),"confirmed_at":latest.get::<Option<i64>,_>("confirmed_at"),"device_checks_pending":pending,"ports_operation_id":latest.get::<Uuid,_>("ports_operation_id"),"permissions_operation_id":latest.get::<Uuid,_>("permissions_operation_id"),"deployment_requested":false,"bootstrap":bootstrap,"operations":operations,"checks":checks}),
    )
}

pub(super) async fn view(state: &AppState, headers: &HeaderMap, server: i64) -> ApiResult<Value> {
    let mut tx = state.pool.begin().await?;
    super::super::super::entitlements::lock(&mut tx).await?;
    let context = context(&mut tx, server).await?;
    let mut result = aggregate_tx(
        state,
        server,
        &mut tx,
        &context,
        evidence_permission(state, headers, server).await?,
    )
    .await?;
    let changed = ordinary_shape_changes_tx(&mut tx, server, &context.nodes).await?;
    result["application"] = json!({"requires_preflight":!changed.is_empty(),"changed_node_ids":changed,"state":if changed.is_empty(){"ordinary_shape_unchanged"}else if result["confirmed"]==true{"confirmed_candidate"}else{"needs_preflight"},"revocations_and_same_shape_user_changes_remain_automatic":true});
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn require_confirmed_tx(
    state: &AppState,
    headers: &HeaderMap,
    server: i64,
    tx: &mut Transaction<'_, Postgres>,
) -> ApiResult<()> {
    let context = context(tx, server).await?;
    let status = aggregate_tx(
        state,
        server,
        tx,
        &context,
        evidence_permission(state, headers, server).await?,
    )
    .await?;
    if status["ready"] != true || status["confirmed"] != true {
        return Err(ApiError::Conflict(format!(
            "服务器 #{server} 尚无当前业务指纹一致、五分钟内且已明确确认的完整部署预检；请先采集并确认"
        )));
    }
    Ok(())
}

fn shape(node: &Node) -> ApiResult<Value> {
    let mut shape = serde_json::to_value(node).map_err(anyhow::Error::from)?;
    let object = shape
        .as_object_mut()
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("node shape is not an object")))?;
    for field in ["users", "enabled", "name"] {
        object.remove(field);
    }
    Ok(shape)
}

fn added_or_changed(
    before: &[Node],
    after: &[Node],
    ordinary: &BTreeSet<i64>,
) -> ApiResult<Vec<i64>> {
    let before = before
        .iter()
        .filter(|node| node.enabled && !node.users.is_empty() && ordinary.contains(&node.id))
        .map(|node| Ok((node.id, shape(node)?)))
        .collect::<ApiResult<std::collections::BTreeMap<_, _>>>()?;
    let mut changed = Vec::new();
    for node in after
        .iter()
        .filter(|node| node.enabled && !node.users.is_empty() && ordinary.contains(&node.id))
    {
        if before.get(&node.id) != Some(&shape(node)?) {
            changed.push(node.id);
        }
    }
    changed.sort_unstable();
    Ok(changed)
}

pub(crate) async fn ordinary_shape_changes_tx(
    tx: &mut Transaction<'_, Postgres>,
    server: i64,
    desired: &[Node],
) -> ApiResult<Vec<i64>> {
    let ordinary:Vec<i64>=sqlx::query_scalar("SELECT n.id FROM nodes n WHERE n.server_id=$1 AND n.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM singbox_chains c LEFT JOIN singbox_ordered_chain_hops h ON h.chain_id=c.id WHERE (c.deleted_at IS NULL OR c.phase<>'retired') AND (c.entry_node_id=n.id OR c.exit_node_id=n.id OR h.managed_node_id=n.id))")
        .bind(server).fetch_all(&mut **tx).await?;
    let previous:Option<Value>=sqlx::query_scalar("SELECT source_json FROM deployments WHERE server_id=$1 AND module='singbox' ORDER BY rev DESC LIMIT 1").bind(server).fetch_optional(&mut **tx).await?;
    let previous = previous
        .map(super::super::super::ordered_paths::models::public_nodes)
        .transpose()
        .map_err(anyhow::Error::from)?
        .unwrap_or_default();
    added_or_changed(&previous, desired, &ordinary.into_iter().collect())
}

pub(crate) async fn publisher_ready_tx(
    state: &AppState,
    server: i64,
    tx: &mut Transaction<'_, Postgres>,
) -> ApiResult<bool> {
    let actor:Option<i64>=sqlx::query_scalar("SELECT confirmed_by FROM singbox_deployment_preflights WHERE server_id=$1 ORDER BY sequence DESC LIMIT 1").bind(server).fetch_optional(&mut **tx).await?.flatten();
    let Some(actor) = actor else {
        return Ok(false);
    };
    for capability in [
        "proxy:write",
        "operations:read",
        "monitoring:read",
        "diagnostics:write",
    ] {
        match crate::control_center::require_actor_server(state, actor, server, capability).await {
            Ok(_) => {}
            Err(ApiError::Forbidden(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    let context = context(tx, server).await?;
    let evidence = aggregate_tx(state, server, tx, &context, true).await?;
    Ok(evidence["ready"] == true && evidence["confirmed"] == true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct Confirm {
    id: Uuid,
    confirm: bool,
}

pub(in super::super) async fn confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
    Json(request): Json<Confirm>,
) -> ApiResult<Json<Value>> {
    let actor =
        crate::control_center::require_server(&state, &headers, server, "proxy:write").await?;
    crate::control_center::require_recent_proof(&state, &headers).await?;
    for permission in ["operations:read", "monitoring:read", "diagnostics:write"] {
        crate::control_center::require_server(&state, &headers, server, permission).await?;
    }
    if !request.confirm {
        return Err(ApiError::BadRequest("请明确确认逐项预检结果".into()));
    }
    let mut tx = state.pool.begin().await?;
    super::super::super::entitlements::lock(&mut tx).await?;
    let context = context(&mut tx, server).await?;
    let aggregate = aggregate_tx(
        &state,
        server,
        &mut tx,
        &context,
        evidence_permission(&state, &headers, server).await?,
    )
    .await?;
    if aggregate["id"] != json!(request.id) || aggregate["ready"] != true {
        return Err(ApiError::Conflict(
            "完整预检尚未通过，或业务/证据已改变；未知、失败和过期均不能确认".into(),
        ));
    }
    let now = now_timestamp();
    sqlx::query("UPDATE singbox_deployment_preflights SET confirmed_at=COALESCE(confirmed_at,$2),confirmed_by=COALESCE(confirmed_by,$3) WHERE id=$1").bind(request.id).bind(now).bind(actor).execute(&mut *tx).await?;
    super::super::super::business::mark_dirty(&mut tx, &[server]).await?;
    event(&mut tx,Some(actor),None,"runtime_preflight_confirmed",json!({"id":request.id,"server_id":server,"publication_resumed":true,"deployment_requested":false,"checks":aggregate["checks"]})).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id":request.id,"confirmed":true,"publication_resumed":true,"deployment_requested":false,"expires_at":aggregate["expires_at"]}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_gate_preserves_revocations_but_checks_first_listener_and_material_changes() {
        let before:Node=serde_json::from_value(json!({"id":1,"name":"TEST_ONLY","port":443,"public_host":"proxy.example.invalid","sni":"proxy.example.invalid","private_key":"TEST_ONLY-private","public_key":"TEST_ONLY-public","short_id":"01020304","users":[{"user_id":1,"uuid":"00000000-0000-4000-8000-000000000001","credential":"TEST_ONLY-old"}]})).expect("node fixture");
        let ordinary = BTreeSet::from([1]);
        let mut next = before.clone();
        next.users[0].credential = "TEST_ONLY-new".into();
        next.name = "TEST_ONLY-renamed".into();
        assert!(
            added_or_changed(
                std::slice::from_ref(&before),
                std::slice::from_ref(&next),
                &ordinary
            )
            .expect("same shape")
            .is_empty()
        );
        next.users.clear();
        assert!(
            added_or_changed(
                std::slice::from_ref(&before),
                std::slice::from_ref(&next),
                &ordinary
            )
            .expect("revocation")
            .is_empty()
        );
        next = before.clone();
        next.enabled = false;
        assert!(
            added_or_changed(
                std::slice::from_ref(&before),
                std::slice::from_ref(&next),
                &ordinary
            )
            .expect("disable")
            .is_empty()
        );
        assert!(
            added_or_changed(std::slice::from_ref(&before), &[], &ordinary)
                .expect("delete")
                .is_empty()
        );
        assert_eq!(
            added_or_changed(&[], std::slice::from_ref(&before), &ordinary)
                .expect("first listener"),
            vec![1]
        );
        next = before.clone();
        next.port = 8443;
        assert_eq!(
            added_or_changed(
                std::slice::from_ref(&before),
                std::slice::from_ref(&next),
                &ordinary
            )
            .expect("port changed"),
            vec![1]
        );
        next = before.clone();
        next.private_key = "TEST_ONLY-new-material".into();
        assert_eq!(
            added_or_changed(
                std::slice::from_ref(&before),
                std::slice::from_ref(&next),
                &ordinary
            )
            .expect("key material changed"),
            vec![1]
        );
        assert!(
            added_or_changed(&[], std::slice::from_ref(&before), &BTreeSet::new())
                .expect("chain has own gate")
                .is_empty()
        );
    }
    #[test]
    fn socket_evidence_does_not_guess_process_names_or_convert_truncation_to_free_ports() {
        let required = vec![Listener {
            protocol: "tcp".into(),
            address: "::".into(),
            port: 443,
            purpose: "TEST_ONLY".into(),
        }];
        let mut receipt = json!({"succeeded":true,"completed_at":100,"result":{"stdout":"tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"sing-box\",pid=12,fd=3))","truncated":false}});
        let permissions = json!({"succeeded":true,"completed_at":100,"result":{"service_manager":{"managed_unit":"sinan-singbox@main.service","managed_pid":13}}});
        assert_eq!(
            ports_check(&receipt, &permissions, &required, 90, 101, true)["state"],
            "failed"
        );
        receipt["result"]["truncated"] = json!(true);
        assert_eq!(
            ports_check(&receipt, &permissions, &required, 90, 101, true)["state"],
            "unknown"
        );
        receipt["result"]["truncated"] = json!(false);
        let mut permissions = permissions;
        permissions["result"]["service_manager"]["managed_pid"] = json!(12);
        assert_eq!(
            ports_check(&receipt, &permissions, &required, 90, 101, false)["state"],
            "failed"
        );
        assert_eq!(
            ports_check(&receipt, &permissions, &required, 90, 101, true)["state"],
            "passed"
        );
        assert_eq!(
            ports_check(&receipt, &permissions, &required, 90, 500, true)["state"],
            "unknown"
        );
    }
    #[test]
    fn missing_service_authorization_is_unknown_even_with_directory_access() {
        let receipt = json!({"succeeded":true,"completed_at":100,"result":{"sampled_at":100,"module":"sing-box","runtime_account":{"known":true,"uid":1001,"gid":1001},"runtime_directory":{"path":"/TEST_ONLY/sing-box@main","symlink_free":true,"readable":true,"writable":true,"executable":true,"runtime_readable":true,"runtime_executable":true,"error":null,"runtime_error":null},"service_manager":{"available":true,"management_authorized":null,"privileged_effective_uid":1000}}});
        let checks = permission_checks(&receipt, 90, 101);
        assert_eq!(checks[0]["state"], "passed");
        assert_eq!(checks[1]["state"], "unknown");
        assert_eq!(checks[1]["blocking"], true);
    }
    #[test]
    fn acme_storage_requires_real_child_directory_receipts() {
        let directory = |path: &str| json!({"path":path,"symlink_free":true,"readable":true,"writable":true,"executable":true,"runtime_readable":true,"runtime_writable":true,"runtime_executable":true,"runtime_error":null,"error":null});
        let mut receipt = json!({"succeeded":true,"completed_at":100,"result":{"module":"sing-box","sampled_at":100,"runtime_account":{"known":true,"uid":1001,"gid":1001},"runtime_directory":directory("/TEST_ONLY/sing-box@main")}});
        assert_eq!(storage_check(&receipt, 90, 101)["state"], "unknown");
        receipt["result"]["data_directory"] = directory("/TEST_ONLY/sing-box@main/data");
        receipt["result"]["certificate_directory"] =
            directory("/TEST_ONLY/sing-box@main/data/certificates");
        assert_eq!(storage_check(&receipt, 90, 101)["state"], "passed");
        receipt["result"]["certificate_directory"]["runtime_writable"] = json!(false);
        assert_eq!(storage_check(&receipt, 90, 101)["state"], "failed");
        receipt["result"]["certificate_directory"]["runtime_writable"] = json!(true);
        receipt["result"]["runtime_account"]["known"] = json!(false);
        assert_eq!(storage_check(&receipt, 90, 101)["state"], "unknown");
        receipt["result"]["runtime_account"]["known"] = json!(true);
        receipt["result"]["certificate_directory"]["symlink_free"] = json!(false);
        assert_eq!(storage_check(&receipt, 90, 101)["state"], "failed");
        assert_eq!(storage_check(&receipt, 90, 500)["state"], "unknown");
    }
}
