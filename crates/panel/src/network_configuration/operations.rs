use super::{documents, models::Configuration};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::fleet::Operation;
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/servers/{server}/inventory",
            post(inventory),
        )
        .route(
            "/api/network-configuration/documents/{id}/execute",
            post(execute),
        )
        .route(
            "/api/network-configuration/documents/{id}/observations",
            get(observations),
        )
}

async fn inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server): Path<i64>,
) -> ApiResult<Json<Value>> {
    if crate::control_center::authenticate(&state, &headers)
        .await?
        .token_id
        .is_some()
    {
        return Err(ApiError::Forbidden(
            "异步服务器盘点需要管理员会话，API令牌不可排队".into(),
        ));
    }
    let actor =
        crate::control_center::require_server(&state, &headers, server, "network:read").await?;
    let request = json!({"action":"inventory"});
    let id = crate::fleet::enqueue_for_actor(
        &state,
        server,
        actor,
        Operation::SystemNetwork {
            operation: request.clone(),
        },
    )
    .await?;
    link(&state, id, None, None, server, &request).await?;
    Ok(Json(
        json!({"operation_id":id,"status":"queued","from":"selected_agent","server_id":server}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Execute {
    action: String,
    revision: i64,
    snapshot_id: Option<Uuid>,
    confirmed: bool,
}
async fn execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Execute>,
) -> ApiResult<Json<Value>> {
    let read_only = ["status", "tunnel_status", "mesh_status", "firewall_status"]
        .contains(&input.action.as_str());
    if crate::control_center::authenticate(&state, &headers)
        .await?
        .token_id
        .is_some()
    {
        return Err(ApiError::Forbidden(
            "异步服务器操作需要管理员会话，API令牌不可排队".into(),
        ));
    }
    let document = documents::load(&state, id).await?;
    let config = documents::configuration(&document)?;
    documents::access(&state, &headers, &config, !read_only).await?;
    if document.revision != input.revision {
        return Err(ApiError::Conflict("台账版本已改变，请重新预览".into()));
    }
    if !read_only {
        if !input.confirmed {
            return Err(ApiError::BadRequest(
                "执行前需确认目标、参数及本机授权".into(),
            ));
        }
        crate::control_center::require_recent_proof(&state, &headers).await?;
    }
    let (server, operation, request) = match config {
        Configuration::Forwarding {
            server_id,
            owner,
            enabled,
            listen_address,
            listen_port,
            target_address,
            target_port,
            protocol,
            ..
        } => {
            if owner != "sinan" {
                return Err(ApiError::Conflict(
                    "外部映射仅维护台账，司南不部署或停止外部服务".into(),
                ));
            }
            if !["start", "stop", "status"].contains(&input.action.as_str())
                || (input.action == "start" && !enabled)
            {
                return Err(ApiError::BadRequest(
                    "请先启用规则并使用启动、停止或状态操作".into(),
                ));
            }
            let request = json!({"action":input.action,"rule_id":id,"listen_address":listen_address,"listen_port":listen_port,"target_address":target_address,"target_port":target_port,"protocol":protocol});
            (
                server_id,
                Operation::PortForward {
                    operation: request.clone(),
                },
                request,
            )
        }
        Configuration::Tuning {
            server_id,
            parameters,
            restore_after_secs,
            ..
        } => {
            if !["temporary", "confirm", "persist", "restore"].contains(&input.action.as_str()) {
                return Err(ApiError::BadRequest(
                    "请选择临时应用、确认、持久化或恢复".into(),
                ));
            }
            let snapshot = if input.action == "temporary" {
                Uuid::new_v4()
            } else {
                input
                    .snapshot_id
                    .ok_or_else(|| ApiError::BadRequest("请选择该配置的临时快照".into()))?
            };
            if input.action != "temporary" {
                let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_operation_links l JOIN fleet_operations o ON o.id=l.operation_id WHERE l.document_id=$1 AND l.server_id=$2 AND l.request->>'snapshot_id'=$3 AND l.request->>'action'='temporary' AND o.status='succeeded')").bind(id).bind(server_id).bind(snapshot.to_string()).fetch_one(&state.pool).await?;
                if !owned {
                    return Err(ApiError::Conflict(
                        "快照不属于该服务器配置或临时应用尚未确认成功".into(),
                    ));
                }
            }
            let request = json!({"action":input.action,"snapshot_id":snapshot,"parameters":parameters,"restore_after_secs":restore_after_secs});
            (
                server_id,
                Operation::SystemNetwork {
                    operation: request.clone(),
                },
                request,
            )
        }
        Configuration::Tunnel {
            server_id,
            relay_address,
            relay_port,
            relay_account,
            relay_host_key,
            listen_address,
            listen_port,
            target_address,
            target_port,
            enabled,
            ..
        } => {
            if !["tunnel_key", "tunnel_start", "tunnel_stop", "tunnel_status"]
                .contains(&input.action.as_str())
                || (input.action == "tunnel_start" && !enabled)
            {
                return Err(ApiError::BadRequest(
                    "反向隧道操作无效或尚未允许启动".into(),
                ));
            }
            let request = json!({"action":input.action,"tunnel_id":id,"relay_address":relay_address,"relay_port":relay_port,"relay_account":relay_account,"relay_host_key":relay_host_key,"listen_address":listen_address,"listen_port":listen_port,"target_address":target_address,"target_port":target_port});
            (
                server_id,
                Operation::SystemNetwork {
                    operation: request.clone(),
                },
                request,
            )
        }
        Configuration::Mesh {
            server_id,
            address,
            listen_port,
            peers,
            ..
        } => {
            if ![
                "mesh_apply",
                "mesh_stop",
                "mesh_status",
                "mesh_restore",
                "mesh_persist",
            ]
            .contains(&input.action.as_str())
            {
                return Err(ApiError::BadRequest("私有组网操作无效".into()));
            }
            let request = json!({"action":input.action,"mesh_id":id,"address":address,"listen_port":listen_port,"peers":peers});
            (
                server_id,
                Operation::SystemNetwork {
                    operation: request.clone(),
                },
                request,
            )
        }
        Configuration::Firewall {
            server_id,
            rules,
            management_ports,
            restore_after_secs,
            ..
        } => {
            if ![
                "firewall_temporary",
                "firewall_confirm",
                "firewall_persist",
                "firewall_restore",
                "firewall_status",
            ]
            .contains(&input.action.as_str())
            {
                return Err(ApiError::BadRequest("防火墙操作无效".into()));
            }
            let snapshot = if input.action == "firewall_temporary" {
                Uuid::new_v4()
            } else {
                input
                    .snapshot_id
                    .ok_or_else(|| ApiError::BadRequest("请选择该防火墙的临时快照".into()))?
            };
            if input.action != "firewall_temporary" {
                let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM network_operation_links l JOIN fleet_operations o ON o.id=l.operation_id WHERE l.document_id=$1 AND l.server_id=$2 AND l.request->>'snapshot_id'=$3 AND l.request->>'action'='firewall_temporary' AND o.status='succeeded')").bind(id).bind(server_id).bind(snapshot.to_string()).fetch_one(&state.pool).await?;
                if !owned {
                    return Err(ApiError::Conflict(
                        "防火墙快照不属于本配置或临时应用未成功".into(),
                    ));
                }
            }
            let request = json!({"action":input.action,"firewall_id":id,"snapshot_id":snapshot,"rules":rules,"management_ports":management_ports,"restore_after_secs":restore_after_secs});
            (
                server_id,
                Operation::SystemNetwork {
                    operation: request.clone(),
                },
                request,
            )
        }
        _ => {
            return Err(ApiError::Conflict(
                "该台账由明确维护方执行，尚无自动部署能力".into(),
            ));
        }
    };
    let actor = crate::control_center::require_server(
        &state,
        &headers,
        server,
        if read_only {
            "network:read"
        } else {
            "network:write"
        },
    )
    .await?;
    let operation_id = crate::fleet::enqueue_for_actor(&state, server, actor, operation).await?;
    link(
        &state,
        operation_id,
        Some(id),
        Some(document.revision),
        server,
        &request,
    )
    .await?;
    Ok(Json(
        json!({"operation_id":operation_id,"status":"queued","server_id":server,"request":request,"result":"awaiting_agent"}),
    ))
}

async fn link(
    state: &AppState,
    id: Uuid,
    document: Option<Uuid>,
    revision: Option<i64>,
    server: i64,
    request: &Value,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO network_operation_links(operation_id,document_id,revision,server_id,request,created_at) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(document).bind(revision).bind(server).bind(request).bind(sinan_protocol::now_timestamp()).execute(&state.pool).await?;
    Ok(())
}

async fn observations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let document = documents::load(&state, id).await?;
    documents::access(
        &state,
        &headers,
        &documents::configuration(&document)?,
        false,
    )
    .await?;
    let measured:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'source',source,'server_id',server_id,'result',result,'observed_at',observed_at) FROM network_observations WHERE document_id=$1 ORDER BY observed_at DESC LIMIT 100").bind(id).fetch_all(&state.pool).await?;
    let operations:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',l.operation_id,'revision',l.revision,'server_id',l.server_id,'request',l.request,'created_at',l.created_at,'status',CASE WHEN o.status='dispatched' AND o.expires_at<$2 THEN 'unknown' ELSE o.status END,'result',o.result) FROM network_operation_links l JOIN fleet_operations o ON o.id=l.operation_id WHERE l.document_id=$1 ORDER BY l.created_at DESC LIMIT 100").bind(id).bind(sinan_protocol::now_timestamp()).fetch_all(&state.pool).await?;
    let mut visible_measured = Vec::new();
    for measurement in measured {
        let allowed = match measurement["server_id"].as_i64() {
            Some(server) => {
                crate::control_center::require_server(&state, &headers, server, "network:read")
                    .await
                    .is_ok()
            }
            None => true,
        };
        if allowed {
            visible_measured.push(measurement);
        }
    }
    let mut visible_operations = Vec::new();
    for operation in operations {
        if let Some(server) = operation["server_id"].as_i64()
            && crate::control_center::require_server(&state, &headers, server, "network:read")
                .await
                .is_ok()
        {
            visible_operations.push(operation);
        }
    }
    Ok(Json(
        json!({"configured":document.config,"active_version":document.active_version,"measurements":visible_measured,"operations":visible_operations,"reachability":"requires_selected_source_probe"}),
    ))
}
