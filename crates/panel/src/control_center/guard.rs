use super::access::{Principal, authenticate, require_recent_proof};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;

pub fn redact(value: &Value) -> Value {
    fn walk(value: &Value, depth: usize) -> Value {
        if depth > 8 {
            return json!("[已截断]");
        }
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .take(64)
                    .map(|(key, value)| {
                        let lower = key.to_ascii_lowercase();
                        let sensitive = [
                            "password",
                            "token",
                            "secret",
                            "private",
                            "credential",
                            "authorization",
                            "command",
                            "content",
                            "input",
                            "certificate_pem",
                            "uuid",
                            "short_id",
                            "totp",
                            "otp",
                            "api_key",
                            "access_key",
                            "subscription",
                        ]
                        .iter()
                        .any(|item| lower.contains(item))
                            || ["url", "uri", "raw", "yaml", "payload", "bundle", "text"]
                                .contains(&lower.as_str())
                            || lower.ends_with("_url")
                            || lower.ends_with("_uri");
                        (
                            key.clone(),
                            if sensitive {
                                json!("[已脱敏]")
                            } else {
                                walk(value, depth + 1)
                            },
                        )
                    })
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .take(32)
                    .map(|value| walk(value, depth + 1))
                    .collect(),
            ),
            Value::String(value) => json!(value.chars().take(512).collect::<String>()),
            value => value.clone(),
        }
    }
    walk(value, 0)
}

fn audit_request(path: &str, value: &Value) -> Value {
    let mut value = value.clone();
    if path.starts_with("/api/fleet/terminals/") && path.ends_with("/input") {
        // PTY data includes commands and interactive passwords. Keep window
        // metadata, but never persist the terminal byte stream in audit rows.
        if let Some(object) = value.as_object_mut() {
            object.insert("data".into(), json!("[已脱敏]"));
        }
    }
    redact(&value)
}

fn independent_identity(path: &str) -> bool {
    path.starts_with("/api/agent/")
        || path == "/api/login"
        || path.starts_with("/api/login/passkey/")
        || path == "/api/logout"
        || path == "/api/dashboard/access"
        || path.starts_with("/api/plugins/sing-box/portal/")
        || path.starts_with("/api/network-workbench/shared/")
        || path.starts_with("/api/bootstrap/")
}

fn feature(path: &str) -> Option<&'static str> {
    if path == "/api/control-center/observers" {
        return Some("monitoring");
    }
    if path.starts_with("/api/control-center/") {
        return Some("security");
    }
    if path.starts_with("/api/plugins/sing-box/") {
        return Some("proxy");
    }
    if path.starts_with("/api/plugins/ddns/") {
        return Some("dns");
    }
    if path == "/api/plugins/alicloud" || path.starts_with("/api/plugins/alicloud/") {
        return Some("cloud");
    }
    if path.starts_with("/api/network-workbench/") {
        return Some("diagnostics");
    }
    if path.starts_with("/api/network-configuration/") {
        return Some("network");
    }
    if path.starts_with("/api/operations/backups") || path.starts_with("/api/operations/backup-") {
        return Some("recovery");
    }
    if path.starts_with("/api/operations/cloud") || path == "/api/operations/suppliers" {
        return Some("cloud");
    }
    if path.starts_with("/api/operations/") {
        return Some("operations");
    }
    if path.contains("/terminal") {
        return Some("terminal");
    }
    if path.contains("/files")
        || path.contains("/configurations")
        || path.contains("/config-history")
    {
        return Some("files");
    }
    if path.contains("/services") {
        return Some("services");
    }
    if path.contains("/commands") {
        return Some("terminal");
    }
    if path.contains("/diagnostics")
        || path.contains("/node-quality")
        || path.contains("/tcp-quality")
        || path.contains("/ip-quality")
        || path.starts_with("/api/plugins/tcpquality/")
    {
        return Some("diagnostics");
    }
    if path.starts_with("/api/fleet/") || path.starts_with("/api/servers") {
        return Some("servers");
    }
    if path.starts_with("/api/dashboard/")
        || path.starts_with("/api/statistics")
        || path.starts_with("/api/latency-tasks")
        || path.starts_with("/api/probes/")
        || path.starts_with("/api/notifications")
        || path.starts_with("/api/alert-rules")
        || path.starts_with("/api/telemetry/")
    {
        return Some("monitoring");
    }
    if path.starts_with("/api/security/")
        || path.starts_with("/api/settings")
        || path.starts_with("/api/artifacts")
        || path.starts_with("/api/exchange-rates")
    {
        return Some("security");
    }
    None
}

fn server_path(path: &str) -> Option<i64> {
    let parts: Vec<_> = path.split('/').collect();
    parts.windows(2).find_map(|pair| {
        (pair[0] == "servers")
            .then(|| pair[1].parse::<i64>().ok().filter(|id| *id > 0))
            .flatten()
    })
}

fn own_account_path(path: &str) -> bool {
    path.starts_with("/api/security/totp")
        || path == "/api/me"
        || path == "/api/control-center/me"
        || path == "/api/control-center/reauth"
        || path == "/api/control-center/events"
        || path == "/api/control-center/export/servers"
        || path == "/api/control-center/search"
        || path.starts_with("/api/control-center/preferences/")
        || path == "/api/control-center/sessions"
        || path.starts_with("/api/control-center/sessions/")
}

fn high_risk(path: &str, method: &Method) -> bool {
    if *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS {
        return false;
    }
    if own_account_path(path) {
        return false;
    }
    if *method == Method::POST
        && path.starts_with("/api/operations/cloud/hetzner/accounts/")
        && path.ends_with("/refresh")
    {
        return false;
    }
    *method == Method::DELETE
        || path.contains("/enrollment")
        || path.contains("/commands")
        || path.contains("/terminal")
        || path.contains("/credentials")
        || path.contains("/restore")
        || path.contains("/administrators")
        || path.contains("/cloud/")
        || path.contains("/power")
        || path.contains("/bandwidth")
        || path.contains("/security-group")
        || (path.starts_with("/api/plugins/alicloud/")
            && !path.ends_with("/preview")
            && !path.ends_with("/refresh"))
        || (path.starts_with("/api/plugins/sing-box/")
            && !path.ends_with("/preview")
            && (path.contains("/nodes")
                || path.contains("/accesses")
                || path.contains("/external-accesses")
                || path.contains("/subscription/reset")))
}

async fn allowed(
    _state: &AppState,
    actor: &Principal,
    path: &str,
    method: &Method,
) -> ApiResult<()> {
    if own_account_path(path) {
        if actor.token_id.is_some()
            && ![
                "/api/me",
                "/api/control-center/me",
                "/api/control-center/search",
                "/api/control-center/events",
                "/api/control-center/export/servers",
            ]
            .contains(&path)
        {
            return Err(ApiError::Forbidden(
                "工作区、账号安全和会话操作需要交互式管理员会话".into(),
            ));
        }
        return Ok(());
    }
    if actor.role == "owner" && actor.token_id.is_none() {
        return Ok(());
    }
    let typed_fleet = path.starts_with("/api/fleet/operations/")
        || path.starts_with("/api/fleet/terminals/")
        || path.ends_with("/fleet/operations");
    if typed_fleet {
        if let Some(id) = server_path(path)
            && !actor.allows_server(id)
        {
            return Err(ApiError::Forbidden(
                "当前管理员或 API 令牌未获授权访问此服务器".into(),
            ));
        }
        // These handlers derive capability and server scope from the typed stored operation.
        return Ok(());
    }
    if path.starts_with("/api/network-configuration/documents/")
        && path.ends_with("/execute")
        && *method == Method::POST
    {
        // The stored document and typed action determine read versus write access.
        if !actor.allows("network:read") && !actor.allows("network:write") {
            return Err(ApiError::Forbidden(
                "当前管理员或 API 令牌没有网络操作权限".into(),
            ));
        }
        return Ok(());
    }
    let feature =
        feature(path).ok_or_else(|| ApiError::Forbidden("此接口尚未开放给受限管理员".into()))?;
    let read = *method == Method::GET
        || *method == Method::HEAD
        || (*method == Method::POST
            && path.starts_with("/api/operations/cloud/hetzner/accounts/")
            && path.ends_with("/refresh"))
        || (path.starts_with("/api/network-configuration/servers/")
            && path.ends_with("/inventory"))
        || (path.starts_with("/api/plugins/ddns/")
            && ((path.starts_with("/api/plugins/ddns/rules/") && path.ends_with("/preview"))
                || path.ends_with("/check")
                || path.ends_with("/resolve")
                || (path.starts_with("/api/plugins/ddns/accounts/")
                    && path.contains("/records/")
                    && path.ends_with("/reconcile"))));
    let capability = format!("{feature}:{}", if read { "read" } else { "write" });
    if !actor.allows(&capability) {
        return Err(ApiError::Forbidden(
            "当前管理员或 API 令牌没有此功能权限".into(),
        ));
    }
    if feature == "security" {
        return Err(ApiError::Forbidden("全局安全设置需要所有者会话".into()));
    }
    if let Some(id) = server_path(path) {
        if !actor.allows_server(id) {
            return Err(ApiError::Forbidden(
                "当前管理员或 API 令牌未获授权访问此服务器".into(),
            ));
        }
    } else if !actor.global_servers()
        && !(path == "/api/servers" && read)
        && !path.starts_with("/api/plugins/ddns/")
        && !path.starts_with("/api/network-workbench/")
        && !path.starts_with("/api/network-configuration/")
        && !path.starts_with("/api/operations/")
        && !(read && (path == "/api/fleet/templates" || path == "/api/network-workbench/catalog"))
    {
        return Err(ApiError::Forbidden(
            "跨服务器入口需要全服务器授权；可从已授权服务器详情进入".into(),
        ));
    }
    Ok(())
}

async fn snapshot(state: &AppState, path: &str) -> ApiResult<Value> {
    let query_id = if let Some(id) = path
        .strip_prefix("/api/servers/")
        .filter(|value| !value.contains('/'))
        .and_then(|value| value.parse::<i64>().ok())
    {
        Some(("SELECT to_jsonb(s) FROM servers s WHERE id=$1", id))
    } else {
        path.strip_prefix("/api/plugins/sing-box/nodes/")
            .filter(|value| !value.contains('/'))
            .and_then(|value| value.parse::<i64>().ok())
            .map(|id| ("SELECT to_jsonb(n) FROM nodes n WHERE id=$1", id))
    };
    if let Some((query, id)) = query_id {
        let value: Option<Value> = sqlx::query_scalar(query)
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
        return Ok(value.as_ref().map(redact).unwrap_or(Value::Null));
    }
    Ok(json!({"state":"unavailable","reason":"此入口的变更前后证据由对应任务或版本历史保存"}))
}

pub async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if !path.starts_with("/api/") || independent_identity(&path) {
        return next.run(request).await;
    }
    let headers = request.headers().clone();
    let actor = match authenticate(&state, &headers).await {
        Ok(actor) => actor,
        Err(ApiError::Unauthorized) if path.starts_with("/api/dashboard/") => {
            return next.run(request).await;
        }
        Err(error) => return error.into_response(),
    };
    let method = request.method().clone();
    if let Err(error) = allowed(&state, &actor, &path, &method).await {
        let _ = sqlx::query("INSERT INTO management_audit(admin_id,token_id,action,object_path,request_diff,result,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(actor.admin_id).bind(actor.token_id).bind(method.as_str()).bind(&path).bind(json!({"body":"[拒绝请求未读取]"})).bind(json!({"phase":"authorization-denied","success":false})).bind(now_timestamp()).execute(&state.pool).await;
        return error.into_response();
    }
    if high_risk(&path, &method)
        && let Err(error) = require_recent_proof(&state, &headers).await
    {
        return error.into_response();
    }
    let mutation = method != Method::GET && method != Method::HEAD && method != Method::OPTIONS;
    let (request, audit_id) = if mutation {
        let (parts, body) = request.into_parts();
        // Audit collection must preserve the largest registered JSON endpoint
        // budget. Individual extractors retain their own smaller body limits.
        let maximum = 3 * 1024 * 1024;
        let mut bytes = Vec::new();
        let mut chunks = body.into_data_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    return ApiError::BadRequest("请求正文读取失败".into()).into_response();
                }
            };
            if chunk.len() > maximum - bytes.len() {
                return (
                    axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                    Json(json!({"error":"请求正文超过管理接口限制"})),
                )
                    .into_response();
            }
            bytes.extend_from_slice(&chunk);
        }
        let requested = serde_json::from_slice::<Value>(&bytes)
            .map(|value| audit_request(&path, &value))
            .unwrap_or(json!({"bytes":bytes.len(),"body":"[非JSON正文未记录]"}));
        let before = match snapshot(&state, &path).await {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
        let diff = json!({"before":before,"requested":requested,"after":{"state":"pending"}});
        let audit=sqlx::query_scalar::<_,i64>("INSERT INTO management_audit(admin_id,token_id,action,object_path,request_diff,result,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id")
            .bind(actor.admin_id).bind(actor.token_id).bind(method.as_str()).bind(&path).bind(diff).bind(json!({"phase":"accepted"})).bind(now_timestamp()).fetch_one(&state.pool).await;
        let id = match audit {
            Ok(id) => id,
            Err(error) => return ApiError::Database(error).into_response(),
        };
        (Request::from_parts(parts, Body::from(bytes)), Some(id))
    } else {
        (request, None)
    };
    let mut response = next.run(request).await;
    if let Some(id) = audit_id {
        let after = snapshot(&state, &path)
            .await
            .unwrap_or(json!({"state":"unavailable","reason":"结果状态读取失败"}));
        if let Err(error)=sqlx::query("UPDATE management_audit SET result=$2,request_diff=jsonb_set(request_diff,'{after}',$3) WHERE id=$1").bind(id).bind(json!({"phase":"returned","http_status":response.status().as_u16(),"success":response.status().is_success(),"snapshot_semantics":"邻近请求的状态观察；事务性差异以功能历史为准"})).bind(after).execute(&state.pool).await {
            tracing::error!(%error,audit_id=id,"audit result persistence failed");
        }
    }
    if path == "/api/servers"
        && method == Method::GET
        && response.status().is_success()
        && !actor.global_servers()
    {
        let (parts, body) = response.into_parts();
        let bytes = match to_bytes(body, 16 * 1024 * 1024).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return ApiError::Internal(anyhow::anyhow!("server list filtering failed"))
                    .into_response();
            }
        };
        let filtered = match serde_json::from_slice::<Vec<Value>>(&bytes) {
            Ok(values) => values
                .into_iter()
                .filter(|value| {
                    value
                        .get("id")
                        .and_then(Value::as_i64)
                        .is_some_and(|id| actor.allows_server(id))
                })
                .collect::<Vec<_>>(),
            Err(error) => return ApiError::Internal(error.into()).into_response(),
        };
        let bytes = match serde_json::to_vec(&filtered) {
            Ok(bytes) => bytes,
            Err(error) => return ApiError::Internal(error.into()).into_response(),
        };
        response = Response::from_parts(parts, Body::from(bytes));
        response.headers_mut().remove(header::CONTENT_LENGTH);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_audit_keeps_window_metadata_without_input() {
        let secret = "TEST_ONLY terminal password sentinel";
        let value = audit_request(
            "/api/fleet/terminals/00000000-0000-0000-0000-000000000001/input",
            &json!({"data":secret,"columns":80,"rows":24}),
        );
        assert_eq!(value["data"], "[已脱敏]");
        assert_eq!(value["columns"], 80);
        assert_eq!(value["rows"], 24);
        assert!(!value.to_string().contains(secret));
        assert_eq!(
            audit_request(
                "/api/control-center/preferences/view",
                &json!({"data":"sort"})
            )["data"],
            "sort"
        );
    }
    #[test]
    fn audit_redacts_nested_secrets_and_payloads() {
        let value = redact(
            &json!({"name":"example","credentials":{"token":"never"},"nested":{"password":"never","server_id":2},"command":"secret command"}),
        );
        assert_eq!(value["name"], "example");
        assert_eq!(value["credentials"], "[已脱敏]");
        assert_eq!(value["nested"]["password"], "[已脱敏]");
        assert_eq!(value["nested"]["server_id"], 2);
        assert!(!value.to_string().contains("never"));
    }
    #[test]
    fn api_id_cannot_be_misread_as_a_server_scope() {
        assert_eq!(
            server_path("/api/plugins/sing-box/servers/3/deployments"),
            Some(3)
        );
        assert_eq!(server_path("/api/plugins/sing-box/users/3"), None);
        assert!(high_risk("/api/servers/3/commands", &Method::POST));
    }
}
