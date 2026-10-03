use super::event;
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Definition {
    #[serde(default)]
    selection_groups: Vec<Selection>,
    dns: Option<Value>,
    route: Option<Value>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    tag: String,
    outbounds: Vec<String>,
    default: Option<String>,
}

fn known_keys(value: &Value, keys: &[&str]) -> ApiResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("DNS 与路由配置必须是 JSON 对象".into()))?;
    if object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(ApiError::BadRequest(
            "模板包含当前客户端模型无法表达的字段；请保留草稿并使用完整原始配置，不会静默丢弃字段"
                .into(),
        ));
    }
    Ok(())
}

fn validate(definition: &Definition) -> ApiResult<()> {
    if definition.selection_groups.len() > 16 {
        return Err(ApiError::BadRequest("选择组最多 16 个".into()));
    }
    let mut tags = BTreeSet::new();
    for group in &definition.selection_groups {
        if group.tag.is_empty()
            || group.tag.len() > 64
            || group.tag.chars().any(char::is_control)
            || !tags.insert(&group.tag)
            || group.outbounds.is_empty()
            || group.outbounds.len() > 200
            || group
                .outbounds
                .iter()
                .any(|tag| tag.len() > 256 || tag.chars().any(char::is_control))
            || group.outbounds.iter().collect::<BTreeSet<_>>().len() != group.outbounds.len()
            || group
                .default
                .as_ref()
                .is_some_and(|tag| !group.outbounds.contains(tag))
        {
            return Err(ApiError::BadRequest(
                "选择组名称、成员或默认成员无效".into(),
            ));
        }
    }
    if let Some(dns) = &definition.dns {
        known_keys(
            dns,
            &[
                "servers",
                "rules",
                "final",
                "strategy",
                "disable_cache",
                "disable_expire",
                "independent_cache",
                "cache_capacity",
                "reverse_mapping",
            ],
        )?;
        if let Some(servers) = dns.get("servers") {
            let servers = servers
                .as_array()
                .filter(|v| v.len() <= 16)
                .ok_or_else(|| ApiError::BadRequest("DNS 服务器应为最多 16 项的数组".into()))?;
            let mut dns_tags = BTreeSet::new();
            for server in servers {
                known_keys(
                    server,
                    &[
                        "type",
                        "tag",
                        "server",
                        "server_port",
                        "detour",
                        "domain_resolver",
                        "path",
                        "headers",
                        "tls",
                    ],
                )?;
                if !matches!(
                    server["type"].as_str(),
                    Some("local" | "udp" | "tcp" | "tls" | "https" | "quic" | "h3")
                ) {
                    return Err(ApiError::BadRequest(
                        "当前模板不支持此 DNS 服务器类型".into(),
                    ));
                }
                let tag = server["tag"]
                    .as_str()
                    .filter(|tag| {
                        !tag.is_empty() && tag.len() <= 64 && !tag.chars().any(char::is_control)
                    })
                    .ok_or_else(|| ApiError::BadRequest("DNS 服务器需设置有效标签".into()))?;
                if !dns_tags.insert(tag) {
                    return Err(ApiError::BadRequest("DNS 服务器标签重复".into()));
                }
                if server["type"] != "local"
                    && !server["server"].as_str().is_some_and(|host| {
                        !host.is_empty()
                            && host.len() <= 253
                            && !host.chars().any(|c| c.is_whitespace() || c.is_control())
                    })
                {
                    return Err(ApiError::BadRequest("DNS 服务器地址无效".into()));
                }
                if server.get("server_port").is_some_and(|port| {
                    !port
                        .as_u64()
                        .is_some_and(|port| (1..=65535).contains(&port))
                }) {
                    return Err(ApiError::BadRequest("DNS 服务器端口无效".into()));
                }
                if let Some(tls) = server.get("tls") {
                    known_keys(
                        tls,
                        &[
                            "enabled",
                            "server_name",
                            "insecure",
                            "alpn",
                            "min_version",
                            "max_version",
                            "cipher_suites",
                            "certificate",
                            "certificate_path",
                        ],
                    )?;
                }
            }
            for tag in dns.get("final").into_iter().chain(
                dns.get("rules")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|rule| rule.get("server")),
            ) {
                if !tag.as_str().is_some_and(|tag| dns_tags.contains(tag)) {
                    return Err(ApiError::BadRequest(
                        "DNS 规则或默认服务器引用不存在".into(),
                    ));
                }
            }
        } else if dns.get("final").is_some()
            || dns
                .get("rules")
                .is_some_and(|rules| rules.as_array().is_some_and(|rules| !rules.is_empty()))
        {
            return Err(ApiError::BadRequest(
                "DNS 模板引用服务器前必须提供服务器清单".into(),
            ));
        }
        validate_rules(dns.get("rules"), true)?;
    }
    if let Some(route) = &definition.route {
        known_keys(
            route,
            &[
                "rules",
                "final",
                "auto_detect_interface",
                "default_domain_resolver",
            ],
        )?;
        validate_rules(route.get("rules"), false)?;
    }
    Ok(())
}

fn validate_rules(value: Option<&Value>, dns: bool) -> ApiResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let rules = value
        .as_array()
        .filter(|v| v.len() <= 128)
        .ok_or_else(|| ApiError::BadRequest("规则应为最多 128 项的数组".into()))?;
    for rule in rules {
        if dns {
            known_keys(
                rule,
                &[
                    "domain",
                    "domain_suffix",
                    "domain_keyword",
                    "query_type",
                    "action",
                    "server",
                    "strategy",
                ],
            )?;
        } else {
            known_keys(
                rule,
                &[
                    "domain",
                    "domain_suffix",
                    "domain_keyword",
                    "ip_cidr",
                    "port",
                    "protocol",
                    "action",
                    "outbound",
                ],
            )?;
        }
        if rule
            .get("action")
            .is_some_and(|a| !matches!(a.as_str(), Some("route" | "reject")))
        {
            return Err(ApiError::BadRequest(
                "模板仅表达 route 与 reject 动作，其他动作不会被丢弃或替换".into(),
            ));
        }
        for key in [
            "domain",
            "domain_suffix",
            "domain_keyword",
            "ip_cidr",
            "protocol",
        ] {
            let Some(value) = rule.get(key) else {
                continue;
            };
            let valid_string = value
                .as_str()
                .is_some_and(|value| !value.is_empty() && value.len() <= 1024);
            let valid_array = value.as_array().is_some_and(|values| {
                !values.is_empty()
                    && values.len() <= 128
                    && values.iter().all(|value| {
                        value
                            .as_str()
                            .is_some_and(|value| !value.is_empty() && value.len() <= 1024)
                    })
            });
            if !valid_string && !valid_array {
                return Err(ApiError::BadRequest(
                    "模板规则匹配字段应为非空字符串或有界字符串数组".into(),
                ));
            }
        }
        if rule.get("port").is_some_and(|value| {
            !value
                .as_u64()
                .is_some_and(|port| (1..=65535).contains(&port))
                && !value.as_array().is_some_and(|values| {
                    !values.is_empty()
                        && values.len() <= 128
                        && values.iter().all(|port| {
                            port.as_u64()
                                .is_some_and(|port| (1..=65535).contains(&port))
                        })
                })
        }) {
            return Err(ApiError::BadRequest(
                "路由规则端口应为有效端口或有界端口数组".into(),
            ));
        }
        if rule.get("action").is_none_or(|action| action == "route")
            && rule
                .get(if dns { "server" } else { "outbound" })
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(ApiError::BadRequest(
                "路由动作需指定目标服务器或出站".into(),
            ));
        }
    }
    Ok(())
}

pub(in super::super) fn apply_definition(
    content: String,
    definition: Option<&Value>,
) -> ApiResult<String> {
    let Some(definition) = definition else {
        return Ok(content);
    };
    let definition: Definition = serde_json::from_value(definition.clone())
        .map_err(|_| ApiError::Conflict("客户端模板格式已不受支持，请修正模板".into()))?;
    validate(&definition)?;
    let mut value: Value = serde_json::from_str(&content).map_err(anyhow::Error::from)?;
    let outbounds = value["outbounds"]
        .as_array_mut()
        .ok_or_else(|| ApiError::Conflict("生成配置缺少出站列表".into()))?;
    let leaf_tags: BTreeSet<String> = outbounds
        .iter()
        .filter(|v| v["type"] != "selector")
        .filter_map(|v| v["tag"].as_str().map(str::to_owned))
        .collect();
    for group in &definition.selection_groups {
        if leaf_tags.contains(&group.tag)
            || group.outbounds.iter().any(|tag| !leaf_tags.contains(tag))
        {
            return Err(ApiError::Conflict(
                "模板引用的节点已不可用或名称冲突，请重新确认选择组；不丢弃成员、不自动直连".into(),
            ));
        }
        outbounds.retain(|v| v["tag"] != group.tag);
        let mut selector = json!({"type":"selector","tag":group.tag,"outbounds":group.outbounds});
        if let Some(default) = &group.default {
            selector["default"] = json!(default);
        }
        outbounds.push(selector);
    }
    let all_tags: BTreeSet<String> = outbounds
        .iter()
        .filter_map(|v| v["tag"].as_str().map(str::to_owned))
        .collect();
    if let Some(route) = &definition.route {
        for tag in route.get("final").into_iter().chain(
            route
                .get("rules")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|rule| rule.get("outbound")),
        ) {
            if !tag.as_str().is_some_and(|tag| all_tags.contains(tag)) {
                return Err(ApiError::Conflict(
                    "路由模板引用的出站不可用，请修改模板".into(),
                ));
            }
        }
        value["route"] = route.clone();
    }
    if let Some(dns) = &definition.dns {
        for server in dns
            .get("servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if server
                .get("detour")
                .is_some_and(|v| !v.as_str().is_some_and(|tag| all_tags.contains(tag)))
            {
                return Err(ApiError::Conflict("DNS 模板引用的出站不可用".into()));
            }
        }
        value["dns"] = dns.clone();
    }
    serde_json::to_string_pretty(&value).map_err(|e| ApiError::Internal(e.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TemplateQuery {
    reveal: Option<bool>,
}

pub(super) fn redact_definition(value: &Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    let sensitive = lower == "headers"
                        || [
                            "password",
                            "secret",
                            "private",
                            "credential",
                            "authorization",
                            "token",
                            "api_key",
                            "api-key",
                        ]
                        .iter()
                        .any(|field| lower.contains(field));
                    (
                        key.clone(),
                        if sensitive {
                            json!("[已脱敏]")
                        } else {
                            redact_definition(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_definition).collect()),
        value => value.clone(),
    }
}

pub(super) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(request): Query<TemplateQuery>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "proxy:read").await?;
    let reveal = if request.reveal == Some(true) {
        super::super::secret_access::require_reveal(&state, &headers).await?;
        true
    } else {
        super::super::secret_access::may_reveal(&state, &headers).await?
    };
    let mut tx = state.pool.begin().await?;
    super::super::business::lock_user(&mut tx, id).await?;
    let mut template: Option<Value> =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM singbox_client_templates t WHERE user_id=$1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if !reveal && let Some(template) = &mut template {
        template["definition"] = redact_definition(&template["definition"]);
    }
    if reveal && template.is_some() {
        let administrator =
            crate::control_center::require_capability(&state, &headers, "proxy:write").await?;
        event(
            &mut tx,
            Some(administrator),
            Some(id),
            "security_client_template_read",
            json!({"credential_values_recorded":false}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"template":template,"definition_redacted":!reveal&&template.is_some(),"credential_access_reason":super::super::secret_access::REASON,"supported_client":"singbox","supported_version":"1.14.2","schema_validation":true,"runtime_validation":false,"limitations":"其他客户端和版本未提供兼容矩阵；模板字段超出表达范围时拒绝保存，不静默丢弃"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Save {
    expected_revision: i64,
    client: String,
    client_version: String,
    definition: Definition,
}

pub(super) async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<Save>,
) -> ApiResult<Json<Value>> {
    let administrator = super::super::secret_access::require_reveal(&state, &headers).await?;
    if request.client != "singbox" || request.client_version != "1.14.2" {
        return Err(ApiError::BadRequest(
            "当前仅支持 sing-box 1.14.2 完整 JSON 模板；其他客户端/版本未完成兼容支持".into(),
        ));
    }
    if request.expected_revision < 0
        || request.expected_revision >= super::super::business::MAX_SAFE_INTEGER
    {
        return Err(ApiError::BadRequest("客户端模板版本无效或达到上限".into()));
    }
    validate(&request.definition)?;
    let definition = serde_json::to_value(&request.definition).map_err(anyhow::Error::from)?;
    if serde_json::to_vec(&definition)
        .map_err(anyhow::Error::from)?
        .len()
        > 65536
    {
        return Err(ApiError::BadRequest("客户端模板超过 64 KiB".into()));
    }
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    super::super::business::lock_user(&mut tx, id).await?;
    let revision: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM singbox_client_templates WHERE user_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if revision.unwrap_or(0) != request.expected_revision {
        return Err(ApiError::Conflict(
            "客户端模板已修改，请刷新；当前草稿保留".into(),
        ));
    }
    let content = reference_content(&mut tx, id).await?;
    apply_definition(content, Some(&definition))?;
    let revision = request
        .expected_revision
        .checked_add(1)
        .ok_or_else(|| ApiError::Conflict("模板版本达到上限".into()))?;
    sqlx::query("INSERT INTO singbox_client_templates(user_id,revision,client,client_version,definition,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(user_id) DO UPDATE SET revision=EXCLUDED.revision,client=EXCLUDED.client,client_version=EXCLUDED.client_version,definition=EXCLUDED.definition,updated_at=EXCLUDED.updated_at")
        .bind(id).bind(revision).bind(request.client).bind(request.client_version).bind(&definition).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    event(&mut tx,Some(administrator),Some(id),"client_template_update",json!({"revision":revision,"selection_groups":request.definition.selection_groups.len(),"dns_configured":request.definition.dns.is_some(),"route_configured":request.definition.route.is_some()})).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"saved":true,"revision":revision,"runtime_validation":false,"reference_validation":true,"subscription_generated":false}),
    ))
}

async fn reference_content(tx: &mut Transaction<'_, Postgres>, user: i64) -> ApiResult<String> {
    let managed: Vec<i64> = sqlx::query_scalar(
        "SELECT node_id FROM singbox_desired_accesses WHERE user_id=$1 ORDER BY node_id",
    )
    .bind(user)
    .fetch_all(&mut **tx)
    .await?;
    let mut tags: Vec<String> = managed.into_iter().map(|id| format!("node-{id}")).collect();
    let external = super::super::external_access::subscription_nodes(tx, user).await?;
    tags.extend(
        external
            .entries
            .iter()
            .filter(|node| node.available)
            .map(|node| {
                format!(
                    "external-node-{} {}",
                    node.reference.external_node_id,
                    node.name.trim()
                )
            }),
    );
    // This document is exclusively a bounded reference set for template editing.
    // It never becomes a subscription or carries proxy transport credentials.
    let mut outbounds: Vec<Value> = tags
        .iter()
        .map(|tag| json!({"type":"authorized_reference","tag":tag}))
        .collect();
    outbounds.push(json!({"type":"selector","tag":"proxy","outbounds":tags}));
    outbounds.push(json!({"type":"direct","tag":"direct"}));
    serde_json::to_string(&json!({"outbounds":outbounds,"route":{"final":"proxy"}}))
        .map_err(|e| ApiError::Internal(e.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Client {
    client: String,
    version: String,
    format: String,
}

pub(super) async fn compatibility(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(request): Json<Client>,
) -> ApiResult<Json<Value>> {
    crate::control_center::require_capability(&state, &headers, "proxy:read").await?;
    let supported =
        request.client == "singbox" && request.version == "1.14.2" && request.format == "singbox";
    if !supported {
        return Ok(Json(
            json!({"available":false,"client":request.client,"version":request.version,"format":request.format,"reason":"当前仅提供 sing-box 1.14.2 完整 JSON 模型；不能确认其他客户端或版本对协议与字段的支持","dropped_fields":[]}),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let content = super::super::subscriptions::content_on(&mut tx, id, true).await;
    tx.commit().await?;
    match content {
        Ok(content) => {
            let value: Value = serde_json::from_str(&content).map_err(anyhow::Error::from)?;
            Ok(Json(
                json!({"available":true,"client":"singbox","version":"1.14.2","format":"singbox","protocols":value["outbounds"].as_array().into_iter().flatten().filter_map(|v|v["type"].as_str()).collect::<BTreeSet<_>>(),"dropped_fields":[],"schema_model":"当前固定编译器模型","runtime_validation":false,"reason":"配置生成成功；仍需由目标客户端执行配置检查及实际连接验证"}),
            ))
        }
        Err(ApiError::Conflict(reason)) => Ok(Json(
            json!({"available":false,"reason":reason,"dropped_fields":[],"runtime_validation":false}),
        )),
        Err(error) => Err(error),
    }
}
