use super::{cloudflare::Failure, model::Rule};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub line: String,
    pub values: Vec<String>,
    pub ttl: u64,
    pub proxied: bool,
    pub active: bool,
    pub marker: Option<String>,
}

pub(super) fn expected_matches(
    current: Option<&Snapshot>,
    expected: Option<&Snapshot>,
) -> Result<(), Failure> {
    if expected.is_some() && current != expected {
        return Err("remote_changed".into());
    }
    Ok(())
}

pub(super) fn target_snapshot(rule: &Rule, ip: std::net::IpAddr, id: String) -> Snapshot {
    Snapshot {
        id,
        name: rule.config.record_name.clone(),
        kind: rule.config.record_type.clone(),
        line: rule.config.line.clone(),
        values: vec![ip.to_string()],
        ttl: u64::from(rule.config.ttl),
        proxied: rule.config.proxied,
        active: true,
        marker: None,
    }
}

use super::{
    history::{self, Entry},
    load, model,
    providers::Providers,
};
use crate::{
    AppState, auth,
    error::{ApiError, ApiResult},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::time::Duration;
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/plugins/ddns/rules/{id}/preview", post(preview))
        .route("/api/plugins/ddns/rules/{id}/history", get(history_list))
        .route(
            "/api/plugins/ddns/rules/{id}/rollback",
            post(super::rollback::rollback),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    revision: i64,
}

async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PreviewRequest>,
) -> ApiResult<Json<Value>> {
    auth::require_admin(&state, &headers).await?;
    let mut rule = load(&state.pool, id).await?;
    crate::control_center::require_server(&state, &headers, rule.config.server_id, "dns:read")
        .await?;
    if rule.revision != input.revision {
        return Err(ApiError::Conflict("规则已被修改，请刷新后预览".into()));
    }
    if rule.lease_until > sinan_protocol::now_timestamp() {
        return Err(ApiError::Conflict("规则正在执行，请稍后核对".into()));
    }
    let info = model::observation(&state.pool, rule.config.server_id).await?;
    let desired = info.select(
        &rule.config,
        rule.last_ip.as_deref(),
        sinan_protocol::now_timestamp(),
    );
    let _permit = state
        .quality_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let client = Providers::new().map_err(|_| ApiError::Busy)?;
    let result = tokio::time::timeout(Duration::from_secs(super::REQUEST_BUDGET), async {
        super::credentials::hydrate(&state.pool, &mut rule)
            .await
            .map_err(|_| Failure::from("credential_unavailable"))?;
        client.inspect(&rule).await
    })
    .await
    .unwrap_or_else(|_| Err("request_timeout".into()));
    let (remote, error) = match result {
        Ok(remote) => (remote, None),
        Err(error) => (None, Some(error.code.to_owned())),
    };
    let checked_at = sinan_protocol::now_timestamp();
    let change = match (error.is_some(), desired.as_ref(), remote.as_ref()) {
        (false, Ok(desired), Some(remote))
            if remote.values == vec![desired.to_string()]
                && remote.ttl == u64::from(rule.config.ttl)
                && remote.proxied == rule.config.proxied =>
        {
            "unchanged"
        }
        (false, Ok(_), Some(_)) => "update",
        (false, Ok(_), None) => "create",
        _ => "blocked",
    };
    let desired_ip = desired.as_ref().ok().map(ToString::to_string);
    let mut tx = state.pool.begin().await?;
    // This is a provider read observation, never evidence of public DNS propagation.
    history::append(
        &mut tx,
        Entry {
            id: Uuid::new_v4(),
            rule_id: id,
            server_id: rule.config.server_id,
            revision: rule.revision,
            operation: "check".into(),
            desired_ip: desired_ip.clone(),
            previous: None,
            observed: remote.clone(),
            status: if error.is_some() { "error" } else { "checked" }.into(),
            error_code: error.clone(),
            occurred_at: checked_at,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"revision":rule.revision,"desired_ip":desired_ip,"remote":remote,
        "source_error":desired.err(),"error_code":error,"change":change,"checked_at":checked_at,
        "evidence":"provider_read","resolver_observed":null}),
    ))
}

async fn history_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Entry>>> {
    auth::require_admin(&state, &headers).await?;
    crate::control_center::require_capability(&state, &headers, "dns:read").await?;
    // History survives rule removal and contains no credentials.
    let actor = crate::control_center::authenticate(&state, &headers).await?;
    Ok(Json(
        history::list(&state.pool, id)
            .await?
            .into_iter()
            .filter(|entry| actor.allows_server(entry.server_id))
            .collect(),
    ))
}
