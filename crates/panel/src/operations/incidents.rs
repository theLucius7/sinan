mod certificates;
use super::{api::authorize, model::label};
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
    settings::Settings,
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    control_center::require_capability(&state, &headers, "operations:read").await?;
    let rows=sqlx::query("SELECT id,server_id,to_jsonb(i)||jsonb_build_object('maintenance_suppressed',EXISTS(SELECT 1 FROM operations_maintenance m WHERE i.server_id=ANY(m.targets) AND m.suppress_notifications AND m.starts_at<=$1 AND m.ends_at>$1)) AS value FROM operations_incidents i ORDER BY opened_at DESC LIMIT 200").bind(now_timestamp()).fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    let now = now_timestamp();
    for row in rows {
        match authorize_incident(&state, &headers, row.get("id"), false).await {
            Ok(_) => {
                let mut value: Value = row.get("value");
                if certificates::certificate(value["source_key"].as_str().unwrap_or("")).is_some()
                    && certificates::suppressed(&state, &value["evidence"], now).await?
                {
                    value["maintenance_suppressed"] = json!(true);
                }
                values.push(value);
            }
            Err(ApiError::Forbidden(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Json(values))
}

pub async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    authorize_incident(&state, &headers, id, false).await?;
    let incident: Value =
        sqlx::query_scalar("SELECT to_jsonb(i) FROM operations_incidents i WHERE id=$1")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    let notes:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(n) FROM operations_incident_notes n WHERE incident_id=$1 ORDER BY created_at,id").bind(id).fetch_all(&state.pool).await?;
    let deliveries:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(d)-'payload' FROM operations_incident_deliveries d WHERE incident_id=$1 ORDER BY id").bind(id).fetch_all(&state.pool).await?;
    Ok(Json(
        json!({"incident":incident,"timeline":notes,"deliveries":deliveries}),
    ))
}

pub(super) async fn authorize_incident(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    write: bool,
) -> ApiResult<i64> {
    let row =
        sqlx::query("SELECT server_id,source_key,evidence FROM operations_incidents WHERE id=$1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let server: Option<i64> = row.get("server_id");
    let source: String = row.get("source_key");
    if let Some(certificate) = certificates::certificate(&source) {
        certificates::access(
            state,
            headers,
            certificate,
            &row.get::<Value, _>("evidence"),
            write,
        )
        .await?;
    }
    if let Some(job) = source
        .strip_prefix("job:")
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        let targets: Vec<i64> =
            sqlx::query_scalar("SELECT targets FROM operations_jobs WHERE id=$1")
                .bind(job)
                .fetch_one(&state.pool)
                .await?;
        authorize(state, headers, &targets, write).await?;
    }
    if row.get::<String, _>("source_key").starts_with("service:")
        && let Some(server) = server
    {
        control_center::require_server(state, headers, server, "services:read").await?;
    }
    if source.starts_with("cancellation:")
        && let Some(server) = server
    {
        control_center::require_server(state, headers, server, "servers:read").await?;
    }
    if row.get::<String, _>("source_key").starts_with("cloud:") {
        control_center::require_capability(
            state,
            headers,
            if write { "cloud:write" } else { "cloud:read" },
        )
        .await?;
    }
    if row.get::<String, _>("source_key").starts_with("backup:") {
        super::require_global(
            state,
            headers,
            if write {
                "recovery:write"
            } else {
                "recovery:read"
            },
        )
        .await?;
    }
    if server.is_none() && certificates::certificate(&source).is_none() {
        super::require_global(
            state,
            headers,
            if write {
                "operations:write"
            } else {
                "operations:read"
            },
        )
        .await?;
    }
    authorize(
        state,
        headers,
        &server.into_iter().collect::<Vec<_>>(),
        write,
    )
    .await
}

pub async fn assignees(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    authorize_incident(&state, &headers, id, true).await?;
    let incident =
        sqlx::query("SELECT server_id,source_key,evidence FROM operations_incidents WHERE id=$1")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    let server: Option<i64> = incident.get("server_id");
    let source: String = incident.get("source_key");
    let rows=sqlx::query("SELECT admin_id,display_name FROM administrator_profiles WHERE enabled AND (role='owner' OR (role='operator' AND capabilities ? 'operations:write')) ORDER BY display_name").fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    for row in rows {
        let actor: i64 = row.get("admin_id");
        if !assignee_allowed(
            &state,
            actor,
            server,
            &source,
            &incident.get::<Value, _>("evidence"),
        )
        .await?
        {
            continue;
        }
        values.push(json!({"id":actor,"name":row.get::<String,_>("display_name")}));
    }
    Ok(Json(values))
}

async fn assignee_allowed(
    state: &AppState,
    actor: i64,
    server: Option<i64>,
    source: &str,
    evidence: &Value,
) -> ApiResult<bool> {
    match control_center::require_actor_capability(state, actor, "operations:write").await {
        Ok(()) => {}
        Err(ApiError::Forbidden(_)) => return Ok(false),
        Err(error) => return Err(error),
    }
    if let Some(certificate) = certificates::certificate(source)
        && !certificates::assignee(state, actor, certificate, evidence).await?
    {
        return Ok(false);
    }
    if let Some(server) = server {
        if !control_center::actor_server_allowed(&state.pool, actor, server, "operations:write")
            .await?
        {
            return Ok(false);
        }
        if source.starts_with("service:")
            && !control_center::actor_server_allowed(&state.pool, actor, server, "services:read")
                .await?
        {
            return Ok(false);
        }
        if source.starts_with("cancellation:")
            && !control_center::actor_server_allowed(&state.pool, actor, server, "servers:read")
                .await?
        {
            return Ok(false);
        }
    } else if certificates::certificate(source).is_none() {
        let global:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM administrator_profiles WHERE admin_id=$1 AND enabled AND all_servers)").bind(actor).fetch_one(&state.pool).await?;
        if !global {
            return Ok(false);
        }
    }
    for (prefix, capability) in [("cloud:", "cloud:write"), ("backup:", "recovery:write")] {
        if source.starts_with(prefix) {
            match control_center::require_actor_capability(state, actor, capability).await {
                Ok(()) => {}
                Err(ApiError::Forbidden(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
    }
    if let Some(job) = source
        .strip_prefix("job:")
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        let targets: Vec<i64> =
            sqlx::query_scalar("SELECT targets FROM operations_jobs WHERE id=$1")
                .bind(job)
                .fetch_one(&state.pool)
                .await?;
        for target in targets {
            if !control_center::actor_server_allowed(&state.pool, actor, target, "operations:write")
                .await?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    kind: String,
    note: String,
    assignee: Option<i64>,
    evidence: Option<Recovery>,
    escalation_after_secs: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    observed_at: i64,
    method: String,
    reference: String,
    healthy: bool,
}

pub async fn action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<Action>,
) -> ApiResult<Json<Value>> {
    let actor = authorize_incident(&state, &headers, id, true).await?;
    label(&request.note, 4096)?;
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM operations_incidents WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let mut evidence = json!({});
    match request.kind.as_str() {
        "acknowledge" => {
            sqlx::query("UPDATE operations_incidents SET status='acknowledged',acknowledged_at=COALESCE(acknowledged_at,$2),acknowledged_by=$3 WHERE id=$1 AND status<>'resolved'").bind(id).bind(now).bind(actor).execute(&mut *tx).await?;
        }
        "assign" => {
            let assignee = request
                .assignee
                .ok_or_else(|| ApiError::BadRequest("请选择处理管理员".into()))?;
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM admins WHERE id=$1)")
                    .bind(assignee)
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                return Err(ApiError::BadRequest("处理管理员不存在".into()));
            }
            if !assignee_allowed(
                &state,
                assignee,
                row.get("server_id"),
                &row.get::<String, _>("source_key"),
                &row.get::<Value, _>("evidence"),
            )
            .await?
            {
                return Err(ApiError::Conflict(
                    "处理管理员没有此故障的功能及完整目标权限".into(),
                ));
            }
            sqlx::query("UPDATE operations_incidents SET assignee=$2 WHERE id=$1")
                .bind(id)
                .bind(assignee)
                .execute(&mut *tx)
                .await?;
            evidence = json!({"assignee":assignee});
        }
        "escalation" => {
            let after = request
                .escalation_after_secs
                .filter(|v| (60..=604800).contains(v))
                .ok_or_else(|| ApiError::BadRequest("升级间隔须为 60 秒至 7 天".into()))?;
            sqlx::query("UPDATE operations_incidents SET escalation_after_secs=$2 WHERE id=$1")
                .bind(id)
                .bind(after)
                .execute(&mut *tx)
                .await?;
            evidence = json!({"escalation_after_secs":after});
        }
        "resolve" => {
            let proof = request
                .evidence
                .ok_or_else(|| ApiError::BadRequest("恢复必须提供实际检测证据".into()))?;
            label(&proof.method, 128)?;
            label(&proof.reference, 2048)?;
            if !proof.healthy
                || proof.observed_at < row.get::<i64, _>("opened_at")
                || proof.observed_at > now
                || proof.observed_at < now - 600
            {
                return Err(ApiError::BadRequest(
                    "恢复证据须为故障发生后十分钟内的正常检测结果".into(),
                ));
            }
            evidence = json!({"kind":"administrator_observation","observed_at":proof.observed_at,"method":proof.method,"reference":proof.reference,"healthy":true,"actor":actor});
            sqlx::query("UPDATE operations_incidents SET status='resolved',resolved_at=$2,recovery_evidence=$3,conclusion=$4 WHERE id=$1 AND status<>'resolved'").bind(id).bind(now).bind(&evidence).bind(&request.note).execute(&mut *tx).await?;
            enqueue(&mut tx, id, "recovery", now).await?;
        }
        "note" => {}
        _ => return Err(ApiError::BadRequest("事件动作无效".into())),
    }
    note(
        &mut tx,
        id,
        Some(actor),
        &request.kind,
        &request.note,
        evidence,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id,"action":request.kind})))
}

async fn note(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    actor: Option<i64>,
    kind: &str,
    text: &str,
    evidence: Value,
    now: i64,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO operations_incident_notes(incident_id,actor,kind,note,evidence,created_at) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(actor).bind(kind).bind(text).bind(evidence).bind(now).execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn observe(state: &AppState) -> ApiResult<()> {
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let alerts=sqlx::query("SELECT * FROM server_alert_events WHERE resolved_at IS NULL OR resolved_at>$1 ORDER BY id DESC LIMIT 200").bind(now-600).fetch_all(&mut *tx).await?;
    for alert in alerts {
        let id: i64 = alert.get("id");
        let key = format!("notification:{id}");
        let resolved: Option<i64> = alert.get("resolved_at");
        let evidence: Value = alert.get("details");
        if resolved.is_none() {
            open(
                &mut tx,
                &key,
                Some(alert.get("server_id")),
                &alert.get::<String, _>("message"),
                "warning",
                evidence,
                alert.get("opened_at"),
                Some(id),
            )
            .await?;
        } else if let Some(resolved) = resolved
            && alert.get::<Option<String>, _>("resolution").as_deref() == Some("recovered")
            && evidence
                .pointer("/recovery/observed_at")
                .and_then(Value::as_i64)
                .is_some()
        {
            recover(&mut tx, &key, evidence["recovery"].clone(), resolved, false).await?;
        }
    }
    let services=sqlx::query("SELECT m.*,s.last_seen FROM server_module_status m JOIN servers s ON s.id=m.server_id WHERE s.deleted_at IS NULL AND m.updated_at>0 LIMIT 500").fetch_all(&mut *tx).await?;
    for service in services {
        let server: i64 = service.get("server_id");
        let module: String = service.get("module");
        let sampled: i64 = service.get("updated_at");
        let key = format!("service:{server}:{module}");
        let fresh = sampled <= now
            && now - sampled <= 120
            && service
                .get::<Option<i64>, _>("last_seen")
                .is_some_and(|v| v <= now && now - v <= 60);
        if !fresh {
            continue;
        }
        let evidence = json!({"module":module,"observed_at":sampled,"target_rev":service.get::<i64,_>("target_rev"),"applied_rev":service.get::<i64,_>("applied_rev"),"healthy":service.get::<bool,_>("healthy"),"error":service.get::<Option<String>,_>("last_error")});
        if service.get::<bool, _>("healthy")
            && service.get::<i64, _>("target_rev") == service.get::<i64, _>("applied_rev")
        {
            recover(&mut tx, &key, evidence, sampled, true).await?;
        } else {
            open(
                &mut tx,
                &key,
                Some(server),
                &format!("受管服务 {module} 未健康或目标配置未应用"),
                "critical",
                evidence,
                sampled,
                None,
            )
            .await?;
        }
    }
    let jobs=sqlx::query("SELECT id,name,status,targets,updated_at FROM operations_jobs WHERE (status IN ('queued','paused','uncertain') AND created_at<$1) OR (status IN ('succeeded','failed','cancelled') AND updated_at>$2) ORDER BY created_at LIMIT 100").bind(now-300).bind(now-600).fetch_all(&mut *tx).await?;
    for job in jobs {
        let id: Uuid = job.get("id");
        let key = format!("job:{id}");
        let status: String = job.get("status");
        let evidence =
            json!({"job_id":id,"status":status,"updated_at":job.get::<i64,_>("updated_at")});
        if matches!(status.as_str(), "succeeded" | "failed" | "cancelled") {
            recover(&mut tx,&key,json!({"task_terminal":true,"execution_status":status,"job_id":id,"observed_at":job.get::<i64,_>("updated_at")}),job.get("updated_at"),true).await?;
        } else {
            let ids: Vec<i64> = job.get("targets");
            open(
                &mut tx,
                &key,
                ids.first().copied(),
                &format!("任务 {} 长期等待或结果未知", job.get::<String, _>("name")),
                "warning",
                evidence,
                now,
                None,
            )
            .await?;
        }
    }
    certificates::observe(&mut tx, now).await?;
    let escalations:Vec<Uuid>=sqlx::query_scalar("UPDATE operations_incidents SET escalated_at=$1 WHERE status<>'resolved' AND source_key NOT LIKE 'cancellation:%' AND escalated_at IS NULL AND opened_at+escalation_after_secs<=$1 RETURNING id").bind(now).fetch_all(&mut *tx).await?;
    for id in escalations {
        note(
            &mut tx,
            id,
            None,
            "escalated",
            "故障超过升级提醒间隔",
            json!({"observed_at":now}),
            now,
        )
        .await?;
        enqueue(&mut tx, id, "escalation", now).await?;
    }
    tx.commit().await?;
    dispatch(state, now).await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn open(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    server: Option<i64>,
    title: &str,
    severity: &str,
    evidence: Value,
    observed: i64,
    notification: Option<i64>,
) -> ApiResult<()> {
    let title: String = if title.trim().is_empty() {
        "已记录故障，请查看来源证据".into()
    } else {
        title.chars().take(1024).collect()
    };
    let id = Uuid::new_v4();
    let inserted=sqlx::query("INSERT INTO operations_incidents(id,source_key,server_id,title,severity,status,opened_at,observed_at,evidence,notification_event) VALUES($1,$2,$3,$4,$5,'open',$6,$6,$7,$8) ON CONFLICT(source_key) WHERE status<>'resolved' DO UPDATE SET evidence=EXCLUDED.evidence,observed_at=EXCLUDED.observed_at RETURNING id")
        .bind(id).bind(key).bind(server).bind(&title).bind(severity).bind(observed).bind(&evidence).bind(notification).fetch_one(&mut **tx).await?;
    if inserted.get::<Uuid, _>("id") == id {
        note(tx, id, None, "opened", &title, evidence, observed).await?;
        if notification.is_none() {
            enqueue(tx, id, "alert", observed).await?;
        }
    }
    Ok(())
}

pub(super) async fn recover(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    evidence: Value,
    observed: i64,
    notify: bool,
) -> ApiResult<()> {
    let ids:Vec<Uuid>=sqlx::query_scalar("UPDATE operations_incidents SET status='resolved',resolved_at=$2,recovery_evidence=$3,conclusion='已有新观测确认该故障条件结束' WHERE source_key=$1 AND status<>'resolved' AND opened_at<=$2 RETURNING id")
        .bind(key).bind(observed).bind(&evidence).fetch_all(&mut **tx).await?;
    for id in ids {
        note(
            tx,
            id,
            None,
            "recovery_observed",
            "已记录恢复依据",
            evidence.clone(),
            observed,
        )
        .await?;
        if notify {
            enqueue(tx, id, "recovery", observed).await?;
        }
    }
    Ok(())
}

async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    kind: &str,
    now: i64,
) -> ApiResult<()> {
    let settings: Value = sqlx::query_scalar("SELECT settings FROM panel_settings WHERE singleton")
        .fetch_one(&mut **tx)
        .await?;
    let settings: Settings = serde_json::from_value(settings).map_err(anyhow::Error::from)?;
    if !settings.notification_enabled {
        return Ok(());
    }
    let row=sqlx::query("SELECT i.title,i.severity,COALESCE(s.name,'面板') AS name FROM operations_incidents i LEFT JOIN servers s ON s.id=i.server_id WHERE i.id=$1").bind(id).fetch_one(&mut **tx).await?;
    let title = if kind == "recovery" {
        "故障恢复已核对"
    } else if kind == "escalation" {
        "故障升级提醒"
    } else if row.get::<String, _>("severity") == "info" {
        "运维提醒事项"
    } else {
        "运维故障事件"
    };
    let name: String = row.get("name");
    let message: String = row.get("title");
    let time = now.to_string();
    let event_id = id.to_string();
    for (channel, payload) in crate::notifications::plugin::render(
        &settings,
        &crate::notifications::webhook::Message {
            title,
            server: &name,
            message: &message,
            time: &time,
            event: kind,
            event_id: &event_id,
            category: "operations",
        },
    ) {
        let (text, status, error) = match payload {
            Ok(text) => (text, "pending", None),
            Err(error) => (String::new(), "failed", Some(error)),
        };
        sqlx::query("INSERT INTO operations_incident_deliveries(incident_id,channel,kind,payload,status,next_attempt_at,last_error) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING").bind(id).bind(channel).bind(kind).bind(text).bind(status).bind(now).bind(error).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn dispatch(state: &AppState, now: i64) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    let settings: Value = sqlx::query_scalar("SELECT settings FROM panel_settings WHERE singleton")
        .fetch_one(&mut *tx)
        .await?;
    let settings: Settings = serde_json::from_value(settings).map_err(anyhow::Error::from)?;
    if !settings.notification_enabled {
        return Ok(());
    }
    let rows=sqlx::query("SELECT d.*,i.server_id,i.status AS incident_status,i.source_key,i.evidence FROM operations_incident_deliveries d JOIN operations_incidents i ON i.id=d.incident_id WHERE d.status='pending' AND d.next_attempt_at<=$1 ORDER BY d.id LIMIT 4 FOR UPDATE OF d SKIP LOCKED").bind(now).fetch_all(&mut *tx).await?;
    for row in rows {
        let id: i64 = row.get("id");
        let server: Option<i64> = row.get("server_id");
        let server_suppressed = if let Some(server) = server {
            super::notifications_suppressed(&state.pool, server, now).await?
        } else {
            false
        };
        let certificate_suppressed = certificates::certificate(&row.get::<String, _>("source_key"))
            .is_some()
            && certificates::suppressed(state, &row.get::<Value, _>("evidence"), now).await?;
        if server_suppressed || certificate_suppressed {
            sqlx::query("UPDATE operations_incident_deliveries SET next_attempt_at=$2 WHERE id=$1")
                .bind(id)
                .bind(now + 60)
                .execute(&mut *tx)
                .await?;
            continue;
        }
        if row.get::<String, _>("incident_status") == "resolved"
            && row.get::<String, _>("kind") != "recovery"
        {
            sqlx::query("UPDATE operations_incident_deliveries SET status='cancelled' WHERE id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            continue;
        }
        let channel: String = row.get("channel");
        let payload: String = row.get("payload");
        let attempts: i32 = row.get("attempts");
        match crate::notifications::plugin::send(&settings, &channel, &payload).await {
            Ok(()) => {
                sqlx::query("UPDATE operations_incident_deliveries SET status='sent',attempts=attempts+1,delivered_at=$2,last_error=NULL WHERE id=$1").bind(id).bind(now).execute(&mut *tx).await?;
            }
            Err((error, retry)) => {
                sqlx::query("UPDATE operations_incident_deliveries SET status=CASE WHEN attempts>=4 THEN 'failed' ELSE 'pending' END,attempts=attempts+1,last_error=$2,next_attempt_at=$3 WHERE id=$1").bind(id).bind(error).bind(now+retry.unwrap_or(30*(1_i64<<attempts.min(5)))).execute(&mut *tx).await?;
            }
        }
    }
    tx.commit().await?;
    Ok(())
}
