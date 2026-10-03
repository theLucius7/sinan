use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use serde::Deserialize;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use uuid::Uuid;

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Value>>> {
    let actor = control_center::authenticate(&state, &headers).await?;
    if !actor.allows("operations:read") {
        return Err(ApiError::Forbidden("没有退订提醒读取授权".into()));
    }
    if !actor.allows("servers:read") {
        return Ok(Json(Vec::new()));
    }
    let permitted: Vec<i64> = actor
        .token_servers
        .as_ref()
        .unwrap_or(&actor.server_ids)
        .iter()
        .copied()
        .filter(|id| actor.allows_server(*id))
        .collect();
    let rows=sqlx::query("SELECT r.id AS record_id,r.server_id,s.name AS server_name,r.valid_until,r.reference,COALESCE(c.enabled,false) AS enabled,COALESCE(c.lead_secs,604800) AS lead_secs,c.notified_at,c.last_error FROM fleet_cost_records r JOIN servers s ON s.id=r.server_id LEFT JOIN operations_cancellation_reminders c ON c.record_id=r.id WHERE r.kind='cancellation' AND s.deleted_at IS NULL AND ($1 OR r.server_id=ANY($2)) ORDER BY r.occurred_at DESC,r.id DESC LIMIT 500").bind(actor.global_servers()).bind(permitted).fetch_all(&state.pool).await?;
    let mut values = Vec::new();
    for row in rows {
        let server: i64 = row.get("server_id");
        match control_center::require_server(&state, &headers, server, "operations:read").await {
            Ok(_) => {}
            Err(ApiError::Forbidden(_)) => continue,
            Err(error) => return Err(error),
        }
        match control_center::require_server(&state, &headers, server, "servers:read").await {
            Ok(_) => {}
            Err(ApiError::Forbidden(_)) => continue,
            Err(error) => return Err(error),
        }
        values.push(json!({"record_id":row.get::<Uuid,_>("record_id"),"server_id":server,"server_name":row.get::<String,_>("server_name"),"valid_until":row.get::<Option<i64>,_>("valid_until"),"reference":row.get::<String,_>("reference"),"enabled":row.get::<bool,_>("enabled"),"lead_secs":row.get::<i64,_>("lead_secs"),"notified_at":row.get::<Option<i64>,_>("notified_at"),"last_error":row.get::<Option<String>,_>("last_error")}));
    }
    Ok(Json(values))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configure {
    record_id: Uuid,
    enabled: bool,
    lead_secs: i64,
}
pub async fn configure(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Configure>,
) -> ApiResult<Json<Value>> {
    if control_center::authenticate(&state, &headers)
        .await?
        .token_id
        .is_some()
    {
        return Err(ApiError::Forbidden(
            "延迟退订提醒需由管理员会话配置，API 令牌不可创建或修改此计划".into(),
        ));
    }
    if !(3600..=2592000).contains(&input.lead_secs) {
        return Err(ApiError::BadRequest(
            "退订提醒提前量须为一小时至三十天".into(),
        ));
    }
    let row=sqlx::query("SELECT r.server_id,r.valid_until FROM fleet_cost_records r JOIN servers s ON s.id=r.server_id WHERE r.id=$1 AND r.kind='cancellation' AND s.deleted_at IS NULL").bind(input.record_id).fetch_optional(&state.pool).await?.ok_or(ApiError::NotFound)?;
    let server: i64 = row.get("server_id");
    let actor =
        control_center::require_server(&state, &headers, server, "operations:write").await?;
    control_center::require_server(&state, &headers, server, "servers:read").await?;
    if input.enabled && row.get::<Option<i64>, _>("valid_until").is_none() {
        return Err(ApiError::BadRequest(
            "此退订记录没有明确生效日期，不能启用日期提醒".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO operations_cancellation_reminders(record_id,enabled,lead_secs,configured_by,configured_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(record_id) DO UPDATE SET enabled=$2,lead_secs=$3,configured_by=$4,configured_at=$5,last_error=NULL")
        .bind(input.record_id).bind(input.enabled).bind(input.lead_secs).bind(actor).bind(now_timestamp()).execute(&mut *tx).await?;
    if !input.enabled {
        sqlx::query("UPDATE operations_incident_deliveries SET status='cancelled' WHERE status='pending' AND incident_id=(SELECT incident_id FROM operations_cancellation_reminders WHERE record_id=$1)").bind(input.record_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"record_id":input.record_id,"enabled":input.enabled,"side_effect":"仅提醒，不执行退订、停服或付款","replay_after_notified":false}),
    ))
}

pub(super) async fn tick(state: &AppState) -> ApiResult<()> {
    let now = now_timestamp();
    let mut tx = state.pool.begin().await?;
    let rows=sqlx::query("SELECT c.record_id,c.configured_by,c.lead_secs,r.server_id,r.valid_until,r.reference,s.name FROM operations_cancellation_reminders c JOIN fleet_cost_records r ON r.id=c.record_id JOIN servers s ON s.id=r.server_id WHERE c.enabled AND c.notified_at IS NULL AND r.kind='cancellation' AND r.valid_until IS NOT NULL AND r.valid_until-c.lead_secs<=$1 AND s.deleted_at IS NULL ORDER BY r.valid_until LIMIT 32 FOR UPDATE OF c SKIP LOCKED").bind(now).fetch_all(&mut *tx).await?;
    for row in rows {
        let record: Uuid = row.get("record_id");
        let server: i64 = row.get("server_id");
        let actor: i64 = row.get("configured_by");
        if !control_center::actor_server_allowed(&state.pool, actor, server, "operations:write")
            .await?
            || !control_center::actor_server_allowed(&state.pool, actor, server, "servers:read")
                .await?
        {
            sqlx::query("UPDATE operations_cancellation_reminders SET enabled=false,last_error='配置者服务器或提醒权限已撤销，提醒已暂停' WHERE record_id=$1").bind(record).execute(&mut *tx).await?;
            continue;
        }
        let source = format!("cancellation:{record}");
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM operations_incidents WHERE source_key=$1 ORDER BY opened_at LIMIT 1",
        )
        .bind(&source)
        .fetch_optional(&mut *tx)
        .await?;
        let incident = if let Some(id) = existing {
            id
        } else {
            super::incidents::open(&mut tx,&source,Some(server),&format!("服务器 {} 的计划退订日期需要核对",row.get::<String,_>("name")),"info",json!({"record_id":record,"valid_until":row.get::<i64,_>("valid_until"),"reference":row.get::<String,_>("reference"),"lead_secs":row.get::<i64,_>("lead_secs"),"source":"人工费用台账：计划退订生效日期","action_executed":false,"observed_at":now}),now,None).await?;
            sqlx::query_scalar(
                "SELECT id FROM operations_incidents WHERE source_key=$1 AND status<>'resolved'",
            )
            .bind(&source)
            .fetch_one(&mut *tx)
            .await?
        };
        sqlx::query("UPDATE operations_cancellation_reminders SET notified_at=$2,incident_id=$3,last_error=NULL WHERE record_id=$1").bind(record).bind(now).bind(incident).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::PgPool;
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[sqlx::test]
    async fn explicit_reminders_do_not_replay_and_revocation_stops_new_events(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let directory = Directory(std::env::temp_dir().join(format!(
            "sinan-cancellation-reminder-test-{}",
            Uuid::new_v4()
        )));
        std::fs::create_dir(&directory.0)?;
        let state = AppState::new(
            pool.clone(),
            Config {
                database_url: String::new(),
                listen: "127.0.0.1:0".parse()?,
                public_url: "http://127.0.0.1".into(),
                data_dir: directory.0.clone(),
                admin_password: Some("cancellation-reminder-test-password".into()),
            },
        )
        .await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name) VALUES('TEST_ONLY reminder') RETURNING id",
        )
        .fetch_one(&pool)
        .await?;
        let now = now_timestamp();
        let record = Uuid::new_v4();
        let unconfigured = Uuid::new_v4();
        for id in [record, unconfigured] {
            sqlx::query("INSERT INTO fleet_cost_records(id,server_id,kind,amount_minor,currency,occurred_at,valid_until,reference,created_at) VALUES($1,$2,'cancellation',0,'USD',$3,$4,'TEST_ONLY planned cancellation',$3)").bind(id).bind(server).bind(now).bind(now+3600).execute(&pool).await?;
        }
        sqlx::query("INSERT INTO operations_cancellation_reminders(record_id,enabled,lead_secs,configured_by,configured_at) VALUES($1,true,604800,1,$2)").bind(record).bind(now).execute(&pool).await?;
        tick(&state).await?;
        tick(&state).await?;
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM operations_incidents WHERE source_key LIKE 'cancellation:%'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(events, 1);
        sqlx::query(
            "UPDATE operations_incidents SET status='resolved',resolved_at=$1 WHERE source_key=$2",
        )
        .bind(now)
        .bind(format!("cancellation:{record}"))
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE operations_cancellation_reminders SET enabled=false WHERE record_id=$1",
        )
        .bind(record)
        .execute(&pool)
        .await?;
        tick(&state).await?;
        sqlx::query("UPDATE operations_cancellation_reminders SET enabled=true WHERE record_id=$1")
            .bind(record)
            .execute(&pool)
            .await?;
        tick(&state).await?;
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM operations_incidents WHERE source_key LIKE 'cancellation:%'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(events, 1);
        sqlx::query("INSERT INTO operations_cancellation_reminders(record_id,enabled,lead_secs,configured_by,configured_at) VALUES($1,true,604800,1,$2)").bind(unconfigured).bind(now).execute(&pool).await?;
        sqlx::query("UPDATE administrator_profiles SET enabled=false WHERE admin_id=1")
            .execute(&pool)
            .await?;
        tick(&state).await?;
        let active: bool = sqlx::query_scalar(
            "SELECT enabled FROM operations_cancellation_reminders WHERE record_id=$1",
        )
        .bind(unconfigured)
        .fetch_one(&pool)
        .await?;
        assert!(!active);
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM operations_incidents WHERE source_key LIKE 'cancellation:%'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(events, 1);
        Ok(())
    }
}
