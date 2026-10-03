//! Certificate issuance incidents come only from persisted issuer results.
use crate::{
    AppState, control_center,
    error::{ApiError, ApiResult},
};
use axum::http::HeaderMap;
use serde_json::{Value, json};
use sqlx::{PgConnection, Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) fn certificate(source: &str) -> Option<Uuid> {
    source
        .strip_prefix("certificate:")
        .and_then(|value| Uuid::parse_str(value).ok())
}
async fn scope(connection: &mut PgConnection, id: Uuid) -> ApiResult<Vec<i64>> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM network_documents WHERE id=$1 AND kind='certificate')",
    )
    .bind(id)
    .fetch_one(&mut *connection)
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    Ok(sqlx::query_scalar("SELECT DISTINCT server FROM (SELECT (target->>'server_id')::bigint AS server FROM network_documents c CROSS JOIN LATERAL jsonb_array_elements(COALESCE(c.config->'targets','[]'::jsonb)) target WHERE c.id=$1 UNION ALL SELECT (server#>>'{}')::bigint AS server FROM network_documents c JOIN network_documents d ON d.id::text IN (SELECT jsonb_array_elements_text(COALESCE(c.config->'domain_ids','[]'::jsonb))) CROSS JOIN LATERAL jsonb_array_elements(COALESCE(d.config->'server_ids','[]'::jsonb)) server WHERE c.id=$1 AND d.kind='domain') scope WHERE server>0 ORDER BY server")
        .bind(id).fetch_all(connection).await?)
}
fn frozen(evidence: &Value) -> Vec<i64> {
    evidence["server_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_i64)
        .filter(|server| *server > 0)
        .collect()
}
async fn all_scope(state: &AppState, id: Uuid, evidence: &Value) -> ApiResult<Vec<i64>> {
    let mut connection = state.pool.acquire().await?;
    let mut servers = scope(&mut connection, id).await?;
    servers.extend(frozen(evidence));
    servers.sort_unstable();
    servers.dedup();
    Ok(servers)
}
pub(super) async fn access(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    evidence: &Value,
    write: bool,
) -> ApiResult<()> {
    control_center::require_capability(state, headers, "network:read").await?;
    let capability = if write {
        "operations:write"
    } else {
        "operations:read"
    };
    for server in all_scope(state, id, evidence).await? {
        control_center::require_server(state, headers, server, "network:read").await?;
        control_center::require_server(state, headers, server, capability).await?;
    }
    Ok(())
}
pub(super) async fn assignee(
    state: &AppState,
    actor: i64,
    id: Uuid,
    evidence: &Value,
) -> ApiResult<bool> {
    match control_center::require_actor_capability(state, actor, "network:read").await {
        Ok(()) => {}
        Err(ApiError::Forbidden(_)) => return Ok(false),
        Err(error) => return Err(error),
    }
    for server in all_scope(state, id, evidence).await? {
        if !control_center::actor_server_allowed(&state.pool, actor, server, "network:read").await?
            || !control_center::actor_server_allowed(&state.pool, actor, server, "operations:write")
                .await?
        {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(super) async fn suppressed(state: &AppState, evidence: &Value, now: i64) -> ApiResult<bool> {
    for server in frozen(evidence) {
        if super::super::notifications_suppressed(&state.pool, server, now).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) async fn observe(tx: &mut Transaction<'_, Postgres>, now: i64) -> ApiResult<()> {
    let rows = sqlx::query("SELECT j.*,d.config->>'name' AS certificate_name,v.not_before AS version_starts_at,v.not_after AS version_expires_at FROM (SELECT DISTINCT ON(certificate_id) * FROM network_acme_jobs ORDER BY certificate_id,created_at DESC,id DESC) j JOIN network_documents d ON d.id=j.certificate_id LEFT JOIN network_certificate_versions v ON v.id=j.version_id AND v.certificate_id=j.certificate_id WHERE (j.status IN ('failed','unknown') AND NOT EXISTS(SELECT 1 FROM operations_incidents i WHERE i.source_key='certificate:'||j.certificate_id::text AND i.evidence->>'job_id'=j.id::text)) OR (j.status='succeeded' AND j.result->'issued'='true'::jsonb AND j.result->'saved'='true'::jsonb AND v.not_before<=$1 AND v.not_after>$1 AND j.completed_at>0 AND j.completed_at<=$1 AND EXISTS(SELECT 1 FROM operations_incidents i WHERE i.source_key='certificate:'||j.certificate_id::text AND i.status<>'resolved')) ORDER BY j.created_at DESC LIMIT 128")
        .bind(now).fetch_all(&mut **tx).await?;
    for row in rows {
        let id: Uuid = row.get("certificate_id");
        let job: Uuid = row.get("id");
        let status: String = row.get("status");
        let completion: Option<i64> = row.get("completed_at");
        let key = format!("certificate:{id}");
        let result: Value = row.get::<Option<Value>, _>("result").unwrap_or(Value::Null);
        if status == "succeeded"
            && result["issued"] == true
            && result["saved"] == true
            && row.get::<Option<Uuid>, _>("version_id").is_some()
            && row
                .get::<Option<i64>, _>("version_starts_at")
                .is_some_and(|start| start <= now)
            && row
                .get::<Option<i64>, _>("version_expires_at")
                .is_some_and(|expiry| expiry > now)
            && completion.is_some_and(|at| at > 0 && at <= now)
        {
            super::recover(tx,&key,json!({"source":"network_acme_jobs","job_id":job,"certificate_id":id,"issued":true,"saved":true,"deployed":false,"handshake_verified":false,"version_id":row.get::<Option<Uuid>,_>("version_id"),"observed_at":completion}),completion.unwrap_or(now),true).await?;
        } else if ["failed", "unknown"].contains(&status.as_str()) {
            let already: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations_incidents WHERE source_key=$1 AND evidence->>'job_id'=$2)")
                .bind(&key).bind(job.to_string()).fetch_one(&mut **tx).await?;
            if already {
                continue;
            }
            let mut servers = scope(tx, id).await?;
            let previous: Option<Value> = sqlx::query_scalar("SELECT evidence FROM operations_incidents WHERE source_key=$1 AND status<>'resolved'")
                .bind(&key).fetch_optional(&mut **tx).await?;
            if let Some(previous) = previous {
                servers.extend(frozen(&previous));
                servers.sort_unstable();
                servers.dedup();
            }
            let observed = completion.filter(|at| *at > 0 && *at <= now).unwrap_or(now);
            let code = result["error_code"]
                .as_str()
                .unwrap_or("issuer_result_unknown");
            let code: String = code
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '_' | '-'))
                .take(128)
                .collect();
            let code = if code.is_empty() {
                "issuer_result_unknown".to_owned()
            } else {
                code
            };
            let evidence = json!({"source":"network_acme_jobs","certificate_id":id,"job_id":job,"status":status,"error_code":code,
                "server_ids":servers,"tool_version":row.get::<Value,_>("request")["tool_version"],
                "started_at":row.get::<Option<i64>,_>("started_at"),"completed_at":completion,"observed_at":observed,
                "issued":result["issued"].as_bool().map(|value|json!(value)).unwrap_or_else(||json!("unknown")),
                "saved":result["saved"].as_bool().map(|value|json!(value)).unwrap_or_else(||json!("unknown")),
                "cleanup_required":result["cleanup_required"],"automatic_renewal":row.get::<Value,_>("request")["automatic_renewal"]});
            let name: String = row
                .get::<Option<String>, _>("certificate_name")
                .unwrap_or_else(|| id.to_string())
                .chars()
                .take(128)
                .collect();
            let title = format!(
                "证书 {name} 签发或续期{}，请核对来源结果",
                if status == "failed" {
                    "失败"
                } else {
                    "结果未知"
                }
            );
            super::open(
                tx,
                &key,
                servers.first().copied(),
                &title,
                "warning",
                evidence.clone(),
                observed,
                None,
            )
            .await?;
            let incident: Uuid = sqlx::query_scalar(
                "SELECT id FROM operations_incidents WHERE source_key=$1 AND status<>'resolved'",
            )
            .bind(&key)
            .fetch_one(&mut **tx)
            .await?;
            super::note(
                tx,
                incident,
                None,
                "certificate_observation",
                &title,
                evidence,
                observed,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[sqlx::test]
    async fn certificate_visibility_checks_current_frozen_and_token_scopes(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Directory(
            std::env::temp_dir().join(format!("sinan-certificate-scope-{}", Uuid::new_v4())),
        );
        std::fs::create_dir(&directory.0)?;
        let state = AppState::new(
            pool.clone(),
            crate::config::Config {
                database_url: String::new(),
                listen: "127.0.0.1:0".parse()?,
                public_url: "http://127.0.0.1:1".into(),
                data_dir: directory.0.clone(),
                admin_password: Some("TEST_ONLY certificate scope".into()),
            },
        )
        .await?;
        let mut servers = Vec::new();
        for name in ["target", "historical-target"] {
            servers.push(
                sqlx::query_scalar::<_, i64>("INSERT INTO servers(name) VALUES($1) RETURNING id")
                    .bind(name)
                    .fetch_one(&pool)
                    .await?,
            );
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO network_documents(id,kind,config,created_at,updated_at) VALUES($1,'certificate',$2,1,1)")
            .bind(id).bind(json!({"name":"fixture.example.com","targets":[{"server_id":servers[0]}],"domain_ids":[]})).execute(&pool).await?;
        let actor:i64=sqlx::query_scalar("INSERT INTO admins(password_hash) SELECT password_hash FROM admins WHERE id=1 RETURNING id").fetch_one(&pool).await?;
        let caps = json!(["network:read", "operations:read", "operations:write"]);
        sqlx::query("INSERT INTO administrator_profiles(admin_id,login_name,display_name,role,all_servers,capabilities,created_at,updated_at) VALUES($1,$2,'TEST_ONLY certificate','operator',false,$3,0,0)")
            .bind(actor).bind(format!("certificate-{actor}")).bind(&caps).execute(&pool).await?;
        sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
            .bind(actor)
            .bind(servers[0])
            .execute(&pool)
            .await?;
        let session = crate::auth::random_token();
        sqlx::query("INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES($1,$2,$3)")
            .bind(crate::auth::hash_token(&session))
            .bind(actor)
            .bind(sinan_protocol::now_timestamp() + 3600)
            .execute(&pool)
            .await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("sinan_session={session}").parse()?,
        );
        let historical = json!({"server_ids":servers});
        assert!(matches!(
            access(&state, &headers, id, &historical, false).await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(!assignee(&state, actor, id, &historical).await?);
        sqlx::query("INSERT INTO administrator_server_grants(admin_id,server_id) VALUES($1,$2)")
            .bind(actor)
            .bind(servers[1])
            .execute(&pool)
            .await?;
        access(&state, &headers, id, &historical, true).await?;
        assert!(assignee(&state, actor, id, &historical).await?);
        let token = format!("sinan_api_{}", crate::auth::random_token());
        sqlx::query("INSERT INTO management_api_tokens(id,admin_id,token_hash,name,capabilities,server_ids,all_servers,expires_at,created_at) VALUES($1,1,$2,'TEST_ONLY certificate',$3,$4,false,$5,0)")
            .bind(Uuid::new_v4()).bind(crate::auth::hash_token(&token)).bind(&caps).bind(json!([servers[0]])).bind(sinan_protocol::now_timestamp()+3600).execute(&pool).await?;
        let mut token_headers = HeaderMap::new();
        token_headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse()?,
        );
        assert!(matches!(
            access(&state, &token_headers, id, &historical, false).await,
            Err(ApiError::Forbidden(_))
        ));
        sqlx::query("UPDATE network_documents SET config=$2 WHERE id=$1")
            .bind(id)
            .bind(json!({"name":"fixture.example.com","targets":[],"domain_ids":[]}))
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM administrator_server_grants WHERE admin_id=$1 AND server_id=$2")
            .bind(actor)
            .bind(servers[1])
            .execute(&pool)
            .await?;
        assert!(matches!(
            access(&state, &headers, id, &historical, false).await,
            Err(ApiError::Forbidden(_))
        ));
        access(&state, &headers, id, &json!({}), false).await?;
        sqlx::query("UPDATE administrator_profiles SET capabilities=$2 WHERE admin_id=$1")
            .bind(actor)
            .bind(json!(["operations:read", "operations:write"]))
            .execute(&pool)
            .await?;
        assert!(matches!(
            access(&state, &headers, id, &json!({}), false).await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(!assignee(&state, actor, id, &json!({})).await?);
        Ok(())
    }
    #[sqlx::test]
    async fn certificate_scope_includes_every_deployment_and_referenced_domain_server(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let mut ids = Vec::new();
        for name in ["target", "domain-a", "domain-b"] {
            let id: i64 = sqlx::query_scalar("INSERT INTO servers(name) VALUES($1) RETURNING id")
                .bind(name)
                .fetch_one(&pool)
                .await?;
            ids.push(id);
        }
        let domain = Uuid::new_v4();
        sqlx::query("INSERT INTO network_documents(id,kind,config,created_at,updated_at) VALUES($1,'domain',$2,1,1)")
            .bind(domain).bind(json!({"name":"fixture.example.com","server_ids":[ids[1],ids[2]]})).execute(&pool).await?;
        let certificate = Uuid::new_v4();
        sqlx::query("INSERT INTO network_documents(id,kind,config,created_at,updated_at) VALUES($1,'certificate',$2,1,1)")
            .bind(certificate).bind(json!({"name":"fixture.example.com","targets":[{"server_id":ids[0]}],"domain_ids":[domain]})).execute(&pool).await?;
        let mut connection = pool.acquire().await?;
        assert_eq!(scope(&mut connection, certificate).await?, ids);
        assert!(scope(&mut connection, Uuid::new_v4()).await.is_err());
        assert_eq!(
            frozen(&json!({"server_ids":[ids[0],-1,null]})),
            vec![ids[0]]
        );
        Ok(())
    }
    #[sqlx::test]
    async fn failures_unknown_and_success_use_real_issuer_evidence_and_do_not_repeat(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO admins(id,password_hash) VALUES(1,'TEST_ONLY')")
            .execute(&pool)
            .await?;
        let settings = json!({"notification_enabled":true,"webhook":{"enabled":true,"preset":"custom","url":"https://example.invalid/","headers":"{}","body":crate::notifications::webhook::DEFAULT_BODY}});
        sqlx::query("UPDATE panel_settings SET settings=$1 WHERE singleton")
            .bind(settings)
            .execute(&pool)
            .await?;
        let server: i64 = sqlx::query_scalar(
            "INSERT INTO servers(name) VALUES('TEST_ONLY certificate') RETURNING id",
        )
        .fetch_one(&pool)
        .await?;
        let certificate = Uuid::new_v4();
        sqlx::query("INSERT INTO network_documents(id,kind,config,created_at,updated_at) VALUES($1,'certificate',$2,1,1)")
            .bind(certificate).bind(json!({"name":"fixture.example.com","targets":[{"server_id":server}],"domain_ids":[]})).execute(&pool).await?;
        let job = Uuid::new_v4();
        sqlx::query("INSERT INTO network_acme_jobs(id,certificate_id,plan_revision,requested_by,certificate_revision,domain_snapshot,request,status,created_at,completed_at,result) VALUES($1,$2,1,1,1,'[]',$3,'failed',10,20,$4)")
            .bind(job).bind(certificate).bind(json!({"tool_version":"fixture","automatic_renewal":true})).bind(json!({"error_code":"issuer_artifact_invalid","cleanup_required":false})).execute(&pool).await?;
        let mut tx = pool.begin().await?;
        observe(&mut tx, 30).await?;
        observe(&mut tx, 40).await?;
        tx.commit().await?;
        let (count,deliveries):(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM operations_incidents),(SELECT count(*) FROM operations_incident_deliveries)").fetch_one(&pool).await?;
        assert_eq!((count, deliveries), (1, 1));
        let failed_evidence: Value =
            sqlx::query_scalar("SELECT evidence FROM operations_incidents")
                .fetch_one(&pool)
                .await?;
        assert_eq!(failed_evidence["issued"], "unknown");
        assert_eq!(failed_evidence["saved"], "unknown");
        sqlx::query("UPDATE network_acme_jobs SET status='reconciled' WHERE id=$1")
            .bind(job)
            .execute(&pool)
            .await?;
        let mut tx = pool.begin().await?;
        observe(&mut tx, 50).await?;
        tx.commit().await?;
        let status: String = sqlx::query_scalar("SELECT status FROM operations_incidents")
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "open");
        let unknown = Uuid::new_v4();
        sqlx::query("INSERT INTO network_acme_jobs(id,certificate_id,plan_revision,requested_by,certificate_revision,domain_snapshot,request,status,created_at,result) VALUES($1,$2,1,1,1,'[]',$3,'unknown',60,$4)")
            .bind(unknown).bind(certificate).bind(json!({"tool_version":"fixture"})).bind(json!({"error_code":"worker_interrupted","cleanup_required":true})).execute(&pool).await?;
        let mut tx = pool.begin().await?;
        observe(&mut tx, 70).await?;
        tx.commit().await?;
        let status: String = sqlx::query_scalar("SELECT status FROM operations_incidents")
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "open");
        let version = Uuid::new_v4();
        sqlx::query("INSERT INTO network_certificate_versions(id,certificate_id,revision,public_chain,fingerprint,not_before,not_after,created_at) VALUES($1,$2,1,'TEST_ONLY','fixture',1,1000,80)").bind(version).bind(certificate).execute(&pool).await?;
        sqlx::query("UPDATE network_acme_jobs SET status='succeeded',completed_at=90,version_id=$2,result=$3 WHERE id=$1")
            .bind(unknown).bind(version).bind(json!({"issued":true,"saved":true})).execute(&pool).await?;
        sqlx::query("UPDATE network_certificate_versions SET not_after=85 WHERE id=$1")
            .bind(version)
            .execute(&pool)
            .await?;
        let mut tx = pool.begin().await?;
        observe(&mut tx, 100).await?;
        tx.commit().await?;
        let status: String = sqlx::query_scalar("SELECT status FROM operations_incidents")
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "open");
        sqlx::query("UPDATE network_certificate_versions SET not_after=1000 WHERE id=$1")
            .bind(version)
            .execute(&pool)
            .await?;
        sqlx::query("UPDATE network_certificate_versions SET not_before=200 WHERE id=$1")
            .bind(version)
            .execute(&pool)
            .await?;
        let mut tx = pool.begin().await?;
        observe(&mut tx, 100).await?;
        tx.commit().await?;
        let status: String = sqlx::query_scalar("SELECT status FROM operations_incidents")
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "open");
        sqlx::query("UPDATE network_certificate_versions SET not_before=1 WHERE id=$1")
            .bind(version)
            .execute(&pool)
            .await?;
        let mut tx = pool.begin().await?;
        observe(&mut tx, 100).await?;
        tx.commit().await?;
        let status: String = sqlx::query_scalar("SELECT status FROM operations_incidents")
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "resolved");
        let recovery: Value =
            sqlx::query_scalar("SELECT recovery_evidence FROM operations_incidents")
                .fetch_one(&pool)
                .await?;
        assert_eq!(recovery["deployed"], false);
        assert_eq!(recovery["handshake_verified"], false);
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM operations_incident_deliveries WHERE kind='recovery'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(count, 1);
        Ok(())
    }
}
