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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub tool_version: String,
    pub credential_id: Uuid,
    pub email: String,
    pub staging: bool,
    pub terms_accepted: bool,
    pub license_accepted: bool,
    pub automatic_renewal: bool,
    pub renew_before_days: u32,
}
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/network-configuration/certificates/{id}/acme-plan",
            get(plan).put(save),
        )
        .route(
            "/api/network-configuration/certificates/{id}/issue",
            post(issue),
        )
        .route(
            "/api/network-configuration/certificates/{id}/issuance",
            get(jobs),
        )
}

async fn permission(state: &AppState, headers: &HeaderMap, id: Uuid, write: bool) -> ApiResult<()> {
    let config = documents::configuration(&documents::load(state, id).await?)?;
    if !matches!(config, Configuration::Certificate { .. }) {
        return Err(ApiError::BadRequest("请选择证书台账".into()));
    }
    documents::access(state, headers, &config, write).await?;
    if write {
        let Configuration::Certificate {
            renewal: super::models::RenewalPolicy::Dns01 { ddns_rule_id, .. },
            ..
        } = config
        else {
            return Err(ApiError::Conflict(
                "请先配置DNS-01续期方式与明确的签发维护方".into(),
            ));
        };
        let server: i64 = sqlx::query_scalar("SELECT server_id FROM ddns_rules WHERE id=$1")
            .bind(ddns_rule_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
        crate::control_center::require_server(state, headers, server, "dns:write").await?;
        crate::control_center::require_recent_proof(state, headers).await?;
    }
    Ok(())
}
async fn plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    permission(&state, &headers, id, false).await?;
    let value:Option<Value>=sqlx::query_scalar("SELECT jsonb_build_object('config',config,'revision',revision,'next_run_at',next_run_at,'status',status,'updated_at',updated_at) FROM network_acme_plans WHERE certificate_id=$1").bind(id).fetch_optional(&state.pool).await?;
    Ok(Json(
        json!({"plan":value,"tool":"lego","license":"MIT","tool_source":"https://github.com/go-acme/lego","tool_supply":"signed_release_inventory","deployment":"explicit_maintenance_owner","private_key":"encrypted_credential_reference"}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    config: Plan,
    revision: Option<i64>,
}
async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Save>,
) -> ApiResult<Json<Value>> {
    permission(&state, &headers, id, true).await?;
    let actor = crate::control_center::require_capability(&state, &headers, "dns:write").await?;
    if !sinan_protocol::release::safe_component(&input.config.tool_version)
        || input.config.tool_version == "latest"
        || input.config.email.len() > 254
        || !input.config.email.contains('@')
        || input.config.email.chars().any(char::is_control)
        || !input.config.terms_accepted
        || !input.config.license_accepted
        || !(7..=60).contains(&input.config.renew_before_days)
    {
        return Err(ApiError::BadRequest(
            "请选择固定工具版本、有效邮箱，确认签发条款与MIT许可；续期阈值为7–60天".into(),
        ));
    }
    // Resolve once before saving so a disabled or undecryptable credential cannot be scheduled.
    let secret = crate::control_center::credentials::resolve_reference(
        &state,
        input.config.credential_id,
        "dns",
        "acme-plan",
    )
    .await?;
    if secret
        .get("provider")
        .is_some_and(|value| value.as_str() != Some("cloudflare"))
        || secret["api_token"]
            .as_str()
            .is_none_or(|value| value.is_empty())
    {
        return Err(ApiError::BadRequest(
            "当前DNS-01执行器需Cloudflare DNS凭据及api_token".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    let previous: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM network_acme_plans WHERE certificate_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if previous != input.revision {
        return Err(ApiError::Conflict("签发计划版本已改变".into()));
    }
    let now = sinan_protocol::now_timestamp();
    if previous.is_some() {
        sqlx::query("UPDATE network_acme_plans SET config=$2,revision=revision+1,next_run_at=$3,status='pending',updated_at=$3,requested_by=$4 WHERE certificate_id=$1").bind(id).bind(json!(input.config)).bind(now).bind(actor).execute(&mut *tx).await?;
    } else {
        sqlx::query("INSERT INTO network_acme_plans(certificate_id,config,next_run_at,updated_at,requested_by) VALUES($1,$2,$3,$3,$4)").bind(id).bind(json!(input.config)).bind(now).bind(actor).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"saved":true,"execution":"awaiting_worker","revision":previous.unwrap_or(0)+1}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    confirmed: bool,
    remote_reconciled: bool,
}
async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Issue>,
) -> ApiResult<Json<Value>> {
    permission(&state, &headers, id, true).await?;
    let actor = crate::control_center::require_capability(&state, &headers, "dns:write").await?;
    if !input.confirmed {
        return Err(ApiError::BadRequest(
            "签发将访问Cloudflare和所选ACME服务，请明确确认".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    let plan = sqlx::query(
        "SELECT revision,config FROM network_acme_plans WHERE certificate_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if input.remote_reconciled {
        sqlx::query("UPDATE network_acme_jobs SET status='reconciled',completed_at=$2 WHERE certificate_id=$1 AND status='unknown'").bind(id).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    }
    let job = queue(&mut tx, id, actor, plan.get("revision"), plan.get("config")).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"operation_id":job,"status":"queued","issued":false,"saved":false,"deployed":false,"handshake_verified":false}),
    ))
}
async fn jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<Value>>> {
    permission(&state, &headers, id, false).await?;
    Ok(Json(sqlx::query_scalar("SELECT jsonb_build_object('id',id,'status',status,'created_at',created_at,'started_at',started_at,'completed_at',completed_at,'result',result,'version_id',version_id,'private_key_reference',key_secret_ref) FROM network_acme_jobs WHERE certificate_id=$1 ORDER BY created_at DESC LIMIT 100").bind(id).fetch_all(&state.pool).await?))
}

async fn queue(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    certificate: Uuid,
    actor: i64,
    revision: i64,
    config: Value,
) -> ApiResult<Uuid> {
    let id = Uuid::new_v4();
    let document =
        sqlx::query("SELECT revision,config FROM network_documents WHERE id=$1 FOR SHARE")
            .bind(certificate)
            .fetch_one(&mut **tx)
            .await?;
    let Configuration::Certificate { domain_ids, .. } =
        serde_json::from_value(document.get("config")).map_err(anyhow::Error::from)?
    else {
        return Err(ApiError::Conflict("证书台账类型已改变".into()));
    };
    let mut domains = Vec::new();
    for domain in domain_ids {
        let row=sqlx::query("SELECT revision,config->>'name' AS name FROM network_documents WHERE id=$1 AND kind='domain' FOR SHARE").bind(domain).fetch_one(&mut **tx).await?;
        domains.push(json!({"id":domain,"revision":row.get::<i64,_>("revision"),"name":row.get::<String,_>("name")}));
    }
    let result=sqlx::query("INSERT INTO network_acme_jobs(id,certificate_id,requested_by,certificate_revision,domain_snapshot,plan_revision,request,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'queued',$8)").bind(id).bind(certificate).bind(actor).bind(document.get::<i64,_>("revision")).bind(json!(domains)).bind(revision).bind(config).bind(sinan_protocol::now_timestamp()).execute(&mut **tx).await;
    if result.as_ref().is_err_and(|error| {
        error
            .as_database_error()
            .is_some_and(|value| value.is_unique_violation())
    }) {
        return Err(ApiError::Conflict(
            "存在排队、执行或未知结果的签发；先核对远端，避免自动重复下单".into(),
        ));
    }
    result?;
    Ok(id)
}

pub(super) async fn run(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tick.tick().await;
        match iteration(&state).await {
            Ok(()) => {
                let _=crate::control_center::system::heartbeat(&state.pool,"network-certificates","healthy",json!({"scope":"dispatcher","iteration":"completed","certificate_results":"issuance_history"})).await;
            }
            Err(error) => {
                let _ = crate::control_center::system::heartbeat(
                    &state.pool,
                    "network-certificates",
                    "failed",
                    json!({"scope":"dispatcher","error":"iteration_failed"}),
                )
                .await;
                tracing::warn!(error=%error,"certificate worker iteration failed");
            }
        }
    }
}
async fn iteration(state: &AppState) -> ApiResult<()> {
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE network_acme_jobs SET status='unknown',result=jsonb_build_object('error_code','worker_interrupted','cleanup_required',true) WHERE status='running' AND started_at<$1").bind(now-900).execute(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    let plans=sqlx::query("SELECT certificate_id,requested_by,revision,config FROM network_acme_plans p WHERE (config->>'automatic_renewal')::boolean AND next_run_at<=$1 AND NOT EXISTS(SELECT 1 FROM network_acme_jobs j WHERE j.certificate_id=p.certificate_id AND j.status IN ('queued','running','unknown')) AND NOT EXISTS(SELECT 1 FROM network_documents d JOIN network_certificate_versions v ON v.id=d.active_version WHERE d.id=p.certificate_id AND v.not_after>$1+86400*(p.config->>'renew_before_days')::bigint) LIMIT 8 FOR UPDATE OF p SKIP LOCKED").bind(now).fetch_all(&mut *tx).await?;
    for plan in plans {
        queue(
            &mut tx,
            plan.get("certificate_id"),
            plan.get("requested_by"),
            plan.get("revision"),
            plan.get("config"),
        )
        .await?;
    }
    let job=sqlx::query("UPDATE network_acme_jobs SET status='running',started_at=$1 WHERE id=(SELECT id FROM network_acme_jobs WHERE status='queued' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,certificate_id,requested_by,plan_revision,request").bind(now).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    let Some(job) = job else {
        return Ok(());
    };
    let id: Uuid = job.get("id");
    let certificate: Uuid = job.get("certificate_id");
    let plan: Plan = serde_json::from_value(job.get("request")).map_err(anyhow::Error::from)?;
    let execution = super::acme_executor::execute(
        state,
        id,
        certificate,
        &plan,
        job.get("plan_revision"),
        job.get("requested_by"),
    );
    tokio::pin!(execution);
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(30));
    let result = loop {
        tokio::select! {value=&mut execution=>break value,_=heartbeat.tick()=>{let _=crate::control_center::system::heartbeat(&state.pool,"network-certificates","healthy",json!({"scope":"dispatcher","phase":"processing_job","job_id":id,"certificate_issued":"pending_job_result"})).await;}}
    };
    let (status, value) = match result {
        Ok(value) => ("succeeded", value),
        Err(error) => {
            let code = error.to_string();
            let before_execution = matches!(
                error,
                ApiError::NotFound | ApiError::Unauthorized | ApiError::Forbidden(_)
            ) || matches!(
                code.as_str(),
                "acme_executor_requires_unix"
                    | "certificate_configuration_missing"
                    | "issuance_plan_changed"
                    | "issuance_scope_changed"
                    | "certificate_domain_missing"
                    | "cloudflare_dns_token_missing"
                    | "unsupported_issuer_platform"
                    | "release_trust_root_missing"
                    | "issuer_signature_invalid"
                    | "issuer_platform_artifact_missing"
                    | "issuer_artifact_invalid"
                    | "issuer_work_directory_unavailable"
                    | "issuer_spawn_failed"
                    | "issuer_account_material_invalid"
                    | "issuer_account_path_invalid"
            );
            (
                if before_execution {
                    "failed"
                } else {
                    "unknown"
                },
                json!({"error_code":code,"issued":if before_execution{json!(false)}else{json!("unknown")},"saved":false,"deployed":false,"cleanup_required":!before_execution}),
            )
        }
    };
    sqlx::query("UPDATE network_acme_jobs SET status=$2,result=$3,completed_at=$4 WHERE id=$1 AND status='running'").bind(id).bind(status).bind(value).bind(sinan_protocol::now_timestamp()).execute(&state.pool).await?;
    sqlx::query("UPDATE network_acme_plans SET next_run_at=$2,status=$3,updated_at=$4 WHERE certificate_id=$1").bind(certificate).bind(now+86400).bind(status).bind(now).execute(&state.pool).await?;
    Ok(())
}
