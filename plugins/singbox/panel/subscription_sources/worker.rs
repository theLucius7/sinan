use super::{
    fetch::{self, FetchConfig, FetchOutcome},
    jobs,
    models::*,
    service, snapshots,
};
use crate::{
    AppState,
    error::ApiResult,
    subscription_parser::{self, FormatHint, PARSER_VERSION},
};
use sinan_protocol::now_timestamp;
use sqlx::{FromRow, PgConnection};
use std::{
    collections::{BTreeSet, HashMap},
    time::Duration,
};
use tokio::{task::JoinSet, time::Instant};
use uuid::Uuid;

pub(super) struct Claim {
    pub job_id: Uuid,
    pub source_id: i64,
    pub settings_revision: i64,
    pub identity_epoch: i64,
    pub parser_version: String,
    pub token: Uuid,
    pub input: SourceInput,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub previous_revision: Option<Uuid>,
    pub work_deadline: Instant,
}

#[derive(FromRow)]
struct QueuedJob {
    id: Uuid,
    source_id: i64,
    settings_revision: i64,
    identity_epoch: i64,
    parser_version: String,
}

async fn expire(connection: &mut PgConnection, local: &[Uuid]) -> ApiResult<()> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT source_id FROM singbox_subscription_source_jobs WHERE status IN ('running','cancelling') AND deadline_at<=$1 AND NOT(id=ANY($2)) ORDER BY source_id")
        .bind(now_timestamp()).bind(local).fetch_all(&mut *connection).await?;
    for source in ids {
        sqlx::query("SELECT id FROM singbox_ordered_subscription_sources WHERE id=$1 FOR UPDATE")
            .bind(source)
            .fetch_one(&mut *connection)
            .await?;
        let jobs: Vec<(Uuid, String, Option<serde_json::Value>, i64, i64)> = sqlx::query_as("SELECT id,status,error,settings_revision,identity_epoch FROM singbox_subscription_source_jobs WHERE source_id=$1 AND status IN ('running','cancelling') AND deadline_at<=$2 AND NOT(id=ANY($3)) FOR UPDATE")
            .bind(source).bind(now_timestamp()).bind(local).fetch_all(&mut *connection).await?;
        for (id, status, saved_error, revision, epoch) in jobs {
            let requested =
                saved_error.and_then(|value| serde_json::from_value::<SourceFailure>(value).ok());
            let (terminal, error) = if status == "cancelling"
                && requested
                    .as_ref()
                    .is_some_and(|error| matches!(error.kind.as_str(), "cancelled" | "superseded"))
            {
                let error = requested.expect("cancellation checked");
                (error.kind.clone(), error)
            } else {
                (
                    "failed".into(),
                    SourceFailure::new(
                        "done",
                        "interrupted",
                        "来源任务中断或超过期限，未替换上次成功结果",
                    ),
                )
            };
            sqlx::query("UPDATE singbox_subscription_source_jobs SET status=$2,stage='done',claim_token=NULL,finished_at=$3,error=$4 WHERE id=$1")
                .bind(id).bind(&terminal).bind(now_timestamp()).bind(serde_json::json!(error)).execute(&mut *connection).await?;
            if terminal == "failed" {
                sqlx::query("UPDATE singbox_ordered_subscription_sources SET last_error=$4 WHERE id=$1 AND settings_revision=$2 AND identity_epoch=$3 AND deleted_at IS NULL AND NOT archived")
                    .bind(source).bind(revision).bind(epoch).bind(serde_json::json!(error)).execute(&mut *connection).await?;
            }
        }
    }
    Ok(())
}

async fn claim_due(state: &AppState, local: &BTreeSet<Uuid>) -> ApiResult<Vec<Claim>> {
    renew(state, local).await?;
    let mut tx = state.pool.begin().await?;
    // This short scheduler lock also bounds workers across panel processes.
    sqlx::query("SELECT pg_advisory_xact_lock(73402903,1)")
        .execute(&mut *tx)
        .await?;
    expire(&mut tx, &local.iter().copied().collect::<Vec<_>>()).await?;
    let due = sqlx::query_as::<_, SourceRow>(&format!("SELECT {SOURCE_COLUMNS} FROM singbox_ordered_subscription_sources WHERE deleted_at IS NULL AND NOT archived AND next_refresh_at<=$1 ORDER BY next_refresh_at,id LIMIT 16 FOR UPDATE SKIP LOCKED"))
        .bind(now_timestamp()).fetch_all(&mut *tx).await?;
    for source in due {
        jobs::enqueue(&mut tx, &source).await?;
    }
    let running: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM singbox_subscription_source_jobs WHERE status IN ('running','cancelling')").fetch_one(&mut *tx).await?;
    let capacity = 4i64
        .saturating_sub(running)
        .min(4i64.saturating_sub(local.len() as i64))
        .max(0);
    let queue = sqlx::query_as::<_, QueuedJob>("SELECT id,source_id,settings_revision,identity_epoch,parser_version FROM singbox_subscription_source_jobs WHERE status='queued' ORDER BY created_at,id LIMIT $1")
        .bind(capacity).fetch_all(&mut *tx).await?;
    let mut claims = Vec::with_capacity(queue.len());
    for job in queue {
        let source = sqlx::query_as::<_, SourceRow>(&format!("SELECT {SOURCE_COLUMNS} FROM singbox_ordered_subscription_sources WHERE id=$1 FOR UPDATE SKIP LOCKED"))
            .bind(job.source_id).fetch_optional(&mut *tx).await?;
        let Some(source) = source else { continue };
        let status: String = sqlx::query_scalar(
            "SELECT status FROM singbox_subscription_source_jobs WHERE id=$1 FOR UPDATE",
        )
        .bind(job.id)
        .fetch_one(&mut *tx)
        .await?;
        if status != "queued" {
            continue;
        }
        if source.deleted_at.is_some()
            || source.archived
            || source.settings_revision != job.settings_revision
            || source.identity_epoch != job.identity_epoch
            || job.parser_version != PARSER_VERSION
        {
            sqlx::query("UPDATE singbox_subscription_source_jobs SET status='superseded',stage='done',finished_at=$2,error=$3 WHERE id=$1")
                .bind(job.id).bind(now_timestamp()).bind(serde_json::json!(SourceFailure::new("done","superseded","任务输入已过期，未更新当前来源"))).execute(&mut *tx).await?;
            if source.deleted_at.is_none() && !source.archived {
                sqlx::query(
                    "UPDATE singbox_ordered_subscription_sources SET next_refresh_at=$2 WHERE id=$1",
                )
                .bind(source.id)
                .bind(now_timestamp())
                .execute(&mut *tx)
                .await?;
            }
            continue;
        }
        let input: SourceInput =
            serde_json::from_value(source.input_config.clone()).map_err(anyhow::Error::from)?;
        let token = Uuid::new_v4();
        let cache_matches = source.conditional_settings_revision == Some(source.settings_revision)
            && source.conditional_identity_epoch == Some(source.identity_epoch)
            && match source.current_success_revision {
                Some(id) => service::revision(&mut tx, id).await?.parser_version == PARSER_VERSION,
                None => false,
            };
        let now = now_timestamp();
        sqlx::query("UPDATE singbox_subscription_source_jobs SET status='running',stage=$2,claim_token=$3,started_at=$4,deadline_at=$5 WHERE id=$1")
            .bind(job.id).bind(if source.kind == "url" { "fetch" } else { "parse" }).bind(token).bind(now).bind(now+45).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE singbox_ordered_subscription_sources SET last_attempt_at=$2 WHERE id=$1",
        )
        .bind(source.id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        claims.push(Claim {
            job_id: job.id,
            source_id: source.id,
            settings_revision: job.settings_revision,
            identity_epoch: job.identity_epoch,
            parser_version: job.parser_version,
            token,
            input,
            etag: cache_matches.then_some(source.conditional_etag).flatten(),
            last_modified: cache_matches
                .then_some(source.conditional_last_modified)
                .flatten(),
            previous_revision: cache_matches
                .then_some(source.current_success_revision)
                .flatten(),
            work_deadline: Instant::now() + Duration::from_secs(30),
        });
    }
    tx.commit().await?;
    Ok(claims)
}

async fn renew(state: &AppState, local: &BTreeSet<Uuid>) -> ApiResult<()> {
    if !local.is_empty() {
        sqlx::query("UPDATE singbox_subscription_source_jobs SET deadline_at=$2 WHERE id=ANY($1) AND status IN ('running','cancelling')")
            .bind(local.iter().copied().collect::<Vec<_>>()).bind(now_timestamp()+45).execute(&state.pool).await?;
    }
    Ok(())
}

async fn interrupted(state: &AppState, claim: &Claim) -> SourceFailure {
    let mut poll = tokio::time::interval(Duration::from_millis(200));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(claim.work_deadline) => return SourceFailure::new("done","timeout","来源任务超过总处理期限，未替换上次成功结果"),
            _ = poll.tick() => {
                let result=tokio::time::timeout_at(claim.work_deadline,
                    sqlx::query_as::<_,(String,Option<Uuid>,Option<serde_json::Value>)>("SELECT status,claim_token,error FROM singbox_subscription_source_jobs WHERE id=$1").bind(claim.job_id).fetch_optional(&state.pool)).await;
                match result {
                    Ok(Ok(Some((status, token, error)))) if status == "running" && token == Some(claim.token) => { let _ = error; }
                    Ok(Ok(Some((_, _, Some(error))))) => return serde_json::from_value(error).unwrap_or_else(|_| SourceFailure::new("done","superseded","任务输入已过期")),
                    Ok(Ok(_)) => return SourceFailure::new("done","superseded","任务输入已过期"),
                    Ok(Err(_)) => return SourceFailure::new("done","database","任务状态暂时不可确认，未更新来源"),
                    Err(_) => return SourceFailure::new("done","timeout","来源任务超过总处理期限，未替换上次成功结果"),
                }
            }
        }
    }
}

async fn stage(state: &AppState, claim: &Claim, value: &str) -> ApiResult<bool> {
    Ok(sqlx::query("UPDATE singbox_subscription_source_jobs SET stage=$3 WHERE id=$1 AND claim_token=$2 AND status='running'")
        .bind(claim.job_id).bind(claim.token).bind(value).execute(&state.pool).await?.rows_affected()==1)
}

async fn process(state: &AppState, claim: Claim) -> ApiResult<()> {
    let fetched = match &claim.input {
        SourceInput::Inline { content } => FetchOutcome::Modified {
            body: content.as_bytes().to_vec(),
            etag: None,
            last_modified: None,
        },
        SourceInput::Url { url, auth_headers } => {
            let config = FetchConfig {
                url: url.clone(),
                auth_headers: auth_headers.clone(),
                etag: claim.etag.clone(),
                last_modified: claim.last_modified.clone(),
            };
            let result = tokio::select! { result=fetch::fetch(&config)=>result, error=interrupted(state,&claim)=>Err(error) };
            match result {
                Ok(value) => value,
                Err(error) => return snapshots::failure(state, &claim, error).await,
            }
        }
    };
    match fetched {
        FetchOutcome::NotModified {
            etag,
            last_modified,
        } => match snapshots::unchanged(state, &claim, etag, last_modified).await {
            Ok(()) => Ok(()),
            Err(_) => {
                snapshots::failure(
                    state,
                    &claim,
                    SourceFailure::new(
                        "store",
                        "database",
                        "来源确认结果未能保存，保留上次成功结果",
                    ),
                )
                .await
            }
        },
        FetchOutcome::Modified {
            body,
            etag,
            last_modified,
        } => {
            if !stage(state, &claim, "parse").await? {
                return snapshots::failure(
                    state,
                    &claim,
                    SourceFailure::new("done", "superseded", "任务已经停止或输入已过期"),
                )
                .await;
            }
            let mut parse = tokio::task::spawn_blocking(move || {
                subscription_parser::parse_subscription(&body, FormatHint::Auto)
            });
            let result = tokio::select! {
                result=&mut parse => result,
                error=interrupted(state,&claim) => {
                    // Dropping a blocking handle does not stop its thread. Keep
                    // the job ownership and worker slot until bounded parsing ends.
                    let _=sqlx::query("UPDATE singbox_subscription_source_jobs SET status='cancelling',error=$3 WHERE id=$1 AND claim_token=$2 AND status='running'")
                        .bind(claim.job_id).bind(claim.token).bind(serde_json::json!(error)).execute(&state.pool).await;
                    let _ = parse.await;
                    return snapshots::failure(state,&claim,error).await;
                }
            };
            let parsed = match result {
                Ok(Ok(parsed)) => parsed,
                Ok(Err(error)) => {
                    return snapshots::failure(
                        state,
                        &claim,
                        SourceFailure::new("parse", error.code, error.message),
                    )
                    .await;
                }
                Err(_) => {
                    return snapshots::failure(
                        state,
                        &claim,
                        SourceFailure::new("parse", "interrupted", "解析任务中断，未更新来源"),
                    )
                    .await;
                }
            };
            if !stage(state, &claim, "store").await? {
                return snapshots::failure(
                    state,
                    &claim,
                    SourceFailure::new("done", "superseded", "任务已经停止或输入已过期"),
                )
                .await;
            }
            match snapshots::save(state, &claim, parsed, etag, last_modified).await {
                Ok(()) => Ok(()),
                Err(_) => {
                    snapshots::failure(
                        state,
                        &claim,
                        SourceFailure::new(
                            "store",
                            "database",
                            "解析结果未能保存，保留上次成功结果",
                        ),
                    )
                    .await
                }
            }
        }
    }
}

/// A bounded poll is also used by embedders; it has no network-policy override.
pub async fn run_once(state: &AppState) -> ApiResult<()> {
    let claims = claim_due(state, &BTreeSet::new()).await?;
    let mut workers = JoinSet::new();
    let mut local = BTreeSet::new();
    let mut task_ids = HashMap::new();
    let mut first_error = None;
    for claim in claims {
        local.insert(claim.job_id);
        let id = claim.job_id;
        let state = state.clone();
        let handle = workers.spawn(async move { process(&state, claim).await });
        task_ids.insert(handle.id(), id);
    }
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !workers.is_empty() {
        tokio::select! {
            result=workers.join_next_with_id()=>match result {
                Some(Ok((task_id, result))) => {
                    if let Some(id) = task_ids.remove(&task_id) {
                        local.remove(&id);
                    }
                    if let Err(error) = result {
                        first_error.get_or_insert(error);
                    }
                },
                Some(Err(error))=>{if let Some(id)=task_ids.remove(&error.id()){local.remove(&id);}first_error.get_or_insert(crate::error::ApiError::Internal(error.into()));},
                None=>{},
            },
            _=poll.tick()=>{if let Err(error)=renew(state,&local).await{first_error.get_or_insert(error);}},
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub async fn run(state: AppState) {
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut workers = JoinSet::new();
    let mut local = BTreeSet::new();
    let mut task_ids = HashMap::new();
    loop {
        tokio::select! {
            _=poll.tick()=>match claim_due(&state,&local).await {
                Ok(claims)=>for claim in claims { local.insert(claim.job_id);let id=claim.job_id; let state=state.clone(); let handle=workers.spawn(async move { process(&state,claim).await });task_ids.insert(handle.id(),id); },
                Err(_)=>tracing::error!("subscription source scheduler failed; pending work retained"),
            },
            result=workers.join_next_with_id(), if !workers.is_empty()=>match result {
                Some(Ok((task_id,result)))=>{if let Some(id)=task_ids.remove(&task_id){local.remove(&id);if result.is_err(){tracing::error!(job_id=%id,"subscription source task persistence failed; lease retained");}}},
                Some(Err(error))=>{if let Some(id)=task_ids.remove(&error.id()){local.remove(&id);}tracing::error!("subscription source worker interrupted; lease retained");},
                None=>{},
            }
        }
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
