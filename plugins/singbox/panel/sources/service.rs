use super::{
    fetch,
    model::{JOB_COLUMNS, Job},
    parse::{self, ImportError, PARSER_VERSION, ParsedBatch},
};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgPool};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

const SCHEDULER_LOCK: i64 = 831_240_051;

pub(super) async fn queue(pool: &PgPool, source_id: i64) -> ApiResult<Job> {
    let mut tx = pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    let job = queue_on(&mut tx, source_id).await?;
    tx.commit().await?;
    Ok(job)
}

pub(super) async fn queue_on(connection: &mut PgConnection, source_id: i64) -> ApiResult<Job> {
    let (revision, epoch, archived): (i64, i64, bool) = sqlx::query_as("SELECT settings_revision,identity_epoch,archived FROM singbox_subscription_sources WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(source_id).fetch_optional(&mut *connection).await?.ok_or(ApiError::NotFound)?;
    if archived {
        return Err(ApiError::Conflict("来源已归档，请先恢复来源".into()));
    }
    let now = sinan_protocol::now_timestamp();
    sqlx::query("UPDATE singbox_source_jobs SET state='superseded',phase='finished',finished_at=$2 WHERE source_id=$1 AND state IN ('queued','running') AND (settings_revision<>$3 OR identity_epoch<>$4 OR parser_version<>$5)")
        .bind(source_id).bind(now).bind(revision).bind(epoch).bind(PARSER_VERSION).execute(&mut *connection).await?;
    if let Some(job) = sqlx::query_as::<_, Job>(&format!("SELECT {JOB_COLUMNS} FROM singbox_source_jobs WHERE source_id=$1 AND state IN ('queued','running')"))
        .bind(source_id).fetch_optional(&mut *connection).await? {
        return Ok(job);
    }
    let job = sqlx::query_as(&format!("INSERT INTO singbox_source_jobs(id,source_id,settings_revision,identity_epoch,parser_version,state,phase,created_at) VALUES($1,$2,$3,$4,$5,'queued','queued',$6) RETURNING {JOB_COLUMNS}"))
        .bind(Uuid::new_v4()).bind(source_id).bind(revision).bind(epoch).bind(PARSER_VERSION).bind(now).fetch_one(&mut *connection).await?;
    Ok(job)
}

pub(super) fn kick(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = drain(&state).await {
            tracing::warn!(error = %error, "subscription job scheduler failed");
        }
    });
}

pub async fn refresh_due(state: &AppState) -> anyhow::Result<()> {
    let now = sinan_protocol::now_timestamp();
    sqlx::query("DELETE FROM singbox_source_previews WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.pool)
        .await?;
    // A crashed worker cannot retain a running slot indefinitely. Results still
    // require both the source revision and the live job state at commit.
    let mut tx = state.pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    sqlx::query("UPDATE singbox_subscription_sources s SET last_error='worker_interrupted' FROM singbox_source_jobs j WHERE s.id=j.source_id AND s.settings_revision=j.settings_revision AND s.identity_epoch=j.identity_epoch AND ((j.state='running' AND j.lease_expires_at<$1) OR (j.state IN ('queued','running') AND j.parser_version<>$2))")
        .bind(now).bind(PARSER_VERSION).execute(&mut *tx).await?;
    sqlx::query("UPDATE singbox_source_jobs SET state='failed',phase='finished',error_code='worker_interrupted',finished_at=$1 WHERE (state='running' AND lease_expires_at<$1) OR (state IN ('queued','running') AND parser_version<>$2)")
        .bind(now).bind(PARSER_VERSION).execute(&mut *tx).await?;
    tx.commit().await?;
    let due: Vec<i64> = sqlx::query_scalar("SELECT id FROM singbox_subscription_sources s WHERE kind='url' AND auto_refresh AND NOT archived AND deleted_at IS NULL AND COALESCE(next_refresh_at,0)<=$1 AND NOT EXISTS(SELECT 1 FROM singbox_source_jobs j WHERE j.source_id=s.id AND j.state IN ('queued','running')) ORDER BY next_refresh_at NULLS FIRST,id LIMIT 16")
        .bind(now).fetch_all(&state.pool).await?;
    for id in due {
        if let Err(error) = queue(&state.pool, id).await
            && !matches!(error, ApiError::NotFound | ApiError::Conflict(_))
        {
            return Err(error.into());
        }
    }
    drain(state).await?;
    Ok(())
}

#[derive(FromRow)]
struct Input {
    id: Uuid,
    source_id: i64,
    settings_revision: i64,
    identity_epoch: i64,
    kind: String,
    secret_url: Option<String>,
    secret_authorization: Option<String>,
    secret_content: Option<String>,
    current_revision_id: Option<i64>,
    etag: Option<String>,
    last_modified: Option<String>,
    cache_valid: bool,
    user_agent: String,
}

async fn claim(pool: &PgPool) -> ApiResult<Option<Input>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SCHEDULER_LOCK)
        .execute(&mut *tx)
        .await?;
    let running: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM singbox_source_jobs WHERE state='running'")
            .fetch_one(&mut *tx)
            .await?;
    if running >= 4 {
        return Ok(None);
    }
    let input: Option<Input> = sqlx::query_as("SELECT j.id,j.source_id,j.settings_revision,j.identity_epoch,s.kind,s.secret_url,s.secret_authorization,s.secret_content,s.user_agent,s.current_revision_id,s.etag,s.last_modified,COALESCE(s.cache_settings_revision=j.settings_revision AND s.cache_identity_epoch=j.identity_epoch AND r.parser_version=j.parser_version,FALSE) AS cache_valid FROM singbox_source_jobs j JOIN singbox_subscription_sources s ON s.id=j.source_id LEFT JOIN singbox_source_revisions r ON r.id=s.current_revision_id WHERE j.state='queued' AND NOT s.archived AND s.deleted_at IS NULL AND j.settings_revision=s.settings_revision AND j.identity_epoch=s.identity_epoch AND j.parser_version=$1 ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF j,s SKIP LOCKED")
        .bind(PARSER_VERSION).fetch_optional(&mut *tx).await?;
    if let Some(input) = &input {
        let now = sinan_protocol::now_timestamp();
        sqlx::query("UPDATE singbox_source_jobs SET state='running',phase=$2,started_at=$3,lease_expires_at=$3+90 WHERE id=$1")
            .bind(input.id).bind(if input.kind == "url" { "downloading" } else { "parsing" }).bind(now).execute(&mut *tx).await?;
        sqlx::query("UPDATE singbox_subscription_sources SET last_attempt_at=$2,next_refresh_at=CASE WHEN kind='url' AND auto_refresh THEN $2+refresh_interval_seconds ELSE NULL END WHERE id=$1")
            .bind(input.source_id).bind(now).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(input)
}

async fn drain(state: &AppState) -> ApiResult<()> {
    for _ in 0..4 {
        let Ok(permit) = parse::try_admit() else {
            break;
        };
        let Some(input) = claim(&state.pool).await? else {
            break;
        };
        let pool = state.pool.clone();
        tokio::spawn(async move {
            let source_id = input.source_id;
            let job_id = input.id;
            let result = tokio::select! {
                result = run(&pool, &input, permit) => result,
                _ = wait_for_cancellation(&pool, input.id) => Ok(()),
            };
            if let Err(error) = result {
                // Only categorical errors are persisted or logged; reqwest and
                // parser diagnostics may contain subscription credentials.
                let code = match error {
                    WorkerError::Import(error) => error.0,
                    WorkerError::Database => "storage_failed",
                };
                if fail(&pool, &input, code).await.is_err() {
                    tracing::warn!(source_id, %job_id, "subscription failure could not be persisted");
                }
            }
        });
    }
    Ok(())
}

async fn wait_for_cancellation(pool: &PgPool, job_id: Uuid) {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM singbox_source_jobs WHERE id=$1 AND state='running')",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        {
            Ok(true) => {}
            _ => return,
        }
    }
}

#[derive(Debug)]
enum WorkerError {
    Import(ImportError),
    Database,
}
impl From<ImportError> for WorkerError {
    fn from(value: ImportError) -> Self {
        Self::Import(value)
    }
}
impl From<sqlx::Error> for WorkerError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}
impl From<ApiError> for WorkerError {
    fn from(_: ApiError) -> Self {
        Self::Database
    }
}

async fn run(
    pool: &PgPool,
    input: &Input,
    permit: OwnedSemaphorePermit,
) -> Result<(), WorkerError> {
    let result = if input.kind == "url" {
        fetch::download(
            input
                .secret_url
                .as_deref()
                .ok_or(ImportError("invalid_source_settings"))?,
            input.secret_authorization.as_deref(),
            if input.cache_valid {
                input.etag.as_deref()
            } else {
                None
            },
            if input.cache_valid {
                input.last_modified.as_deref()
            } else {
                None
            },
            &input.user_agent,
        )
        .await?
    } else {
        fetch::FetchResult {
            body: Some(
                input
                    .secret_content
                    .as_deref()
                    .ok_or(ImportError("invalid_source_settings"))?
                    .as_bytes()
                    .to_vec(),
            ),
            etag: None,
            last_modified: None,
            traffic: None,
        }
    };
    let (parsed, _permit) = if let Some(body) = result.body {
        sqlx::query(
            "UPDATE singbox_source_jobs SET phase='parsing' WHERE id=$1 AND state='running'",
        )
        .bind(input.id)
        .execute(pool)
        .await?;
        let (_body, body_sha256, batch, permit) = parse::admitted_parse(body, permit).await?;
        (Some((body_sha256, batch)), permit)
    } else {
        (None, permit)
    };
    commit_result(
        pool,
        input,
        parsed,
        result.etag,
        result.last_modified,
        result.traffic,
    )
    .await
}

#[cfg(test)]
async fn commit(
    pool: &PgPool,
    input: &Input,
    parsed: Option<(String, ParsedBatch)>,
    etag: Option<String>,
    last_modified: Option<String>,
) -> Result<(), WorkerError> {
    commit_result(pool, input, parsed, etag, last_modified, None).await
}

async fn commit_result(
    pool: &PgPool,
    input: &Input,
    parsed: Option<(String, ParsedBatch)>,
    etag: Option<String>,
    last_modified: Option<String>,
    traffic: Option<Value>,
) -> Result<(), WorkerError> {
    let mut tx = pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    let active: Option<bool> = sqlx::query_scalar("SELECT TRUE FROM singbox_subscription_sources s JOIN singbox_source_jobs j ON j.source_id=s.id WHERE s.id=$1 AND s.settings_revision=$2 AND s.identity_epoch=$3 AND NOT s.archived AND s.deleted_at IS NULL AND j.id=$4 AND j.state='running' AND j.parser_version=$5 FOR UPDATE OF s,j")
        .bind(input.source_id).bind(input.settings_revision).bind(input.identity_epoch).bind(input.id).bind(PARSER_VERSION).fetch_optional(&mut *tx).await?;
    if active.is_none() {
        tx.rollback().await?;
        return Ok(());
    }
    // Source writes use the same topology lock, so the predicate remains true
    // until the transaction commits, including cancellation and archival.
    let now = sinan_protocol::now_timestamp();
    let not_modified = parsed.is_none();
    let revision_id = if let Some((body_sha256, batch)) = parsed {
        super::revisions::save_on(
            &mut tx,
            input.source_id,
            input.settings_revision,
            input.identity_epoch,
            &body_sha256,
            batch,
            now,
        )
        .await?
    } else {
        if !input.cache_valid {
            return Err(ImportError("unexpected_not_modified").into());
        }
        input
            .current_revision_id
            .ok_or(ImportError("unexpected_not_modified"))?
    };
    super::revisions::save_traffic_on(&mut tx, input.source_id, traffic, now).await?;
    if not_modified {
        sqlx::query("UPDATE singbox_subscription_sources SET changes=jsonb_build_object('added',0,'updated',0,'missing',0,'unsupported',(SELECT unsupported_count FROM singbox_source_revisions WHERE id=$2)) WHERE id=$1")
            .bind(input.source_id).bind(revision_id).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE singbox_subscription_sources SET current_revision_id=$2,last_success_at=$3,last_error=NULL,etag=$4,last_modified=$5,cache_settings_revision=$6,cache_identity_epoch=$7 WHERE id=$1")
        .bind(input.source_id).bind(revision_id).bind(now).bind(etag.or_else(|| not_modified.then(|| input.etag.clone()).flatten())).bind(last_modified.or_else(|| not_modified.then(|| input.last_modified.clone()).flatten())).bind(input.settings_revision).bind(input.identity_epoch).execute(&mut *tx).await?;
    sqlx::query("UPDATE singbox_source_jobs SET state='succeeded',phase='finished',result_revision_id=$2,finished_at=$3 WHERE id=$1 AND state='running'")
        .bind(input.id).bind(revision_id).bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn fail(pool: &PgPool, input: &Input, code: &str) -> ApiResult<()> {
    let mut tx = pool.begin().await?;
    super::super::entitlements::lock(&mut tx).await?;
    let result = sqlx::query("UPDATE singbox_source_jobs SET state='failed',phase='finished',error_code=$2,finished_at=$3 WHERE id=$1 AND state='running'")
        .bind(input.id).bind(code).bind(sinan_protocol::now_timestamp()).execute(&mut *tx).await?;
    if result.rows_affected() == 1 {
        sqlx::query("UPDATE singbox_subscription_sources SET last_error=$2 WHERE id=$1 AND settings_revision=$3 AND identity_epoch=$4")
            .bind(input.source_id).bind(code).bind(input.settings_revision).bind(input.identity_epoch).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};

    async fn fixture(pool: &PgPool) -> Result<i64> {
        Ok(sqlx::query_scalar("INSERT INTO singbox_subscription_sources(name,kind,secret_content,created_at) VALUES('fixture','inline','http://proxy.example.com:443',0) RETURNING id").fetch_one(pool).await?)
    }

    #[sqlx::test(migrations = "../../../crates/panel/migrations")]
    async fn successful_fetch_metadata_updates_atomically_and_failure_retains_cache(
        pool: PgPool,
    ) -> Result<()> {
        let source = fixture(&pool).await?;
        queue(&pool, source).await?;
        let input = claim(&pool).await?.context("claim")?;
        let body = b"http://proxy.example.com:443#fixture";
        commit_result(
            &pool,
            &input,
            Some((parse::digest(body), parse::parse(body)?)),
            Some("test-etag".into()),
            None,
            Some(serde_json::json!({"download":12,"total":100})),
        )
        .await
        .map_err(|_| anyhow::anyhow!("first metadata commit"))?;
        let first = super::super::model::get_on(&pool, source).await?;
        ensure!(first.traffic["download"] == 12 && first.traffic["updated_at"].is_i64());
        ensure!(
            first.changes == serde_json::json!({"added":1,"updated":0,"missing":0,"unsupported":0})
        );
        queue(&pool, source).await?;
        let unchanged = claim(&pool).await?.context("unchanged claim")?;
        ensure!(unchanged.cache_valid);
        commit_result(
            &pool,
            &unchanged,
            None,
            None,
            None,
            Some(serde_json::json!({"download":20,"total":100})),
        )
        .await
        .map_err(|_| anyhow::anyhow!("304 metadata commit"))?;
        let cached = super::super::model::get_on(&pool, source).await?;
        ensure!(
            cached.traffic["download"] == 20
                && cached.current_revision_id == first.current_revision_id
        );
        ensure!(
            cached.changes
                == serde_json::json!({"added":0,"updated":0,"missing":0,"unsupported":0})
        );
        queue(&pool, source).await?;
        let failed = claim(&pool).await?.context("failed claim")?;
        fail(&pool, &failed, "download_failed").await?;
        let retained = super::super::model::get_on(&pool, source).await?;
        ensure!(
            retained.stale
                && retained.traffic == cached.traffic
                && retained.current_revision_id == cached.current_revision_id
        );
        Ok(())
    }

    #[sqlx::test(migrations = "../../../crates/panel/migrations")]
    async fn concurrent_refreshes_share_one_job_and_global_claims_are_bounded(
        pool: PgPool,
    ) -> Result<()> {
        let source = fixture(&pool).await?;
        let (first, second) = tokio::join!(queue(&pool, source), queue(&pool, source));
        ensure!(first?.id == second?.id);
        for _ in 0..4 {
            let id = fixture(&pool).await?;
            queue(&pool, id).await?;
        }
        for _ in 0..4 {
            ensure!(claim(&pool).await?.is_some());
        }
        ensure!(claim(&pool).await?.is_none());
        let running: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM singbox_source_jobs WHERE state='running'")
                .fetch_one(&pool)
                .await?;
        ensure!(running == 4);
        Ok(())
    }

    #[sqlx::test(migrations = "../../../crates/panel/migrations")]
    async fn stale_cancelled_and_archived_jobs_never_commit_downloaded_content(
        pool: PgPool,
    ) -> Result<()> {
        for action in ["revision", "epoch", "archive", "cancel"] {
            let source = fixture(&pool).await?;
            let job = queue(&pool, source).await?;
            let input = claim(&pool).await?.context("claimed job")?;
            match action {
                "revision" => {
                    sqlx::query("UPDATE singbox_subscription_sources SET settings_revision=settings_revision+1 WHERE id=$1").bind(source).execute(&pool).await?;
                }
                "epoch" => {
                    sqlx::query("UPDATE singbox_subscription_sources SET identity_epoch=identity_epoch+1 WHERE id=$1").bind(source).execute(&pool).await?;
                }
                "archive" => {
                    sqlx::query(
                        "UPDATE singbox_subscription_sources SET archived=TRUE WHERE id=$1",
                    )
                    .bind(source)
                    .execute(&pool)
                    .await?;
                }
                _ => {
                    sqlx::query("UPDATE singbox_source_jobs SET state='cancelled' WHERE id=$1")
                        .bind(job.id)
                        .execute(&pool)
                        .await?;
                }
            }
            let bytes = b"http://proxy.example.com:443";
            commit(
                &pool,
                &input,
                Some((parse::digest(bytes), parse::parse(bytes)?)),
                None,
                None,
            )
            .await
            .map_err(|_| anyhow::anyhow!("commit fixture"))?;
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM singbox_source_revisions WHERE source_id=$1",
            )
            .bind(source)
            .fetch_one(&pool)
            .await?;
            ensure!(count == 0, "late result committed after {action}");
            sqlx::query("UPDATE singbox_source_jobs SET state='superseded' WHERE id=$1")
                .bind(job.id)
                .execute(&pool)
                .await?;
        }
        Ok(())
    }

    #[sqlx::test(migrations = "../../../crates/panel/migrations")]
    async fn conditional_refreshes_bind_validators_to_successful_content_and_settings(
        pool: PgPool,
    ) -> Result<()> {
        let source: i64 = sqlx::query_scalar("INSERT INTO singbox_subscription_sources(name,kind,secret_url,source_host,created_at) VALUES('fixture','url','https://source.example.com/subscription','source.example.com',0) RETURNING id").fetch_one(&pool).await?;
        queue(&pool, source).await?;
        let first = claim(&pool).await?.context("first claim")?;
        ensure!(!first.cache_valid);
        let bytes = b"http://proxy.example.com:443#first";
        commit(
            &pool,
            &first,
            Some((parse::digest(bytes), parse::parse(bytes)?)),
            Some("\"fixture-v1\"".into()),
            Some("Wed, 01 Jan 2025 00:00:00 GMT".into()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("initial commit"))?;
        let original: (i64, i64, String) = sqlx::query_as("SELECT external_node_id,id,config_sha256 FROM singbox_external_node_versions WHERE source_id=$1").bind(source).fetch_one(&pool).await?;

        queue(&pool, source).await?;
        let unchanged = claim(&pool).await?.context("304 claim")?;
        ensure!(unchanged.cache_valid && unchanged.etag.as_deref() == Some("\"fixture-v1\""));
        commit(&pool, &unchanged, None, None, None)
            .await
            .map_err(|_| anyhow::anyhow!("304 commit"))?;
        let revisions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM singbox_source_revisions WHERE source_id=$1")
                .bind(source)
                .fetch_one(&pool)
                .await?;
        ensure!(revisions == 1, "304 created a new content batch");

        queue(&pool, source).await?;
        let renamed = claim(&pool).await?.context("200 claim")?;
        ensure!(
            renamed.cache_valid
                && renamed.etag == unchanged.etag
                && renamed.last_modified == unchanged.last_modified
        );
        let bytes = b"http://proxy.example.com:443#renamed";
        commit(
            &pool,
            &renamed,
            Some((parse::digest(bytes), parse::parse(bytes)?)),
            None,
            None,
        )
        .await
        .map_err(|_| anyhow::anyhow!("renamed commit"))?;
        let latest: (i64, i64, String, String) = sqlx::query_as("SELECT external_node_id,id,config_sha256,name FROM singbox_external_node_versions WHERE source_id=$1 ORDER BY id DESC LIMIT 1").bind(source).fetch_one(&pool).await?;
        ensure!(
            latest.0 == original.0
                && latest.1 != original.1
                && latest.2 == original.2
                && latest.3 == "renamed"
        );
        let validators: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT etag,last_modified FROM singbox_subscription_sources WHERE id=$1",
        )
        .bind(source)
        .fetch_one(&pool)
        .await?;
        ensure!(
            validators == (None, None),
            "200 without validators retained a stale cache token"
        );

        sqlx::query("UPDATE singbox_subscription_sources SET settings_revision=settings_revision+1 WHERE id=$1").bind(source).execute(&pool).await?;
        queue(&pool, source).await?;
        let changed_settings = claim(&pool).await?.context("settings claim")?;
        ensure!(!changed_settings.cache_valid);
        ensure!(matches!(
            commit(&pool, &changed_settings, None, None, None).await,
            Err(WorkerError::Import(ImportError("unexpected_not_modified")))
        ));
        Ok(())
    }

    #[sqlx::test(migrations = "../../../crates/panel/migrations")]
    async fn a_parser_upgrade_supersedes_old_jobs_without_reusing_their_work(
        pool: PgPool,
    ) -> Result<()> {
        for state in ["queued", "running"] {
            let source = fixture(&pool).await?;
            let old_job = Uuid::new_v4();
            sqlx::query("INSERT INTO singbox_source_jobs(id,source_id,settings_revision,identity_epoch,parser_version,state,phase,created_at) VALUES($1,$2,1,1,'sinan-subscriptions-1',$3,'parsing',0)")
                .bind(old_job).bind(source).bind(state).execute(&pool).await?;
            let new_job = queue(&pool, source).await?;
            ensure!(new_job.id != old_job);
            let old: (String, String, Option<i64>) = sqlx::query_as(
                "SELECT state,phase,finished_at FROM singbox_source_jobs WHERE id=$1",
            )
            .bind(old_job)
            .fetch_one(&pool)
            .await?;
            ensure!(old.0 == "superseded" && old.1 == "finished" && old.2.is_some());
            let input = claim(&pool).await?.context("new parser claim")?;
            ensure!(input.id == new_job.id && !input.cache_valid);
            ensure!(queue(&pool, source).await?.id == new_job.id);
            sqlx::query("UPDATE singbox_source_jobs SET state='cancelled' WHERE id=$1")
                .bind(new_job.id)
                .execute(&pool)
                .await?;
        }
        Ok(())
    }

    #[sqlx::test(migrations = "../../../crates/panel/migrations")]
    async fn a_parser_upgrade_requires_new_content_and_preserves_immutable_history(
        pool: PgPool,
    ) -> Result<()> {
        let source: i64 = sqlx::query_scalar("INSERT INTO singbox_subscription_sources(name,kind,secret_url,source_host,created_at) VALUES('fixture','url','https://source.example.com/subscription','source.example.com',0) RETURNING id").fetch_one(&pool).await?;
        let body = b"proxies: [{name: fixture, type: vmess, server: proxy.example.com, port: 443, uuid: 00000000-0000-0000-0000-000000000001, cipher: auto, network: h2}]";
        // Seed an actual legacy normalization, rather than rewriting an immutable
        // current revision to pretend that it came from the old parser.
        let config = serde_json::json!({
            "type":"vmess","server":"proxy.example.com","server_port":443,
            "uuid":"00000000-0000-0000-0000-000000000001","security":"auto",
            "transport":{"type":"http"}
        });
        let hash = parse::digest(&serde_json::to_vec(&config)?);
        let outbound = sinan_compiler::external::ExternalOutbound(config.clone());
        let capabilities = serde_json::to_value(outbound.capabilities()?)?;
        let identity = format!(
            "endpoint:{}",
            parse::digest(&serde_json::to_vec(&outbound.identity_value())?)
        );
        let revision: i64 = sqlx::query_scalar("INSERT INTO singbox_source_revisions(source_id,settings_revision,identity_epoch,parser_version,body_sha256,format,supported_count,unsupported_count,fetched_at) VALUES($1,1,1,'sinan-subscriptions-1',$2,'clash_yaml',1,0,12) RETURNING id")
            .bind(source).bind(parse::digest(body)).fetch_one(&pool).await?;
        let node: i64 = sqlx::query_scalar("INSERT INTO singbox_external_nodes(source_id,identity_epoch,identity_key,name,last_seen_revision_id) VALUES($1,1,$2,'fixture',$3) RETURNING id")
            .bind(source).bind(identity).bind(revision).fetch_one(&pool).await?;
        let version: i64 = sqlx::query_scalar("INSERT INTO singbox_external_node_versions(external_node_id,source_id,source_revision_id,identity_epoch,parser_version,name,config_json,config_sha256,capabilities_json,created_at) VALUES($1,$2,$3,1,'sinan-subscriptions-1','fixture',$4,$5,$6,12) RETURNING id")
            .bind(node).bind(source).bind(revision).bind(&config).bind(&hash).bind(capabilities).fetch_one(&pool).await?;
        sqlx::query("UPDATE singbox_external_nodes SET current_version_id=$2 WHERE id=$1")
            .bind(node)
            .bind(version)
            .execute(&pool)
            .await?;
        sqlx::query("UPDATE singbox_subscription_sources SET current_revision_id=$2,last_success_at=12,etag='\"legacy\"',last_modified='Wed, 01 Jan 2025 00:00:00 GMT',cache_settings_revision=1,cache_identity_epoch=1 WHERE id=$1")
            .bind(source).bind(revision).execute(&pool).await?;

        queue(&pool, source).await?;
        let stale = claim(&pool).await?.context("parser upgrade claim")?;
        ensure!(stale.current_revision_id == Some(revision));
        ensure!(stale.etag.is_some() && stale.last_modified.is_some() && !stale.cache_valid);
        ensure!(matches!(
            commit(&pool, &stale, None, None, None).await,
            Err(WorkerError::Import(ImportError("unexpected_not_modified")))
        ));
        fail(&pool, &stale, "unexpected_not_modified").await?;
        let unchanged: (Option<i64>, Option<i64>, Option<String>) = sqlx::query_as("SELECT current_revision_id,last_success_at,last_error FROM singbox_subscription_sources WHERE id=$1")
            .bind(source).fetch_one(&pool).await?;
        ensure!(
            unchanged
                == (
                    Some(revision),
                    Some(12),
                    Some("unexpected_not_modified".into())
                )
        );

        queue(&pool, source).await?;
        let fresh = claim(&pool).await?.context("fresh content claim")?;
        let parsed = parse::parse(body)?;
        ensure!(parsed.nodes.is_empty() && parsed.rejected.len() == 1);
        ensure!(parsed.rejected[0].reason == "unsupported_h2_without_tls");
        commit(
            &pool,
            &fresh,
            Some((parse::digest(body), parsed)),
            None,
            None,
        )
        .await
        .map_err(|_| anyhow::anyhow!("fresh parser commit"))?;
        let old: (Value, String, String) = sqlx::query_as("SELECT config_json,config_sha256,parser_version FROM singbox_external_node_versions WHERE id=$1")
            .bind(version).fetch_one(&pool).await?;
        ensure!(old == (config, hash, "sinan-subscriptions-1".into()));
        let old_revision: (String, i32) = sqlx::query_as(
            "SELECT parser_version,supported_count FROM singbox_source_revisions WHERE id=$1",
        )
        .bind(revision)
        .fetch_one(&pool)
        .await?;
        ensure!(old_revision == ("sinan-subscriptions-1".into(), 1));
        let latest: (i64, String, i32, i32) = sqlx::query_as("SELECT r.id,r.parser_version,r.supported_count,r.unsupported_count FROM singbox_source_revisions r JOIN singbox_subscription_sources s ON s.current_revision_id=r.id WHERE s.id=$1")
            .bind(source).fetch_one(&pool).await?;
        ensure!(
            latest.0 != revision && latest.1 == PARSER_VERSION && latest.2 == 0 && latest.3 == 1
        );
        let missing: (bool, Option<i64>) = sqlx::query_as(
            "SELECT present,current_version_id FROM singbox_external_nodes WHERE id=$1",
        )
        .bind(node)
        .fetch_one(&pool)
        .await?;
        ensure!(missing == (false, Some(version)));
        Ok(())
    }
}
