use super::{models::*, worker::Claim};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
    subscription_parser::{ParseStatus, ParsedSubscription},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_protocol::now_timestamp;
use sqlx::{PgConnection, Postgres, QueryBuilder, Transaction};
use std::collections::BTreeMap;
use uuid::Uuid;

async fn finish(
    connection: &mut PgConnection,
    claim: &Claim,
    status: &str,
    error: Option<&SourceFailure>,
    revision: Option<Uuid>,
) -> ApiResult<()> {
    if matches!(status, "succeeded" | "unchanged") && InstantDeadline::expired(claim) {
        return Err(ApiError::Conflict(
            "来源任务超过处理期限，未提交新结果".into(),
        ));
    }
    sqlx::query("UPDATE singbox_subscription_source_jobs SET status=$3,stage='done',claim_token=NULL,finished_at=$4,error=$5,source_revision_id=$6 WHERE id=$1 AND claim_token=$2 AND status IN ('running','cancelling')")
        .bind(claim.job_id).bind(claim.token).bind(status).bind(now_timestamp()).bind(error.map(|error| json!(error))).bind(revision).execute(connection).await?;
    Ok(())
}

async fn guard<'a>(
    state: &'a AppState,
    claim: &Claim,
) -> ApiResult<Option<Transaction<'a, Postgres>>> {
    let mut tx = state.pool.begin().await?;
    let source = sqlx::query_as::<_, SourceRow>(&format!(
        "SELECT {SOURCE_COLUMNS} FROM singbox_ordered_subscription_sources WHERE id=$1 FOR UPDATE"
    ))
    .bind(claim.source_id)
    .fetch_one(&mut *tx)
    .await?;
    let job: (String, Option<Uuid>, Option<Value>, Option<i64>)=sqlx::query_as("SELECT status,claim_token,error,deadline_at FROM singbox_subscription_source_jobs WHERE id=$1 FOR UPDATE")
        .bind(claim.job_id).fetch_one(&mut *tx).await?;
    if job.1 != Some(claim.token) || !matches!(job.0.as_str(), "running" | "cancelling") {
        tx.commit().await?;
        return Ok(None);
    }
    let (status, error) = if source.deleted_at.is_some()
        || source.archived
        || source.settings_revision != claim.settings_revision
        || source.identity_epoch != claim.identity_epoch
    {
        (
            Some("superseded"),
            Some(SourceFailure::new(
                "done",
                "superseded",
                "来源输入已过期，未更新当前来源",
            )),
        )
    } else if job.0 == "cancelling" {
        let error = job
            .2
            .and_then(|value| serde_json::from_value::<SourceFailure>(value).ok())
            .unwrap_or_else(|| SourceFailure::new("done", "cancelled", "来源任务已取消"));
        let status = match error.kind.as_str() {
            "superseded" => "superseded",
            "cancelled" => "cancelled",
            _ => "failed",
        };
        (Some(status), Some(error))
    } else if job.3.is_none_or(|deadline| deadline <= now_timestamp())
        || InstantDeadline::expired(claim)
    {
        (
            Some("failed"),
            Some(SourceFailure::new(
                "done",
                "timeout",
                "来源任务超过期限，未替换上次成功结果",
            )),
        )
    } else {
        (None, None)
    };
    if let Some(status) = status {
        finish(&mut tx, claim, status, error.as_ref(), None).await?;
        if status == "failed" {
            sqlx::query(
                "UPDATE singbox_ordered_subscription_sources SET last_error=$2 WHERE id=$1",
            )
            .bind(claim.source_id)
            .bind(error.map(|error| json!(error)))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(None);
    }
    Ok(Some(tx))
}

struct InstantDeadline;
impl InstantDeadline {
    fn expired(claim: &Claim) -> bool {
        tokio::time::Instant::now() >= claim.work_deadline
    }
}

pub(super) async fn failure(
    state: &AppState,
    claim: &Claim,
    error: SourceFailure,
) -> ApiResult<()> {
    let Some(mut tx) = guard(state, claim).await? else {
        return Ok(());
    };
    let status = match error.kind.as_str() {
        "cancelled" => "cancelled",
        "superseded" => "superseded",
        _ => "failed",
    };
    finish(&mut tx, claim, status, Some(&error), None).await?;
    if status == "failed" {
        sqlx::query("UPDATE singbox_ordered_subscription_sources SET last_error=$2 WHERE id=$1")
            .bind(claim.source_id)
            .bind(json!(error))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(super) async fn unchanged(
    state: &AppState,
    claim: &Claim,
    etag: Option<String>,
    last_modified: Option<String>,
) -> ApiResult<()> {
    let Some(previous) = claim.previous_revision else {
        return failure(
            state,
            claim,
            SourceFailure::new(
                "fetch",
                "unexpected_304",
                "来源返回 304，但当前设置没有可复用的成功批次",
            ),
        )
        .await;
    };
    if claim.etag.is_none() && claim.last_modified.is_none() {
        return failure(
            state,
            claim,
            SourceFailure::new(
                "fetch",
                "unexpected_304",
                "来源未收到有效条件请求却返回 304，保留上次结果",
            ),
        )
        .await;
    }
    let Some(mut tx) = guard(state, claim).await? else {
        return Ok(());
    };
    let same:bool=sqlx::query_scalar("SELECT COALESCE(current_success_revision=$2 AND conditional_settings_revision=$3 AND conditional_identity_epoch=$4,FALSE) FROM singbox_ordered_subscription_sources WHERE id=$1")
        .bind(claim.source_id).bind(previous).bind(claim.settings_revision).bind(claim.identity_epoch).fetch_one(&mut *tx).await?;
    if !same {
        tx.rollback().await?;
        return failure(
            state,
            claim,
            SourceFailure::new(
                "fetch",
                "unexpected_304",
                "条件请求缓存已经过期，未更新当前来源",
            ),
        )
        .await;
    }
    sqlx::query("UPDATE singbox_ordered_subscription_sources SET last_success_at=$2,last_error=NULL,conditional_etag=COALESCE($3,conditional_etag),conditional_last_modified=COALESCE($4,conditional_last_modified),updated_at=$2 WHERE id=$1")
        .bind(claim.source_id).bind(now_timestamp()).bind(etag).bind(last_modified).execute(&mut *tx).await?;
    finish(&mut tx, claim, "unchanged", None, Some(previous)).await?;
    tx.commit().await?;
    Ok(())
}

struct PreparedNode {
    id: Uuid,
    version: Uuid,
    key: Option<String>,
    identity_state: &'static str,
    preview: Value,
    config: Option<Value>,
    digest: Option<String>,
    supported: bool,
    capabilities: Value,
    reasons: Value,
}

fn identity_keys(parsed: &ParsedSubscription) -> Vec<Option<String>> {
    let mut provider_counts = BTreeMap::<&str, usize>::new();
    let mut fingerprint_counts = BTreeMap::<&str, usize>::new();
    for node in &parsed.nodes {
        if let Some(value) = node.provider_metadata_id.as_deref() {
            *provider_counts.entry(value).or_default() += 1;
        }
        if let Some(value) = node.identity_fingerprint.as_deref() {
            *fingerprint_counts.entry(value).or_default() += 1;
        }
    }
    parsed
        .nodes
        .iter()
        .map(|node| match node.provider_metadata_id.as_deref() {
            Some(value) if provider_counts.get(value) == Some(&1) => {
                Some(format!("provider:{:x}", Sha256::digest(value.as_bytes())))
            }
            Some(_) => None,
            None => node
                .identity_fingerprint
                .as_deref()
                .filter(|value| fingerprint_counts.get(value) == Some(&1))
                .map(|value| format!("fingerprint:{value}")),
        })
        .collect()
}

pub(super) async fn save(
    state: &AppState,
    claim: &Claim,
    parsed: ParsedSubscription,
    etag: Option<String>,
    last_modified: Option<String>,
) -> ApiResult<()> {
    if parsed.parser_version != claim.parser_version {
        return failure(
            state,
            claim,
            SourceFailure::new("parse", "superseded", "解析器版本已改变，未更新来源"),
        )
        .await;
    }
    let keys = identity_keys(&parsed);
    let lookup: Vec<&str> = keys.iter().filter_map(Option::as_deref).collect();
    let Some(mut tx) = guard(state, claim).await? else {
        return Ok(());
    };
    let existing:Vec<(Uuid,String)>=sqlx::query_as("SELECT id,identity_key FROM singbox_ordered_external_nodes WHERE source_id=$1 AND identity_epoch=$2 AND identity_state='unique' AND identity_key=ANY($3)")
        .bind(claim.source_id).bind(claim.identity_epoch).bind(&lookup).fetch_all(&mut *tx).await?;
    let existing: BTreeMap<String, Uuid> =
        existing.into_iter().map(|(id, key)| (key, id)).collect();
    let mut prepared = Vec::with_capacity(parsed.nodes.len());
    let mut counts = NodeCounts::default();
    for (node, key) in parsed.nodes.into_iter().zip(keys) {
        let identity_state = if key.is_some() {
            "unique"
        } else if node.identity_fingerprint.is_some() || node.provider_metadata_id.is_some() {
            "ambiguous"
        } else {
            "unresolved"
        };
        let id = key
            .as_ref()
            .and_then(|key| existing.get(key))
            .copied()
            .unwrap_or_else(Uuid::new_v4);
        let supported = node.preview.parse_status == ParseStatus::Supported
            && node.outbound.is_some()
            && node.content_digest.is_some();
        counts.supported += i64::from(supported);
        counts.unsupported += i64::from(!supported);
        counts.ambiguous += i64::from(identity_state == "ambiguous");
        let capabilities = node
            .outbound
            .as_ref()
            .map(|outbound| json!({"tcp":outbound.tcp(),"udp":outbound.udp()}))
            .unwrap_or_else(|| json!({"tcp":false,"udp":false}));
        let reasons: Vec<&str> = node
            .preview
            .unsupported_reasons
            .iter()
            .map(|reason| reason.message.as_str())
            .collect();
        prepared.push(PreparedNode {
            id,
            version: Uuid::new_v4(),
            key,
            identity_state,
            preview: json!(node.preview),
            config: if supported {
                Some(serde_json::to_value(node.outbound.as_ref()).map_err(anyhow::Error::from)?)
            } else {
                None
            },
            digest: if supported { node.content_digest } else { None },
            supported,
            capabilities,
            reasons: json!(reasons),
        });
    }
    let ids: Vec<Uuid> = prepared.iter().map(|node| node.id).collect();
    counts.missing=sqlx::query_scalar("SELECT COUNT(*) FROM singbox_ordered_external_nodes WHERE source_id=$1 AND identity_epoch=$2 AND identity_state='unique' AND NOT(id=ANY($3))")
        .bind(claim.source_id).bind(claim.identity_epoch).bind(&ids).fetch_one(&mut *tx).await?;
    let revision = Uuid::new_v4();
    let now = now_timestamp();
    let format = serde_json::to_value(parsed.format)
        .map_err(anyhow::Error::from)?
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("解析格式无效".into()))?
        .to_owned();
    sqlx::query("INSERT INTO singbox_subscription_source_revisions(id,source_id,job_id,settings_revision,identity_epoch,parser_version,format,raw_digest,parsed_at,counts,warnings) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(revision).bind(claim.source_id).bind(claim.job_id).bind(claim.settings_revision).bind(claim.identity_epoch).bind(&claim.parser_version).bind(format).bind(parsed.raw_digest).bind(now).bind(json!(counts)).bind(json!(parsed.warnings)).execute(&mut *tx).await?;
    if !prepared.is_empty() {
        let mut nodes = QueryBuilder::<Postgres>::new(
            "INSERT INTO singbox_ordered_external_nodes(id,source_id,identity_epoch,identity_key,identity_state,created_at) ",
        );
        nodes.push_values(&prepared, |mut row, node| {
            row.push_bind(node.id)
                .push_bind(claim.source_id)
                .push_bind(claim.identity_epoch)
                .push_bind(&node.key)
                .push_bind(node.identity_state)
                .push_bind(now);
        });
        nodes
            .push(" ON CONFLICT(id) DO NOTHING")
            .build()
            .execute(&mut *tx)
            .await?;
        let mut versions = QueryBuilder::<Postgres>::new(
            "INSERT INTO singbox_ordered_external_node_versions(id,node_id,source_revision_id,normalized_config,content_digest,public_preview,capabilities,supported,reasons) ",
        );
        versions.push_values(&prepared, |mut row, node| {
            row.push_bind(node.version)
                .push_bind(node.id)
                .push_bind(revision)
                .push_bind(&node.config)
                .push_bind(&node.digest)
                .push_bind(&node.preview)
                .push_bind(&node.capabilities)
                .push_bind(node.supported)
                .push_bind(&node.reasons);
        });
        versions.build().execute(&mut *tx).await?;
        let mut membership = QueryBuilder::<Postgres>::new(
            "INSERT INTO singbox_subscription_revision_nodes(source_revision_id,ordinal,node_id,version_id,public_preview,identity_state) ",
        );
        membership.push_values(prepared.iter().enumerate(), |mut row, (ordinal, node)| {
            row.push_bind(revision)
                .push_bind(ordinal as i32)
                .push_bind(node.id)
                .push_bind(node.version)
                .push_bind(&node.preview)
                .push_bind(node.identity_state);
        });
        membership.build().execute(&mut *tx).await?;
        let mut latest = QueryBuilder::<Postgres>::new(
            "UPDATE singbox_ordered_external_nodes n SET latest_version=v.version_id,last_seen_revision=",
        );
        latest.push_bind(revision).push(" FROM (");
        latest.push_values(&prepared, |mut row, node| {
            row.push_bind(node.id).push_bind(node.version);
        });
        latest
            .push(") AS v(id,version_id) WHERE n.id=v.id")
            .build()
            .execute(&mut *tx)
            .await?;
    }
    if InstantDeadline::expired(claim) {
        return Err(ApiError::Conflict(
            "来源结果保存超过期限，未提交批次".into(),
        ));
    }
    sqlx::query("UPDATE singbox_ordered_subscription_sources SET current_success_revision=$2,last_success_at=$3,last_error=NULL,conditional_etag=$4,conditional_last_modified=$5,conditional_settings_revision=$6,conditional_identity_epoch=$7,updated_at=$3 WHERE id=$1")
        .bind(claim.source_id).bind(revision).bind(now).bind(etag).bind(last_modified).bind(claim.settings_revision).bind(claim.identity_epoch).execute(&mut *tx).await?;
    finish(&mut tx, claim, "succeeded", None, Some(revision)).await?;
    tx.commit().await?;
    Ok(())
}
