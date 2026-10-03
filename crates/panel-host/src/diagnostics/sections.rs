use super::*;

pub async fn upload_section(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(update): Json<DiagnosticSectionUpdate>,
) -> ApiResult<StatusCode> {
    let server_id = auth::require_agent(&state, &headers).await?;
    if id != update.id || !update.valid() || update.collected_at > now_timestamp() + 300 {
        return Err(ApiError::BadRequest(
            "报告章节编号、内容、版本或时间无效".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    // Projection may write server caches. Keep the same server -> job lock order
    // as creation, cancellation and terminal updates.
    sqlx::query("SELECT id FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(server_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let row = sqlx::query("SELECT j.expected_sections,j.job,j.created_at,j.expires_at,j.generation FROM diagnostic_jobs j WHERE j.id=$1 AND j.server_id=$2 FOR UPDATE")
        .bind(id).bind(server_id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let expected: Vec<String> = row.get("expected_sections");
    if expected.len() > sinan_protocol::DIAGNOSTIC_SECTION_COUNT || !expected.contains(&update.name)
    {
        return Err(ApiError::BadRequest("任务没有登记此报告章节".into()));
    }
    let node_results = crate::diagnostic_plugins::nodequality::node_queries::parse_section(
        &row.get::<Value, _>("job"),
        &update,
        row.get("created_at"),
        row.get("expires_at"),
    )?;
    let saved = sqlx::query(
        "SELECT text,complete,revision FROM diagnostic_report_sections WHERE job_id=$1 AND name=$2",
    )
    .bind(id)
    .bind(&update.name)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(saved) = saved {
        let revision: i64 = saved.get("revision");
        if revision as u64 == update.revision
            && (saved.get::<String, _>("text") != update.text
                || saved.get::<bool, _>("complete") != update.complete)
        {
            return Err(ApiError::Conflict("同一报告章节版本的内容不一致".into()));
        }
        if revision as u64 == update.revision {
            tx.commit().await?;
            // Replayed durable sections repair a cache write that failed after
            // the chapter committed. Job locks are released before server locks.
            crate::diagnostic_plugins::nodequality::node_queries::persist_section(
                &state,
                server_id,
                node_results,
            )
            .await?;
            return Ok(StatusCode::NO_CONTENT);
        }
        if revision as u64 > update.revision
            || (saved.get::<bool, _>("complete") && !update.complete)
        {
            tx.commit().await?;
            return Ok(StatusCode::NO_CONTENT);
        }
    }
    let total: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(octet_length(text)),0)::bigint FROM diagnostic_report_sections WHERE job_id=$1 AND name<>$2")
        .bind(id).bind(&update.name).fetch_one(&mut *tx).await?;
    if total + update.text.len() as i64 > REPORT_LIMIT as i64 {
        return Err(ApiError::BadRequest("已保存报告章节超过 512 KiB".into()));
    }
    let job: Value = row.get("job");
    if let Some(plugin) = crate::diagnostic_plugins::for_job(&job) {
        plugin
            .record_section(
                service::SectionContext {
                    server_id,
                    job: &job,
                    created_at: row.get("created_at"),
                    expires_at: row.get("expires_at"),
                    job_generation: row.get("generation"),
                },
                &update,
                &mut tx,
            )
            .await?;
    }
    sqlx::query("INSERT INTO diagnostic_report_sections(job_id,name,text,complete,revision,collected_at,received_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(job_id,name) DO UPDATE SET text=EXCLUDED.text,complete=EXCLUDED.complete,revision=EXCLUDED.revision,collected_at=EXCLUDED.collected_at,received_at=EXCLUDED.received_at")
        .bind(id).bind(&update.name).bind(&update.text).bind(update.complete).bind(update.revision as i64).bind(update.collected_at).bind(now_timestamp()).execute(&mut *tx).await?;
    sqlx::query("UPDATE diagnostic_jobs j SET report_completeness=CASE WHEN (SELECT COUNT(*) FROM diagnostic_report_sections s WHERE s.job_id=j.id AND s.complete)=cardinality(j.expected_sections) THEN 'complete' ELSE 'partial' END WHERE j.id=$1")
        .bind(id).execute(&mut *tx).await?;
    // Execution status, terminal error and legacy text are deliberately preserved.
    tx.commit().await?;
    crate::diagnostic_plugins::nodequality::node_queries::persist_section(
        &state,
        server_id,
        node_results,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
