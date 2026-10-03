use super::*;
use crate::diagnostic_plugins;
use sinan_protocol::{DIAGNOSTIC_SERVICE_CAPABILITY, DiagnosticResourceBudget};
use std::{collections::BTreeMap, future::Future, pin::Pin};

pub type PlanFuture<'a> = Pin<Box<dyn Future<Output = ApiResult<JobPlan>> + Send + 'a>>;
pub type SectionFuture<'a> = Pin<Box<dyn Future<Output = ApiResult<()>> + Send + 'a>>;

pub struct SectionContext<'a> {
    pub server_id: i64,
    pub job: &'a Value,
    pub created_at: i64,
    pub expires_at: i64,
    pub job_generation: i64,
}

pub struct JobPlan {
    pub timeout_secs: u64,
    pub budget: DiagnosticResourceBudget,
    pub options: BTreeMap<String, String>,
    pub expected_sections: Vec<String>,
    pub metadata: BTreeMap<String, Value>,
}

/// Plugins translate parameters and parse reports; the service owns task state.
pub trait DiagnosticPlugin: Send + Sync {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn required_capabilities(&self) -> &'static [&'static str];
    fn required_os(&self) -> Option<&'static str> {
        Some("linux")
    }
    fn start_denial(&self, _job: &Value) -> Option<&'static str> {
        None
    }
    fn can_dispatch(&self, _job: &Value, _capabilities: &Value) -> bool {
        true
    }
    fn plan<'a>(
        &'a self,
        request: Value,
        server_id: i64,
        connection: &'a mut sqlx::PgConnection,
    ) -> PlanFuture<'a>;
    fn report_url_allowed(&self, _value: &str) -> bool {
        false
    }
    /// Parse and project an accepted chapter inside the service's transaction.
    fn record_section<'a>(
        &'a self,
        _context: SectionContext<'a>,
        _update: &'a DiagnosticSectionUpdate,
        _connection: &'a mut sqlx::PgConnection,
    ) -> SectionFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Serialize)]
pub struct PluginReadiness {
    pub plugin: &'static str,
    pub title: &'static str,
    pub version: &'static str,
    pub ready: bool,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct DiagnosticView {
    pub cancel_supported: bool,
    pub plugins: Vec<PluginReadiness>,
    pub reports: Vec<ReportRecord>,
}

pub fn ready(
    row: &sqlx::postgres::PgRow,
    plugin: &dyn DiagnosticPlugin,
) -> ApiResult<&'static str> {
    let info: Value = row.get("static_info");
    if plugin
        .required_os()
        .is_some_and(|os| info["os"].as_str() != Some(os))
    {
        let reason = if plugin.required_os() == Some("linux") {
            "当前诊断插件仅支持已识别的 Linux 设备"
        } else {
            "当前诊断插件不支持此设备操作系统"
        };
        return Err(ApiError::Conflict(reason.into()));
    }
    if !row.get::<Option<i64>, _>("last_seen").is_some_and(|seen| {
        seen <= now_timestamp() + 60 && now_timestamp().saturating_sub(seen) <= 60
    }) {
        return Err(ApiError::Conflict(
            "Agent 当前离线，请在设备上线后运行诊断".into(),
        ));
    }
    let capabilities: Value = row.get("capabilities");
    for required in [
        sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY,
        sinan_protocol::DIAGNOSTIC_SECTIONS_CAPABILITY,
        DIAGNOSTIC_SERVICE_CAPABILITY,
        sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY,
    ]
    .into_iter()
    .chain(plugin.required_capabilities().iter().copied())
    {
        if !capabilities
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(required)))
        {
            return Err(ApiError::Conflict(
                "此 Agent 尚不支持当前诊断服务，请先升级 Agent".into(),
            ));
        }
    }
    match info["arch"].as_str() {
        Some("aarch64" | "arm64") => Ok("arm64"),
        Some("x86_64" | "amd64") => Ok("amd64"),
        _ => Err(ApiError::Conflict("设备架构未知，无法运行诊断插件".into())),
    }
}

pub(crate) async fn readiness(
    state: &AppState,
    row: &sqlx::postgres::PgRow,
    plugin: &dyn DiagnosticPlugin,
) -> PluginReadiness {
    let result = async {
        let arch = ready(row, plugin)?;
        artifacts::descriptor(state, plugin.id(), plugin.version(), arch).await?;
        Ok::<(), ApiError>(())
    }
    .await;
    PluginReadiness {
        plugin: plugin.id(),
        title: plugin.title(),
        version: plugin.version(),
        ready: result.is_ok(),
        reason: result.err().map(|error| match error {
            ApiError::NotFound => "诊断插件制品尚未上传，请先准备对应架构的校验与签名制品".into(),
            error => error.to_string(),
        }),
    }
}

pub async fn history(
    state: &AppState,
    server_id: i64,
    plugin: Option<&str>,
) -> ApiResult<Vec<ReportRecord>> {
    reject_queued(&mut *state.pool.acquire().await?, server_id).await?;
    let query = HISTORY_QUERY.replace(
        "WHERE j.server_id=$1",
        "WHERE j.server_id=$1 AND ($2::text IS NULL OR j.job->>'plugin'=$2 OR ($2='nodequality' AND j.job->>'plugin' IS NULL))",
    );
    Ok(sqlx::query_as(&query)
        .bind(server_id)
        .bind(plugin)
        .fetch_all(&state.pool)
        .await?)
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<DiagnosticView>> {
    auth::require_admin(&state, &headers).await?;
    expire(&state).await?;
    let row = sqlx::query(
        "SELECT static_info,last_seen,capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let mut plugins = Vec::new();
    for plugin in diagnostic_plugins::all() {
        plugins.push(readiness(&state, &row, *plugin).await);
    }
    Ok(Json(DiagnosticView {
        cancel_supported: cancel_supported(&row.get::<Value, _>("capabilities")),
        plugins,
        reports: history(&state, id, None).await?,
    }))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, plugin)): Path<(i64, String)>,
    Json(request): Json<Value>,
) -> ApiResult<(StatusCode, Json<ReportRecord>)> {
    auth::require_admin(&state, &headers).await?;
    let plugin = diagnostic_plugins::find(&plugin)
        .ok_or_else(|| ApiError::BadRequest("诊断插件没有登记".into()))?;
    Ok((
        StatusCode::CREATED,
        Json(create_job(&state, id, plugin, request).await?),
    ))
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn validate_plan(plugin: &dyn DiagnosticPlugin, plan: &JobPlan) -> ApiResult<()> {
    let names = &plan.expected_sections;
    let mut distinct = std::collections::BTreeSet::new();
    let reserved = [
        "id",
        "plugin",
        "version",
        "artifact",
        "timeout_secs",
        "expires_at",
        "options",
        "resource_budget",
    ];
    if !valid_component(plugin.id())
        || !valid_component(plugin.version())
        || !(1..=3600).contains(&plan.timeout_secs)
        || !plan.budget.valid()
        || names.is_empty()
        || names.len() > sinan_protocol::DIAGNOSTIC_SECTION_COUNT
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                || !distinct.insert(name)
        })
        || plan.options.len() > 32
        || plan
            .options
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 64 || value.len() > 64 * 1024)
        || plan
            .options
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > 256 * 1024
        || plan.metadata.len() > 16
        || plan
            .metadata
            .keys()
            .any(|key| key.len() > 64 || reserved.contains(&key.as_str()))
        || serde_json::to_vec(&plan.metadata).map_or(true, |value| value.len() > 64 * 1024)
    {
        return Err(ApiError::BadRequest(
            "诊断计划的预算、参数或报告章节无效".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn create_job(
    state: &AppState,
    id: i64,
    plugin: &dyn DiagnosticPlugin,
    request: Value,
) -> ApiResult<ReportRecord> {
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT static_info,last_seen,capabilities FROM servers WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let arch = ready(&row, plugin)?;
    reject_queued(&mut tx, id).await?;
    let now = now_timestamp();
    sqlx::query("UPDATE diagnostic_jobs SET status='failed',error='任务超时或设备未及时回报',updated_at=$2 WHERE server_id=$1 AND status IN ('queued','running') AND expires_at<=$2")
        .bind(id).bind(now).execute(&mut *tx).await?;
    let active: bool = sqlx::query_scalar(UNRESOLVED_QUERY)
        .bind(id)
        .bind(None::<Uuid>)
        .fetch_one(&mut *tx)
        .await?;
    if active {
        return Err(ApiError::Conflict(
            "此服务器已有诊断任务或正在等待清理、取消确认，请等待设备完成".into(),
        ));
    }
    let plan = plugin.plan(request, id, &mut tx).await?;
    validate_plan(plugin, &plan)?;
    let artifact = artifacts::descriptor(state, plugin.id(), plugin.version(), arch)
        .await
        .map_err(|error| match error {
            ApiError::NotFound => {
                ApiError::Conflict("诊断插件制品尚未上传，请先准备对应架构的校验与签名制品".into())
            }
            error => error,
        })?;
    let job = DiagnosticJob {
        id: Uuid::new_v4(),
        plugin: plugin.id().into(),
        version: plugin.version().into(),
        artifact,
        timeout_secs: plan.timeout_secs,
        expires_at: Some(now + plan.timeout_secs as i64 + 300),
        resource_budget: Some(plan.budget),
        options: plan.options,
    };
    let mut saved_job = serde_json::to_value(&job).map_err(anyhow::Error::from)?;
    for (key, value) in plan.metadata {
        saved_job[&key] = value;
    }
    sqlx::query("INSERT INTO diagnostic_jobs(id,server_id,job,created_at,updated_at,expires_at,expected_sections) VALUES($1,$2,$3,$4,$4,$5,$6)")
        .bind(job.id).bind(id).bind(saved_job).bind(now).bind(job.expires_at)
        .bind(plan.expected_sections).execute(&mut *tx).await?;
    let record = sqlx::query_as(RECORD_QUERY)
        .bind(job.id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(record)
}

pub(super) async fn reject_queued(
    connection: &mut sqlx::PgConnection,
    server_id: i64,
) -> ApiResult<()> {
    let rows = sqlx::query("SELECT id,job FROM diagnostic_jobs WHERE server_id=$1 AND status='queued' ORDER BY created_at,id FOR UPDATE")
        .bind(server_id).fetch_all(&mut *connection).await?;
    for row in rows {
        let job: Value = row.get("job");
        if let Some(reason) =
            diagnostic_plugins::for_job(&job).and_then(|plugin| plugin.start_denial(&job))
        {
            // A panel queue may lag a durable device start. Keep completion false so
            // an existing checkpoint can still return its late report or cancel.
            sqlx::query("UPDATE diagnostic_jobs SET status='failed',error=$3,updated_at=$4 WHERE id=$1 AND server_id=$2 AND status='queued'")
                .bind(row.get::<Uuid,_>("id")).bind(server_id).bind(reason).bind(now_timestamp())
                .execute(&mut *connection).await?;
        }
    }
    Ok(())
}

pub(super) fn validate_plugin_report(job: &Value, report: &DiagnosticReport) -> ApiResult<()> {
    let Some(url) = &report.report_url else {
        // Historical text remains writable even when its plugin metadata predates registration.
        return Ok(());
    };
    // Before registration, every diagnostic belonged to the original plugin.
    let plugin = diagnostic_plugins::for_job(job)
        .ok_or_else(|| ApiError::Conflict("任务的诊断插件已不可用".into()))?;
    if !plugin.report_url_allowed(url) {
        return Err(ApiError::BadRequest(
            "报告链接不符合已登记插件的允许范围".into(),
        ));
    }
    Ok(())
}

pub fn cancel_supported(capabilities: &Value) -> bool {
    super::cancellation::supported(capabilities)
}
