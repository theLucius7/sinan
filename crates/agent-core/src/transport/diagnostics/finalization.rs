use super::*;
use std::path::{Component, Path};

pub(super) fn validate_saved_target(
    config: &Config,
    spec: &DiagnosticSpec,
    service: &ServiceJob,
) -> Result<Uuid> {
    let id = Uuid::parse_str(&spec.id)?;
    let directory = config.runtime_root.join("diagnostics").join(id.to_string());
    ensure!(
        !id.is_nil()
            && spec.id == id.to_string()
            && service.unit == format!("sinan-diagnostic-{id}.service")
            && spec.job_dir == directory
            && service.working_directory == directory
            && spec.binary_path == service.program
            && spec.binary_path.starts_with(&config.install_root)
            && service.timeout_secs == spec.timeout_secs
            && (1..=3600).contains(&spec.timeout_secs)
            && [&directory, &spec.binary_path].into_iter().all(|path| {
                path.is_absolute()
                    && path
                        .components()
                        .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            }),
        "saved diagnostic target differs from its owned task identity"
    );
    Ok(id)
}

pub(super) async fn stop_and_confirm(
    services: &dyn ServiceManager,
    unit: &str,
    directory: &Path,
) -> Result<()> {
    // An unreadable status must not suppress a stop of the already bound unit.
    let status = tokio::time::timeout(Duration::from_millis(250), services.job_status(unit)).await;
    if !matches!(status, Ok(Ok(JobStatus::Missing))) {
        services.stop(unit).await.context("停止诊断单元失败")?;
    }
    // Losing proof capability must not suppress the stop of an existing target,
    // but it still prevents completion and credential deletion.
    ensure!(
        services.supports_confirmed_cancellation(),
        "diagnostic cleanup confirmation is not supported"
    );
    ensure!(
        services
            .diagnostic_cleanup_confirmed(unit, directory)
            .await?,
        "设备仍有活动进程或挂载，等待清理确认"
    );
    ensure!(
        services.job_status(unit).await? != JobStatus::Running,
        "诊断仍有排队或活动任务，等待清理确认"
    );
    Ok(())
}

impl DiagnosticWorker {
    pub(super) fn current_status_update(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<DiagnosticUpdate> {
        let Checkpoint::Started {
            spec,
            service,
            protection_stop_reason,
            terminal_update,
            cleanup_error,
            ..
        } = checkpoint
        else {
            anyhow::bail!("only a started diagnostic has a device status");
        };
        let id = validate_saved_target(&self.config, spec, service)?;
        if protection_stop_reason.is_some() || terminal_update.is_some() {
            let cause = terminal_update
                .as_ref()
                .and_then(|update| update.error.as_deref())
                .or(protection_stop_reason.as_deref());
            let mut error = "等待设备确认诊断进程和挂载清理；确认前不能开始下一项诊断".to_owned();
            if let Some(cause) = cause {
                error.push_str(&format!("；原执行结果：{cause}"));
            }
            if let Some(cleanup) = cleanup_error {
                error.push_str(&format!("；清理原因：{cleanup}"));
            }
            return Ok(DiagnosticUpdate {
                id,
                status: DiagnosticStatus::Cleaning,
                report: terminal_update
                    .as_ref()
                    .and_then(|update| update.report.clone()),
                error: Some(error.chars().take(4096).collect()),
            });
        }
        Ok(DiagnosticUpdate {
            id,
            status: DiagnosticStatus::Running,
            report: None,
            error: None,
        })
    }

    pub(super) async fn observe_and_notify(
        &self,
        checkpoint: &Checkpoint,
        client: Option<&PanelClient>,
    ) -> Result<()> {
        let result = self.observe(checkpoint).await;
        if result.is_err()
            && let Some(client) = client
            && let Some(saved @ Checkpoint::Started { .. }) = self.active()?
        {
            let update = self.current_status_update(&saved)?;
            if update.status == DiagnosticStatus::Cleaning
                && let Err(error) = self.bounded(client.diagnostic_update(&update)).await
            {
                tracing::warn!(%error, "pending diagnostic cleanup status will be retried");
            }
        }
        result
    }

    pub(super) fn record_cleanup_error(&self, id: Uuid, error: &anyhow::Error) -> Result<()> {
        if let Some(mut saved @ Checkpoint::Started { .. }) = self.active()? {
            let Checkpoint::Started {
                spec,
                protection_stop_reason,
                terminal_update,
                cleanup_error,
                ..
            } = &mut saved
            else {
                unreachable!()
            };
            if spec.id == id.to_string()
                && (protection_stop_reason.is_some() || terminal_update.is_some())
            {
                *cleanup_error = Some(format!("{error:#}").chars().take(4096).collect());
                self.save_if_owned(&saved)?;
            }
        }
        Ok(())
    }

    pub(super) async fn finish_cleanup(&self, checkpoint: &Checkpoint) -> Result<()> {
        let Checkpoint::Started {
            spec,
            service,
            terminal_update: Some(update),
            ..
        } = checkpoint
        else {
            anyhow::bail!("diagnostic cleanup requires a durable terminal result");
        };
        let id = validate_saved_target(&self.config, spec, service)?;
        ensure!(
            update.id == id
                && update.status.is_terminal()
                && (update.status != DiagnosticStatus::Succeeded || update.report.is_some())
                && update.report.as_ref().is_none_or(
                    |report| !report.text.trim().is_empty() && report.text.len() <= MAX_REPORT
                ),
            "invalid saved diagnostic terminal result"
        );
        if self.cancellation_requested(id)? {
            return Ok(());
        }
        self.bounded(stop_and_confirm(
            self.services.as_ref(),
            &service.unit,
            &spec.job_dir,
        ))
        .await
        .context("诊断清理尚未确认，将保留任务并继续重试")?;
        if self.cancellation_requested(id)? {
            return Ok(());
        }
        self.finish_owned(update.as_ref().clone())
    }
}
