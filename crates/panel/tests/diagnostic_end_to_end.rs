#![forbid(unsafe_code)]

#[allow(dead_code)]
mod e2e_support;
mod release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use e2e_support::{Harness, eventually};
use flate2::{Compression, write::GzEncoder};
use reqwest::Method;
use serde_json::json;
use sinan_adapter_nodequality::{NodeQualityAdapter, VERSION};
use sinan_adapter_sdk::{BoxFuture, JobStatus, ServiceJob, ServiceManager};
use sinan_agent_core::{State, fake::FakeResourceOps, identity, system::SystemOps, transport};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[derive(Default)]
struct IndependentServices {
    starts: AtomicUsize,
    stops: AtomicUsize,
    block_stop: AtomicBool,
    jobs: Mutex<BTreeMap<String, (PathBuf, JobStatus)>>,
}

impl IndependentServices {
    fn finish(&self) -> Result<()> {
        for (directory, status) in self.jobs.lock().unwrap().values_mut() {
            fs::write(
                directory.join("result.txt"),
                "# NodeQuality\n\nHardware, IP and network fixture report.\n",
            )?;
            fs::write(
                directory.join("report-url.txt"),
                "https://nodequality.com/r/EXAMPLE_REPORT\n",
            )?;
            *status = JobStatus::Succeeded;
        }
        Ok(())
    }
}

impl ServiceManager for IndependentServices {
    fn running_diagnostic_units(&self) -> BoxFuture<'_, Vec<String>> {
        Box::pin(async {
            Ok(self
                .jobs
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, (_, status))| *status == JobStatus::Running)
                .map(|(unit, _)| unit.clone())
                .collect())
        })
    }
    fn reload<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn restart<'a>(&'a self, _: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn supports_confirmed_cancellation(&self) -> bool {
        true
    }
    fn supports_diagnostic_cpu_ceiling(&self) -> bool {
        // TEST_ONLY explicit simulated backend; no native controller is probed.
        true
    }
    fn diagnostic_cleanup_confirmed<'a>(
        &'a self,
        unit: &'a str,
        _: &'a std::path::Path,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move { Ok(!self.jobs.lock().unwrap().contains_key(unit)) })
    }
    fn stop<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.stops.fetch_add(1, Ordering::SeqCst);
            anyhow::ensure!(
                !self.block_stop.load(Ordering::SeqCst),
                "fixture stop not confirmed"
            );
            self.jobs.lock().unwrap().remove(unit);
            Ok(())
        })
    }
    fn is_active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
    fn start_job<'a>(&'a self, job: &'a ServiceJob) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            // TEST_ONLY: this backend records a bounded daily service contract;
            // it does not start a native service or certify a host CPU controller.
            assert_eq!(job.timeout_secs, 90);
            assert_eq!(job.memory_max.get(), 64 * 1024 * 1024);
            assert_eq!(job.tasks_max.get(), 32);
            assert_eq!(job.cpu_max_percent.get(), 100);
            assert_eq!(job.cpu_weight.get(), 10);
            assert_eq!(job.io_weight.get(), 10);
            assert_eq!(job.oom_score_adjust.get(), 500);
            assert!(job.args.windows(2).any(|args| args == ["--mode", "daily"]));
            let mut jobs = self.jobs.lock().unwrap();
            anyhow::ensure!(!jobs.contains_key(&job.unit), "duplicate service start");
            jobs.insert(
                job.unit.clone(),
                (job.working_directory.clone(), JobStatus::Running),
            );
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
    fn job_status<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, JobStatus> {
        Box::pin(async move {
            Ok(self
                .jobs
                .lock()
                .unwrap()
                .get(unit)
                .map(|(_, status)| status.clone())
                .unwrap_or(JobStatus::Missing))
        })
    }
}

// IndependentServices simulates the Linux job backend even on a macOS test host.
async fn mark_simulated_linux(harness: &Harness, id: i64) -> Result<()> {
    sqlx::query("UPDATE servers SET static_info=static_info || $2 WHERE id=$1")
        .bind(id)
        .bind(json!({"os":"linux"}))
        .execute(&harness.state.pool)
        .await?;
    Ok(())
}

fn write_artifact(harness: &Harness) -> Result<()> {
    let binary = format!("#!/bin/bash\nprintf 'nodequality {VERSION}\\n'\n");
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    let mut header = tar::Header::new_gnu();
    header.set_size(binary.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    archive.append_data(&mut header, "nodequality", binary.as_bytes())?;
    let bytes = archive.into_inner()?.finish()?;
    release_fixture::write(
        &harness.state.config.data_dir,
        "nodequality",
        VERSION,
        "nodequality",
        &bytes,
        binary.as_bytes(),
        "tar.gz",
    )?;
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn node_report_survives_agent_restart_and_is_started_only_once(pool: PgPool) -> Result<()> {
    let harness = Harness::start(pool).await?;
    write_artifact(&harness)?;
    let server = harness
        .api(Method::POST, "/api/servers", json!({"name":"诊断测试节点"}))
        .await?;
    let id = server["id"].as_i64().context("server id")?;
    let token = harness
        .api(
            Method::POST,
            &format!("/api/servers/{id}/enrollment"),
            json!({}),
        )
        .await?;
    let mut config = harness.agent_config();
    config.public_ips = vec!["192.0.2.10".into(), "2001:db8::10".into()];
    identity::enroll(
        &config,
        token["token"].as_str().context("enrollment token")?,
    )
    .await?;
    let services = Arc::new(IndependentServices::default());
    let start = || {
        tokio::spawn(transport::run_with_diagnostics(
            config.clone(),
            vec![],
            vec![Arc::new(NodeQualityAdapter::new())],
            Arc::new(FakeResourceOps::new(Arc::new(SystemOps))),
            services.clone(),
            "diagnostic-test-agent",
        ))
    };
    let agent = start();
    eventually(
        "diagnostic capability and reported addresses",
        15,
        || async {
            let row: (serde_json::Value, serde_json::Value) =
                sqlx::query_as("SELECT capabilities,static_info FROM servers WHERE id=$1")
                    .bind(id)
                    .fetch_one(&harness.state.pool)
                    .await?;
            Ok(row.0.as_array().is_some_and(|caps| {
                caps.iter().any(|cap| cap == "diagnostic:nodequality")
                    && caps
                        .iter()
                        .any(|cap| cap == sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY)
            }) && row.1["ip_addresses"]
                .as_array()
                .is_some_and(|ips| ips.iter().any(|ip| ip == "192.0.2.10")))
        },
    )
    .await?;
    mark_simulated_linux(&harness, id).await?;
    let report = harness
        .api(
            Method::POST,
            &format!("/api/servers/{id}/node-quality/reports"),
            json!({"mode":"daily","ip_version":"both"}),
        )
        .await?;
    let report_id = report["id"].as_str().context("report job id")?.to_owned();
    eventually("independent report service start", 15, || async {
        Ok(services.starts.load(Ordering::SeqCst) == 1)
    })
    .await?;
    agent.abort();
    let _ = agent.await;
    assert!(
        State::open(&config.state_db)?
            .get_json::<serde_json::Value>("diagnostics:active")?
            .is_some_and(|checkpoint| !checkpoint.is_null()),
        "diagnostic-only restart must recover an existing managed checkpoint"
    );
    let mut state = State::open(&config.state_db)?;
    let mut saved: serde_json::Value = state
        .get_json("diagnostics:active")?
        .context("saved start")?;
    saved["Started"]["spec"]["version"] = json!("a92fca6c0067df29ddd03fdc2fee6f3000f64545-r2");
    saved["Started"]["spec"]["options"] = json!({});
    state.set_json("diagnostics:active", &saved)?;
    drop(state);
    sqlx::query("UPDATE diagnostic_jobs SET status='running',job=jsonb_set(jsonb_set(job,'{options}','{}'),'{version}','\"a92fca6c0067df29ddd03fdc2fee6f3000f64545-r2\"') WHERE id=$1")
        .bind(uuid::Uuid::parse_str(&report_id)?).execute(&harness.state.pool).await?;
    services.finish()?;
    let restarted = start();
    eventually(
        "completed report returned after agent restart",
        20,
        || async {
            anyhow::ensure!(
                !restarted.is_finished(),
                "diagnostic-only Agent exited while recovering its report"
            );
            let row: (String, Option<serde_json::Value>) =
                sqlx::query_as("SELECT status,report FROM diagnostic_jobs WHERE id=$1")
                    .bind(uuid::Uuid::parse_str(&report_id)?)
                    .fetch_one(&harness.state.pool)
                    .await?;
            Ok(row.0 == "succeeded"
                && row.1.is_some_and(|report| {
                    report["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("fixture report"))
                }))
        },
    )
    .await?;
    assert_eq!(services.starts.load(Ordering::SeqCst), 1);
    let detail = harness
        .api(
            Method::GET,
            &format!("/api/servers/{id}/node-quality"),
            json!({}),
        )
        .await?;
    assert!(detail.to_string().contains("EXAMPLE_REPORT"));
    restarted.abort();
    let _ = restarted.await;
    Ok(())
}

#[path = "diagnostic_end_to_end/cancellation.rs"]
mod cancellation;

#[path = "diagnostic_end_to_end/chain_gate.rs"]
mod chain_gate;
