#![forbid(unsafe_code)]

use super::scheduling_tests::{ControlledOps, accepted, authorize, until};
use super::*;
use std::{
    collections::VecDeque,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Notify, oneshot},
    task::JoinHandle,
};

struct Fixture {
    state: SharedState,
    ops: Arc<ControlledOps>,
    retirement: Arc<crate::retirement::Retirement>,
}

impl Fixture {
    fn new() -> Result<Self> {
        Self::open(Path::new(":memory:"))
    }

    fn open(path: &Path) -> Result<Self> {
        let state = Arc::new(Mutex::new(crate::State::open(path)?));
        let ops = Arc::new(ControlledOps::default());
        let retirement = Arc::new(crate::retirement::Retirement::new(
            crate::Config::default(),
            state.clone(),
            vec![],
            ops.clone(),
            Arc::new(crate::fake::FakeServiceManager::default()),
        )?);
        Ok(Self {
            state,
            ops,
            retirement,
        })
    }

    fn sample(
        &self,
        clients: watch::Receiver<Option<Arc<PanelClient>>>,
        leases: watch::Receiver<Option<AcceptedLease>>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(sample_loop(
            self.state.clone(),
            self.ops.clone(),
            clients,
            leases,
            self.retirement.clone(),
        ))
    }
}

fn spec(id: u128, fast: bool) -> ProbeSpec {
    authorize(ProbeSpec {
        id: Uuid::from_u128(id),
        name: format!("fixture-{id}"),
        kind: ProbeKind::Icmp,
        target: if fast { "127.0.0.1" } else { "127.0.0.2" }.into(),
        port: None,
        interval_secs: 3600,
        carrier: String::new(),
        enabled: true,
        monitor: None,
        execution_authorized: None,
    })
}

fn local_client() -> Result<Arc<PanelClient>> {
    Ok(Arc::new(PanelClient::new(
        "http://127.0.0.1:1",
        "fixture-session",
    )?))
}

async fn stop<T>(worker: JoinHandle<T>) {
    worker.abort();
    match worker.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("worker returned before it was stopped"),
    }
}

#[tokio::test]
async fn cold_start_does_not_execute_cached_configuration_without_a_fresh_lease() -> Result<()> {
    let fixture = Fixture::new()?;
    let probe = spec(1, true);
    let mut legacy = probe.clone();
    legacy.monitor = None;
    legacy.execution_authorized = Some(true);
    let mut invalid = probe.clone();
    invalid
        .monitor
        .as_mut()
        .unwrap()
        .authorization
        .as_mut()
        .unwrap()
        .scope
        .clear();
    fixture.state.lock().unwrap().set_json(
        "probes:configuration",
        &(now_timestamp(), vec![probe.clone()]),
    )?;
    let client = local_client()?;
    let (_clients, clients) = watch::channel(Some(client.clone()));
    let (leases, lease_receiver) = watch::channel(None);
    let worker = fixture.sample(clients, lease_receiver);
    for cached in [
        serde_json::json!([now_timestamp(), [probe.clone()]]),
        serde_json::json!([now_timestamp() - 86_400, [probe.clone()]]),
        serde_json::json!([now_timestamp() + 86_400, [probe.clone()]]),
        serde_json::json!([now_timestamp(), [legacy]]),
        serde_json::json!([now_timestamp(), [invalid]]),
        serde_json::json!("TEST_ONLY malformed legacy permission cache"),
    ] {
        fixture
            .state
            .lock()
            .unwrap()
            .set_json("probes:configuration", &cached)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 0);
        assert!(fixture.state.lock().unwrap().probe_results()?.is_empty());
        assert!(!worker.is_finished());
    }

    let fresh = accepted(
        &client,
        std::slice::from_ref(&probe),
        1,
        Duration::from_secs(90),
    );
    let lease_id = fresh.snapshot.id;
    leases.send_replace(Some(fresh));
    until(|| fixture.state.lock().unwrap().probe_results().unwrap().len() == 1).await?;
    let results = fixture.state.lock().unwrap().probe_results()?;
    let execution = results[0]
        .execution
        .as_ref()
        .context("fresh sample lacks execution proof")?;
    assert_eq!(execution.lease_id, lease_id);
    assert_eq!(execution.probe.spec, probe);
    assert_eq!(execution.revision, 1);
    stop(worker).await;
    Ok(())
}

#[tokio::test]
async fn expired_work_and_full_probe_outbox_do_not_stop_the_scheduler() -> Result<()> {
    let fixture = Fixture::new()?;
    let client = local_client()?;
    let (_clients, clients) = watch::channel(Some(client.clone()));
    let (leases, receiver) = watch::channel(Some(accepted(
        &client,
        &[spec(1, false)],
        1,
        Duration::from_secs(1),
    )));
    let worker = fixture.sample(clients, receiver);
    until(|| fixture.ops.active.load(Ordering::SeqCst) == 1).await?;
    until(|| fixture.ops.active.load(Ordering::SeqCst) == 0).await?;
    assert!(!worker.is_finished());
    {
        let state = fixture.state.lock().unwrap();
        state.connection.execute_batch("CREATE TABLE TEST_ONLY_storage_fill(payload BLOB); CREATE TRIGGER TEST_ONLY_probe_storage_full BEFORE INSERT ON probe_outbox BEGIN INSERT INTO TEST_ONLY_storage_fill VALUES(zeroblob(65536)); END;")?;
        let pages: i64 = state
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        state
            .connection
            .execute_batch(&format!("PRAGMA max_page_count={pages}"))?;
    }
    leases.send_replace(Some(accepted(
        &client,
        &[spec(2, true), spec(3, true)],
        2,
        Duration::from_secs(90),
    )));
    until(|| fixture.ops.starts.load(Ordering::SeqCst) >= 3).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!worker.is_finished());
    assert!(fixture.state.lock().unwrap().probe_results()?.is_empty());
    fixture
        .state
        .lock()
        .unwrap()
        .connection
        .execute_batch("DROP TRIGGER TEST_ONLY_probe_storage_full")?;
    leases.send_replace(Some(accepted(
        &client,
        &[spec(4, true)],
        3,
        Duration::from_secs(90),
    )));
    until(|| {
        !fixture
            .state
            .lock()
            .unwrap()
            .probe_results()
            .unwrap()
            .is_empty()
    })
    .await?;
    stop(worker).await;
    Ok(())
}

#[tokio::test]
async fn expired_disconnected_replaced_and_revoked_leases_abort_inflight_samples() -> Result<()> {
    for reason in [
        "expiry",
        "disconnect",
        "session",
        "empty",
        "permission",
        "removed",
    ] {
        let fixture = Fixture::new()?;
        let client = local_client()?;
        let probe = spec(1, false);
        let duration = if reason == "expiry" {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(90)
        };
        let lease = accepted(&client, std::slice::from_ref(&probe), 1, duration);
        let (clients, client_receiver) = watch::channel(Some(client.clone()));
        let (leases, lease_receiver) = watch::channel(Some(lease));
        let worker = fixture.sample(client_receiver, lease_receiver);
        until(|| fixture.ops.active.load(Ordering::SeqCst) == 1).await?;
        match reason {
            "expiry" => {}
            "disconnect" => {
                clients.send_replace(None);
            }
            // The replacement deliberately has identical URL and credentials;
            // the old lease belongs to the previous connection instance.
            "session" => {
                clients.send_replace(Some(local_client()?));
            }
            "empty" => {
                leases.send_replace(Some(accepted(&client, &[], 2, Duration::from_secs(90))));
            }
            "permission" => {
                let mut changed = accepted(&client, &[probe], 2, Duration::from_secs(90));
                changed.snapshot.probes[0].authorization.scope = "replacement permission".into();
                changed.snapshot.probes[0]
                    .spec
                    .monitor
                    .as_mut()
                    .unwrap()
                    .authorization = Some(changed.snapshot.probes[0].authorization.clone());
                leases.send_replace(Some(changed));
            }
            "removed" => {
                leases.send_replace(None);
            }
            _ => unreachable!(),
        }
        until(|| fixture.ops.active.load(Ordering::SeqCst) == 0).await?;
        assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 1, "{reason}");
        let guard = timeout(Duration::from_millis(500), fixture.retirement.gate.write()).await?;
        drop(guard);
        fixture.ops.release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            fixture.state.lock().unwrap().probe_results()?.is_empty(),
            "{reason}"
        );
        stop(worker).await;
    }
    Ok(())
}

#[tokio::test]
async fn coalesced_connection_and_same_definition_lease_updates_cancel_the_old_measurement()
-> Result<()> {
    let fixture = Fixture::new()?;
    let original_client = local_client()?;
    let probe = spec(1, false);
    let (clients, client_receiver) = watch::channel(Some(original_client.clone()));
    let (leases, lease_receiver) = watch::channel(Some(accepted(
        &original_client,
        std::slice::from_ref(&probe),
        1,
        Duration::from_secs(90),
    )));
    let worker = fixture.sample(client_receiver, lease_receiver);
    until(|| fixture.ops.active.load(Ordering::SeqCst) == 1).await?;

    let replacement = local_client()?;
    let renewed = accepted(
        &replacement,
        std::slice::from_ref(&probe),
        2,
        Duration::from_secs(90),
    );
    // No await between these writes: the current-thread runtime cannot poll the
    // old measurement until watch has coalesced the intermediate cleared state.
    clients.send_replace(None);
    leases.send_replace(None);
    clients.send_replace(Some(replacement.clone()));
    leases.send_replace(Some(renewed));
    until(|| fixture.ops.active.load(Ordering::SeqCst) == 0).await?;
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 1);
    fixture.ops.release.notify_waiters();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(fixture.state.lock().unwrap().probe_results()?.is_empty());

    // Fresh work on the replacement connection is still authorized. The old
    // target's persisted period prevents its aborted run from starting again.
    let fresh = spec(2, true);
    let next = accepted(
        &replacement,
        &[probe.clone(), fresh.clone()],
        3,
        Duration::from_secs(90),
    );
    let lease_id = next.snapshot.id;
    leases.send_replace(Some(next));
    until(|| fixture.state.lock().unwrap().probe_results().unwrap().len() == 1).await?;
    let results = fixture.state.lock().unwrap().probe_results()?;
    assert_eq!(results[0].probe_id, fresh.id);
    assert_ne!(results[0].probe_id, probe.id);
    assert_eq!(results[0].execution.as_ref().unwrap().lease_id, lease_id);
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 2);
    stop(worker).await;
    Ok(())
}

#[tokio::test]
async fn persisted_sampling_period_survives_worker_restart_and_metadata_changes() -> Result<()> {
    let directory = std::env::temp_dir().join(format!("sinan-probe-period-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("state.sqlite");
    let fixture = Fixture::open(&path)?;
    let client = local_client()?;
    let probe = spec(1, true);
    let (_clients, client_receiver) = watch::channel(Some(client.clone()));
    let (leases, lease_receiver) = watch::channel(Some(accepted(
        &client,
        std::slice::from_ref(&probe),
        1,
        Duration::from_secs(90),
    )));
    let worker = fixture.sample(client_receiver.clone(), lease_receiver.clone());
    until(|| fixture.state.lock().unwrap().probe_results().unwrap().len() == 1).await?;
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 1);
    stop(worker).await;
    drop(fixture);

    let fixture = Fixture::open(&path)?;
    let mut renamed = probe.clone();
    renamed.name = "renamed fixture".into();
    renamed.carrier = "fixture carrier".into();
    leases.send_replace(Some(accepted(
        &client,
        std::slice::from_ref(&renamed),
        2,
        Duration::from_secs(90),
    )));
    let worker = fixture.sample(client_receiver, lease_receiver);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.state.lock().unwrap().probe_results()?.len(), 1);

    // A genuinely new target proves the restarted scheduler is still running.
    let fresh = spec(2, true);
    leases.send_replace(Some(accepted(
        &client,
        &[renamed, fresh.clone()],
        3,
        Duration::from_secs(90),
    )));
    until(|| fixture.state.lock().unwrap().probe_results().unwrap().len() == 2).await?;
    let results = fixture.state.lock().unwrap().probe_results()?;
    assert_eq!(
        results
            .iter()
            .filter(|result| result.probe_id == probe.id)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.probe_id == fresh.id)
            .count(),
        1
    );
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 1);
    stop(worker).await;
    drop(fixture);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[tokio::test]
async fn acceptance_persists_revision_and_definition_barriers_across_reopen() -> Result<()> {
    let directory = std::env::temp_dir().join(format!("sinan-probe-lease-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("state.sqlite");
    let client = local_client()?;
    let original = accepted(&client, &[spec(1, false)], 4, Duration::from_secs(90)).snapshot;
    {
        let state = Arc::new(Mutex::new(crate::State::open(&path)?));
        leases::accept_lease(
            original.clone(),
            7,
            &state,
            client.clone(),
            Instant::now(),
            None,
        )?;
    }
    {
        let state = Arc::new(Mutex::new(crate::State::open(&path)?));
        let mut rollback = original.clone();
        rollback.revision = 3;
        assert!(
            leases::accept_lease(rollback, 7, &state, client.clone(), Instant::now(), None)
                .is_err()
        );
        let mut rewritten = original.clone();
        rewritten.probes[0].authorization.scope = "different permission".into();
        rewritten.probes[0]
            .spec
            .monitor
            .as_mut()
            .unwrap()
            .authorization = Some(rewritten.probes[0].authorization.clone());
        assert!(rewritten.valid());
        assert!(
            leases::accept_lease(rewritten, 7, &state, client.clone(), Instant::now(), None)
                .is_err()
        );
        let mut older_time = original.clone();
        older_time.revision = 5;
        older_time.issued_at -= 1;
        older_time.expires_at -= 1;
        assert!(
            leases::accept_lease(older_time, 7, &state, client.clone(), Instant::now(), None)
                .is_err()
        );
        let mut renewed = original.clone();
        renewed.id = Uuid::new_v4();
        leases::accept_lease(renewed, 7, &state, client.clone(), Instant::now(), None)?;
        let mut changed = original;
        changed.revision = 5;
        changed.probes[0].authorization.scope = "replacement permission".into();
        changed.probes[0]
            .spec
            .monitor
            .as_mut()
            .unwrap()
            .authorization = Some(changed.probes[0].authorization.clone());
        leases::accept_lease(changed, 7, &state, client, Instant::now(), None)?;
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[tokio::test]
async fn expired_future_and_invalid_authorization_leases_never_persist_permission() -> Result<()> {
    let fixture = Fixture::new()?;
    let client = local_client()?;
    let original = accepted(&client, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    for reason in [
        "expired",
        "future",
        "missing-authorization",
        "invalid-scope",
    ] {
        let mut rejected = original.clone();
        match reason {
            "expired" => {
                rejected.issued_at -= 91;
                rejected.expires_at -= 91;
                assert!(rejected.valid());
            }
            "future" => {
                rejected.issued_at += 3600;
                rejected.expires_at += 3600;
                assert!(rejected.valid());
            }
            "missing-authorization" => {
                rejected.probes[0]
                    .spec
                    .monitor
                    .as_mut()
                    .unwrap()
                    .authorization = None;
                assert!(!rejected.valid());
            }
            "invalid-scope" => {
                rejected.probes[0].authorization.scope.clear();
                rejected.probes[0]
                    .spec
                    .monitor
                    .as_mut()
                    .unwrap()
                    .authorization = Some(rejected.probes[0].authorization.clone());
                assert!(!rejected.valid());
            }
            _ => unreachable!(),
        }
        assert!(
            leases::accept_lease(
                rejected,
                7,
                &fixture.state,
                client.clone(),
                Instant::now(),
                None
            )
            .is_err(),
            "{reason}"
        );
        assert!(
            fixture
                .state
                .lock()
                .unwrap()
                .get_json::<serde_json::Value>("probes:lease-high-water:7")?
                .is_none(),
            "{reason} persisted execution permission"
        );
    }
    assert!(fixture.state.lock().unwrap().probe_results()?.is_empty());
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn acceptance_deducts_request_latency_and_never_restarts_the_lease_clock() -> Result<()> {
    let fixture = Fixture::new()?;
    let client = local_client()?;
    let mut snapshot = accepted(&client, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    snapshot.expires_at = snapshot.issued_at + 3;
    snapshot.probes[0].authorization.expires_at = Some(snapshot.expires_at);
    snapshot.probes[0]
        .spec
        .monitor
        .as_mut()
        .unwrap()
        .authorization = Some(snapshot.probes[0].authorization.clone());
    let before = Instant::now();
    let request_started = before - Duration::from_secs(2);
    let accepted = leases::accept_lease(
        snapshot.clone(),
        7,
        &fixture.state,
        client.clone(),
        request_started,
        None,
    )?;
    assert!(accepted.deadline <= request_started + Duration::from_secs(3));
    assert!(accepted.deadline > before);
    let (_clients, clients) = watch::channel(Some(client.clone()));
    let (_leases, lease_receiver) = watch::channel(Some(accepted));
    let worker = fixture.sample(clients, lease_receiver);
    until(|| fixture.ops.active.load(Ordering::SeqCst) == 1).await?;
    timeout(
        Duration::from_millis(1500),
        until(|| fixture.ops.active.load(Ordering::SeqCst) == 0),
    )
    .await??;
    assert!(fixture.state.lock().unwrap().probe_results()?.is_empty());
    stop(worker).await;

    let elapsed = Instant::now() - Duration::from_secs(4);
    snapshot.id = Uuid::new_v4();
    assert!(leases::accept_lease(snapshot, 7, &fixture.state, client, elapsed, None).is_err());
    Ok(())
}

#[tokio::test]
async fn reusing_a_lease_never_extends_its_monotonic_deadline_after_clock_recalibration()
-> Result<()> {
    let fixture = Fixture::new()?;
    let client = local_client()?;
    let mut snapshot = accepted(&client, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    snapshot.issued_at -= 60;
    snapshot.expires_at -= 60;
    let first = leases::accept_lease(
        snapshot.clone(),
        7,
        &fixture.state,
        client.clone(),
        Instant::now(),
        None,
    )?;
    fixture
        .state
        .lock()
        .unwrap()
        .set_json("clock_offset_ms", &-60_000_i64)?;
    let renewed = leases::accept_lease(
        snapshot.clone(),
        7,
        &fixture.state,
        client.clone(),
        Instant::now(),
        Some(&first),
    )?;
    assert_eq!(renewed.deadline, first.deadline);
    assert!(renewed.panel_millis() >= first.panel_millis().saturating_sub(10));

    let mut rewritten = snapshot.clone();
    rewritten.expires_at -= 1;
    assert!(rewritten.valid());
    assert!(
        leases::accept_lease(
            rewritten,
            7,
            &fixture.state,
            client.clone(),
            Instant::now(),
            Some(&first),
        )
        .is_err()
    );
    let mut expired = first;
    expired.deadline = Instant::now() - Duration::from_secs(1);
    assert!(
        leases::accept_lease(
            snapshot,
            7,
            &fixture.state,
            client,
            Instant::now(),
            Some(&expired),
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn intervening_lease_receipts_cannot_extend_or_rewrite_an_earlier_live_identity() -> Result<()>
{
    let fixture = Fixture::new()?;
    let client = local_client()?;
    let mut snapshot = accepted(&client, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    snapshot.issued_at -= 60;
    snapshot.expires_at -= 60;
    let mut receipts = leases::LeaseReceipts::default();
    let first = receipts.accept(
        snapshot.clone(),
        7,
        &fixture.state,
        client.clone(),
        Instant::now() - Duration::from_secs(5),
    )?;
    let mut intervening = snapshot.clone();
    intervening.id = Uuid::new_v4();
    receipts.accept(
        intervening,
        7,
        &fixture.state,
        client.clone(),
        Instant::now(),
    )?;
    fixture
        .state
        .lock()
        .unwrap()
        .set_json("clock_offset_ms", &-60_000_i64)?;
    let repeated = receipts.accept(
        snapshot.clone(),
        7,
        &fixture.state,
        client.clone(),
        Instant::now(),
    )?;
    assert_eq!(repeated.deadline, first.deadline);
    let mut rewritten = snapshot;
    rewritten.expires_at -= 1;
    assert!(rewritten.valid());
    assert!(
        receipts
            .accept(rewritten, 7, &fixture.state, client, Instant::now())
            .is_err()
    );
    assert!(fixture.state.lock().unwrap().probe_results()?.is_empty());
    assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn live_receipt_retention_is_bounded_and_advancing_issuance_releases_old_receipts()
-> Result<()> {
    let fixture = Fixture::new()?;
    let client = local_client()?;
    let original = accepted(&client, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    let mut receipts = leases::LeaseReceipts::default();
    for _ in 0..64 {
        let mut snapshot = original.clone();
        snapshot.id = Uuid::new_v4();
        receipts.accept(snapshot, 7, &fixture.state, client.clone(), Instant::now())?;
    }
    let mut overflow = original.clone();
    overflow.id = Uuid::new_v4();
    assert!(
        receipts
            .accept(overflow, 7, &fixture.state, client.clone(), Instant::now())
            .is_err()
    );
    let saved = fixture
        .state
        .lock()
        .unwrap()
        .get_json::<serde_json::Value>("probes:lease-high-water:7")?
        .unwrap();
    assert_eq!(saved["issued_at"], original.issued_at);
    fixture
        .state
        .lock()
        .unwrap()
        .set_json("clock_offset_ms", &91_000_i64)?;
    let mut renewed = original.clone();
    renewed.id = Uuid::new_v4();
    renewed.issued_at += 91;
    renewed.expires_at += 91;
    receipts.accept(renewed, 7, &fixture.state, client.clone(), Instant::now())?;
    assert!(
        receipts
            .accept(original, 7, &fixture.state, client, Instant::now())
            .is_err()
    );
    Ok(())
}

struct Reply {
    status: u16,
    body: String,
    entered: Option<oneshot::Sender<()>>,
    release: Option<Arc<Notify>>,
}

impl Reply {
    fn lease(snapshot: &sinan_protocol::ProbeLease) -> Result<Self> {
        Ok(Self {
            status: 200,
            body: serde_json::to_string(snapshot)?,
            entered: None,
            release: None,
        })
    }
}

struct HttpFixture {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    worker: JoinHandle<()>,
}

impl HttpFixture {
    async fn new(replies: Vec<Reply>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let worker = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let replies = replies.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") && headers.len() < 4096 {
                        let mut byte = [0];
                        if !matches!(
                            timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
                            Ok(Ok(1))
                        ) {
                            return;
                        }
                        headers.push(byte[0]);
                    }
                    let request = String::from_utf8_lossy(&headers)
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    recorded.lock().unwrap().push(request);
                    let reply = replies.lock().unwrap().pop_front();
                    let Some(mut reply) = reply else {
                        return;
                    };
                    if let Some(entered) = reply.entered.take() {
                        let _ = entered.send(());
                    }
                    if let Some(release) = reply.release {
                        release.notified().await;
                    }
                    let response = format!(
                        "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        reply.status,
                        reply.body.len(),
                        reply.body,
                    );
                    // A superseded or timed-out client may already have closed its socket.
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Ok(Self {
            origin,
            requests,
            worker,
        })
    }

    fn client(&self, token: &str) -> Result<Arc<PanelClient>> {
        Ok(Arc::new(PanelClient::new(&self.origin, token)?))
    }

    fn assert_lease_request(&self) {
        let requests = self.requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|request| request == "GET /api/agent/v1/probe-lease HTTP/1.1"),
            "{requests:?}"
        );
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

#[tokio::test]
async fn failed_refresh_revokes_execution_without_forgetting_the_receipt_deadline() -> Result<()> {
    let fixture = Fixture::new()?;
    let prototype = local_client()?;
    let mut snapshot = accepted(&prototype, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    snapshot.issued_at -= 60;
    snapshot.expires_at -= 60;
    let (failed_entered, failed_request) = oneshot::channel();
    let release = Arc::new(Notify::new());
    let http = HttpFixture::new(vec![
        Reply::lease(&snapshot)?,
        Reply {
            status: 503,
            body: "{}".into(),
            entered: Some(failed_entered),
            release: Some(release.clone()),
        },
        Reply::lease(&snapshot)?,
    ])
    .await?;
    let client = http.client("fixture-session")?;
    let (_clients, clients) = watch::channel(Some(client));
    let (leases, mut authority) = watch::channel(None);
    let synchronizer = tokio::spawn(synchronize_with_cadence(
        7,
        fixture.state.clone(),
        clients,
        leases,
        fixture.retirement.clone(),
        (Duration::from_millis(25), Duration::from_millis(150)),
    ));
    timeout(Duration::from_secs(2), authority.changed()).await??;
    let initial = authority
        .borrow_and_update()
        .clone()
        .context("first lease was not accepted")?;
    timeout(Duration::from_secs(2), failed_request).await??;
    fixture
        .state
        .lock()
        .unwrap()
        .set_json("clock_offset_ms", &-60_000_i64)?;
    release.notify_one();
    timeout(Duration::from_secs(2), authority.changed()).await??;
    assert!(authority.borrow_and_update().is_none());
    timeout(Duration::from_secs(2), authority.changed()).await??;
    let reused = authority
        .borrow_and_update()
        .clone()
        .context("same receipt was not recovered")?;
    assert_eq!(reused.snapshot, snapshot);
    assert_eq!(reused.deadline, initial.deadline);
    http.assert_lease_request();
    stop(synchronizer).await;
    Ok(())
}

#[tokio::test]
async fn unauthorized_forbidden_and_invalid_refreshes_clear_the_previous_lease() -> Result<()> {
    for case in ["unauthorized", "forbidden", "wrong-server", "invalid-json"] {
        let fixture = Fixture::new()?;
        let prototype = local_client()?;
        let snapshot = accepted(&prototype, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
        let reply = match case {
            "unauthorized" => Reply {
                status: 401,
                body: "{}".into(),
                entered: None,
                release: None,
            },
            "forbidden" => Reply {
                status: 403,
                body: "{}".into(),
                entered: None,
                release: None,
            },
            "wrong-server" => {
                let mut wrong = snapshot;
                wrong.server_id = 8;
                Reply::lease(&wrong)?
            }
            "invalid-json" => Reply {
                status: 200,
                body: "not JSON".into(),
                entered: None,
                release: None,
            },
            _ => unreachable!(),
        };
        let http = HttpFixture::new(vec![reply]).await?;
        let client = http.client("fixture-session")?;
        let (_clients, clients) = watch::channel(Some(client.clone()));
        let (leases, lease_receiver) = watch::channel(Some(accepted(
            &client,
            &[spec(1, false)],
            1,
            Duration::from_secs(90),
        )));
        let synchronizer = tokio::spawn(synchronize(
            7,
            fixture.state.clone(),
            clients,
            leases,
            fixture.retirement.clone(),
        ));
        until(|| !http.requests.lock().unwrap().is_empty()).await?;
        until(|| lease_receiver.borrow().is_none()).await?;
        http.assert_lease_request();
        assert_eq!(fixture.ops.starts.load(Ordering::SeqCst), 0);
        stop(synchronizer).await;
    }
    Ok(())
}

#[tokio::test]
async fn a_hung_refresh_has_a_five_second_budget_and_does_not_block_other_tasks() -> Result<()> {
    let fixture = Fixture::new()?;
    let (entered, request_started) = oneshot::channel();
    let release = Arc::new(Notify::new());
    let http = HttpFixture::new(vec![Reply {
        status: 200,
        body: "{}".into(),
        entered: Some(entered),
        release: Some(release.clone()),
    }])
    .await?;
    let client = http.client("fixture-session")?;
    let (_clients, clients) = watch::channel(Some(client.clone()));
    let (leases, lease_receiver) = watch::channel(Some(accepted(
        &client,
        &[spec(1, false)],
        1,
        Duration::from_secs(90),
    )));
    let synchronizer = tokio::spawn(synchronize(
        7,
        fixture.state.clone(),
        clients,
        leases,
        fixture.retirement.clone(),
    ));
    timeout(Duration::from_secs(2), request_started).await??;
    let waiting_since = Instant::now();
    let ticks = Arc::new(AtomicUsize::new(0));
    let observed = ticks.clone();
    let unrelated = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            tick.tick().await;
            observed.fetch_add(1, Ordering::SeqCst);
        }
    });
    timeout(Duration::from_secs(6), async {
        while lease_receiver.borrow().is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert!(waiting_since.elapsed() >= Duration::from_secs(4));
    assert!(ticks.load(Ordering::SeqCst) >= 25);
    http.assert_lease_request();
    release.notify_waiters();
    stop(unrelated).await;
    stop(synchronizer).await;
    Ok(())
}

#[tokio::test]
async fn changing_connection_drops_the_old_request_and_late_responses_cannot_revive_it()
-> Result<()> {
    let fixture = Fixture::new()?;
    let prototype = local_client()?;
    let old = accepted(&prototype, &[spec(1, false)], 1, Duration::from_secs(90)).snapshot;
    let new = accepted(&prototype, &[], 2, Duration::from_secs(90)).snapshot;
    let (entered, old_request) = oneshot::channel();
    let release = Arc::new(Notify::new());
    let mut held = Reply::lease(&old)?;
    held.entered = Some(entered);
    held.release = Some(release.clone());
    let http = HttpFixture::new(vec![held, Reply::lease(&new)?]).await?;
    let client = http.client("old-session")?;
    let (clients, client_receiver) = watch::channel(Some(client));
    let (leases, lease_receiver) = watch::channel(None);
    let synchronizer = tokio::spawn(synchronize(
        7,
        fixture.state.clone(),
        client_receiver,
        leases,
        fixture.retirement.clone(),
    ));
    timeout(Duration::from_secs(2), old_request).await??;
    let replacement = http.client("new-session")?;
    clients.send_replace(Some(replacement.clone()));
    timeout(
        Duration::from_secs(4),
        until(|| {
            lease_receiver
                .borrow()
                .as_ref()
                .is_some_and(|lease| lease.snapshot.id == new.id)
        }),
    )
    .await??;
    release.notify_waiters();
    tokio::time::sleep(Duration::from_millis(100)).await;
    {
        let lease = lease_receiver.borrow();
        let lease = lease
            .as_ref()
            .context("late response revoked the accepted replacement")?;
        assert_eq!(lease.snapshot.id, new.id);
        assert_eq!(lease.snapshot.revision, 2);
        assert!(Arc::ptr_eq(&lease.session, &replacement));
        assert!(lease.snapshot.probes.is_empty());
    }
    http.assert_lease_request();
    assert_eq!(http.requests.lock().unwrap().len(), 2);
    stop(synchronizer).await;
    Ok(())
}

#[cfg(unix)]
mod process_cleanup {
    use super::*;
    use sinan_adapter_sdk::{BoxFuture, CommandOutput, Execution};
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    struct ProcessOps {
        script: PathBuf,
        directory: PathBuf,
        active: AtomicUsize,
    }

    struct Active<'a>(&'a AtomicUsize);
    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Privileged for ProcessOps {
        fn execute<'a>(&'a self, _: &'a Path, _: &'a [String]) -> BoxFuture<'a, CommandOutput> {
            Box::pin(async { anyhow::bail!("only bounded fixture execution is supported") })
        }
        fn execute_bounded<'a>(
            &'a self,
            program: &'a Path,
            args: &'a [String],
            seconds: u32,
            maximum: usize,
        ) -> BoxFuture<'a, Execution> {
            Box::pin(async move {
                ensure!(
                    program == Path::new("env")
                        && args.last().is_some_and(|target| target == "127.0.0.2"),
                    "unexpected probe command"
                );
                self.active.fetch_add(1, Ordering::SeqCst);
                let _active = Active(&self.active);
                // This is a private process-tree fixture, never the host ICMP tool.
                crate::system::SystemOps
                    .execute_bounded(
                        Path::new("sh"),
                        &[
                            self.script.to_string_lossy().into_owned(),
                            self.directory.to_string_lossy().into_owned(),
                        ],
                        seconds,
                        maximum,
                    )
                    .await
            })
        }
        fn create_dir<'a>(&'a self, _: &'a Path, _: u32, _: Option<&'a str>) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("unexpected filesystem operation") })
        }
        fn write_file<'a>(
            &'a self,
            _: &'a Path,
            _: &'a [u8],
            _: u32,
            _: Option<&'a str>,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("unexpected filesystem operation") })
        }
        fn atomic_symlink<'a>(&'a self, _: &'a Path, _: &'a Path) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("unexpected filesystem operation") })
        }
        fn remove_symlink<'a>(&'a self, _: &'a Path) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("unexpected filesystem operation") })
        }
        fn install_archive<'a>(
            &'a self,
            _: &'a Path,
            _: &'a Path,
            _: &'a str,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { anyhow::bail!("unexpected filesystem operation") })
        }
    }

    async fn process_group(group: u32) -> Result<Vec<(u32, String)>> {
        let output = tokio::process::Command::new("ps")
            .args(["-axo", "pid=,pgid=,stat="])
            .output()
            .await?;
        ensure!(
            output.status.success(),
            "could not inspect fixture process group"
        );
        Ok(String::from_utf8(output.stdout)?
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let pid = fields.next()?.parse().ok()?;
                let process_group: u32 = fields.next()?.parse().ok()?;
                let status = fields.next()?.to_owned();
                (process_group == group).then_some((pid, status))
            })
            .collect())
    }

    #[tokio::test]
    async fn connection_revocation_kills_the_private_command_tree_and_releases_retirement()
    -> Result<()> {
        let directory =
            std::env::temp_dir().join(format!("sinan-probe-process-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let script = directory.join("fixture.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
printf '%s\n' "$$" > "$1/parent.pid"
sh -c '
    sleep 30 &
    printf "%s\n" "$!" > "$1/grandchild.pid"
    sleep 2
    : > "$1/escaped"
    wait
' fixture "$1" &
printf '%s\n' "$!" > "$1/child.pid"
wait
"#,
        )?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
        let ops = Arc::new(ProcessOps {
            script,
            directory: directory.clone(),
            active: AtomicUsize::new(0),
        });
        let state = Arc::new(Mutex::new(crate::State::open(Path::new(":memory:"))?));
        let retirement = Arc::new(crate::retirement::Retirement::new(
            crate::Config::default(),
            state.clone(),
            vec![],
            ops.clone(),
            Arc::new(crate::fake::FakeServiceManager::default()),
        )?);
        let client = local_client()?;
        let (clients, client_receiver) = watch::channel(Some(client.clone()));
        let initial = accepted(&client, &[spec(1, false)], 1, Duration::from_secs(4));
        let expires = initial.deadline;
        let (leases, lease_receiver) = watch::channel(Some(initial));
        let worker = tokio::spawn(sample_loop(
            state.clone(),
            ops.clone(),
            client_receiver,
            lease_receiver,
            retirement.clone(),
        ));
        until(|| {
            ["parent.pid", "child.pid", "grandchild.pid"]
                .iter()
                .all(|name| {
                    std::fs::read_to_string(directory.join(name))
                        .ok()
                        .and_then(|value| value.trim().parse::<u32>().ok())
                        .is_some_and(|pid| pid > 1)
                })
        })
        .await?;
        let parent: u32 = std::fs::read_to_string(directory.join("parent.pid"))?
            .trim()
            .parse()?;
        let child: u32 = std::fs::read_to_string(directory.join("child.pid"))?
            .trim()
            .parse()?;
        let grandchild: u32 = std::fs::read_to_string(directory.join("grandchild.pid"))?
            .trim()
            .parse()?;
        let before = process_group(parent).await?;
        for pid in [parent, child, grandchild] {
            assert!(
                before
                    .iter()
                    .any(|(found, status)| *found == pid && !status.starts_with('Z'))
            );
        }
        assert!(
            expires.saturating_duration_since(Instant::now()) > Duration::from_secs(2),
            "fixture became ready too close to lease expiry"
        );
        let cancelled_at = Instant::now();
        clients.send_replace(None);
        timeout(
            Duration::from_secs(1),
            until(|| ops.active.load(Ordering::SeqCst) == 0),
        )
        .await??;
        timeout(Duration::from_secs(1), async {
            loop {
                let remaining = process_group(parent).await?;
                // Some Unix environments reap orphaned zombies asynchronously.
                // No member may still execute or reach the delayed marker.
                if remaining.iter().all(|(_, status)| status.starts_with('Z')) {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        assert!(
            cancelled_at.elapsed() < Duration::from_secs(2),
            "fixture was not stopped by connection revocation"
        );
        let guard = timeout(Duration::from_millis(500), retirement.gate.write()).await?;
        drop(guard);
        assert!(state.lock().unwrap().probe_results()?.is_empty());
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(
            !directory.join("escaped").exists(),
            "fixture descendant survived scheduler cancellation"
        );
        assert!(state.lock().unwrap().probe_results()?.is_empty());
        // The same lease's later expiry cannot restart a disconnected command.
        tokio::time::sleep_until(expires + Duration::from_millis(50)).await;
        assert_eq!(ops.active.load(Ordering::SeqCst), 0);
        assert!(state.lock().unwrap().probe_results()?.is_empty());
        leases.send_replace(None);
        stop(worker).await;
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}
