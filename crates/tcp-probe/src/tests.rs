use crate::{
    engine::{Limits, Network, NetworkFuture, resolved_addresses, run_with, run_with_deadline},
    *,
};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

pub(crate) mod fixture;
mod safety;
use fixture::{Directory, target};

#[tokio::test]
async fn real_ipv4_and_ipv6_connections_close_without_application_data() {
    use tokio::{io::AsyncReadExt, net::TcpListener};
    for host in ["127.0.0.1", "::1"] {
        let listener = match TcpListener::bind((host, 0)).await {
            Ok(listener) => listener,
            // Hosts and containers without an IPv6 stack cannot provide the owned listener.
            Err(error) if host.contains(':') => {
                eprintln!("skipped IPv6 case: loopback unavailable ({error})");
                continue;
            }
            Err(error) => panic!("IPv4 loopback listener: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut byte = [0; 1];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            }
        });
        let directory = Directory::new();
        let (options, mut journal) = directory
            .prepare(
                vec![target(1, host, address.port())],
                if host.contains(':') {
                    IpVersion::V6
                } else {
                    IpVersion::V4
                },
            )
            .await;
        let report = run(&options, &mut journal).await.unwrap();
        assert!(report.complete);
        let result = &report.targets[0];
        assert_eq!(result.dns_attempts, 0);
        assert_eq!(result.address, Some(address.to_string()));
        assert_eq!(result.samples.len(), 4);
        assert!(
            result
                .samples
                .iter()
                .all(|sample| sample.error.is_none() && sample.latency_ms.is_some())
        );
        assert_eq!(result.summary.connection_success_percent, Some(100.0));
        server.await.unwrap();
        directory.assert_reports(&report);
    }
}

#[tokio::test]
async fn refusal_and_missing_family_do_not_fabricate_latency() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let directory = Directory::new();
    let (options, mut journal) = directory
        .prepare(
            vec![target(1, "127.0.0.1", port), target(2, "::1", port)],
            IpVersion::V4,
        )
        .await;
    let report = run(&options, &mut journal).await.unwrap();
    assert!(report.complete);
    assert_eq!(
        report.targets[0].summary.connection_success_percent,
        Some(0.0)
    );
    assert_eq!(report.targets[0].summary.latency_mean_ms, None);
    assert!(
        report.targets[0]
            .samples
            .iter()
            .all(|sample| sample.latency_ms.is_none()
                && sample.error.as_deref() == Some("connect_refused"))
    );
    assert_eq!(report.targets[1].summary.connection_success_percent, None);
    assert_eq!(report.targets[1].summary.latency_mean_ms, None);
    assert_eq!(
        report.targets[1].error.as_deref(),
        Some("ip_family_unavailable")
    );
    directory.assert_reports(&report);
}

enum Dns {
    Addresses(Vec<SocketAddr>),
    ReadyLate(Vec<SocketAddr>, Duration),
    Error,
    Pending,
}
struct FakeNetwork {
    dns: Dns,
    dns_calls: AtomicUsize,
    active: Arc<AtomicUsize>,
    peak: AtomicUsize,
    connections: Mutex<Vec<SocketAddr>>,
    pending: bool,
    ready_connect_delay: Duration,
}
impl FakeNetwork {
    fn new(dns: Dns, pending: bool) -> Arc<Self> {
        Arc::new(Self {
            dns,
            dns_calls: AtomicUsize::new(0),
            active: Arc::new(AtomicUsize::new(0)),
            peak: AtomicUsize::new(0),
            connections: Mutex::new(Vec::new()),
            pending,
            ready_connect_delay: Duration::ZERO,
        })
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Network for FakeNetwork {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> NetworkFuture<'a, Vec<SocketAddr>> {
        self.dns_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            match &self.dns {
                Dns::Addresses(addresses) => Ok(addresses.clone()),
                Dns::ReadyLate(addresses, delay) => {
                    // Model a ready resolver result whose polling was delayed past its deadline.
                    std::thread::sleep(*delay);
                    Ok(addresses.clone())
                }
                Dns::Error => Err(std::io::Error::other("fixture DNS failure")),
                Dns::Pending => std::future::pending().await,
            }
        })
    }
    fn connect(&self, address: SocketAddr) -> NetworkFuture<'_, ()> {
        self.connections.lock().unwrap().push(address);
        Box::pin(async move {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let _guard = Active(self.active.clone());
            if !self.ready_connect_delay.is_zero() {
                std::thread::sleep(self.ready_connect_delay);
                return Ok(());
            }
            if self.pending {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok(())
        })
    }
}
fn fast_limits() -> Limits {
    Limits {
        dns: Duration::from_millis(20),
        connect: Duration::from_millis(60),
        interval: Duration::from_millis(1),
        total: Duration::from_secs(2),
        publication: Duration::from_millis(250),
    }
}

#[tokio::test]
async fn verified_snapshot_is_frozen_and_public_options_cannot_replace_its_digest() {
    let directory = Directory::new();
    let (options, mut journal) = directory
        .prepare(vec![target(1, "127.0.0.1", 12345)], IpVersion::V4)
        .await;
    std::fs::write(
        directory.path.join("targets.json"),
        serde_json::to_vec(&Snapshot {
            schema: 1,
            targets: vec![target(2, "127.0.0.2", 54321)],
        })
        .unwrap(),
    )
    .unwrap();
    let network = FakeNetwork::new(Dns::Error, false);
    let report = run_with(&options, &mut journal, network.clone(), fast_limits())
        .await
        .unwrap();
    assert_eq!(report.target_digest, options.target_digest);
    assert_eq!(
        report.targets[0].target.id,
        target(1, "127.0.0.1", 12345).id
    );
    assert!(
        network
            .connections
            .lock()
            .unwrap()
            .iter()
            .all(|address| *address == "127.0.0.1:12345".parse::<SocketAddr>().unwrap())
    );
    let mut changed = options;
    changed.target_digest = "0".repeat(64);
    assert!(
        run_with(&changed, &mut journal, network, fast_limits())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dns_runs_once_and_one_matching_socket_is_used_with_bounded_parallelism() {
    for (family, opposite, first, alternate) in [
        (
            IpVersion::V4,
            "[::1]:12345",
            "127.0.0.1:12345",
            "127.0.0.2:12345",
        ),
        (
            IpVersion::V6,
            "127.0.0.1:12345",
            "[::1]:12345",
            "[::2]:12345",
        ),
    ] {
        let first: SocketAddr = first.parse().unwrap();
        let mut addresses = vec![opposite.parse().unwrap(); 32];
        addresses.extend([first, alternate.parse().unwrap()]);
        for concurrency in [1, 2] {
            let network = FakeNetwork::new(Dns::Addresses(addresses.clone()), false);
            let directory = Directory::new();
            let (mut options, mut journal) = directory
                .prepare(
                    vec![
                        target(1, "first.example.test", 12345),
                        target(2, "second.example.test", 12345),
                    ],
                    family,
                )
                .await;
            options.count = 8;
            options.concurrency = concurrency;
            let report = run_with(&options, &mut journal, network.clone(), fast_limits())
                .await
                .unwrap();
            assert!(report.complete);
            assert_eq!(network.dns_calls.load(Ordering::SeqCst), 2);
            assert!(
                report
                    .targets
                    .iter()
                    .all(|target| target.dns_attempts == 1 && target.samples.len() == 8)
            );
            assert_eq!(network.connections.lock().unwrap().len(), 16);
            assert!(
                network
                    .connections
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|address| *address == first)
            );
            assert!(network.peak.load(Ordering::SeqCst) <= usize::from(concurrency));
            assert_eq!(network.active.load(Ordering::SeqCst), 0);
            directory.assert_reports(&report);
        }
    }
}

#[test]
fn native_dns_retains_each_usable_family_without_truncating_before_selection() {
    for (opposite, requested) in [
        ("[::1]:12345", "127.0.0.1:12345"),
        ("127.0.0.1:12345", "[::1]:12345"),
    ] {
        let opposite: SocketAddr = opposite.parse().unwrap();
        let requested: SocketAddr = requested.parse().unwrap();
        let mut addresses = vec![
            "0.0.0.0:12345".parse().unwrap(),
            "[ff02::1]:12345".parse().unwrap(),
        ];
        addresses.extend(std::iter::repeat_n(opposite, 32));
        addresses.extend([requested, requested]);
        let retained = resolved_addresses(addresses);
        assert_eq!(retained, vec![opposite, requested]);
    }
}

#[tokio::test]
async fn dns_failure_timeout_and_no_matching_family_preserve_unknown_results() {
    for (dns, error) in [
        (Dns::Error, "dns_error"),
        (Dns::Pending, "dns_timeout"),
        (
            Dns::Addresses(vec!["[::1]:12345".parse().unwrap()]),
            "ip_family_unavailable",
        ),
    ] {
        let directory = Directory::new();
        let network = FakeNetwork::new(dns, false);
        let (options, mut journal) = directory
            .prepare(
                vec![target(1, "unknown.example.test", 12345)],
                IpVersion::V4,
            )
            .await;
        let report = run_with(&options, &mut journal, network.clone(), fast_limits())
            .await
            .unwrap();
        assert!(report.complete);
        assert_eq!(report.targets[0].error.as_deref(), Some(error));
        assert_eq!(report.targets[0].summary.connection_success_percent, None);
        assert_eq!(report.targets[0].summary.latency_mean_ms, None);
        assert!(network.connections.lock().unwrap().is_empty());
        assert_eq!(network.dns_calls.load(Ordering::SeqCst), 1);
        directory.assert_reports(&report);
    }
}

#[tokio::test]
async fn ready_dns_result_after_probe_cutoff_cannot_start_a_connection() {
    let directory = Directory::new();
    let address = "127.0.0.1:12345".parse().unwrap();
    let network = FakeNetwork::new(
        Dns::ReadyLate(vec![address], Duration::from_millis(1250)),
        false,
    );
    let (options, mut journal) = directory
        .prepare(vec![target(1, "late.example.test", 12345)], IpVersion::V4)
        .await;
    let mut limits = fast_limits();
    limits.total = Duration::from_secs(3);
    limits.publication = Duration::from_secs(2);
    limits.dns = Duration::from_secs(2);
    let report = run_with(&options, &mut journal, network.clone(), limits)
        .await
        .unwrap();
    assert_eq!(network.dns_calls.load(Ordering::SeqCst), 1);
    assert!(network.connections.lock().unwrap().is_empty());
    assert!(!report.complete && report.deadline_exceeded);
    assert_eq!(report.targets[0].status, "partial");
    assert!(report.targets[0].samples.is_empty());
    assert_eq!(report.targets[0].error.as_deref(), Some("total_timeout"));
    assert_eq!(report.targets[0].summary.connection_success_percent, None);
    directory.assert_reports(&report);
}

#[tokio::test]
async fn ready_dns_and_connect_results_after_local_timeouts_do_not_fabricate_success() {
    let directory = Directory::new();
    let address = "127.0.0.1:12345".parse().unwrap();
    let network = FakeNetwork::new(
        Dns::ReadyLate(vec![address], Duration::from_millis(50)),
        false,
    );
    let (options, mut journal) = directory
        .prepare(vec![target(1, "late.example.test", 12345)], IpVersion::V4)
        .await;
    let report = run_with(&options, &mut journal, network.clone(), fast_limits())
        .await
        .unwrap();
    assert!(report.complete && !report.deadline_exceeded);
    assert_eq!(report.targets[0].error.as_deref(), Some("dns_timeout"));
    assert!(network.connections.lock().unwrap().is_empty());
    directory.assert_reports(&report);

    let directory = Directory::new();
    let mut network = FakeNetwork::new(Dns::Error, false);
    Arc::get_mut(&mut network).unwrap().ready_connect_delay = Duration::from_millis(90);
    let (options, mut journal) = directory
        .prepare(vec![target(1, "127.0.0.1", 12345)], IpVersion::V4)
        .await;
    let report = run_with(&options, &mut journal, network.clone(), fast_limits())
        .await
        .unwrap();
    assert!(report.complete && !report.deadline_exceeded);
    assert_eq!(network.connections.lock().unwrap().len(), 4);
    assert_eq!(
        report.targets[0].summary.connection_success_percent,
        Some(0.0)
    );
    assert!(report.targets[0].samples.iter().all(|sample| {
        sample.error.as_deref() == Some("connect_timeout") && sample.latency_ms.is_none()
    }));
    directory.assert_reports(&report);
}

async fn publish_across_deadline(
    options: Options,
    mut journal: Journal,
    network: Arc<FakeNetwork>,
    limits: Limits,
    outer_deadline: Option<tokio::time::Instant>,
) -> Report {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    // Initial scope, targets and two progress updates each write three files.
    // Hold the first sample's real atomic write before sync/rename.
    let targets = journal.snapshot(&options).unwrap().targets.len();
    let actual_deadline =
        journal.gate_publication_after(3 * (1 + targets + 2), entered.clone(), release.clone());
    let started = std::time::Instant::now();
    let handle = tokio::spawn({
        let network = network.clone();
        async move { run_with_deadline(&options, &mut journal, network, limits, outer_deadline).await }
    });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let probe_deadline = actual_deadline
        .lock()
        .unwrap()
        .expect("engine's actual probe deadline");
    if let Some(outer_deadline) = outer_deadline {
        assert_eq!(probe_deadline, outer_deadline - limits.publication);
    }
    tokio::time::sleep_until(probe_deadline + Duration::from_millis(20)).await;
    assert_eq!(network.active.load(Ordering::SeqCst), 0);
    assert!(
        !handle.is_finished(),
        "publication must retain its reserved budget"
    );
    release.notify_one();
    let report = handle.await.unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(!report.targets[0].samples.is_empty());
    report
}

#[tokio::test]
async fn deadline_includes_queued_targets_and_preserves_atomic_partial_sections() {
    let directory = Directory::new();
    let network = FakeNetwork::new(Dns::Error, true);
    let (options, journal) = directory
        .prepare(
            (1..=8).map(|id| target(id, "127.0.0.1", 12345)).collect(),
            IpVersion::V4,
        )
        .await;
    let mut limits = fast_limits();
    // Keep one second for probes while allowing fsync of all eight partial
    // sections on slower filesystems; production publication remains two seconds.
    limits.total = Duration::from_secs(3);
    limits.publication = Duration::from_secs(2);
    limits.connect = Duration::from_millis(250);
    let report = publish_across_deadline(options, journal, network.clone(), limits, None).await;
    assert_eq!(report.targets[0].status, "partial");
    assert!(!report.targets[0].complete);
    assert!(!report.complete && report.deadline_exceeded);
    assert_eq!(network.active.load(Ordering::SeqCst), 0);
    assert!(network.connections.lock().unwrap().len() <= 4);
    assert!(
        report.targets[0]
            .samples
            .iter()
            .all(|sample| sample.error.as_deref() == Some("connect_timeout")
                && sample.latency_ms.is_none())
    );
    assert!(
        report.targets[1..]
            .iter()
            .all(|target| target.status == "not_attempted"
                && target.samples.is_empty()
                && target.summary.connection_success_percent.is_none())
    );
    directory.assert_reports(&report);
}

#[tokio::test]
async fn caller_deadline_includes_prior_inspection_without_restarting_the_budget() {
    let caller_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let directory = Directory::new();
    let network = FakeNetwork::new(Dns::Error, true);
    let (options, journal) = directory
        .prepare(vec![target(1, "127.0.0.1", 12345)], IpVersion::V4)
        .await;
    // Model time already spent by the caller before entering the probe engine.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut limits = fast_limits();
    limits.total = Duration::from_secs(3);
    limits.publication = Duration::from_secs(2);
    limits.connect = Duration::from_millis(250);
    let report =
        publish_across_deadline(options, journal, network, limits, Some(caller_deadline)).await;
    assert!(!report.complete && report.deadline_exceeded);
    assert_eq!(report.targets[0].status, "partial");
    assert!(tokio::time::Instant::now() < caller_deadline);
    directory.assert_reports(&report);
}

#[tokio::test]
async fn buffered_attempts_during_publication_remain_known_after_deadline() {
    let directory = Directory::new();
    let network = FakeNetwork::new(Dns::Error, false);
    let (options, journal) = directory
        .prepare(
            (1..=8)
                .map(|id| target(id, "127.0.0.1", 12345 + id as u16))
                .collect(),
            IpVersion::V4,
        )
        .await;
    let mut limits = fast_limits();
    limits.total = Duration::from_secs(3);
    limits.publication = Duration::from_secs(2);
    let report = publish_across_deadline(options, journal, network.clone(), limits, None).await;
    assert!(!report.complete && report.deadline_exceeded);
    assert!(report.targets[0].complete);
    assert!(report.targets[1].complete);
    for address in network.connections.lock().unwrap().iter() {
        let target = report
            .targets
            .iter()
            .find(|target| target.target.port == address.port())
            .unwrap();
        assert_ne!(target.status, "not_attempted");
        assert_eq!(
            target.address.as_deref(),
            Some(address.to_string().as_str())
        );
    }
    for target in &report.targets {
        let name = format!("tcp_target_{}", target.target.id.replace('-', ""));
        let section: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path.join("sections").join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let saved: serde_json::Value =
            serde_json::from_str(section["text"].as_str().unwrap()).unwrap();
        assert_eq!(saved["status"], target.status);
        assert_eq!(section["complete"], target.complete);
    }
    directory.assert_reports(&report);
}

#[tokio::test]
async fn outer_cancellation_drops_probes_and_keeps_previously_published_sections() {
    let directory = Directory::new();
    let network = FakeNetwork::new(Dns::Error, true);
    let (options, mut journal) = directory
        .prepare(vec![target(1, "127.0.0.1", 12345)], IpVersion::V4)
        .await;
    let handle = tokio::spawn({
        let network = network.clone();
        async move { run_with(&options, &mut journal, network, fast_limits()).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while network.active.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    assert_eq!(network.active.load(Ordering::SeqCst), 0);
    let body: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.path.join("result.json")).unwrap())
            .unwrap();
    assert_eq!(body["complete"], false);
    assert_eq!(
        body["targets"][0]["summary"]["latency_mean_ms"],
        serde_json::Value::Null
    );
    assert!(directory.path.join("sections/tcp_scope.json").is_file());
}
