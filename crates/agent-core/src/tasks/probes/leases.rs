use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct AcceptedLease {
    pub(super) snapshot: sinan_protocol::ProbeLease,
    pub(super) received: Instant,
    pub(super) deadline: Instant,
    pub(super) session: Arc<PanelClient>,
}

impl AcceptedLease {
    pub(super) fn current(&self, client: Option<&Arc<PanelClient>>) -> bool {
        self.deadline > Instant::now()
            && client.is_some_and(|client| Arc::ptr_eq(client, &self.session))
    }

    pub(super) fn panel_time(&self) -> i64 {
        self.panel_millis() / 1000
    }

    pub(super) fn panel_millis(&self) -> i64 {
        // A panel may reuse an already issued lease. Map its remaining lifetime
        // to the receipt's monotonic clock rather than restarting at issued_at.
        let remaining = self
            .deadline
            .saturating_duration_since(self.received)
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let elapsed = self.received.elapsed().as_millis().min(i64::MAX as u128) as i64;
        self.snapshot
            .expires_at
            .saturating_mul(1000)
            .saturating_sub(remaining)
            .saturating_add(elapsed)
    }
}

#[derive(Default)]
pub(super) struct LeaseReceipts {
    accepted: HashMap<Uuid, AcceptedLease>,
}

impl LeaseReceipts {
    pub(super) fn accept(
        &mut self,
        snapshot: sinan_protocol::ProbeLease,
        server_id: i64,
        state: &SharedState,
        session: Arc<PanelClient>,
        request_started: Instant,
    ) -> Result<AcceptedLease> {
        // An intervening receipt must not forget the original deadline or bytes
        // of a lease that the panel can still legitimately repeat. Issuance is
        // monotonic in the durable high-water mark, so older expired receipts
        // can be dropped once a newer issuance passes their absolute expiry.
        let retained = self
            .accepted
            .values()
            .filter(|lease| lease.snapshot.expires_at > snapshot.issued_at)
            .count();
        ensure!(
            self.accepted.contains_key(&snapshot.id) || retained < 64,
            "too many live probe lease receipts"
        );
        let previous = self.accepted.get(&snapshot.id);
        let lease = accept_lease(
            snapshot,
            server_id,
            state,
            session,
            request_started,
            previous,
        )?;
        self.accepted
            .retain(|_, saved| saved.snapshot.expires_at > lease.snapshot.issued_at);
        self.accepted.insert(lease.snapshot.id, lease.clone());
        Ok(lease)
    }
}

#[derive(Serialize, Deserialize)]
struct HighWater {
    revision: u64,
    definitions: String,
    issued_at: i64,
}

pub(super) fn accept_lease(
    snapshot: sinan_protocol::ProbeLease,
    server_id: i64,
    state: &SharedState,
    session: Arc<PanelClient>,
    request_started: Instant,
    previous: Option<&AcceptedLease>,
) -> Result<AcceptedLease> {
    ensure!(snapshot.valid(), "invalid probe execution lease");
    ensure!(
        snapshot.server_id == server_id,
        "probe lease belongs to another device"
    );
    let received = Instant::now();
    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
    let panel_now =
        now_millis().saturating_add(state.get_json::<i64>("clock_offset_ms")?.unwrap_or(0)) / 1000;
    ensure!(
        snapshot.issued_at <= panel_now.saturating_add(5) && snapshot.expires_at > panel_now,
        "probe lease is expired or has a future issuance time"
    );
    let remaining = snapshot
        .expires_at
        .saturating_sub(panel_now)
        .min(snapshot.expires_at.saturating_sub(snapshot.issued_at));
    let mut deadline = request_started + Duration::from_secs(remaining as u64);
    if let Some(previous) = previous
        && previous.snapshot.id == snapshot.id
    {
        ensure!(
            previous.snapshot == snapshot,
            "probe lease identity was rewritten"
        );
        // Renewing a receipt may coincide with host clock or offset changes.
        // Its original monotonic execution deadline can only become shorter.
        deadline = deadline.min(previous.deadline);
    }
    ensure!(deadline > received, "probe lease expired during delivery");
    let mut definitions = snapshot.probes.clone();
    definitions.sort_by_key(|probe| probe.spec.id);
    let definitions = format!("{:x}", Sha256::digest(serde_json::to_vec(&definitions)?));
    let key = format!("probes:lease-high-water:{server_id}");
    if let Some(previous) = state.get_json::<HighWater>(&key)? {
        ensure!(
            snapshot.revision >= previous.revision,
            "probe configuration revision was rolled back"
        );
        ensure!(
            snapshot.revision != previous.revision || definitions == previous.definitions,
            "probe configuration changed without a new revision"
        );
        ensure!(
            snapshot.issued_at >= previous.issued_at,
            "probe lease issuance was rolled back"
        );
    }
    state.set_json(
        &key,
        &HighWater {
            revision: snapshot.revision,
            definitions,
            issued_at: snapshot.issued_at,
        },
    )?;
    Ok(AcceptedLease {
        snapshot,
        received,
        deadline,
        session,
    })
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ScheduleEntry {
    pub(super) last_started_at: i64,
    pub(super) interval_secs: u32,
}

pub(super) type Schedule = BTreeMap<Uuid, ScheduleEntry>;

pub(super) fn schedule(state: &SharedState) -> Result<Schedule> {
    let schedule = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
        .get_json::<Schedule>("probes:schedule")?
        .unwrap_or_default();
    ensure!(
        schedule.len() <= 32,
        "probe schedule exceeds its bounded retention"
    );
    ensure!(
        schedule.iter().all(|(id, entry)| !id.is_nil()
            && entry.last_started_at > 0
            && (10..=3600).contains(&entry.interval_secs)),
        "invalid persisted probe schedule"
    );
    Ok(schedule)
}

pub(super) fn record_start(
    state: &SharedState,
    lease: &AcceptedLease,
    spec: &ProbeSpec,
) -> Result<()> {
    let mut state = state
        .lock()
        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
    let mut schedule = state
        .get_json::<Schedule>("probes:schedule")?
        .unwrap_or_default();
    schedule.retain(|id, _| {
        lease
            .snapshot
            .probes
            .iter()
            .any(|probe| probe.spec.id == *id)
    });
    schedule.insert(
        spec.id,
        ScheduleEntry {
            last_started_at: lease.panel_time(),
            interval_secs: spec.interval_secs,
        },
    );
    ensure!(
        schedule.len() <= 32,
        "probe schedule exceeds its bounded retention"
    );
    state.set_json("probes:schedule", &schedule)
}
