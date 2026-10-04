use crate::{SharedState, artifacts::PanelClient};
use anyhow::{Result, ensure};
use sinan_adapter_sdk::{Privileged, TerminalProcess};
use sinan_protocol::fleet::{AccessPolicy, TerminalControl, TerminalEvent};
use std::{
    collections::{HashMap, hash_map::Entry},
    time::{Duration, Instant},
};
use uuid::Uuid;

struct Session {
    account: String,
    process: Option<Box<dyn TerminalProcess>>,
    sequence: i64,
    input_sequence: i64,
    expires_at: i64,
    pending: Option<TerminalEvent>,
    final_state: Option<(String, Option<String>)>,
    finished: bool,
    closing: bool,
}

impl Session {
    async fn stop(&mut self, id: Uuid) {
        self.closing = true;
        let Some(process) = self.process.as_mut() else {
            return;
        };
        let result = tokio::time::timeout(Duration::from_secs(8), process.close()).await;
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => {
                Some("terminal cleanup deadline exceeded; identity retained for recovery".into())
            }
        };
        if error.is_none() {
            self.process = None;
            self.finished = true;
        }
        let outcome = (
            if error.is_none() { "closed" } else { "failed" }.to_owned(),
            error,
        );
        if self.pending.is_some() {
            self.final_state = Some(outcome);
        } else {
            self.pending = Some(TerminalEvent {
                id,
                sequence: self.sequence + 1,
                input_sequence: self.input_sequence,
                output: String::new(),
                state: outcome.0,
                error: outcome.1,
            });
        }
    }
    fn revoked(&self, control: &TerminalControl, local: &AccessPolicy) -> bool {
        self.closing
            || control.close_requested
            || self.account != control.account
            || self.expires_at <= sinan_protocol::now_timestamp()
            || control.expires_at <= sinan_protocol::now_timestamp()
            || !local.terminal_accounts.contains(&self.account)
            || !control.policy.terminal_accounts.contains(&self.account)
    }
}
#[derive(Default)]
pub(super) struct Sessions {
    active: HashMap<Uuid, Session>,
    disconnected: Option<Instant>,
}
impl Sessions {
    pub(super) fn connected(&mut self) {
        self.disconnected = None;
    }
    pub(super) fn has_live(&self) -> bool {
        self.active.values().any(|session| !session.finished)
    }
    pub(super) async fn disconnect(&mut self) {
        if self.disconnected.get_or_insert_with(Instant::now).elapsed() > Duration::from_secs(10) {
            self.close_all().await;
        }
    }
    pub(super) async fn close_all(&mut self) {
        futures_util::future::join_all(
            self.active
                .iter_mut()
                .map(|(id, session)| session.stop(*id)),
        )
        .await;
    }
    pub(super) async fn enforce_local(&mut self, local: &AccessPolicy) {
        futures_util::future::join_all(
            self.active
                .iter_mut()
                .filter(|(_, session)| {
                    session.closing
                        || session.expires_at <= sinan_protocol::now_timestamp()
                        || !local.terminal_accounts.contains(&session.account)
                })
                .map(|(id, session)| session.stop(*id)),
        )
        .await;
    }
    async fn enforce_controls(&mut self, controls: &[TerminalControl], local: &AccessPolicy) {
        futures_util::future::join_all(
            self.active
                .iter_mut()
                .filter(|(id, session)| {
                    controls
                        .iter()
                        .find(|control| control.id == **id)
                        .is_none_or(|control| session.revoked(control, local))
                })
                .map(|(id, session)| session.stop(*id)),
        )
        .await;
        self.active.retain(|id, session| {
            session.process.is_some() || controls.iter().any(|control| control.id == *id)
        });
    }
    pub(super) async fn tick(
        &mut self,
        controls: &[TerminalControl],
        local: &AccessPolicy,
        ops: &dyn Privileged,
        state: &SharedState,
        client: &PanelClient,
    ) -> Result<()> {
        // Stop every revoked or omitted process before an event POST can fail.
        self.enforce_controls(controls, local).await;
        for control in controls {
            if let Entry::Vacant(entry) = self.active.entry(control.id) {
                let already_seen = {
                    state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
                        .get_json::<Vec<Uuid>>("fleet_terminal_seen")?
                        .unwrap_or_default()
                        .contains(&control.id)
                };
                let allowed = local.terminal_accounts.contains(&control.account)
                    && control.policy.terminal_accounts.contains(&control.account)
                    && !control.close_requested
                    && control.expires_at > sinan_protocol::now_timestamp()
                    && !already_seen;
                let opened = if allowed {
                    ops.open_terminal(&control.account, control.columns, control.rows)
                        .await
                } else {
                    Err(anyhow::anyhow!(
                        "session expired, revoked, closed or interrupted by Agent restart"
                    ))
                };
                let (process, pending, finished) = match opened {
                    Ok(process) => (Some(process), None, false),
                    Err(error) => (
                        None,
                        Some(TerminalEvent {
                            id: control.id,
                            sequence: control.output_sequence + 1,
                            input_sequence: 0,
                            output: String::new(),
                            state: "failed".into(),
                            error: Some(error.to_string()),
                        }),
                        true,
                    ),
                };
                {
                    let mut durable = state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
                    let mut seen = durable
                        .get_json::<Vec<Uuid>>("fleet_terminal_seen")?
                        .unwrap_or_default();
                    if !seen.contains(&control.id) {
                        seen.push(control.id);
                    }
                    if seen.len() > 256 {
                        seen.drain(..seen.len() - 256);
                    }
                    durable.set_json("fleet_terminal_seen", &seen)?;
                }
                entry.insert(Session {
                    account: control.account.clone(),
                    process,
                    sequence: control.output_sequence,
                    input_sequence: 0,
                    expires_at: control.expires_at,
                    pending,
                    final_state: None,
                    finished,
                    closing: false,
                });
            }
            let session = self
                .active
                .get_mut(&control.id)
                .expect("registered session");
            if let Some(pending) = &session.pending {
                tokio::time::timeout(
                    Duration::from_secs(2),
                    client.post_json::<serde_json::Value>(
                        "/api/agent/v1/fleet/terminal-events",
                        pending,
                    ),
                )
                .await??;
                session.sequence = pending.sequence;
                session.pending = None;
            }
            if let Some((state, error)) = session.final_state.take() {
                session.pending = Some(TerminalEvent {
                    id: control.id,
                    sequence: session.sequence + 1,
                    input_sequence: session.input_sequence,
                    output: String::new(),
                    state,
                    error,
                });
                continue;
            }
            if session.finished {
                continue;
            }
            if session.closing {
                continue;
            }
            let close = session.revoked(control, local);
            let mut output = String::new();
            let mut ended = false;
            let mut error = None;
            if let Some(process) = session.process.as_mut() {
                if close {
                    ended = true;
                } else {
                    let inputs: Vec<_> = control
                        .inputs
                        .iter()
                        .filter(|input| input.sequence > session.input_sequence)
                        .collect();
                    for input in inputs {
                        if let Err(failure) = tokio::time::timeout(
                            Duration::from_secs(1),
                            process.input(&input.data, input.columns, input.rows),
                        )
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|result| result)
                        {
                            error = Some(failure.to_string());
                            ended = true;
                            break;
                        }
                        session.input_sequence = input.sequence;
                    }
                    if !ended {
                        match tokio::time::timeout(Duration::from_millis(30), process.read()).await
                        {
                            Ok(Ok(Some(data))) => output = data,
                            Ok(Ok(None)) => ended = true,
                            Ok(Err(failure)) => {
                                error = Some(failure.to_string());
                                ended = true;
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            ensure!(output.len() <= 32768, "PTY output exceeded per-frame limit");
            if ended {
                session.stop(control.id).await;
                if error.is_some() {
                    session.final_state = Some(("failed".into(), error));
                }
                continue;
            }
            session.pending = Some(TerminalEvent {
                id: control.id,
                sequence: session.sequence + 1,
                input_sequence: session.input_sequence,
                output,
                state: if error.is_some() {
                    "failed"
                } else if ended {
                    "closed"
                } else {
                    "running"
                }
                .into(),
                error,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sinan_adapter_sdk::BoxFuture;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Process {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }
    impl TerminalProcess for Process {
        fn read(&mut self) -> BoxFuture<'_, Option<String>> {
            Box::pin(async { Ok(Some(String::new())) })
        }
        fn input<'a>(
            &'a mut self,
            _data: &'a str,
            _columns: Option<u16>,
            _rows: Option<u16>,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
        fn close(&mut self) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.fail {
                    anyhow::bail!("TEST_ONLY cleanup unconfirmed");
                }
                Ok(())
            })
        }
    }
    fn session(calls: Arc<AtomicUsize>, fail: bool) -> Session {
        Session {
            account: "operator".into(),
            process: Some(Box::new(Process { calls, fail })),
            sequence: 0,
            input_sequence: 0,
            expires_at: sinan_protocol::now_timestamp() + 60,
            pending: Some(TerminalEvent {
                id: Uuid::nil(),
                sequence: 1,
                input_sequence: 0,
                output: "undelivered".into(),
                state: "running".into(),
                error: None,
            }),
            final_state: None,
            finished: false,
            closing: false,
        }
    }
    #[tokio::test]
    async fn local_revocation_stops_before_pending_delivery_and_retains_failure_identity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut sessions = Sessions::default();
        sessions
            .active
            .insert(Uuid::nil(), session(calls.clone(), true));
        sessions.enforce_local(&AccessPolicy::default()).await;
        let current = sessions.active.get(&Uuid::nil()).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(current.process.is_some() && current.closing && !current.finished);
        assert_eq!(current.pending.as_ref().unwrap().output, "undelivered");
        assert_eq!(current.final_state.as_ref().unwrap().0, "failed");
    }
    #[tokio::test]
    async fn omitted_control_stops_before_delivery_and_does_not_forget_failed_cleanup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut sessions = Sessions::default();
        sessions
            .active
            .insert(Uuid::nil(), session(calls.clone(), true));
        sessions
            .enforce_controls(&[], &AccessPolicy::default())
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(sessions.active.get(&Uuid::nil()).unwrap().process.is_some());
    }
    #[tokio::test]
    async fn unsuccessful_polling_does_not_reset_disconnect_grace() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut sessions = Sessions::default();
        sessions
            .active
            .insert(Uuid::nil(), session(calls.clone(), false));
        sessions.disconnected = Some(Instant::now() - Duration::from_secs(11));
        sessions.disconnect().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(sessions.active.get(&Uuid::nil()).unwrap().finished);
        assert!(sessions.disconnected.is_some());
        sessions.connected();
        assert!(sessions.disconnected.is_none());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn rejected_event_post_cannot_postpone_remote_close_or_local_revocation() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut bytes = [0u8; 32768];
                let _ = connection.read(&mut bytes).await;
                let _ = connection
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        let client = PanelClient::new(&origin, "TEST_ONLY_fleet_session").unwrap();
        let state = Arc::new(std::sync::Mutex::new(
            crate::state::State::open(std::path::Path::new(":memory:")).unwrap(),
        ));
        for remote_close in [true, false] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut sessions = Sessions::default();
            sessions
                .active
                .insert(Uuid::nil(), session(calls.clone(), false));
            let remote = AccessPolicy {
                terminal_accounts: vec!["operator".into()],
                ..AccessPolicy::default()
            };
            let local = if remote_close {
                remote.clone()
            } else {
                AccessPolicy::default()
            };
            let control = TerminalControl {
                id: Uuid::nil(),
                account: "operator".into(),
                policy: remote,
                columns: 80,
                rows: 24,
                expires_at: sinan_protocol::now_timestamp() + 60,
                close_requested: remote_close,
                output_sequence: 0,
                inputs: Vec::new(),
            };
            assert!(
                sessions
                    .tick(
                        &[control],
                        &local,
                        &crate::system::SystemOps,
                        &state,
                        &client
                    )
                    .await
                    .is_err()
            );
            let current = sessions.active.get(&Uuid::nil()).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(current.finished && current.process.is_none());
            assert_eq!(current.pending.as_ref().unwrap().output, "undelivered");
            assert_eq!(current.final_state.as_ref().unwrap().0, "closed");
        }
        server.abort();
    }
}
