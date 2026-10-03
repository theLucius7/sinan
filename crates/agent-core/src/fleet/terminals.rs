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
    process: Option<Box<dyn TerminalProcess>>,
    sequence: i64,
    input_sequence: i64,
    expires_at: i64,
    pending: Option<TerminalEvent>,
    final_state: Option<(String, Option<String>)>,
    finished: bool,
}
#[derive(Default)]
pub(super) struct Sessions {
    active: HashMap<Uuid, Session>,
    disconnected: Option<Instant>,
}
impl Sessions {
    pub(super) fn has_live(&self) -> bool {
        self.active.values().any(|session| !session.finished)
    }
    pub(super) async fn disconnect(&mut self) {
        if self.disconnected.get_or_insert_with(Instant::now).elapsed() > Duration::from_secs(10) {
            self.close_all().await;
        }
    }
    pub(super) async fn close_all(&mut self) {
        for (id, session) in &mut self.active {
            if let Some(mut process) = session.process.take() {
                let result = process.close().await;
                session.finished = true;
                let outcome = (
                    if result.is_ok() { "closed" } else { "failed" }.to_owned(),
                    result.err().map(|error| error.to_string()),
                );
                if session.pending.is_some() {
                    session.final_state = Some(outcome);
                } else {
                    session.pending = Some(TerminalEvent {
                        id: *id,
                        sequence: session.sequence + 1,
                        input_sequence: session.input_sequence,
                        output: String::new(),
                        state: outcome.0,
                        error: outcome.1,
                    });
                }
            }
        }
    }
    pub(super) async fn tick(
        &mut self,
        controls: &[TerminalControl],
        local: &AccessPolicy,
        ops: &dyn Privileged,
        state: &SharedState,
        client: &PanelClient,
    ) -> Result<()> {
        self.disconnected = None;
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
                    process,
                    sequence: control.output_sequence,
                    input_sequence: 0,
                    expires_at: control.expires_at,
                    pending,
                    final_state: None,
                    finished,
                });
            }
            let session = self
                .active
                .get_mut(&control.id)
                .expect("registered session");
            if let Some(pending) = &session.pending {
                client
                    .post_json::<serde_json::Value>("/api/agent/v1/fleet/terminal-events", pending)
                    .await?;
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
            let close = control.close_requested
                || session.expires_at <= sinan_protocol::now_timestamp()
                || !local.terminal_accounts.contains(&control.account);
            let mut output = String::new();
            let mut ended = false;
            let mut error = None;
            if let Some(process) = session.process.as_mut() {
                if close {
                    match process.close().await {
                        Ok(()) => {}
                        Err(failure) => error = Some(failure.to_string()),
                    };
                    ended = true;
                } else {
                    let inputs: Vec<_> = control
                        .inputs
                        .iter()
                        .filter(|input| input.sequence > session.input_sequence)
                        .collect();
                    for input in inputs {
                        if let Err(failure) =
                            process.input(&input.data, input.columns, input.rows).await
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
                    if ended && let Err(failure) = process.close().await {
                        error = Some(failure.to_string());
                    }
                }
            }
            ensure!(output.len() <= 32768, "PTY output exceeded per-frame limit");
            if ended {
                session.process = None;
                session.finished = true;
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
        let missing: Vec<_> = self
            .active
            .keys()
            .filter(|id| !controls.iter().any(|control| control.id == **id))
            .copied()
            .collect();
        for id in missing {
            if let Some(mut session) = self.active.remove(&id)
                && let Some(process) = session.process.as_mut()
            {
                process.close().await?;
            }
        }
        Ok(())
    }
}
