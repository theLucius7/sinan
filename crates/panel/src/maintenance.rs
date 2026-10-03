use crate::AppState;
use std::{future::Future, time::Duration};

const RESTART_DELAY: Duration = Duration::from_secs(5);

/// Aborts the supervised attempt when its supervisor is cancelled at shutdown.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keeps a long-running background loop alive for the lifetime of the panel.
///
/// Each attempt runs in its own task so a panic is observed here instead of
/// silently ending the work while HTTP requests continue to be served. The
/// loops keep their durable state in PostgreSQL, so a restart resumes them.
pub async fn supervise<F, Fut>(name: &'static str, start: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    supervise_with(name, RESTART_DELAY, start).await
}

async fn supervise_with<F, Fut>(name: &'static str, delay: Duration, mut start: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        let attempt = tokio::spawn(start());
        let _abort = AbortOnDrop(attempt.abort_handle());
        match attempt.await {
            Ok(()) => tracing::error!(task = name, "background task stopped; restarting"),
            Err(error) if error.is_panic() => {
                tracing::error!(task = name, "background task panicked; restarting")
            }
            Err(_) => return,
        }
        tokio::time::sleep(delay).await;
    }
}

pub async fn run(state: AppState) {
    let mut poll = tokio::time::interval(Duration::from_secs(30));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        poll.tick().await;
        if let Err(error) = crate::diagnostics::expire(&state).await {
            tracing::error!(%error, "diagnostic expiry cleanup failed");
        }
        if let Err(error) =
            crate::server_assets::renew_due(&state.pool, sinan_protocol::now_timestamp()).await
        {
            tracing::error!(%error, "server expiry renewal failed");
        }
        if let Err(error) =
            crate::auth::purge_expired_sessions(&state.pool, sinan_protocol::now_timestamp()).await
        {
            tracing::error!(%error, "expired session cleanup failed");
        }
        let now = sinan_protocol::now_timestamp();
        if let Err(error) = crate::notifications::evaluate(&state.pool, state.started_at, now).await
        {
            tracing::error!(%error, "server alert evaluation failed");
        }
        if let Err(error) = crate::notifications::dispatch(&state.pool, now).await {
            tracing::error!(%error, "notification delivery failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::supervise_with;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    const DELAY: Duration = Duration::from_millis(10);

    #[tokio::test]
    async fn panicking_and_returning_attempts_are_restarted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let supervisor = tokio::spawn(supervise_with("fixture", DELAY, move || {
            let counter = counter.clone();
            async move {
                match counter.fetch_add(1, Ordering::SeqCst) {
                    0 => panic!("fixture panic"),
                    1 => {}
                    _ => std::future::pending().await,
                }
            }
        }));
        tokio::time::timeout(Duration::from_secs(10), async {
            while attempts.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(DELAY).await;
            }
        })
        .await
        .expect("panicked and returned attempts must be restarted");
        tokio::time::sleep(DELAY * 5).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn cancelling_the_supervisor_stops_the_running_attempt() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
        let (started, ready) = tokio::sync::oneshot::channel::<()>();
        let mut started = Some(started);
        let supervisor = tokio::spawn(supervise_with("fixture", DELAY, move || {
            let sender = sender.clone();
            let started = started.take();
            async move {
                let _held = sender;
                if let Some(started) = started {
                    let _ = started.send(());
                }
                std::future::pending::<()>().await
            }
        }));
        ready.await.unwrap();
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        // The attempt held the last sender; aborting it with its supervisor closes the channel.
        assert!(
            tokio::time::timeout(Duration::from_secs(5), receiver.recv())
                .await
                .expect("the supervised attempt must be aborted with its supervisor")
                .is_none()
        );
    }
}
