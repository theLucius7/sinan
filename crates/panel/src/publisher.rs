//! Compatibility entry points for embedders using the previous public API.
pub use crate::plugins::singbox::publisher::publish_due;

pub async fn run(state: crate::AppState) {
    let maintenance = state.clone();
    tokio::join!(
        crate::maintenance::supervise("maintenance", move || {
            crate::maintenance::run(maintenance.clone())
        }),
        crate::plugins::run(state)
    );
}
