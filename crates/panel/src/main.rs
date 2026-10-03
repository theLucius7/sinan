#![forbid(unsafe_code)]

use sinan_panel::{AppState, config::Config, maintenance::supervise, router};
use sqlx::{PgPool, postgres::PgPoolOptions};

async fn telemetry_history(pool: PgPool) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(60));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let result = sinan_panel::telemetry::maintain(&pool).await;
        let status = if result.is_ok() { "healthy" } else { "failed" };
        if let Err(error) = result {
            tracing::warn!(%error, "telemetry history maintenance failed");
        }
        if let Err(error) = sinan_panel::control_center::system::heartbeat(
            &pool,
            "telemetry-history",
            status,
            serde_json::json!({"source":"history-maintenance-cycle"}),
        )
        .await
        {
            tracing::warn!(%error,"telemetry worker heartbeat failed");
        }
    }
}

async fn network_workbench(state: AppState) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let result = sinan_panel::network_workbench::tick(&state).await;
        let status = if result.is_ok() { "healthy" } else { "failed" };
        if let Err(error) = result {
            tracing::warn!(%error,"network workbench dispatch failed");
        }
        if let Err(error) = sinan_panel::control_center::system::heartbeat(
            &state.pool,
            "network-workbench",
            status,
            serde_json::json!({"source":"dispatch-cycle"}),
        )
        .await
        {
            tracing::warn!(%error,"network workbench heartbeat failed");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let config = Config::from_env()?;
    let listen = config.listen;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    let state = AppState::new(pool, config).await?;
    let recovery_verified = match std::env::var("SINAN_RECOVERY_VERIFY_CREDENTIALS") {
        Ok(value) if value == "true" => {
            let count =
                sinan_panel::control_center::credentials::verify_recovery_material(&state.pool)
                    .await?;
            tracing::info!(
                verified_credentials = count,
                "restored credential material authenticated"
            );
            true
        }
        Ok(value) if value == "false" => false,
        Err(std::env::VarError::NotPresent) => false,
        _ => anyhow::bail!("SINAN_RECOVERY_VERIFY_CREDENTIALS must be true or false"),
    };
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(address = %listener.local_addr()?, "panel started");
    // Background loops are supervised so a panic restarts them instead of
    // silently stopping alerts, renewals, publication or history maintenance.
    let maintenance = tokio::spawn(supervise("maintenance", {
        let state = state.clone();
        move || sinan_panel::maintenance::run(state.clone())
    }));
    let exchange = tokio::spawn(supervise("exchange-rates", {
        let pool = state.pool.clone();
        move || sinan_panel::exchange::run(pool.clone())
    }));
    let telemetry = tokio::spawn(supervise("telemetry-history", {
        let pool = state.pool.clone();
        move || telemetry_history(pool.clone())
    }));
    let plugins = tokio::spawn(sinan_panel::plugins::run(state.clone()));
    let control_center = tokio::spawn(supervise("control-center", {
        let state = state.clone();
        move || sinan_panel::control_center::run(state.clone())
    }));
    let operations = tokio::spawn(supervise("operations", {
        let state = state.clone();
        move || sinan_panel::operations::run(state.clone())
    }));
    let network = tokio::spawn(supervise("network-workbench", {
        let state = state.clone();
        move || network_workbench(state.clone())
    }));
    let certificates = tokio::spawn(supervise("network-certificates", {
        let state = state.clone();
        move || sinan_panel::network_configuration::run(state.clone())
    }));
    let mut application = router(state);
    if recovery_verified {
        application = application.layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                let health_request = request.uri().path() == "/healthz";
                let mut response = next.run(request).await;
                if health_request && response.status().is_success() {
                    response.headers_mut().insert(
                        "x-sinan-recovery-material-verified",
                        axum::http::HeaderValue::from_static("true"),
                    );
                }
                response
            },
        ));
    }
    let result = axum::serve(
        listener,
        application.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await;
    maintenance.abort();
    exchange.abort();
    telemetry.abort();
    plugins.abort();
    control_center.abort();
    operations.abort();
    network.abort();
    certificates.abort();
    result?;
    Ok(())
}
