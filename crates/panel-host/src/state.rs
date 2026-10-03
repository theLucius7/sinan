use crate::{auth, config::Config, ip_quality, telemetry};
use sinan_protocol::Envelope;
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use uuid::Uuid;

#[derive(Clone)]
pub struct AgentConnection {
    pub id: Uuid,
    pub sender: mpsc::Sender<Envelope>,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub started_at: i64,
    pub login_permits: Arc<Semaphore>,
    pub passkeys: Arc<crate::passkeys::Service>,
    pub quality_permits: Arc<Semaphore>,
    pub quality_providers: Arc<ip_quality::ProviderRegistry>,
    pub release_permits: Arc<Semaphore>,
    pub release_keys: Option<Arc<sinan_protocol::release::TrustedKeys>>,
    pub config: Arc<Config>,
    pub connections: Arc<RwLock<HashMap<i64, AgentConnection>>>,
    pub device_lifecycle: Arc<Mutex<()>>,
    pub telemetry_live: Arc<telemetry::LiveStore>,
}

impl AppState {
    pub async fn new(pool: PgPool, config: Config) -> anyhow::Result<Self> {
        sqlx::migrate!("../panel/migrations").run(&pool).await?;
        auth::ensure_admin(&pool, config.admin_password.as_deref()).await?;
        Ok(Self {
            pool,
            started_at: sinan_protocol::now_timestamp(),
            login_permits: Arc::new(Semaphore::new(4)),
            passkeys: Arc::new(crate::passkeys::Service::new(&config.public_url)),
            quality_permits: Arc::new(Semaphore::new(2)),
            quality_providers: Arc::new(ip_quality::ProviderRegistry::from_env()),
            release_permits: Arc::new(Semaphore::new(1)),
            release_keys: sinan_protocol::release::TrustedKeys::compiled()
                .ok()
                .map(Arc::new),
            config: Arc::new(config),
            connections: Arc::default(),
            device_lifecycle: Arc::default(),
            telemetry_live: Arc::default(),
        })
    }
}
