use super::providers::ProviderRegistry;
use super::{
    CACHE_SECS, IpQuality, QualityDatabase, QueryAttempt, QueryError, QueryErrorKind,
    database_result, documentation_ip, public_ip,
};
use futures_util::{StreamExt, stream};
use reqwest::Client;
use sinan_protocol::now_timestamp;
use std::{
    collections::BTreeMap,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

type DatabaseRequest = Pin<Box<dyn Future<Output = (String, QualityDatabase)> + Send>>;

pub(super) async fn query_sources(
    client: &Client,
    registry: &ProviderRegistry,
    ips: &[String],
    allow_documentation_ips: bool,
    total_limit: Duration,
) -> Vec<IpQuality> {
    let now = now_timestamp();
    let attempts = Arc::new(Mutex::new(BTreeMap::new()));
    let mut requests: Vec<DatabaseRequest> = Vec::new();
    for ip in ips {
        for provider in registry.enabled() {
            for &(database, label) in provider.databases() {
                let client = client.clone();
                let provider = provider.clone();
                let ip = ip.clone();
                let attempts = attempts.clone();
                requests.push(Box::pin(async move {
                    let attempt = QueryAttempt::start();
                    attempts
                        .lock()
                        .expect("query attempt lock")
                        .insert((ip.clone(), provider.id(), database), attempt);
                    let result = if ip.parse::<IpAddr>().is_ok_and(|address| {
                        public_ip(address) || (allow_documentation_ips && documentation_ip(address))
                    }) {
                        provider.query(&client, &ip, database).await
                    } else {
                        Err(QueryError::new(
                            QueryErrorKind::NotPublic,
                            "此地址不属于公网单播 IP，未向第三方查询",
                        ))
                    };
                    let mut entry = database_result(database, label, &ip, Some(attempt), result);
                    entry.provider = provider.id().into();
                    (ip, entry)
                }));
            }
        }
    }
    let mut pending = stream::iter(requests).buffer_unordered(4);
    let mut results = Vec::new();
    let deadline = tokio::time::Instant::now() + total_limit;
    while let Ok(Some(result)) = tokio::time::timeout_at(deadline, pending.next()).await {
        results.push(result);
    }
    let results = &results;
    let attempts = &attempts;
    ips.iter()
        .flat_map(|ip| {
            registry.enabled().map(move |provider| {
                let databases: Vec<_> = provider
                    .databases()
                    .iter()
                    .map(|&(database, label)| {
                        results
                            .iter()
                            .find(|(address, entry)| {
                                address == ip
                                    && entry.provider == provider.id()
                                    && entry.database == database
                            })
                            .map(|(_, entry)| entry.clone())
                            .unwrap_or_else(|| {
                                let attempt = attempts
                                    .lock()
                                    .expect("query attempt lock")
                                    .get(&(ip.clone(), provider.id(), database))
                                    .copied();
                                let mut entry = database_result(
                                    database,
                                    label,
                                    ip,
                                    attempt,
                                    Err(QueryError::new(
                                        if attempt.is_some() {
                                            QueryErrorKind::Timeout
                                        } else {
                                            QueryErrorKind::NotAttempted
                                        },
                                        if attempt.is_some() {
                                            "质量查询超过总时间限制"
                                        } else {
                                            "查询批次超过总时间限制，此响应视图尚未开始查询"
                                        },
                                    )),
                                );
                                entry.provider = provider.id().into();
                                entry
                            })
                    })
                    .collect();
                let succeeded = databases
                    .iter()
                    .filter(|entry| entry.status == "succeeded")
                    .count();
                let status = if succeeded == 0 {
                    "failed"
                } else if succeeded == databases.len() {
                    "succeeded"
                } else {
                    "partial"
                };
                let last_attempt_at = databases
                    .iter()
                    .filter_map(|database| database.attempted_at)
                    .max();
                IpQuality {
                    ip: ip.clone(),
                    checked_at: now,
                    expires_at: now + CACHE_SECS,
                    status: status.into(),
                    databases,
                    provider: provider.id().into(),
                    last_attempt_at,
                    last_success_at: None,
                    fresh_until: None,
                    last_error: BTreeMap::new(),
                }
            })
        })
        .collect()
}
