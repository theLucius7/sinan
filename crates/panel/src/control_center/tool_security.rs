use super::{require_owner, require_recent_proof};
use crate::{
    AppState,
    error::{ApiError, ApiResult},
};
use axum::{Json, extract::State, http::HeaderMap};
use futures_util::StreamExt;
use serde_json::{Value, json};
use sinan_protocol::now_timestamp;
use sqlx::Row;
use std::collections::BTreeSet;
use std::time::Duration;

const OSV: &str = "https://api.osv.dev/v1";
const LIMIT: usize = 512 * 1024;
fn packages() -> Vec<Value> {
    serde_json::from_str(include_str!(concat!(
        env!("OUT_DIR"),
        "/dependency-inventory.json"
    )))
    .expect("compiled dependency inventory")
}

fn add_signed_tools(packages: &mut Vec<Value>, entries: &[crate::artifacts::ArtifactEntry]) {
    let versions: BTreeSet<_> = entries
        .iter()
        .filter(|entry| entry.name == "sing-box")
        .map(|entry| entry.version.clone())
        .collect();
    packages.extend(versions.into_iter().map(|version|json!({"name":"github.com/sagernet/sing-box","version":version,"ecosystem":"Go","scope":"available-signed-artifact"})));
}
fn supported(package: &Value) -> bool {
    matches!(package["ecosystem"].as_str(), Some("crates.io" | "Go"))
}

pub async fn inventory(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    let rows = sqlx::query("SELECT * FROM tool_advisory_observations")
        .fetch_all(&state.pool)
        .await?;
    let now = now_timestamp();
    let mut dependencies = packages();
    let signed = match tokio::time::timeout(
        Duration::from_secs(5),
        crate::releases::entries(&state),
    )
    .await
    {
        Ok(Ok(entries)) => {
            add_signed_tools(&mut dependencies, &entries);
            json!({"status":if entries.is_empty(){"empty"}else{"verified"},"entries":entries,"source":"local-signed-artifact-inventory"})
        }
        _ => json!({"status":"unknown","reason":"本地签名制品库存不可用或读取超时"}),
    };
    for package in &mut dependencies {
        let cached = rows.iter().find(|row| {
            row.get::<String, _>("name") == package["name"]
                && row.get::<String, _>("version") == package["version"]
                && row.get::<String, _>("ecosystem") == package["ecosystem"]
        });
        package["advisories"] = cached.map(|row| json!({"status":row.get::<String,_>("status"),
            "checked_at":row.get::<i64,_>("checked_at"),"observed_at":row.get::<Option<i64>,_>("observed_at"),
            "stale":row.get::<Option<i64>,_>("observed_at").is_none_or(|observed|now-observed>86400),"evidence":row.get::<Value,_>("evidence"),
            "error":row.get::<Option<String>,_>("error")})).unwrap_or_else(||json!({"status":"unknown","reason":"尚未查询此精确包版本"}));
    }
    Ok(Json(
        json!({"dependencies":dependencies,"signed_tools":signed,"source":"workspace-Cargo.lock-snapshot",
        "advisory_source":OSV,"automatic_upgrade":false,"query_limit":512,
        "limitations":"工具签名及适配兼容性分别核对。OSV 只查询支持的生态；未记录建议不代表没有风险，修复版本不代表可以直接升级。"}),
    ))
}

async fn bounded_json(response: reqwest::Response) -> anyhow::Result<Value> {
    anyhow::ensure!(
        response.status().is_success(),
        "official advisory API returned non-success status"
    );
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= LIMIT as u64),
        "advisory response limit exceeded"
    );
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            chunk.len() <= LIMIT.saturating_sub(bytes.len()),
            "advisory response limit exceeded"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn vulnerability_ids(result: &Value) -> anyhow::Result<Vec<String>> {
    let object = result
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid advisory result"))?;
    anyhow::ensure!(
        !object.contains_key("error"),
        "individual advisory query failed"
    );
    let Some(vulns) = object.get("vulns") else {
        return Ok(Vec::new());
    };
    let vulns = vulns
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid advisory list"))?;
    anyhow::ensure!(vulns.len() <= 128, "advisory list limit exceeded");
    vulns
        .iter()
        .map(|item| {
            let id = item["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing advisory identity"))?;
            anyhow::ensure!(
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'.' | b'_')),
                "invalid advisory identity"
            );
            Ok(id.to_owned())
        })
        .collect()
}
fn detail(package: &Value, value: &Value) -> Value {
    let mut fixed = BTreeSet::new();
    for affected in value["affected"].as_array().into_iter().flatten().take(128) {
        if affected["package"]["name"] != package["name"]
            || affected["package"]["ecosystem"] != package["ecosystem"]
        {
            continue;
        }
        for range in affected["ranges"]
            .as_array()
            .into_iter()
            .flatten()
            .take(128)
        {
            for event in range["events"].as_array().into_iter().flatten().take(128) {
                if let Some(version) = event["fixed"]
                    .as_str()
                    .filter(|version| version.len() <= 128)
                {
                    fixed.insert(version.to_owned());
                }
            }
        }
    }
    json!({"id":value["id"],"summary":value["summary"].as_str().unwrap_or("").chars().take(512).collect::<String>(),
        "modified":value["modified"],"withdrawn":value["withdrawn"],"fixed_versions":fixed,
        "fixed_source":"OSV affected package range events","compatibility_verified":false})
}
async fn record(
    state: &AppState,
    package: &Value,
    status: &str,
    evidence: Value,
    error: Option<&str>,
) -> ApiResult<()> {
    sqlx::query("INSERT INTO tool_advisory_observations(ecosystem,name,version,status,checked_at,observed_at,evidence,error) VALUES($1,$2,$3,$4,$5,CASE WHEN $6::text IS NULL THEN $5 END,$7,$6) ON CONFLICT(ecosystem,name,version) DO UPDATE SET status=EXCLUDED.status,checked_at=EXCLUDED.checked_at,observed_at=COALESCE(EXCLUDED.observed_at,tool_advisory_observations.observed_at),evidence=CASE WHEN EXCLUDED.error IS NULL THEN EXCLUDED.evidence ELSE tool_advisory_observations.evidence END,error=EXCLUDED.error")
        .bind(package["ecosystem"].as_str().unwrap_or("")).bind(package["name"].as_str().unwrap_or(""))
        .bind(package["version"].as_str().unwrap_or("")).bind(status).bind(now_timestamp()).bind(error).bind(evidence)
        .execute(&state.pool).await?;
    Ok(())
}

pub async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_owner(&state, &headers).await?;
    require_recent_proof(&state, &headers).await?;
    let mut lease = state.pool.begin().await?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(73002112)")
        .fetch_one(&mut *lease)
        .await?;
    if !acquired {
        return Err(ApiError::Busy);
    }
    let last: Option<i64> =
        sqlx::query_scalar("SELECT max(checked_at) FROM tool_advisory_observations")
            .fetch_one(&mut *lease)
            .await?;
    if last.is_some_and(|last| now_timestamp() - last < 300) {
        return Err(ApiError::Conflict(
            "此安全建议查询刚执行过，请五分钟后再试；可以先查看已保存来源结果".into(),
        ));
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .https_only(true)
        .build()
        .map_err(anyhow::Error::from)?;
    let mut all = packages();
    if let Ok(Ok(entries)) =
        tokio::time::timeout(Duration::from_secs(5), crate::releases::entries(&state)).await
    {
        add_signed_tools(&mut all, &entries);
    }
    let selected: Vec<_> = all
        .iter()
        .filter(|package| supported(package))
        .take(512)
        .cloned()
        .collect();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut observed = 0;
    let mut unknown = 0;
    let mut detail_budget = 32usize;
    for batch in selected.chunks(100) {
        let queries:Vec<_>=batch.iter().map(|package|json!({"package":{"name":package["name"],"ecosystem":package["ecosystem"]},"version":package["version"]})).collect();
        let query = async {
            bounded_json(
                client
                    .post(format!("{OSV}/querybatch"))
                    .json(&json!({"queries":queries}))
                    .send()
                    .await?,
            )
            .await
        };
        let results = match tokio::time::timeout_at(deadline, query).await {
            Ok(Ok(value)) => value["results"]
                .as_array()
                .filter(|rows| rows.len() == batch.len())
                .cloned(),
            _ => None,
        };
        let Some(results) = results else {
            for package in batch {
                record(
                    &state,
                    package,
                    "lookup-error",
                    Value::Null,
                    Some("官方查询失败、超时或返回结构无效；保留上次证据"),
                )
                .await?;
                unknown += 1;
            }
            continue;
        };
        for (package, result) in batch.iter().zip(results) {
            let ids = match vulnerability_ids(&result) {
                Ok(ids) => ids,
                Err(_) => {
                    record(
                        &state,
                        package,
                        "lookup-error",
                        Value::Null,
                        Some("官方建议身份或结构无效；保留上次证据"),
                    )
                    .await?;
                    unknown += 1;
                    continue;
                }
            };
            let mut details = Vec::new();
            let mut incomplete = false;
            for id in &ids {
                if detail_budget == 0 {
                    incomplete = true;
                    break;
                }
                detail_budget -= 1;
                let query = async {
                    bounded_json(client.get(format!("{OSV}/vulns/{id}")).send().await?).await
                };
                match tokio::time::timeout_at(deadline, query).await {
                    Ok(Ok(value)) if value["id"].as_str() == Some(id) => {
                        details.push(detail(package, &value))
                    }
                    _ => incomplete = true,
                }
            }
            let status = if ids.is_empty() {
                "no-recorded-advisory"
            } else if incomplete {
                "advisories-incomplete"
            } else {
                "advisories-recorded"
            };
            record(
                &state,
                package,
                status,
                json!({"source":OSV,"ids":ids,"details":details,"details_incomplete":incomplete}),
                None,
            )
            .await?;
            observed += 1;
        }
    }
    lease.commit().await?;
    Ok(Json(
        json!({"observed":observed,"unknown":unknown,"selected":selected.len(),"truncated":all.iter().filter(|package|supported(package)).count()>512,"source":OSV,"automatic_upgrade":false}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_and_unsafe_advisories_cannot_become_clean_results() {
        assert!(vulnerability_ids(&json!(null)).is_err());
        assert!(vulnerability_ids(&json!({"error":{"code":429}})).is_err());
        assert!(vulnerability_ids(&json!({"vulns":null})).is_err());
        assert!(vulnerability_ids(&json!({"vulns":[{"id":"../../secret"}]})).is_err());
        assert!(vulnerability_ids(&json!({"vulns":[{}]})).is_err());
        assert_eq!(vulnerability_ids(&json!({})).unwrap(), Vec::<String>::new());
        assert_eq!(
            vulnerability_ids(&json!({"vulns":[{"id":"RUSTSEC-2026-0001"}]})).unwrap(),
            vec!["RUSTSEC-2026-0001"]
        );
    }
    #[test]
    fn fixed_events_from_another_package_do_not_propose_an_upgrade() {
        let package = json!({"name":"sample","ecosystem":"crates.io"});
        let value = json!({"affected":[{"package":{"name":"different","ecosystem":"crates.io"},"ranges":[{"events":[{"fixed":"2.0.0"}]}]},{"package":{"name":"sample","ecosystem":"crates.io"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]});
        let result = detail(&package, &value);
        assert_eq!(result["fixed_versions"], json!(["1.2.3"]));
        assert_eq!(result["compatibility_verified"], false);
    }
}
