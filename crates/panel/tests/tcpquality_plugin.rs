#![forbid(unsafe_code)]
mod business_support;
#[path = "probe_support.rs"]
mod probe_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::TestPanel;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sinan_panel::diagnostic_plugins::tcpquality::PLUGIN_VERSION;
use sqlx::PgPool;
use uuid::Uuid;

async fn ready(panel: &TestPanel, server: i64) -> Result<()> {
    sqlx::query("UPDATE servers SET static_info=static_info || '{\"os\":\"linux\"}'::jsonb,capabilities=$2,last_seen=$3 WHERE id=$1")
        .bind(server).bind(json!(["diagnostic:nodequality","diagnostic:nodequality-modes","diagnostic:tcpquality","diagnostic:tcpquality-native-v1",sinan_protocol::DIAGNOSTIC_SECTIONS_CAPABILITY,sinan_protocol::DIAGNOSTIC_SERVICE_CAPABILITY,sinan_protocol::DIAGNOSTIC_CPU_CEILING_CAPABILITY,sinan_protocol::DIAGNOSTIC_COMPLETION_CAPABILITY,sinan_protocol::DIAGNOSTIC_CANCEL_CAPABILITY,sinan_protocol::release::ARTIFACT_SIGNATURE_CAPABILITY]))
        .bind(sinan_protocol::now_timestamp()).execute(&panel.state.pool).await?;
    let mut artifacts = Vec::new();
    for (name, version, binary_name) in [
        (
            "nodequality",
            sinan_panel::diagnostics::PLUGIN_VERSION,
            "nodequality",
        ),
        ("tcpquality", PLUGIN_VERSION, "sinan-tcp-probe"),
    ] {
        let binary = b"TEST_ONLY panel routing fixture; never executed";
        let archive = release_fixture::archive(binary_name, binary)?;
        for arch in ["amd64", "arm64"] {
            let mut entry =
                release_support::entry(name, version, binary_name, "tar.gz", &archive, binary);
            entry.arch = arch.into();
            entry.asset_name = sinan_protocol::release::canonical_asset_name(&entry)?;
            artifacts.push((entry, archive.clone()));
        }
    }
    release_fixture::write_entries(&panel.state.config.data_dir, artifacts)?;
    Ok(())
}
async fn probe(panel: &TestPanel, cookie: &str, server: i64, name: &str) -> Result<Value> {
    Ok(panel.admin(Method::POST,&format!("/api/servers/{server}/probes"),cookie,Some(probe_support::authorized(json!({
        "id":Uuid::nil(),"name":name,"kind":"tcp","target":"example.test","port":443,"interval_secs":60,"carrier":"fixture","enabled":true
    })))).await?.error_for_status()?.json().await?)
}
fn path(server: i64) -> String {
    format!("/api/servers/{server}/diagnostics/tcpquality")
}
fn region_path(server: i64, probe: &Value) -> String {
    format!(
        "/api/plugins/tcpquality/servers/{server}/targets/{}",
        probe["id"].as_str().unwrap()
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn tcp_diagnostics_select_only_currently_authorized_targets(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, _ack) = panel
        .authenticated_device(&cookie, "permission filtered diagnostic")
        .await?;
    ready(&panel, server).await?;
    let allowed = probe(&panel, &cookie, server, "allowed fixture").await?;
    for expires_at in [None, Some(sinan_protocol::now_timestamp() - 1)] {
        let id = Uuid::new_v4();
        let mut spec = probe_support::authorized(
            json!({"id":id,"name":"unknown permission fixture","kind":"tcp","target":"unpermitted.example.test","port":443,"interval_secs":60,"carrier":"fixture","enabled":true}),
        );
        if let Some(expires_at) = expires_at {
            spec["monitor"]["authorization"]["expires_at"] = json!(expires_at);
        } else {
            spec["monitor"]["authorization"] = Value::Null;
        }
        sqlx::query("INSERT INTO network_probes(id,server_id,spec) VALUES($1,$2,$3)")
            .bind(id)
            .bind(server)
            .bind(spec)
            .execute(&panel.state.pool)
            .await?;
    }
    let targets: Vec<Value> = panel
        .admin(
            Method::GET,
            &format!("/api/plugins/tcpquality/servers/{server}/targets"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["id"], allowed["id"]);
    let job: Value = panel
        .admin(Method::POST, &path(server), &cookie, Some(json!({})))
        .await?
        .error_for_status()?
        .json()
        .await?;
    let snapshot: Value = serde_json::from_str(job["job"]["options"]["targets"].as_str().unwrap())?;
    assert_eq!(snapshot["targets"].as_array().unwrap().len(), 1);
    assert!(!serde_json::to_string(&snapshot)?.contains("unpermitted.example.test"));
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn tcp_parameters_freeze_only_selected_configured_targets(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, _ack) = panel.authenticated_device(&cookie, "TCP scope").await?;
    ready(&panel, server).await?;
    let first = probe(&panel, &cookie, server, "东亚自有目标").await?;
    let second = probe(&panel, &cookie, server, "未标注地区目标").await?;
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &region_path(server, &first),
                &cookie,
                Some(json!({"region":"east_asia"}))
            )
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &region_path(server, &first),
                &cookie,
                Some(json!({}))
            )
            .await?
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let probe_id = Uuid::parse_str(first["id"].as_str().unwrap())?;
    let preserved: Option<String> =
        sqlx::query_scalar("SELECT region FROM tcpquality_target_regions WHERE probe_id=$1")
            .bind(probe_id)
            .fetch_optional(&panel.state.pool)
            .await?;
    assert_eq!(preserved.as_deref(), Some("east_asia"));
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &region_path(server, &first),
                &cookie,
                Some(json!({"region":null}))
            )
            .await?
            .status(),
        StatusCode::OK
    );
    let cleared: Option<String> =
        sqlx::query_scalar("SELECT region FROM tcpquality_target_regions WHERE probe_id=$1")
            .bind(probe_id)
            .fetch_optional(&panel.state.pool)
            .await?;
    assert_eq!(cleared, None);
    panel
        .admin(
            Method::PATCH,
            &region_path(server, &first),
            &cookie,
            Some(json!({"region":"east_asia"})),
        )
        .await?
        .error_for_status()?;
    let legacy: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/probes"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(
        legacy
            .as_array()
            .unwrap()
            .iter()
            .all(|spec| spec.get("region").is_none())
    );
    let record: Value = panel
        .admin(
            Method::POST,
            &path(server),
            &cookie,
            Some(json!({"region":"east_asia","ip_version":"6","count":8,"concurrency":2})),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let job = &record["job"];
    assert_eq!(job["timeout_secs"], 60);
    assert_eq!(job["version"], PLUGIN_VERSION);
    assert_eq!(
        job["resource_budget"],
        json!({"memory_max":64*1024*1024,"tasks_max":32,"cpu_weight":10,"io_weight":10,"oom_score_adjust":500})
    );
    let raw = job["options"]["targets"].as_str().unwrap();
    assert_eq!(
        job["options"]["target_digest"],
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    );
    let snapshot: Value = serde_json::from_str(raw)?;
    assert_eq!(snapshot["schema"], 1);
    assert_eq!(snapshot["targets"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["targets"][0]["id"], first["id"]);
    assert_eq!(snapshot["targets"][0]["region"], "east_asia");
    assert_eq!(job["tcpquality"]["region"], "east_asia");
    assert_eq!(job["tcpquality"]["upload_enabled"], false);
    assert_eq!(job["tcpquality"]["ranking_enabled"], false);
    assert_eq!(job["tcpquality"]["speedtest_enabled"], false);
    assert_eq!(record["expected_sections"].as_array().unwrap().len(), 4);
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &region_path(server, &first),
                &cookie,
                Some(json!({"region":"europe"}))
            )
            .await?
            .status(),
        StatusCode::OK
    );
    let mut changed = first.clone();
    changed["target"] = json!("changed.test");
    let probe_path = format!(
        "/api/servers/{server}/probes/{}",
        first["id"].as_str().unwrap()
    );
    assert_eq!(
        panel
            .admin(Method::PATCH, &probe_path, &cookie, Some(changed))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let mut metadata = first.clone();
    metadata["name"] = json!("更新后的名称");
    metadata["enabled"] = json!(false);
    panel
        .admin(Method::PATCH, &probe_path, &cookie, Some(metadata))
        .await?
        .error_for_status()?;
    let view: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/diagnostics"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(view["reports"][0]["job"]["options"]["targets"], raw);
    assert_eq!(
        view["reports"][0]["job"]["tcpquality"]["targets"][0]["target"],
        "example.test"
    );
    let inventory: Value = panel
        .admin(
            Method::GET,
            &format!("/api/plugins/tcpquality/servers/{server}/targets"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    let unknown = inventory
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == second["id"])
        .unwrap();
    assert!(unknown["region"].is_null());
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn tcp_and_nodequality_share_duplicates_cancel_confirmation_and_partial_history(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "TCP mutex").await?;
    ready(&panel, server).await?;
    let target = probe(&panel, &cookie, server, "本机受控目标").await?;
    let endpoint = path(server);
    let (first, duplicate) = tokio::join!(
        panel.admin(Method::POST, &endpoint, &cookie, Some(json!({}))),
        panel.admin(Method::POST, &endpoint, &cookie, Some(json!({})))
    );
    let (first, duplicate) = (first?, duplicate?);
    let created = if first.status() == StatusCode::CREATED {
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        first
    } else {
        assert_eq!(first.status(), StatusCode::CONFLICT);
        assert_eq!(duplicate.status(), StatusCode::CREATED);
        duplicate
    };
    let record: Value = created.json().await?;
    let id = record["id"].as_str().unwrap();
    let node = format!("/api/servers/{server}/diagnostics/nodequality");
    assert_eq!(
        panel
            .admin(Method::POST, &node, &cookie, Some(json!({"mode":"daily"})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let chapter_name = format!(
        "tcp_target_{}",
        Uuid::parse_str(target["id"].as_str().unwrap())?.simple()
    );
    let section = json!({"id":id,"name":chapter_name,"text":"保存的独立 TCP 目标章节","complete":true,"revision":1,"collected_at":sinan_protocol::now_timestamp()});
    assert_eq!(
        panel
            .client
            .post(format!(
                "{}/api/agent/v1/diagnostics/{id}/sections",
                panel.base
            ))
            .bearer_auth(&ack.session_token)
            .json(&section)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let cancel_path = format!("/api/servers/{server}/diagnostics/{id}/cancel");
    let requested: Value = panel
        .admin(Method::POST, &cancel_path, &cookie, None)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(requested["status"], "cancel_requested");
    sqlx::query("UPDATE diagnostic_jobs SET expires_at=$2 WHERE id=$1")
        .bind(Uuid::parse_str(id)?)
        .bind(sinan_protocol::now_timestamp() - 1)
        .execute(&panel.state.pool)
        .await?;
    assert_eq!(
        panel
            .admin(Method::POST, &node, &cookie, Some(json!({"mode":"daily"})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let pending: Value = panel
        .client
        .get(format!(
            "{}/api/agent/v1/diagnostics/cancellations",
            panel.base
        ))
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(pending[0]["job"]["id"], id);
    assert_eq!(pending[0]["job"]["plugin"], "tcpquality");
    let confirmation = json!({"server_id":server,"id":id,"plugin":"tcpquality","confirmed":true});
    assert_eq!(
        panel
            .client
            .post(format!(
                "{}/api/agent/v1/diagnostics/{id}/cancel-confirmation",
                panel.base
            ))
            .bearer_auth(&ack.session_token)
            .json(&confirmation)
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    let history: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/diagnostics"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(history["reports"][0]["status"], "cancelled");
    assert_eq!(history["reports"][0]["report_completeness"], "partial");
    assert_eq!(
        history["reports"][0]["sections"][0]["text"],
        "保存的独立 TCP 目标章节"
    );
    let node_record: Value = panel
        .admin(Method::POST, &node, &cookie, Some(json!({"mode":"daily"})))
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        panel
            .admin(Method::POST, &endpoint, &cookie, Some(json!({})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let legacy: Value = panel
        .admin(
            Method::GET,
            &format!("/api/servers/{server}/node-quality/reports"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(legacy["reports"].as_array().unwrap().len(), 1);
    assert_eq!(legacy["reports"][0]["id"], node_record["id"]);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn tcp_rejects_unapproved_parameters_missing_capabilities_and_foreign_targets(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel
        .authenticated_device(&cookie, "TCP validation")
        .await?;
    ready(&panel, server).await?;
    let endpoint = path(server);
    assert_eq!(
        panel
            .admin(Method::POST, &endpoint, &cookie, Some(json!({})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    probe(&panel, &cookie, server, "可用目标").await?;
    for request in [
        json!({"count":256}),
        json!({"concurrency":8}),
        json!({"ip_version":"both"}),
        json!({"region":"all"}),
        json!({"allow_speedtest_staged":true}),
        json!({"no_rootfs":true}),
        json!({"no_rank_upload":false}),
        json!({"command":"echo x"}),
    ] {
        assert_eq!(
            panel
                .admin(Method::POST, &endpoint, &cookie, Some(request))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        panel
            .client
            .post(format!("{}{endpoint}", panel.base))
            .bearer_auth(&ack.session_token)
            .json(&json!({}))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE servers SET capabilities=capabilities-'diagnostic:tcpquality-native-v1' WHERE id=$1").bind(server).execute(&panel.state.pool).await?;
    assert_eq!(
        panel
            .admin(Method::POST, &endpoint, &cookie, Some(json!({})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    ready(&panel, server).await?;
    let other = panel.create_server(&cookie, "外国目标设备").await?;
    let foreign = probe(&panel, &cookie, other, "其他设备目标").await?;
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &region_path(server, &foreign),
                &cookie,
                Some(json!({"region":"east_asia"}))
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        panel
            .admin(
                Method::PATCH,
                &region_path(other, &foreign),
                &cookie,
                Some(json!({"region":"configured"}))
            )
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    for index in 0..8 {
        probe(&panel, &cookie, server, &format!("超限目标{index}")).await?;
    }
    assert_eq!(
        panel
            .admin(Method::POST, &endpoint, &cookie, Some(json!({})))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_jobs WHERE server_id=$1")
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}
