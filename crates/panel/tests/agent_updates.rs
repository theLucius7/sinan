#![forbid(unsafe_code)]
mod business_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
use anyhow::Result;
use business_support::TestPanel;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sinan_protocol::release::canonical_asset_name;
use sqlx::PgPool;

#[sqlx::test]
async fn updates_require_opt_in_matching_platform_and_newer_verified_stable_release(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "updates").await?;
    let url = format!("{}/api/agent/v1/update?download_source=github", panel.base);
    assert_eq!(
        panel.client.get(&url).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let mut artifacts = Vec::new();
    for (version, target) in [
        ("0.9.0", "linux-musl-amd64"),
        ("0.10.0", "linux-musl-amd64"),
        ("1.0.0", "linux-gnu-amd64"),
        ("3.0.0-beta", "linux-musl-amd64"),
    ] {
        let mut entry = release_support::entry(
            "agent",
            version,
            "sinan-agent",
            "raw",
            b"fixture",
            b"fixture",
        );
        entry.arch = target.into();
        entry.asset_name = canonical_asset_name(&entry)?;
        artifacts.push((entry, b"fixture".to_vec()));
    }
    let release_root = release_fixture::write_entries(&panel.state.config.data_dir, artifacts)?;
    // A checksum-only legacy directory must never authorize a newer executable.
    let unsigned = panel.state.config.data_dir.join("artifacts/agent/20.0.0");
    std::fs::create_dir_all(&unsigned)?;
    std::fs::write(unsigned.join("linux-musl-amd64"), b"unsigned")?;
    std::fs::write(
        unsigned.join("SHA256SUMS"),
        format!("{}  linux-musl-amd64\n", release_support::hash(b"unsigned")),
    )?;
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"os":"linux","arch":"amd64","libc":"musl","agent_version":"0.3.0"}))
        .execute(&panel.state.pool)
        .await?;
    let fetch = || {
        panel
            .client
            .get(&url)
            .bearer_auth(&ack.session_token)
            .send()
    };
    assert!(fetch().await?.json::<Value>().await?.is_null());
    sqlx::query("UPDATE servers SET agent_settings=jsonb_set(agent_settings,'{auto_update}','true') WHERE id=$1")
        .bind(server).execute(&panel.state.pool).await?;
    let release: Value = fetch().await?.json().await?;
    assert_eq!(release["version"], "0.10.0");
    assert!(
        release["artifact"]["url"]
            .as_str()
            .unwrap()
            .ends_with("linux-musl-amd64")
    );
    // Runtime ABI detection must not switch the Agent's own update ABI.
    for runtime_libc in ["gnu", "musl", "unknown"] {
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(server)
            .bind(json!({"os":"linux","arch":"amd64","libc":"musl","runtime_libc":runtime_libc,"agent_version":"0.3.0"}))
            .execute(&panel.state.pool)
            .await?;
        let release: Value = fetch().await?.error_for_status()?.json().await?;
        assert_eq!(release["version"], "0.10.0");
        assert!(
            release["artifact"]["url"]
                .as_str()
                .unwrap()
                .ends_with("linux-musl-amd64")
        );
    }
    for info in [
        json!({"os":"linux","arch":"amd64","libc":"musl","agent_version":"0.10.0"}),
        json!({"os":"windows","arch":"arm64","agent_version":"0.3.0"}),
    ] {
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(server)
            .bind(info)
            .execute(&panel.state.pool)
            .await?;
        assert!(fetch().await?.json::<Value>().await?.is_null());
    }
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"os":"linux","arch":"amd64","libc":"musl","agent_version":"0.3.0"}))
        .execute(&panel.state.pool)
        .await?;
    std::fs::write(
        release_root.join("agent/0.10.0/linux-musl-amd64"),
        b"tampered",
    )?;
    // The panel supplies a signed descriptor; binaries are fetched from GitHub.
    let release: Value = fetch().await?.error_for_status()?.json().await?;
    assert!(
        release["artifact"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://github.com/theLucius7/sinan/releases/download/")
    );
    assert!(
        !release["artifact"]["url"]
            .as_str()
            .unwrap()
            .contains(&panel.base)
    );
    sqlx::query("UPDATE servers SET asset_settings=jsonb_set(asset_settings,'{agent_mirror}',to_jsonb($2::text)) WHERE id=$1")
        .bind(server).bind("https://mirror.example.com").execute(&panel.state.pool).await?;
    let release: Value = fetch().await?.error_for_status()?.json().await?;
    assert_eq!(release["download_mirror"], "https://mirror.example.com");
    Ok(())
}

#[sqlx::test]
async fn update_download_capability_requires_exact_negotiation_after_authentication(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "update-source").await?;
    let mut entry = release_support::entry(
        "agent",
        "0.9.0",
        "sinan-agent",
        "raw",
        b"fixture",
        b"fixture",
    );
    entry.arch = "linux-musl-amd64".into();
    entry.asset_name = canonical_asset_name(&entry)?;
    let mut other_arch = entry.clone();
    other_arch.arch = "linux-musl-arm64".into();
    other_arch.asset_name = canonical_asset_name(&other_arch)?;
    let release_directory = release_fixture::write_entries(
        &panel.state.config.data_dir,
        vec![
            (entry, b"fixture".to_vec()),
            (other_arch, b"fixture".to_vec()),
        ],
    )?;
    // The requested ABI is signed but deliberately absent from local inventory.
    std::fs::remove_file(release_directory.join("agent/0.9.0/linux-musl-amd64"))?;
    std::fs::write(
        release_directory.join("inventory.json"),
        br#"{"paths":["agent/0.9.0/linux-musl-arm64"]}"#,
    )?;
    sqlx::query("UPDATE servers SET agent_settings=jsonb_set(agent_settings,'{auto_update}','true'),static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"os":"linux","arch":"amd64","libc":"musl","agent_version":"0.3.0"}))
        .execute(&panel.state.pool)
        .await?;
    let url = format!("{}/api/agent/v1/update", panel.base);
    // The same version may run an old client or a GitHub-capable client.
    for query in [
        "",
        "?download_source=panel",
        "?download_source=",
        "?download_source=GitHub",
        "?download_source=github&download_source=github",
    ] {
        let request_url = format!("{url}{query}");
        assert!(
            panel
                .client
                .get(&request_url)
                .bearer_auth(&ack.session_token)
                .send()
                .await?
                .error_for_status()?
                .json::<Value>()
                .await?
                .is_null()
        );
        for token in [None, Some("invalid-fixture-session")] {
            let mut request = panel.client.get(&request_url);
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            assert_eq!(request.send().await?.status(), StatusCode::UNAUTHORIZED);
        }
    }
    let github_url = format!("{url}?download_source=github");
    let release: Value = panel
        .client
        .get(&github_url)
        .bearer_auth(&ack.session_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(release["version"], "0.9.0");
    assert!(
        release["artifact"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://github.com/theLucius7/sinan/releases/download/")
    );
    sqlx::query("UPDATE servers SET deleted_at=1 WHERE id=$1")
        .bind(server)
        .execute(&panel.state.pool)
        .await?;
    for request_url in [&url, &github_url] {
        assert_eq!(
            panel
                .client
                .get(request_url)
                .bearer_auth(&ack.session_token)
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

#[sqlx::test]
async fn native_installers_require_independently_verified_signed_bootstrap(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let server = panel.create_server(&cookie, "native-install").await?;
    let enrollment: Value = panel
        .admin(
            reqwest::Method::POST,
            &format!("/api/servers/{server}/enrollment"),
            &cookie,
            None,
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(enrollment["install_command"].is_null());
    assert!(enrollment["warning"].as_str().is_some());
    for name in ["install.sh", "install.ps1"] {
        let response = panel
            .client
            .get(format!("{}/{name}", panel.base))
            .query(&[("token", enrollment["token"].as_str().unwrap())])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
    Ok(())
}
