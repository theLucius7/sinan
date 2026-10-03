#![forbid(unsafe_code)]

mod business_support;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::Result;
use business_support::{TestPanel, id};
use reqwest::StatusCode;
use serde_json::json;
use sinan_protocol::release::canonical_asset_name;
use sqlx::PgPool;

#[sqlx::test]
async fn musl_agent_on_gnu_host_receives_legacy_gnu_runtime(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "split-abi").await?;
    let node = id(&panel.create_node(&cookie, server, "split-abi-node").await?)?;
    let user = id(&panel.create_user(&cookie, "split-abi-user").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.publish_now().await?;

    let binary = b"legacy GNU runtime fixture";
    let archive = release_fixture::archive("sing-box", binary)?;
    let mut entry =
        release_support::entry("sing-box", "1.14.2", "sing-box", "tar.gz", &archive, binary);
    entry.arch = "amd64".into();
    entry.asset_name = canonical_asset_name(&entry)?;
    release_fixture::write_entries(
        &panel.state.config.data_dir,
        vec![(entry.clone(), archive.clone())],
    )?;
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"os":"linux","arch":"amd64","libc":"musl","runtime_libc":"gnu"}))
        .execute(&panel.state.pool)
        .await?;
    let response = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let manifest: serde_json::Value = response.json().await?;
    assert!(
        manifest["modules"]["singbox"]["artifact"]["url"]
            .as_str()
            .unwrap()
            .ends_with("/sing-box/1.14.2/amd64")
    );
    // Preserve the legacy selection made by old musl Agents before host detection.
    let mut explicit_gnu = entry.clone();
    explicit_gnu.arch = "linux-gnu-amd64".into();
    explicit_gnu.asset_name = canonical_asset_name(&explicit_gnu)?;
    release_fixture::write_entries(
        &panel.state.config.data_dir,
        vec![
            (entry, archive.clone()),
            (explicit_gnu.clone(), archive.clone()),
        ],
    )?;
    let response = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let manifest: serde_json::Value = response.json().await?;
    assert!(
        manifest["modules"]["singbox"]["artifact"]["url"]
            .as_str()
            .unwrap()
            .ends_with("/sing-box/1.14.2/amd64")
    );
    for info in [
        json!({"os":"linux","arch":"amd64","libc":"musl"}),
        json!({"os":"linux","arch":"amd64","libc":"musl","runtime_libc":"musl"}),
    ] {
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(server)
            .bind(info)
            .execute(&panel.state.pool)
            .await?;
        let response = panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            response.json::<serde_json::Value>().await?["error"]
                .as_str()
                .unwrap()
                .contains("已验签")
        );
    }
    // A GNU Agent already running through a musl compatibility layer keeps its
    // previous GNU identity ahead of the legacy and newly detected host target.
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"os":"linux","arch":"amd64","libc":"gnu","runtime_libc":"musl"}))
        .execute(&panel.state.pool)
        .await?;
    let response = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let manifest: serde_json::Value = response.json().await?;
    assert!(
        manifest["modules"]["singbox"]["artifact"]["url"]
            .as_str()
            .unwrap()
            .ends_with("/sing-box/1.14.2/linux-gnu-amd64")
    );
    // With neither musl nor a signed legacy entry, the GNU host can use GNU.
    release_fixture::write_entries(&panel.state.config.data_dir, vec![(explicit_gnu, archive)])?;
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"os":"linux","arch":"amd64","libc":"musl","runtime_libc":"gnu"}))
        .execute(&panel.state.pool)
        .await?;
    let response = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let manifest: serde_json::Value = response.json().await?;
    assert!(
        manifest["modules"]["singbox"]["artifact"]["url"]
            .as_str()
            .unwrap()
            .ends_with("/sing-box/1.14.2/linux-gnu-amd64")
    );
    Ok(())
}

#[sqlx::test]
async fn runtime_selection_matches_abi_and_preserves_legacy_devices(pool: PgPool) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let cookie = panel.admin_cookie().await?;
    let (server, _socket, ack) = panel.authenticated_device(&cookie, "abi-test").await?;
    let node = id(&panel.create_node(&cookie, server, "abi-node").await?)?;
    let user = id(&panel.create_user(&cookie, "abi-user").await?)?;
    panel.grant(&cookie, user, node).await?;
    panel.publish_now().await?;
    let mut artifacts = Vec::new();
    for target in [
        "amd64",
        "linux-gnu-amd64",
        "linux-musl-amd64",
        "freebsd-amd64",
    ] {
        let binary = target.as_bytes();
        let archive = release_fixture::archive("sing-box", binary)?;
        let mut entry =
            release_support::entry("sing-box", "1.14.2", "sing-box", "tar.gz", &archive, binary);
        entry.arch = target.into();
        entry.asset_name = canonical_asset_name(&entry)?;
        artifacts.push((entry, archive));
    }
    let root = release_fixture::write_entries(&panel.state.config.data_dir, artifacts)?;
    for (info, expected) in [
        (json!({"arch":"amd64"}), Some("amd64")),
        (
            json!({"arch":"amd64","os":"linux","libc":"gnu"}),
            Some("linux-gnu-amd64"),
        ),
        (
            json!({"arch":"amd64","os":"linux","libc":"musl","runtime_libc":"gnu"}),
            Some("linux-musl-amd64"),
        ),
        (
            json!({"arch":"amd64","os":"linux","libc":"musl","runtime_libc":"glibc"}),
            Some("linux-musl-amd64"),
        ),
        (
            json!({"arch":"amd64","os":"linux","libc":"gnu","runtime_libc":"musl"}),
            Some("linux-gnu-amd64"),
        ),
        (
            json!({"arch":"amd64","os":"linux","libc":"glibc","runtime_libc":"musl"}),
            Some("linux-gnu-amd64"),
        ),
        (
            json!({"arch":"amd64","os":"linux","libc":"musl"}),
            Some("linux-musl-amd64"),
        ),
        (
            json!({"arch":"amd64","os":"freebsd"}),
            Some("freebsd-amd64"),
        ),
        (json!({"arch":"amd64","os":"linux","libc":"unknown"}), None),
        (json!({"arch":"amd64","os":"windows"}), None),
    ] {
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(server)
            .bind(info)
            .execute(&panel.state.pool)
            .await?;
        let response = panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?;
        if let Some(target) = expected {
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "runtime target: {target}"
            );
            let value: serde_json::Value = response.json().await?;
            assert!(
                value["modules"]["singbox"]["artifact"]["url"]
                    .as_str()
                    .unwrap()
                    .ends_with(&format!("/sing-box/1.14.2/{target}"))
            );
        } else {
            assert!(!response.status().is_success());
        }
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM singbox_runtime_manifest_facts WHERE server_id=$1"
        )
        .bind(server)
        .fetch_one(&panel.state.pool)
        .await?,
        0,
        "ordinary node revisions must retain legacy platform selection"
    );
    for runtime_libc in [
        json!("unknown"),
        json!(""),
        json!(null),
        json!(false),
        json!(7),
    ] {
        sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
            .bind(server)
            .bind(json!({"arch":"amd64","os":"linux","libc":"gnu","runtime_libc":runtime_libc}))
            .execute(&panel.state.pool)
            .await?;
        let response = panel
            .client
            .get(format!("{}/api/agent/v1/manifest", panel.base))
            .bearer_auth(&ack.session_token)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    std::fs::remove_file(root.join("sing-box/1.14.2/linux-musl-amd64"))?;
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"arch":"amd64","os":"linux","libc":"musl"}))
        .execute(&panel.state.pool)
        .await?;
    let response = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    std::fs::remove_file(root.join("sing-box/1.14.2/linux-gnu-amd64"))?;
    sqlx::query("UPDATE servers SET static_info=$2 WHERE id=$1")
        .bind(server)
        .bind(json!({"arch":"amd64","os":"linux","libc":"gnu","runtime_libc":"musl"}))
        .execute(&panel.state.pool)
        .await?;
    let response = panel
        .client
        .get(format!("{}/api/agent/v1/manifest", panel.base))
        .bearer_auth(&ack.session_token)
        .send()
        .await?;
    // Missing content for the signed preferred GNU identity must not fall back
    // to the remaining valid architecture-only artifact.
    assert_eq!(response.status(), StatusCode::CONFLICT);
    Ok(())
}
