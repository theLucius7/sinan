#![forbid(unsafe_code)]

mod business_support;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;

use anyhow::{Context, Result};
use business_support::TestPanel;
use reqwest::{StatusCode, header};
use sqlx::PgPool;

#[tokio::test]
async fn compiled_embedded_frontend_matches_every_dist_file_for_get_and_head() -> Result<()> {
    use axum::{
        body::to_bytes,
        http::{Method, Uri},
    };
    use std::path::Path;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dist");
    let mut directories = vec![root.clone()];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            anyhow::ensure!(!kind.is_symlink(), "dist must not contain symlinks");
            if kind.is_dir() {
                directories.push(entry.path());
            } else {
                anyhow::ensure!(kind.is_file(), "dist contains a non-file asset");
                files.push(entry.path());
            }
        }
    }
    files.sort();
    anyhow::ensure!(
        files.iter().any(|path| path == &root.join("index.html")),
        "dist is missing index.html"
    );
    anyhow::ensure!(files.len() > 1, "dist is missing built assets");
    for path in files {
        let relative = path
            .strip_prefix(&root)?
            .to_str()
            .context("UTF-8 dist path")?;
        let expected = std::fs::read(&path)?;
        let content_type = match path.extension().and_then(|value| value.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js" | "mjs") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json" | "map") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            Some("ttf") => "font/ttf",
            Some("otf") => "font/otf",
            Some("wasm") => "application/wasm",
            Some("txt") => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };
        let cache = if relative == "index.html" {
            "no-store"
        } else if relative.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        let mut uris = vec![format!("/{relative}")];
        if relative == "index.html" {
            uris.push("/".into());
        }
        for uri in uris {
            for method in [Method::GET, Method::HEAD] {
                let response =
                    sinan_panel::frontend::serve(method.clone(), uri.parse::<Uri>()?).await;
                assert_eq!(response.status(), StatusCode::OK, "{method} {uri}");
                assert_eq!(
                    response.headers()[header::CONTENT_TYPE],
                    content_type,
                    "{method} {uri}"
                );
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    cache,
                    "{method} {uri}"
                );
                assert_eq!(
                    response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                    "nosniff",
                    "{method} {uri}"
                );
                assert_eq!(
                    response.headers()[header::CONTENT_LENGTH],
                    expected.len().to_string(),
                    "{method} {uri}"
                );
                let body = to_bytes(response.into_body(), expected.len().saturating_add(1)).await?;
                if method == Method::HEAD {
                    assert!(body.is_empty(), "HEAD {uri} returned a body");
                } else {
                    assert_eq!(
                        body.as_ref(),
                        expected.as_slice(),
                        "GET {uri} embedded bytes differ from current dist"
                    );
                }
            }
        }
    }
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn embedded_frontend_serves_real_assets_without_masking_missing_endpoints(
    pool: PgPool,
) -> Result<()> {
    let panel = TestPanel::start(pool).await?;
    let response = panel
        .client
        .get(&panel.base)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    let html = response.text().await?;
    assert!(html.to_ascii_lowercase().contains("<!doctype html>"));
    assert!(html.contains("司南"));

    for (extension, content_type) in [
        (".js", "text/javascript; charset=utf-8"),
        (".css", "text/css; charset=utf-8"),
    ] {
        let assets: Vec<_> = html
            .split(['\"', '\''])
            .filter(|part| part.starts_with("/assets/") && part.ends_with(extension))
            .collect();
        anyhow::ensure!(
            !assets.is_empty(),
            "built HTML contains no {extension} asset"
        );
        for asset in assets {
            let url = format!("{}{asset}", panel.base);
            let response = panel.client.get(&url).send().await?.error_for_status()?;
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "public, max-age=31536000, immutable"
            );
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            let length: usize = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .context("asset length")?
                .to_str()?
                .parse()?;
            let bytes = response.bytes().await?;
            assert_eq!(bytes.len(), length);
            assert!(!bytes.is_empty());
            assert!(
                !String::from_utf8_lossy(&bytes)
                    .to_ascii_lowercase()
                    .contains("<!doctype html>")
            );
            let head = panel.client.head(&url).send().await?.error_for_status()?;
            assert_eq!(head.headers()[header::CONTENT_TYPE], content_type);
            assert_eq!(head.headers()[header::CONTENT_LENGTH], length.to_string());
            assert!(head.bytes().await?.is_empty());
        }
    }
    assert_eq!(
        panel
            .client
            .get(format!("{}/index.html?fresh=1", panel.base))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?,
        html
    );
    let anonymous = panel
        .client
        .get(format!("{}/api/typo", panel.base))
        .send()
        .await?;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(
        anonymous
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert!(!anonymous.text().await?.contains("<!doctype html>"));
    let cookie = panel.admin_cookie().await?;
    for path in [
        "/api",
        "/api/typo",
        "/api/agent/v1/not-a-route",
        "/assets/missing.js",
        "/assets/missing.css",
        "/missing-page",
        "/src/main.tsx",
    ] {
        let request = panel.client.get(format!("{}{path}", panel.base));
        let response = if path.starts_with("/api") {
            request.header(header::COOKIE, &cookie)
        } else {
            request
        }
        .send()
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_ne!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert!(
            !response.text().await?.contains("<!doctype html>"),
            "{path}"
        );
    }
    assert_eq!(
        panel.client.post(&panel.base).send().await?.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        panel
            .client
            .get(format!("{}/api/me", panel.base))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}
