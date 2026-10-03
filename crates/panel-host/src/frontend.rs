use axum::{
    body::Body,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct Assets;

pub async fn serve(method: Method, uri: Uri) -> Response {
    let path = uri.path().strip_prefix('/').unwrap_or(uri.path());
    let path = if path.is_empty() { "index.html" } else { path };
    // The UI uses hash routes. Unknown endpoints and missing assets must stay errors.
    if path == "api" || path.starts_with("api/") {
        return not_found();
    }
    let Some(asset) = Assets::get(path) else {
        return not_found();
    };
    if method != Method::GET && method != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD")],
            "不支持的请求方法",
        )
            .into_response();
    }
    let cache = if path == "index.html" {
        "no-store"
    } else if is_hashed_asset(path) {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let length = asset.data.len();
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(asset.data.into_owned())
    };
    (
        [
            (header::CONTENT_TYPE, content_type(path).to_owned()),
            (header::CACHE_CONTROL, cache.to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
        ],
        body,
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        "资源不存在",
    )
        .into_response()
}

fn is_hashed_asset(path: &str) -> bool {
    let Some(stem) = path
        .strip_prefix("assets/")
        .and_then(|path| path.rsplit_once('.').map(|(stem, _)| stem))
    else {
        return false;
    };
    // Vite's default content hash is eight URL-safe characters, including '_' and '-'.
    let bytes = stem.as_bytes();
    bytes.len() > 9
        && bytes[bytes.len() - 9] == b'-'
        && bytes[bytes.len() - 8..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
