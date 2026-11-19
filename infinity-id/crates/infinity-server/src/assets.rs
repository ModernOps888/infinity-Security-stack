//! Serves the embedded admin dashboard (compiled into the binary — no external
//! files or Node build step required to run).

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

fn serve(path: &str) -> Response {
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref())],
                Body::from(content.data.into_owned()),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Fallback handler: serves the requested asset, returns JSON 404 for unknown
/// API prefixes or traversal attempts, or serves the SPA shell for client routes.
pub async fn handler(uri: Uri) -> Response {
    let raw = uri.path();
    if raw.contains("..") || raw.contains('\\') || raw.contains('\0') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if matches!(
        raw,
        p if p.starts_with("/admin/")
            || p == "/admin"
            || p.starts_with("/auth/")
            || p == "/auth"
            || p.starts_with("/oauth/")
            || p == "/oauth"
            || p.starts_with("/mfa/")
            || p == "/mfa"
            || p.starts_with("/.well-known/")
    ) {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": "not_found" })),
        )
            .into_response();
    }
    let path = raw.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    if Assets::get(path).is_some() {
        serve(path)
    } else {
        serve("index.html")
    }
}
