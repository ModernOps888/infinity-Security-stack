use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rust_embed::RustEmbed;
use serde_json::json;

#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

fn serve(path: &str) -> Response {
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let cache = if path == "index.html" {
                "no-store"
            } else {
                "public, max-age=300"
            };
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref()),
                    (header::CACHE_CONTROL, cache),
                ],
                Body::from(content.data.into_owned()),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub async fn handler(uri: Uri) -> Response {
    let raw = uri.path();
    if raw.contains("..") || raw.contains('\\') || raw.contains('\0') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if raw.starts_with("/v1/") || raw == "/v1" || raw.starts_with("/auth/") || raw == "/auth" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "not_found", "error_description": "endpoint not found"})),
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
