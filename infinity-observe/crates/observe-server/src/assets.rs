use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode, Uri};
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
                HeaderValue::from_static("no-store")
            } else {
                HeaderValue::from_static("no-cache")
            };
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| {
                            HeaderValue::from_static("application/octet-stream")
                        }),
                    ),
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
    let raw_path = uri.path();
    let path = raw_path.trim_start_matches('/');
    if path.contains("..") || path.contains('\\') || path.contains('\0') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if path.starts_with("v1/") || path == "v1" || path.starts_with("auth/") || path == "auth" {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "not_found", "error_description": "endpoint not found" })),
        )
            .into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };
    if Assets::get(path).is_some() {
        serve(path)
    } else {
        serve("index.html")
    }
}
