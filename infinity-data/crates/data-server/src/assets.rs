use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::error::ApiError;

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

pub async fn handler(uri: Uri) -> Response {
    let raw_path = uri.path();
    if raw_path == "/api"
        || raw_path.starts_with("/api/")
        || raw_path == "/admin"
        || raw_path.starts_with("/admin/")
        || raw_path == "/auth"
        || raw_path.starts_with("/auth/")
    {
        return ApiError::NotFound("route not found".into()).into_response();
    }
    let path = raw_path.trim_start_matches('/');
    if path.contains("..") || path.contains('\\') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };
    if Assets::get(path).is_some() {
        serve(path)
    } else if path.contains('.') {
        (StatusCode::NOT_FOUND, "not found").into_response()
    } else {
        serve("index.html")
    }
}
