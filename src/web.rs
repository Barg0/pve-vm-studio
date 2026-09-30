//! The browser UI: the files in web/, compiled into the binary.

use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/"]
struct Assets;

pub async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    // Unknown paths get the app shell: the UI routes on the client side.
    let (path, file) = match Assets::get(path) {
        Some(f) if !path.is_empty() => (path, f),
        _ => match Assets::get("index.html") {
            Some(f) => ("index.html", f),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_owned()),
            (header::CACHE_CONTROL, "no-cache".to_owned()),
        ],
        file.data,
    )
        .into_response()
}
