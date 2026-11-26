//! Embedded `SvelteKit` UI asset serving for `Vaelspire Core` (`--features embed-ui`).
//!
//! When built with `--features embed-ui` and `UiMode::Embedded`, the compiled `ui/build/`
//! static assets are served cleanly under `/ui/*` (with SPA fallback to `index.html`).
//! In `UiMode::External` or `UiMode::ApiOnly`, UI routes are disabled so Enterprise can
//! host the UI on a CDN or custom white-label domain.

use axum::Router;
#[cfg(feature = "embed-ui")]
use axum::http::{StatusCode, header};
#[cfg(feature = "embed-ui")]
use axum::response::{IntoResponse, Redirect, Response};
#[cfg(feature = "embed-ui")]
use axum::routing::get;

use crate::config::UiMode;

#[cfg(feature = "embed-ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../ui/build"]
struct EmbeddedUiAssets;

/// Attach `/ui` routes according to `mode` and compile-time `embed-ui` feature.
pub fn attach_ui_routes(router: Router, mode: UiMode) -> Router {
    if mode != UiMode::Embedded {
        return router;
    }

    #[cfg(feature = "embed-ui")]
    {
        router
            .route("/", get(|| async { Redirect::temporary("/ui/") }))
            .route("/ui", get(|| async { Redirect::temporary("/ui/") }))
            .route("/ui/", get(serve_index))
            .route("/ui/{*path}", get(serve_asset))
    }

    #[cfg(not(feature = "embed-ui"))]
    {
        router
    }
}

#[cfg(feature = "embed-ui")]
async fn serve_index() -> Response {
    serve_file("index.html")
}

#[cfg(feature = "embed-ui")]
async fn serve_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    let clean = path.trim_start_matches('/');
    if clean.is_empty() {
        return serve_file("index.html");
    }
    if EmbeddedUiAssets::get(clean).is_some() {
        return serve_file(clean);
    }
    // SPA client-side fallback for routes like /ui/login, /ui/admin, /ui/consent.
    serve_file("index.html")
}

#[cfg(feature = "embed-ui")]
fn serve_file(path: &str) -> Response {
    match EmbeddedUiAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
                file.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
