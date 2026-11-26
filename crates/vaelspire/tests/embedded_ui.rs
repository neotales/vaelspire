//! Integration tests for the optional embedded `SvelteKit` UI (`--features embed-ui`).

#![cfg(feature = "embed-ui")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use vaelspire::bootstrap::ensure_tenant;
use vaelspire::config::{ServerConfig, UiMode};
use vaelspire::server::build_router;
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
use vaelspire_store_sqlite::open;
use zeroize::Zeroizing;

fn config_with_ui_mode(sqlite_path: PathBuf, ui_mode: UiMode) -> ServerConfig {
    ServerConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        sqlite_path,
        tenant_name: "ui-test-tenant".to_owned(),
        issuer_url: "https://auth.example.test".to_owned(),
        ui_mode,
        digest_key: Zeroizing::new([0x55; 32]),
        cookie_secure: false,
        session_cookie: DEFAULT_SESSION_COOKIE.to_owned(),
        csrf_cookie: DEFAULT_CSRF_COOKIE.to_owned(),
        api_key_prefix: "vs".to_owned(),
        allowed_origins: None,
        auditing: true,
        roles: true,
        trust_proxy: false,
        rate_limit: (1000, Duration::from_secs(60)),
        forward_auth_login_url: None,
    }
}

#[tokio::test]
async fn embedded_ui_serves_html_and_respects_ui_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("ui-test.sqlite");
    let store = Arc::new(open(&db_path).await.expect("open sqlite"));
    let tenant = ensure_tenant(&store, "ui-test-tenant")
        .await
        .expect("tenant");

    // 1. Embedded mode serves /ui/ and SPA fallback /ui/admin with HTML.
    let embedded_app = build_router(
        Arc::clone(&store),
        tenant,
        &config_with_ui_mode(db_path.clone(), UiMode::Embedded),
    )
    .expect("embedded router");

    let root = embedded_app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(root.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(root.headers().get("location").unwrap(), "/ui/");

    let index = embedded_app
        .clone()
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(index.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(index.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("Vaelspire"));

    let spa_route = embedded_app
        .oneshot(
            Request::builder()
                .uri("/ui/admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spa_route.status(), StatusCode::OK);

    // 2. ApiOnly / External modes disable /ui/ routes cleanly (404).
    let api_only_app = build_router(
        store,
        tenant,
        &config_with_ui_mode(db_path, UiMode::ApiOnly),
    )
    .expect("api-only");
    let res = api_only_app
        .oneshot(Request::builder().uri("/ui/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
