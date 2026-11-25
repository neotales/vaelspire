//! End-to-end integration tests for the `vaelspire` single-binary server routes:
//! `/health`, `/ready`, `/metrics`, `/.well-known/vaelspire`, admin bootstrap,
//! browser sign-in + `/forward-auth`, sign-out revocation, and API-key `/forward-auth`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use vaelspire::bootstrap::{BootstrapOutcome, bootstrap_admin, ensure_tenant};
use vaelspire::config::{ServerConfig, generate_hex_key, load_or_create_key, parse_hex_key};
use vaelspire::server::build_router;
use vaelspire_auth::ApiKeys;
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
use vaelspire_core::{AuthStore, Timestamp};
use vaelspire_store_sqlite::open;
use zeroize::Zeroizing;

fn test_config(sqlite_path: std::path::PathBuf, digest_key: [u8; 32]) -> ServerConfig {
    ServerConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        sqlite_path,
        tenant_name: "test-tenant".to_owned(),
        digest_key: Zeroizing::new(digest_key),
        cookie_secure: false,
        allowed_origins: None,
        trust_proxy: false,
        session_cookie: DEFAULT_SESSION_COOKIE.to_owned(),
        csrf_cookie: DEFAULT_CSRF_COOKIE.to_owned(),
        api_key_prefix: "vsp".to_owned(),
        auditing: true,
        roles: true,
        rate_limit: (100, Duration::from_secs(60)),
        forward_auth_login_url: None,
    }
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, headers, bytes.to_vec())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let (k, v) = raw.split(';').next()?.split_once('=')?;
            (k.trim() == name).then(|| v.trim().to_owned())
        })
}

#[test]
fn keygen_and_file_persistence_round_trip() {
    let hex = generate_hex_key().expect("keygen");
    assert_eq!(hex.len(), 64);
    let parsed = parse_hex_key(&hex).expect("parse hex");
    assert_eq!(parsed.len(), 32);

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("vaelspire.sqlite");
    let (k1, created_path) = load_or_create_key(None, &db_path).expect("create key");
    assert!(created_path.expect("key path").exists());
    let (k2, _) = load_or_create_key(None, &db_path).expect("reload key");
    assert_eq!(*k1, *k2);
}

#[tokio::test]
async fn health_ready_discovery_and_metrics_work() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("vaelspire.sqlite");
    let store = Arc::new(open(&db_path).await.expect("sqlite"));
    let tenant_id = ensure_tenant(&store, "default").await.expect("tenant");
    // Re-running ensure_tenant returns the exact same ID across restarts.
    let tenant_id_again = ensure_tenant(&store, "default")
        .await
        .expect("tenant reuse");
    assert_eq!(tenant_id, tenant_id_again);

    let app = build_router(store, tenant_id, &test_config(db_path, [9u8; 32])).expect("router");

    let (status, _, body) = send(
        &app,
        Request::get("/health").body(Body::empty()).expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["edition"], "core");

    let (status, _, body) = send(
        &app,
        Request::get("/ready").body(Body::empty()).expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(parsed["status"], "ready");

    let (status, _, body) = send(
        &app,
        Request::get("/.well-known/vaelspire")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(parsed["endpoints"]["forward_auth"], "/forward-auth");

    let (status, headers, body) = send(
        &app,
        Request::get("/metrics").body(Body::empty()).expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .expect("ct")
            .starts_with("text/plain")
    );
    let text = String::from_utf8(body).expect("utf8");
    assert!(text.contains("vaelspire_build_info{"));
    assert!(text.contains("vaelspire_http_requests_total "));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn forward_auth_allows_session_and_api_key_and_denies_revoked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("vaelspire.sqlite");
    let key = [42u8; 32];
    let store = Arc::new(open(&db_path).await.expect("sqlite"));
    let tenant_id = ensure_tenant(&store, "default").await.expect("tenant");

    // Bootstrap admin idempotently.
    let first = bootstrap_admin(
        &store,
        tenant_id,
        "admin@vaelspire.test",
        Zeroizing::new("correct horse battery staple".to_owned()),
        key,
    )
    .await
    .expect("bootstrap");
    let BootstrapOutcome::Created(admin_id) = first else {
        panic!("expected Created on first bootstrap");
    };
    let second = bootstrap_admin(
        &store,
        tenant_id,
        "admin@vaelspire.test",
        Zeroizing::new("correct horse battery staple".to_owned()),
        key,
    )
    .await
    .expect("repeat bootstrap");
    assert_eq!(second, BootstrapOutcome::AlreadyExists(admin_id));

    let app = build_router(
        Arc::clone(&store),
        tenant_id,
        &test_config(db_path.clone(), key),
    )
    .expect("router");

    // 1. Anonymous /forward-auth is denied with 401.
    let (status, _, _) = send(
        &app,
        Request::get("/forward-auth")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2. Fetch CSRF cookie, sign in with bootstrapped admin credentials.
    let (_, headers, _) = send(
        &app,
        Request::get("/session").body(Body::empty()).expect("req"),
    )
    .await;
    let csrf = cookie_value(&headers, DEFAULT_CSRF_COOKIE).expect("csrf cookie");

    let sign_in_req = Request::post("/sign-in")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, format!("{DEFAULT_CSRF_COOKIE}={csrf}"))
        .header("x-csrf-token", &csrf)
        .body(Body::from(
            json!({
                "email": "admin@vaelspire.test",
                "password": "correct horse battery staple"
            })
            .to_string(),
        ))
        .expect("sign-in req");
    let (status, headers, _) = send(&app, sign_in_req).await;
    assert_eq!(status, StatusCode::OK);
    let session_token = cookie_value(&headers, DEFAULT_SESSION_COOKIE).expect("session cookie");

    // 3. /forward-auth succeeds with session cookie and emits identity headers.
    let fwd_req = Request::get("/forward-auth")
        .header(
            header::COOKIE,
            format!("{DEFAULT_SESSION_COOKIE}={session_token}"),
        )
        .body(Body::empty())
        .expect("fwd req");
    let (status, headers, _) = send(&app, fwd_req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-vaelspire-user-id"], admin_id.to_string());
    assert_eq!(headers["x-vaelspire-tenant-id"], tenant_id.to_string());
    assert_eq!(headers["x-vaelspire-email"], "admin@vaelspire.test");
    assert_eq!(headers["x-vaelspire-auth-method"], "session");
    assert!(headers.contains_key("x-vaelspire-session-id"));

    // 4. Sign out revokes session -> /forward-auth denies immediately.
    let sign_out_req = Request::post("/sign-out")
        .header(header::ORIGIN, "http://localhost")
        .header(
            header::COOKIE,
            format!("{DEFAULT_CSRF_COOKIE}={csrf}; {DEFAULT_SESSION_COOKIE}={session_token}"),
        )
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .expect("sign-out req");
    let (status, _, _) = send(&app, sign_out_req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let fwd_after_logout = Request::get("/forward-auth")
        .header(
            header::COOKIE,
            format!("{DEFAULT_SESSION_COOKIE}={session_token}"),
        )
        .body(Body::empty())
        .expect("fwd req");
    let (status, _, _) = send(&app, fwd_after_logout).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 5. Issue an API key and verify both Authorization: Bearer and X-API-Key on /forward-auth.
    let user = store
        .find_user(tenant_id, "admin@vaelspire.test")
        .await
        .expect("user");
    let keys = ApiKeys::new(store.as_ref(), key, Some("vsp")).expect("keys");
    let now = Timestamp::now_utc();
    let issued_key = keys
        .issue(
            &user,
            vec!["read".to_owned()],
            now + time::Duration::hours(1),
            now,
        )
        .await
        .expect("issue key");

    let bearer_req = Request::get("/forward-auth")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", issued_key.expose()),
        )
        .body(Body::empty())
        .expect("bearer req");
    let (status, headers, _) = send(&app, bearer_req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-vaelspire-auth-method"], "api_key");
    assert_eq!(headers["x-vaelspire-email"], "admin@vaelspire.test");
    assert!(headers.contains_key("x-vaelspire-api-key-id"));

    let header_key_req = Request::get("/forward-auth")
        .header("x-api-key", issued_key.expose())
        .body(Body::empty())
        .expect("x-api-key req");
    let (status, _, _) = send(&app, header_key_req).await;
    assert_eq!(status, StatusCode::OK);

    // 6. Verify Prometheus metrics recorded the allow and deny decisions.
    let (_, _, metrics_body) = send(
        &app,
        Request::get("/metrics").body(Body::empty()).expect("req"),
    )
    .await;
    let metrics_text = String::from_utf8(metrics_body).expect("utf8");
    assert!(
        metrics_text
            .contains("vaelspire_forward_auth_total{outcome=\"allow\",method=\"session\"} 1")
    );
    assert!(
        metrics_text
            .contains("vaelspire_forward_auth_total{outcome=\"allow\",method=\"api_key\"} 2")
    );
    assert!(
        metrics_text.contains("vaelspire_forward_auth_total{outcome=\"deny\",method=\"none\"} 1")
    );
    assert!(
        metrics_text
            .contains("vaelspire_forward_auth_total{outcome=\"deny\",method=\"session\"} 1")
    );

    // 7. Configured forward_auth_login_url redirects unauthenticated callers with 302.
    let mut redirect_cfg = test_config(db_path, key);
    redirect_cfg.forward_auth_login_url = Some("https://auth.example.test/login".to_owned());
    let redirect_app = build_router(store, tenant_id, &redirect_cfg).expect("redirect router");
    let (status, headers, _) = send(
        &redirect_app,
        Request::get("/forward-auth")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(headers[header::LOCATION], "https://auth.example.test/login");
}
