//! The mount an application copies, exercised against a real SQLite file.
//!
//! This is the checked companion to the [`vaelspire_axum::AuthRouter::new`]
//! rustdoc example: the store is shared through an `Arc` (no leak), `cookie_secure` is
//! chosen at construction, the tenant exists before the router is built, the digest key
//! is 32 bytes, and `on_proof` is set so the token-issuing routes exist.

// The CSRF cookie comes from a safe `GET /session`.
#![cfg(feature = "session")]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::json;
use tower::ServiceExt;
use vaelspire_axum::{AuthRouter, TokenKind};
use vaelspire_core::{AuthStore, Id, Timestamp, User};
use vaelspire_store_sqlite::open;

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("request")
}

/// The request a browser makes: the CSRF cookie and the same value in the header.
fn post(path: &str, body: &serde_json::Value, csrf: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, format!("neotales.csrf={csrf}"))
        .header("x-csrf-token", csrf)
        .body(Body::from(body.to_string()))
        .expect("request")
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

/// The whole `Set-Cookie` value for `name`, attributes included.
fn cookie_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|text| {
            text.split(';')
                .next()
                .and_then(|first| first.split_once('='))
                .is_some_and(|(key, _)| key == name)
        })
}

/// The value a script reads from `document.cookie`.
fn cookie_value(text: &str) -> &str {
    text.split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map_or("", |(_, value)| value)
}

#[tokio::test]
async fn the_copied_mount_reaches_the_issue_route_through_the_csrf_cookie() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    // One `Arc`, cloned into the router. Nothing is leaked and nothing is `'static`.
    let store = Arc::new(open(path).await.expect("schema"));

    // The tenant exists before the router does.
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "example", Timestamp::now_utc())
        .await
        .expect("tenant");
    store
        .create_user(
            &User {
                id: Id::now_v7(),
                tenant_id: tenant,
                email: "copy@example.test".to_owned(),
            },
            "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA",
            None,
            Timestamp::now_utc(),
        )
        .await
        .expect("user");

    let issued: Arc<Mutex<Vec<(String, TokenKind, String)>>> = Arc::default();
    let sink = Arc::clone(&issued);

    let app = AuthRouter::new(
        // The caller's `Arc`, not a `Box::leak`.
        Arc::clone(&store),
        tenant,
        // 32 bytes, from the secret provider in a real deployment.
        [7u8; 32],
        // Mandatory choice: `true` behind TLS, `false` on plain HTTP.
        true,
    )
    .on_proof(move |email, kind, token| {
        sink.lock()
            .expect("hook")
            .push((email.to_owned(), kind, token.expose().to_owned()));
    })
    .into_router();

    // A safe GET hands the browser a CSRF token.
    let (status, headers, _) = send(&app, get("/session")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = cookie_header(&headers, "neotales.csrf").expect("csrf cookie");
    assert!(
        !cookie.contains("HttpOnly"),
        "script must be able to read the CSRF cookie: {cookie}"
    );

    // The client copies that value into `x-csrf-token`. The pair passes the check and
    // the issue route runs, handing the one-time token to the hook.
    let csrf = cookie_value(cookie);
    let request = post(
        "/email/verify/request",
        &json!({ "email": "copy@example.test" }),
        csrf,
    );
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let issued = issued.lock().expect("hook");
    assert_eq!(issued.len(), 1, "the hook sees the token once");
    assert_eq!(issued[0].0, "copy@example.test");
    assert_eq!(issued[0].1, TokenKind::EmailVerification);
    assert!(!issued[0].2.is_empty(), "a token was minted");
}

/// The same mount with no hook must not expose the issue route at all.
#[tokio::test]
async fn the_same_mount_without_a_hook_has_no_issue_route() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    let store = Arc::new(open(path).await.expect("schema"));

    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "example", Timestamp::now_utc())
        .await
        .expect("tenant");

    let app = AuthRouter::new(Arc::clone(&store), tenant, [7u8; 32], false).into_router();

    let (status, _, _) = send(
        &app,
        post(
            "/email/verify/request",
            &json!({ "email": "copy@example.test" }),
            "irrelevant",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
