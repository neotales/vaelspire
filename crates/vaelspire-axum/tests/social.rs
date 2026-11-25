//! Social sign-in over the real router and a local fake provider.
//!
//! Each fake server accepts one HTTP request and answers JSON, so a callback's token
//! exchange and user-info read never leave loopback.

#![cfg(feature = "social")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::JoinHandle;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::Value;
use sqlx::SqlitePool;
use tower::ServiceExt;
use url::Url;
use vaelspire_axum::{AuthRouter, SocialConfig};
use vaelspire_core::{AuthStore, Id, SocialProvider, Timestamp, User};
use vaelspire_store_sqlite::{SqliteStore, open};

struct Database {
    _file: tempfile::NamedTempFile,
    pool: SqlitePool,
    store: Arc<SqliteStore>,
}

async fn database() -> Database {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    let store = Arc::new(open(path).await.expect("schema"));
    let pool = SqlitePool::connect(path).await.expect("inspection pool");
    Database {
        _file: file,
        pool,
        store,
    }
}

async fn tenant(store: &SqliteStore) -> Id {
    let id = Id::now_v7();
    store
        .create_tenant(id, "social", Timestamp::now_utc())
        .await
        .expect("tenant");
    id
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("request")
}

fn get_with_cookie(path: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
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

fn set_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|text| {
            let first = text.split(';').next()?;
            let (key, value) = first.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

fn headers_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request(stream: &mut std::net::TcpStream) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let Some(end) = headers_end(&buffer) else {
            continue;
        };
        let headers = String::from_utf8_lossy(&buffer[..end]);
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        if buffer.len() >= end + 4 + length {
            break;
        }
    }
}

/// A loopback HTTP server that answers one request with `body` and closes.
fn serve_once(body: impl Into<String>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("fake provider");
    let address = listener.local_addr().expect("address");
    let url = format!("http://{address}/");
    let body = body.into();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        read_request(&mut stream);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).expect("write");
        stream.flush().expect("flush");
    });
    (url, handle)
}

fn config(provider: SocialProvider, token_url: &str, user_info_url: &str) -> SocialConfig {
    SocialConfig::new(
        provider,
        "client-id",
        "client-secret",
        "http://app.test/social/github/callback",
    )
    .authorization_url("https://auth.example/authorize")
    .token_url(token_url)
    .user_info_url(user_info_url)
}

fn router(database: &Database, tenant: Id, config: SocialConfig) -> Router {
    AuthRouter::new(Arc::clone(&database.store), tenant, [11; 32], false)
        .social(config)
        .into_router()
}

async fn start_state(app: &Router, provider: &str) -> String {
    let (status, headers, _) = send(app, get(&format!("/social/{provider}/start"))).await;
    assert_eq!(status, StatusCode::FOUND);
    let location = headers
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location text");
    let url = Url::parse(location).expect("authorization url");
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    params.get("state").expect("state").clone()
}

#[tokio::test]
async fn start_redirects_with_the_configured_callback_and_a_stored_digest() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(
        &database,
        tenant,
        config(
            SocialProvider::GitHub,
            "http://unused.test/token",
            "http://unused.test/user",
        ),
    );

    let (status, headers, _) = send(&app, get("/social/github/start")).await;
    assert_eq!(status, StatusCode::FOUND);
    let location = headers
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location text");
    let url = Url::parse(location).expect("authorization url");
    assert_eq!(url.origin().ascii_serialization(), "https://auth.example");
    assert_eq!(url.path(), "/authorize");
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("client-id")
    );
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("http://app.test/social/github/callback"),
        "the configured callback is used, not a query parameter"
    );
    let state = params.get("state").expect("state");

    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_digest FROM auth_social_state")
        .fetch_all(&database.pool)
        .await
        .expect("stored state");
    assert_eq!(stored.len(), 1, "the start route stores one state");
    assert_eq!(stored[0].len(), 33, "version byte plus 32 digest bytes");
    assert_ne!(
        stored[0],
        state.as_bytes(),
        "the raw state is not the stored value"
    );
}

#[tokio::test]
async fn callback_issues_the_session_cookie_and_refuses_a_reused_state() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let (token_url, token_server) =
        serve_once(r#"{"access_token":"fake-access-token","refresh_token":"fake-refresh-token"}"#);
    let (user_url, user_server) =
        serve_once(r#"{"sub":"9012","email":"social@example.test","email_verified":true}"#);
    let app = router(
        &database,
        tenant,
        config(SocialProvider::GitHub, &token_url, &user_url),
    );
    let state = start_state(&app, "github").await;

    let (status, headers, bytes) = send(
        &app,
        get(&format!("/social/github/callback?code=abc&state={state}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = String::from_utf8(bytes).expect("utf-8");
    let json: Value = serde_json::from_str(&body).expect("json");
    assert!(json.get("user_id").is_some());
    assert!(!body.contains("fake-access-token"));
    assert!(!body.contains("fake-refresh-token"));
    assert!(!body.contains("client-secret"));
    let cookie = set_cookie(&headers, "neotales.session").expect("session cookie");

    // The cookie is the same one `/session` reads.
    let (status, _, _) = send(
        &app,
        get_with_cookie("/session", &format!("neotales.session={cookie}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
        .fetch_one(&database.pool)
        .await
        .expect("sessions");
    assert_eq!(sessions, 1);
    let identities: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_social_identity WHERE provider='github' AND subject='9012'",
    )
    .fetch_one(&database.pool)
    .await
    .expect("identity");
    assert_eq!(identities, 1);

    // The same state cannot be spent again, and no second session appears.
    let (status, _, _) = send(
        &app,
        get(&format!("/social/github/callback?code=abc&state={state}")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
        .fetch_one(&database.pool)
        .await
        .expect("sessions after replay");
    assert_eq!(sessions, 1, "a reused state issues no session");

    token_server.join().expect("token server");
    user_server.join().expect("user server");
}

#[tokio::test]
async fn a_provider_email_owned_by_another_live_account_is_conflict() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    database
        .store
        .create_user(
            &User {
                id: Id::now_v7(),
                tenant_id: tenant,
                email: "taken@example.test".to_owned(),
            },
            "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA",
            None,
            Timestamp::now_utc(),
        )
        .await
        .expect("existing account");

    for verified in [true, false] {
        let (token_url, token_server) = serve_once(r#"{"access_token":"access"}"#);
        let email_verified = if verified { "true" } else { "false" };
        let (user_url, user_server) = serve_once(format!(
            r#"{{"sub":"subject-{verified}","email":"taken@example.test","email_verified":{email_verified}}}"#
        ));
        let app = router(
            &database,
            tenant,
            config(SocialProvider::Google, &token_url, &user_url),
        );
        let state = start_state(&app, "google").await;
        let (status, _, _) = send(
            &app,
            get(&format!("/social/google/callback?code=abc&state={state}")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "verified={verified} never takes over a live account"
        );
        token_server.join().expect("token server");
        user_server.join().expect("user server");
    }

    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
        .fetch_one(&database.pool)
        .await
        .expect("sessions");
    assert_eq!(sessions, 0, "a conflict issues no session");
    let accounts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_user WHERE email='taken@example.test'")
            .fetch_one(&database.pool)
            .await
            .expect("accounts");
    assert_eq!(
        accounts, 1,
        "the existing account is neither copied nor replaced"
    );
    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_social_identity")
        .fetch_one(&database.pool)
        .await
        .expect("identities");
    assert_eq!(linked, 0, "no social identity is attached to the account");
}

#[tokio::test]
async fn unknown_and_unconfigured_providers_do_not_redirect() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(
        &database,
        tenant,
        config(
            SocialProvider::Microsoft,
            "http://unused.test/token",
            "http://unused.test/user",
        ),
    );
    let (status, _, _) = send(&app, get("/social/apple/start")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the provider set is closed");
    let (status, _, _) = send(&app, get("/social/google/start")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
