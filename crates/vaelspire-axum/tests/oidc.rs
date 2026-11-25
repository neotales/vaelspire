//! OIDC routes against local HTTP issuers and SQLite.
#![cfg(feature = "oidc")]

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
use vaelspire_axum::{AuthRouter, OidcConfig};
use vaelspire_core::{AuthStore, Id, OidcProvider, Timestamp, User};
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

fn read_request(stream: &mut std::net::TcpStream) -> String {
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
    String::from_utf8_lossy(&buffer).into_owned()
}

/// A loopback HTTP server that answers one request with `body` and closes.
fn serve_once(body: impl Into<String>) -> (String, JoinHandle<()>) {
    serve_expected(body, None)
}

fn serve_expected(body: impl Into<String>, path: Option<&str>) -> (String, JoinHandle<()>) {
    let path = path.map(str::to_owned);
    let listener = TcpListener::bind("127.0.0.1:0").expect("fake provider");
    let address = listener.local_addr().expect("address");
    let url = format!("http://{address}/");
    let body = body.into();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let request = read_request(&mut stream);
        if let Some(path) = path {
            assert!(request.starts_with(&format!("POST {path} ")));
            assert!(request.contains("redirect_uri="));
        }
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

async fn begin(app: &Router, name: &str) -> String {
    let (status, headers, _) = send(
        app,
        get(&format!(
            "/oidc/{name}/start?redirect_uri=http://evil.invalid"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let url = Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(params["redirect_uri"], "http://app.test/callback");
    params["state"].clone()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Three issuers, replay, and takeover in one fixture.
async fn each_issuer_signs_in_and_refuses_replay_and_email_takeover() {
    for provider in [
        OidcProvider::Authentik,
        OidcProvider::Zitadel,
        OidcProvider::Keycloak,
    ] {
        let db = database().await;
        let tenant = tenant(&db.store).await;
        let name = provider.as_str();
        let mut first_user = None;
        for attempt in 0..3 {
            let expected = if provider == OidcProvider::Keycloak {
                "/protocol/openid-connect/token"
            } else {
                "/configured-token"
            };
            let (token_base, token_thread) = serve_expected(
                r#"{"access_token":"fake-access","refresh_token":"fake-refresh"}"#,
                Some(expected),
            );
            let token = format!("{token_base}configured-token");
            let email = if attempt == 2 {
                "taken@example.test"
            } else {
                "person@example.test"
            };
            let subject = if attempt == 2 { "other" } else { "stable" };
            let (userinfo, user_thread) = serve_once(format!(
                r#"{{"sub":"{subject}","email":"{email}","email_verified":true}}"#
            ));
            if attempt == 2 {
                db.store
                    .create_user(
                        &User {
                            id: Id::now_v7(),
                            tenant_id: tenant,
                            email: email.to_owned(),
                        },
                        "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA",
                        None,
                        Timestamp::now_utc(),
                    )
                    .await
                    .unwrap();
            }
            let issuer = token_base.trim_end_matches('/');
            let mut config = OidcConfig::new(
                provider,
                issuer,
                "client",
                "fake-secret",
                "http://app.test/callback",
            )
            .user_info_url(userinfo);
            if provider != OidcProvider::Keycloak {
                config = config.token_url(token);
            }
            let app = AuthRouter::new(Arc::clone(&db.store), tenant, [11; 32], false)
                .auditing(true)
                .oidc(config)
                .into_router();
            let state = begin(&app, name).await;
            let digest: Vec<u8> = sqlx::query_scalar(
                "SELECT token_digest FROM auth_social_state ORDER BY rowid DESC LIMIT 1",
            )
            .fetch_one(&db.pool)
            .await
            .unwrap();
            assert_ne!(digest, state.as_bytes());
            let path = format!("/oidc/{name}/callback?code=abc&state={state}");
            let (status, headers, body) = send(&app, get(&path)).await;
            if attempt == 2 {
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(set_cookie(&headers, "neotales.session").is_none());
            } else {
                assert_eq!(status, StatusCode::OK);
                let text = String::from_utf8(body).unwrap();
                for secret in ["fake-access", "fake-refresh", "fake-secret"] {
                    assert!(!text.contains(secret));
                }
                let user = serde_json::from_str::<Value>(&text).unwrap()["user_id"].clone();
                if let Some(previous) = &first_user {
                    assert_eq!(&user, previous);
                } else {
                    first_user = Some(user);
                }
                assert!(set_cookie(&headers, "neotales.session").is_some());
                assert_eq!(send(&app, get(&path)).await.0, StatusCode::UNAUTHORIZED);
            }
            token_thread.join().unwrap();
            user_thread.join().unwrap();
        }
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(sessions, 2);
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT json_object('action',action,'outcome',outcome) FROM auth_audit",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert!(rows.iter().any(|row| row.contains("auth.session.issued")));
        for row in rows {
            for secret in ["fake-access", "fake-refresh", "fake-secret"] {
                assert!(!row.contains(secret));
            }
        }
    }
}

#[tokio::test]
async fn audit_insert_failure_rolls_back_session() {
    let db = database().await;
    let tenant = tenant(&db.store).await;
    sqlx::query("CREATE TRIGGER fail_audit BEFORE INSERT ON auth_audit BEGIN SELECT RAISE(ABORT, 'rejected'); END").execute(&db.pool).await.unwrap();
    let (token, token_thread) = serve_once(r#"{"access_token":"fake"}"#);
    let (user, user_thread) =
        serve_once(r#"{"sub":"new","email":"new@example.test","email_verified":true}"#);
    let config = OidcConfig::new(
        OidcProvider::Zitadel,
        &token,
        "client",
        "fake-secret",
        "http://app.test/callback",
    )
    .token_url(token.clone())
    .user_info_url(user);
    let app = AuthRouter::new(Arc::clone(&db.store), tenant, [11; 32], false)
        .auditing(true)
        .oidc(config)
        .into_router();
    let state = begin(&app, "zitadel").await;
    let (status, headers, _) = send(
        &app,
        get(&format!("/oidc/zitadel/callback?code=abc&state={state}")),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(set_cookie(&headers, "neotales.session").is_none());
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
    token_thread.join().unwrap();
    user_thread.join().unwrap();
}
