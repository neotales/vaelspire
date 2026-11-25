//! Router behaviour against a real SQLite file.

#[cfg(all(feature = "password", feature = "session"))]
use axum::Extension;
use axum::Router;
use axum::body::{Body, to_bytes};
#[cfg(all(feature = "password", feature = "session"))]
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::{Value, json};
#[cfg(all(feature = "password", feature = "session"))]
use sqlx::Row;
use sqlx::SqlitePool;
#[cfg(all(feature = "password", feature = "session"))]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
#[cfg(feature = "apikeys")]
use time::Duration;
use tower::ServiceExt;
use vaelspire_axum::AuthRouter;
#[cfg(any(
    all(feature = "password", feature = "session"),
    feature = "email-signin"
))]
use vaelspire_axum::Paths;
#[cfg(feature = "session")]
use vaelspire_axum::TokenKind;
use vaelspire_core::{AuthStore, Id, Timestamp};
use vaelspire_store_sqlite::{SqliteStore, open};

#[cfg(feature = "password")]
const PASSWORD: &str = "correct horse battery staple";

struct Database {
    _file: tempfile::NamedTempFile,
    #[allow(dead_code)]
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

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn rate_limit_rejects_request_after_configured_max() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .rate_limit(2, std::time::Duration::from_secs(60))
        .into_router();

    for _ in 0..2 {
        let (status, _, _) = send(&app, post("/sign-up", &json!({}), None, None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _, body) = send(&app, post("/sign-up", &json!({}), None, None)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error":"rate limit"})
    );
}

#[cfg(feature = "session")]
#[tokio::test]
async fn rate_limit_does_not_limit_safe_get() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .rate_limit(1, std::time::Duration::from_secs(60))
        .into_router();

    for _ in 0..2 {
        let (status, _, _) = send(&app, get("/session", None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

async fn tenant(store: &SqliteStore) -> Id {
    let id = Id::now_v7();
    store
        .create_tenant(id, "router", Timestamp::now_utc())
        .await
        .expect("tenant");
    id
}

/// The mount every test starts from. `cookie_secure` is `false` because the test
/// client speaks plain HTTP and no TLS terminator is in front of it.
fn router(database: &Database, tenant: Id, audited: bool) -> AuthRouter<SqliteStore> {
    AuthRouter::new(Arc::clone(&database.store), tenant, [9; 32], false).auditing(audited)
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).expect("request")
}

fn post(path: &str, body: &Value, csrf: Option<&str>, user_agent: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost");
    if let Some(csrf) = csrf {
        builder = builder
            .header(header::COOKIE, format!("neotales.csrf={csrf}"))
            .header("x-csrf-token", csrf);
    }
    if let Some(user_agent) = user_agent {
        builder = builder.header(header::USER_AGENT, user_agent);
    }
    builder.body(Body::from(body.to_string())).expect("request")
}

/// A `POST` carrying the session cookie and the double-submit pair.
#[cfg(feature = "session")]
fn post_signed(path: &str, body: &Value, session: &str, csrf: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost")
        .header(
            header::COOKIE,
            format!("neotales.session={session}; neotales.csrf={csrf}"),
        )
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

/// Replace the `Origin` the request helpers send, or remove it with `None`.
fn with_origin(mut request: Request<Body>, origin: Option<&str>) -> Request<Body> {
    request.headers_mut().remove(header::ORIGIN);
    if let Some(origin) = origin {
        request.headers_mut().insert(
            header::ORIGIN,
            origin.parse().expect("an origin header value"),
        );
    }
    request
}

/// The `error` string a refusal carries.
fn error_of(bytes: &[u8]) -> String {
    let body: Value = serde_json::from_slice(bytes).expect("json");
    body.get("error")
        .and_then(Value::as_str)
        .expect("an error string")
        .to_owned()
}

#[cfg(feature = "session")]
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

/// The CSRF token a browser would read from the cookie, obtained from a safe GET.
#[cfg(any(
    all(feature = "password", feature = "session"),
    feature = "email-signin"
))]
async fn csrf(app: &Router) -> String {
    let (_, headers, _) = send(app, get("/session", None)).await;
    set_cookie(&headers, "neotales.csrf").expect("csrf cookie")
}

/// The whole `Set-Cookie` value for `name`, attributes included.
#[cfg(feature = "session")]
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

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn path_override_moves_the_route() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .paths(Paths::new().sign_in("/login"))
        .into_router();

    let csrf = csrf(&app).await;
    let credentials = json!({ "email": "path@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, _) = send(&app, post("/sign-in", &credentials, Some(&csrf), None)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default sign-in path is not registered"
    );

    let (status, headers, bytes) =
        send(&app, post("/login", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        set_cookie(&headers, "neotales.session").is_some(),
        "the new path sets the session cookie"
    );
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert!(body.get("user_id").is_some());
}

#[cfg(all(feature = "password", feature = "session"))]
async fn custom_sign_in() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom sign in")
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn handler_override_replaces_only_that_route() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .sign_in(custom_sign_in)
        .into_router();

    let csrf = csrf(&app).await;
    let credentials = json!({ "email": "override@example.test", "password": PASSWORD });

    // The default sign-up handler is untouched.
    let (status, _, _) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, bytes) = send(&app, post("/sign-in", &credentials, None, None)).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(String::from_utf8(bytes).expect("utf-8"), "custom sign in");
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn the_default_handler_can_be_passed_back() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .sign_in(vaelspire_axum::default::sign_in::<SqliteStore>)
        .into_router();

    let csrf = csrf(&app).await;
    let credentials = json!({ "email": "again@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, _) = send(&app, post("/sign-in", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(set_cookie(&headers, "neotales.session").is_some());
}

/// Group routes are mounted by `roles(true)`, use the router's tenant, and a moved path
/// leaves the default unregistered. Cross-tenant refusal and a repeated add are the
/// store suite's job.
#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn group_routes_are_opt_in_and_their_paths_move() {
    let database = database().await;
    let tenant = tenant(&database.store).await;

    let off = router(&database, tenant, false).into_router();
    let csrf = csrf(&off).await;
    let (status, _, _) = send(
        &off,
        post("/groups", &json!({ "name": "platform" }), Some(&csrf), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "group routes stay off until roles(true)"
    );

    let app = router(&database, tenant, false)
        .roles(true)
        .paths(Paths::new().groups("/catalog/groups"))
        .into_router();

    let (status, _, _) = send(
        &app,
        post("/groups", &json!({ "name": "platform" }), Some(&csrf), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default group path is not mounted"
    );

    let (status, _, _) = send(
        &app,
        post(
            "/catalog/groups",
            &json!({ "name": "platform" }),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the CSRF pair is required");

    let (status, _, bytes) = send(
        &app,
        post(
            "/catalog/groups",
            &json!({ "name": "platform" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    let group = body["id"].as_str().expect("group id").to_owned();

    let (status, _, _) = send(
        &app,
        post(
            "/catalog/groups",
            &json!({ "name": "platform" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a duplicate name in the tenant"
    );

    let credentials = json!({ "email": "group@example.test", "password": PASSWORD });
    let (status, _, bytes) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    let user = body["user"]["id"].as_str().expect("user id").to_owned();
    let (status, _, bytes) = send(
        &app,
        post(
            "/memberships",
            &json!({ "user_id": user }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    let membership = body["id"].as_str().expect("membership id").to_owned();

    // Only the create path moved; the two member paths keep their defaults.
    let add = format!("/groups/{group}/members");
    let member = json!({ "membership_id": membership });
    let (status, _, _) = send(&app, post(&add, &member, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the membership is added");
    let (status, _, _) = send(&app, post(&add, &member, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "a repeated add succeeds");

    let remove = format!("/groups/{group}/members/{membership}");
    let (status, _, _) = send(&app, delete(&remove, None, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the membership is removed");
    let (status, _, _) = send(&app, delete(&remove, None, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the pair is gone");
}

#[cfg(feature = "password")]
#[tokio::test]
async fn csrf_is_required_and_the_get_sets_the_cookie() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();

    let credentials = json!({ "email": "csrf@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-up", &credentials, None, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no cookie and no header");

    let (status, headers, _) = send(&app, get("/session", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|text| text.starts_with("neotales.csrf="))
        .expect("csrf cookie on a safe GET")
        .to_owned();
    assert!(
        !cookie.contains("HttpOnly"),
        "the CSRF cookie must be readable by script"
    );

    let csrf = set_cookie(&headers, "neotales.csrf").expect("token");
    let (status, _, _) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED, "a matching pair passes");
}

/// `/memberships` is registered in every build, so the origin rule can be exercised
/// without a session or a CSRF cookie.
#[tokio::test]
async fn a_state_changing_request_from_an_unlisted_origin_is_forbidden() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();

    let (status, _, bytes) = send(
        &app,
        with_origin(post("/memberships", &json!({}), None, None), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a missing Origin is not localhost"
    );
    assert_eq!(error_of(&bytes), "origin");

    let (status, _, bytes) = send(
        &app,
        with_origin(
            post("/memberships", &json!({}), None, None),
            Some("https://evil.example"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&bytes), "origin");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the refusal names only the failed check: {body}"
    );

    // A local origin passes this check and then meets CSRF, which is still on: the
    // origin rule is in addition to it, not instead of it.
    let (status, _, bytes) = send(
        &app,
        with_origin(
            post("/memberships", &json!({}), None, None),
            Some("http://localhost:3000"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&bytes), "csrf");
}

#[tokio::test]
async fn a_configured_origin_list_accepts_only_its_entry() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .allowed_origins(["https://app.example.test"])
        // Turning CSRF off leaves the origin rule standing.
        .csrf_disabled()
        .into_router();

    let (status, _, _) = send(
        &app,
        with_origin(
            post("/memberships", &json!({}), None, None),
            Some("https://app.example.test"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the listed origin reaches the handler and fails on its empty body"
    );

    for origin in [
        "https://app.example.test:8443",
        "http://app.example.test",
        "https://sub.app.example.test",
        "https://app.example.test.evil.example",
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1",
        "null",
    ] {
        let (status, _, bytes) = send(
            &app,
            with_origin(post("/memberships", &json!({}), None, None), Some(origin)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{origin} is not listed");
        assert_eq!(error_of(&bytes), "origin", "{origin}");
    }

    let (status, _, bytes) = send(
        &app,
        with_origin(post("/memberships", &json!({}), None, None), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a missing Origin is refused too"
    );
    assert_eq!(error_of(&bytes), "origin");
}

#[tokio::test]
async fn an_empty_origin_list_refuses_localhost() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .allowed_origins(std::iter::empty::<&str>())
        .csrf_disabled()
        .into_router();

    for origin in [
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "http://[::1]",
    ] {
        let (status, _, bytes) = send(
            &app,
            with_origin(post("/memberships", &json!({}), None, None), Some(origin)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{origin} is not listed");
        assert_eq!(error_of(&bytes), "origin", "{origin}");
    }
}

/// The Origin rule is for state-changing routes only.
#[cfg(feature = "session")]
#[tokio::test]
async fn a_safe_get_is_not_refused_for_origin() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();

    let (status, _, _) = send(
        &app,
        with_origin(get("/session", None), Some("https://evil.example")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "GET /session answers without a session instead of 403"
    );
}

#[cfg(feature = "apikeys")]
#[tokio::test]
async fn api_key_verify_is_not_refused_for_origin() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .api_keys(None)
        .expect("api-key prefix")
        .into_router();

    let (status, _, _) = send(
        &app,
        with_origin(get("/api-keys/verify", None), Some("https://evil.example")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "GET /api-keys/verify answers on its key, not on Origin"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn the_session_token_is_only_in_the_cookie() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();

    let csrf = csrf(&app).await;
    let credentials = json!({ "email": "cookie@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, bytes) =
        send(&app, post("/sign-in", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::OK);

    let token = set_cookie(&headers, "neotales.session").expect("session cookie");
    assert_ne!(token, "");
    let text = String::from_utf8(bytes).expect("utf-8");
    assert!(
        !text.contains(&token),
        "the session token must not appear in the JSON body: {text}"
    );
    assert!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|text| text.starts_with("neotales.session=") && text.contains("HttpOnly")),
        "the session cookie is HttpOnly"
    );
}

/// A `DELETE` carrying the session cookie and, when given, the double-submit pair.
#[cfg(feature = "session")]
fn delete(
    path: &str,
    session: Option<&str>,
    csrf: Option<&str>,
    user_agent: Option<&str>,
) -> Request<Body> {
    let mut cookies = Vec::new();
    if let Some(session) = session {
        cookies.push(format!("neotales.session={session}"));
    }
    if let Some(csrf) = csrf {
        cookies.push(format!("neotales.csrf={csrf}"));
    }
    let mut builder = Request::builder()
        .method("DELETE")
        .uri(path)
        .header(header::ORIGIN, "http://localhost");
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies.join("; "));
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    if let Some(user_agent) = user_agent {
        builder = builder.header(header::USER_AGENT, user_agent);
    }
    builder.body(Body::empty()).expect("request")
}

#[cfg(all(feature = "password", feature = "session"))]
async fn register(app: &Router, email: &str, csrf: &str) {
    let credentials = json!({ "email": email, "password": PASSWORD });
    let (status, _, _) = send(app, post("/sign-up", &credentials, Some(csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[cfg(all(feature = "password", feature = "session"))]
async fn sign_in(app: &Router, email: &str, csrf: &str) -> String {
    let credentials = json!({ "email": email, "password": PASSWORD });
    let (status, headers, _) = send(app, post("/sign-in", &credentials, Some(csrf), None)).await;
    assert_eq!(status, StatusCode::OK);
    set_cookie(&headers, "neotales.session").expect("session cookie")
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn near_expiry_session_slides_and_sets_cookie() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, true).into_router();
    let csrf = csrf(&app).await;
    register(&app, "sliding@example.test", &csrf).await;
    let token = sign_in(&app, "sliding@example.test", &csrf).await;
    let expiry = (Timestamp::now_utc() + time::Duration::minutes(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    sqlx::query("UPDATE auth_session SET expires_at=?")
        .bind(&expiry)
        .execute(&database.pool)
        .await
        .unwrap();
    let app = router(&database, tenant, true).into_router();
    let (status, headers, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={token}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        cookie_header(&headers, "neotales.session")
            .is_some_and(|value| value.contains("Max-Age=86400"))
    );
    let updated: String = sqlx::query_scalar("SELECT expires_at FROM auth_session")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert!(
        Timestamp::parse(&updated, &time::format_description::well_known::Rfc3339).unwrap()
            > Timestamp::now_utc() + time::Duration::hours(23)
    );
    let audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE action='auth.session.extended'")
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(audit, 1);
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn fresh_cookie_is_not_rewritten_and_revoke_invalidates_cached_session() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "cached@example.test", &csrf).await;
    let token = sign_in(&app, "cached@example.test", &csrf).await;
    let before: (String, String) =
        sqlx::query_as("SELECT expires_at,last_seen_at FROM auth_session")
            .fetch_one(&database.pool)
            .await
            .unwrap();
    for _ in 0..2 {
        let (status, headers, _) = send(
            &app,
            get("/session", Some(&format!("neotales.session={token}"))),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(cookie_header(&headers, "neotales.session").is_none());
    }
    let after: (String, String) =
        sqlx::query_as("SELECT expires_at,last_seen_at FROM auth_session")
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    let second_router = router(&database, tenant, false).into_router();
    let (status, _, _) = send(
        &second_router,
        post_signed("/sign-out", &json!({}), &token, &csrf),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={token}"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn zero_cache_duration_reads_the_store_each_time() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .session_cache_duration(std::time::Duration::ZERO)
        .into_router();
    let csrf = csrf(&app).await;
    register(&app, "no-cache@example.test", &csrf).await;
    let token = sign_in(&app, "no-cache@example.test", &csrf).await;
    let cookie = format!("neotales.session={token}");
    assert_eq!(
        send(&app, get("/session", Some(&cookie))).await.0,
        StatusCode::OK
    );
    sqlx::query("UPDATE auth_session SET revoked_at=created_at")
        .execute(&database.pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, get("/session", Some(&cookie))).await.0,
        StatusCode::UNAUTHORIZED
    );
}

/// `GET /sessions` as the caller, returning the listed entries.
#[cfg(feature = "session")]
async fn session_list(app: &Router, path: &str, session: &str) -> Vec<Value> {
    let cookie = format!("neotales.session={session}");
    let (status, _, bytes) = send(app, get(path, Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    body.get("sessions")
        .and_then(Value::as_array)
        .cloned()
        .expect("sessions array")
}

#[cfg(feature = "session")]
fn listed_id(entry: &Value) -> String {
    entry
        .get("id")
        .and_then(Value::as_str)
        .expect("session id")
        .to_owned()
}

#[cfg(feature = "session")]
fn is_current(entry: &Value) -> bool {
    entry.get("current").and_then(Value::as_bool) == Some(true)
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn sessions_list_the_callers_live_sessions_without_a_token() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "list@example.test", &csrf).await;
    let first = sign_in(&app, "list@example.test", &csrf).await;
    let second = sign_in(&app, "list@example.test", &csrf).await;
    register(&app, "elsewhere@example.test", &csrf).await;
    let other = sign_in(&app, "elsewhere@example.test", &csrf).await;

    let (status, _, _) = send(&app, get("/sessions", None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a list needs a signed-in caller"
    );

    let cookie = format!("neotales.session={first}");
    let (status, _, bytes) = send(&app, get("/sessions", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(bytes.clone()).expect("utf-8");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    let sessions = body
        .get("sessions")
        .and_then(Value::as_array)
        .expect("sessions array");
    assert_eq!(sessions.len(), 2, "the caller's two sessions");
    assert_eq!(
        sessions.iter().filter(|entry| is_current(entry)).count(),
        1,
        "exactly one is the current session"
    );
    for entry in sessions {
        assert!(entry.get("id").and_then(Value::as_str).is_some());
        assert!(entry.get("expires_at").and_then(Value::as_i64).is_some());
        assert!(entry.get("token").is_none(), "no bearer value");
        assert!(entry.get("token_digest").is_none(), "no digest");
    }
    assert!(!text.contains(&first), "the token is not echoed: {text}");
    assert!(!text.contains(&second), "the token is not echoed: {text}");
    assert!(
        !text.contains(&other),
        "another account's token is absent: {text}"
    );

    // The other account's session is not in the caller's list, and the caller's are not
    // in the other account's.
    let theirs = session_list(&app, "/sessions", &other).await;
    assert_eq!(
        theirs.len(),
        1,
        "the other account has its own session only"
    );
    let theirs = listed_id(&theirs[0]);
    let mine: Vec<String> = sessions.iter().map(listed_id).collect();
    assert!(!mine.contains(&theirs), "another account's session id");
    let their_view = session_list(&app, "/sessions", &other).await;
    assert_eq!(
        listed_id(&their_view[0]),
        theirs,
        "the list is a store read"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn revoke_one_moves_only_the_named_session_of_the_caller() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "revoke@example.test", &csrf).await;
    let first = sign_in(&app, "revoke@example.test", &csrf).await;
    let second = sign_in(&app, "revoke@example.test", &csrf).await;
    register(&app, "stranger@example.test", &csrf).await;
    let stranger = sign_in(&app, "stranger@example.test", &csrf).await;

    let listed = session_list(&app, "/sessions", &first).await;
    let current = listed
        .iter()
        .find(|entry| is_current(entry))
        .map(listed_id)
        .expect("the current session");
    let retired = listed
        .iter()
        .find(|entry| !is_current(entry))
        .map(listed_id)
        .expect("the other session");

    // The CSRF check guards the revoke.
    let (status, _, _) = send(
        &app,
        delete(&format!("/sessions/{retired}"), Some(&first), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no CSRF pair, no revoke");

    // Another account's identifier is not a revoke.
    let stranger_id = listed_id(&session_list(&app, "/sessions", &stranger).await[0]);
    let (status, _, _) = send(
        &app,
        delete(
            &format!("/sessions/{stranger_id}"),
            Some(&first),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={stranger}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another account's session stays live"
    );

    // The caller's own identifier is revoked.
    let (status, headers, _) = send(
        &app,
        delete(
            &format!("/sessions/{retired}"),
            Some(&first),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_none(),
        "revoking another session leaves the caller's cookie alone"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={second}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the revoked session is gone"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={first}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the presented session survives");

    // Revoking the presented session clears its cookie.
    let (status, headers, _) = send(
        &app,
        delete(
            &format!("/sessions/{current}"),
            Some(&first),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_some_and(|text| text.contains("Max-Age=0")),
        "the current session's cookie is cleared"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={first}"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn revoke_others_keeps_the_presented_cookie() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "others@example.test", &csrf).await;
    let first = sign_in(&app, "others@example.test", &csrf).await;
    let second = sign_in(&app, "others@example.test", &csrf).await;
    register(&app, "untouched@example.test", &csrf).await;
    let untouched = sign_in(&app, "untouched@example.test", &csrf).await;

    let (status, headers, _) =
        send(&app, delete("/sessions", Some(&first), Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_none(),
        "revoke-others sets no cookie"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={second}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the other session is gone"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={first}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the presented session stays");
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={untouched}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another account's session is untouched"
    );
    assert_eq!(
        session_list(&app, "/sessions", &first).await.len(),
        1,
        "only the presented session is left"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn revoke_all_clears_the_cookie_and_every_session() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "all@example.test", &csrf).await;
    let first = sign_in(&app, "all@example.test", &csrf).await;
    let second = sign_in(&app, "all@example.test", &csrf).await;
    register(&app, "unrelated@example.test", &csrf).await;
    let unrelated = sign_in(&app, "unrelated@example.test", &csrf).await;

    let (status, headers, _) = send(
        &app,
        delete("/sessions/all", Some(&first), Some(&csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_some_and(|text| text.contains("Max-Age=0")),
        "revoke-all clears the cookie"
    );
    for token in [&first, &second] {
        let (status, _, _) = send(
            &app,
            get("/session", Some(&format!("neotales.session={token}"))),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "every session is gone");
    }
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={unrelated}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another account's session is untouched"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn a_revoke_is_audited_without_the_token() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let address = SocketAddr::from(([203, 0, 113, 11], 51515));
    let app = router(&database, tenant, true)
        .into_router()
        .layer(Extension(ConnectInfo(address)));
    let csrf = csrf(&app).await;
    register(&app, "audited-revoke@example.test", &csrf).await;
    let first = sign_in(&app, "audited-revoke@example.test", &csrf).await;
    let second = sign_in(&app, "audited-revoke@example.test", &csrf).await;

    let (status, _, _) = send(
        &app,
        delete(
            "/sessions",
            Some(&first),
            Some(&csrf),
            Some("router-test/2"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let rows = sqlx::query(
        "SELECT actor_id, outcome, ip, user_agent FROM auth_audit WHERE action = 'auth.session.revoked'",
    )
    .fetch_all(&database.pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 1, "one revoke writes one row");
    let row = &rows[0];
    let actor: Vec<u8> = sqlx::query_scalar("SELECT id FROM auth_user WHERE email = ?")
        .bind("audited-revoke@example.test")
        .fetch_one(&database.pool)
        .await
        .expect("user id");
    assert_eq!(row.get::<Vec<u8>, _>("actor_id"), actor);
    assert_eq!(row.get::<String, _>("outcome"), "ok");
    assert_eq!(
        row.get::<Option<String>, _>("ip").as_deref(),
        Some("203.0.113.11")
    );
    assert_eq!(
        row.get::<Option<String>, _>("user_agent").as_deref(),
        Some("router-test/2")
    );
    let text = format!(
        "{}{}{}",
        row.get::<String, _>("outcome"),
        row.get::<Option<String>, _>("ip").unwrap_or_default(),
        row.get::<Option<String>, _>("user_agent")
            .unwrap_or_default(),
    );
    assert!(!text.contains(&first), "the row has no token");
    assert!(!text.contains(&second), "the row has no token");
}

#[cfg(feature = "session")]
async fn custom_revoke_others() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom revoke others")
}

#[cfg(feature = "session")]
#[tokio::test]
async fn the_revoke_others_handler_is_overridable() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .revoke_others(custom_revoke_others)
        .into_router();

    let (status, _, bytes) = send(&app, delete("/sessions", None, None, None)).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "custom revoke others"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn session_paths_move_and_the_defaults_stop_answering() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .paths(
            Paths::new()
                .sessions("/auth/sessions")
                .sessions_others("/auth/sessions/others")
                .sessions_all("/auth/sessions/all")
                .session_id("/auth/sessions/{session_id}"),
        )
        .into_router();
    let csrf = csrf(&app).await;
    register(&app, "moved@example.test", &csrf).await;
    let first = sign_in(&app, "moved@example.test", &csrf).await;
    let second = sign_in(&app, "moved@example.test", &csrf).await;

    let (status, _, _) = send(
        &app,
        get("/sessions", Some(&format!("neotales.session={first}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default list path is not registered"
    );
    let listed = session_list(&app, "/auth/sessions", &first).await;
    assert_eq!(listed.len(), 2);
    let retired = listed
        .iter()
        .find(|entry| !is_current(entry))
        .map(listed_id)
        .expect("the other session");

    let (status, _, _) = send(
        &app,
        delete(
            &format!("/sessions/{retired}"),
            Some(&first),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default revoke-one path is not registered"
    );
    let (status, _, _) = send(
        &app,
        delete(
            &format!("/auth/sessions/{retired}"),
            Some(&first),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={second}"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the moved route revoked");

    let (status, _, _) = send(
        &app,
        delete("/sessions/others", Some(&first), Some(&csrf), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default revoke-others path is not registered"
    );
    let (status, _, _) = send(
        &app,
        delete("/auth/sessions/others", Some(&first), Some(&csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &app,
        delete("/sessions/all", Some(&first), Some(&csrf), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default revoke-all path is not registered"
    );
    let (status, headers, _) = send(
        &app,
        delete("/auth/sessions/all", Some(&first), Some(&csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_some_and(|text| text.contains("Max-Age=0"))
    );
}

#[cfg(all(feature = "email-signin", not(feature = "password")))]
#[tokio::test]
async fn session_routes_work_with_password_compiled_out() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    email_user(&database, tenant).await;
    let (issued, sink) = proof_recorder();
    let app = router(&database, tenant, false)
        .on_proof(sink)
        .into_router();
    let csrf = csrf(&app).await;

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "signin@example.test" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let proof = issued.lock().expect("hook")[0].2.clone();
    let (status, headers, _) = send(
        &app,
        post(
            "/email/sign-in",
            &json!({ "token": proof }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session = set_cookie(&headers, "neotales.session").expect("session cookie");

    let listed = session_list(&app, "/sessions", &session).await;
    assert_eq!(listed.len(), 1, "the proof's session is listed");
    assert!(is_current(&listed[0]));
    let (status, headers, _) = send(
        &app,
        delete("/sessions/all", Some(&session), Some(&csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_some_and(|text| text.contains("Max-Age=0"))
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={session}"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn a_denied_sign_in_is_audited_with_the_connection_ip() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let address = SocketAddr::from(([203, 0, 113, 9], 51515));
    let app = router(&database, tenant, true)
        .into_router()
        .layer(Extension(ConnectInfo(address)));

    let csrf = csrf(&app).await;
    let credentials = json!({ "email": "audit@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-up", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::CREATED);

    let wrong = json!({ "email": "audit@example.test", "password": "not the password" });
    let (status, _, _) = send(
        &app,
        post("/sign-in", &wrong, Some(&csrf), Some("router-test/1")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rows = sqlx::query(
        "SELECT outcome, ip, user_agent FROM auth_audit WHERE action = 'auth.session.denied'",
    )
    .fetch_all(&database.pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 1, "one denied sign-in writes one row");
    let row = &rows[0];
    assert_eq!(row.get::<String, _>("outcome"), "denied");
    assert_eq!(
        row.get::<Option<String>, _>("ip").as_deref(),
        Some("203.0.113.9")
    );
    assert_eq!(
        row.get::<Option<String>, _>("user_agent").as_deref(),
        Some("router-test/1")
    );
}

#[cfg(feature = "session")]
#[tokio::test]
async fn the_secure_choice_comes_from_the_constructor() {
    let database = database().await;
    let tenant = tenant(&database.store).await;

    let secure = AuthRouter::new(Arc::clone(&database.store), tenant, [9; 32], true).into_router();
    let (_, headers, _) = send(&secure, get("/session", None)).await;
    assert!(
        cookie_header(&headers, "neotales.csrf").is_some_and(|text| text.contains("; Secure")),
        "the constructor's `true` marks the cookie Secure"
    );

    let plain = router(&database, tenant, false).into_router();
    let (_, headers, _) = send(&plain, get("/session", None)).await;
    assert!(
        cookie_header(&headers, "neotales.csrf").is_some_and(|text| !text.contains("; Secure")),
        "the constructor's `false` omits Secure"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn token_routes_are_absent_without_a_proof_hook() {
    let database = database().await;
    let tenant = tenant(&database.store).await;

    let closed = router(&database, tenant, false).into_router();
    let closed_csrf = csrf(&closed).await;
    for path in [
        "/email/verify/request",
        "/password/reset/request",
        "/invitations",
    ] {
        let (status, _, _) = send(&closed, post(path, &json!({}), Some(&closed_csrf), None)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} is not registered without a proof hook"
        );
    }

    // The consume routes accept a request; an empty body is a 400, not a 404.
    let (status, _, _) = send(
        &closed,
        post("/email/verify", &json!({}), Some(&closed_csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &closed,
        post("/password/reset", &json!({}), Some(&closed_csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &closed,
        post("/invitations/accept", &json!({}), Some(&closed_csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The same paths with a hook are mounted.
    let open = router(&database, tenant, false)
        .on_proof(|_, _, _| {})
        .into_router();
    let open_csrf = csrf(&open).await;
    let (status, _, _) = send(
        &open,
        post(
            "/email/verify/request",
            &json!({ "email": "nobody@example.test" }),
            Some(&open_csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "unknown email still answers 202, so the route exists"
    );
    let (status, _, _) = send(
        &open,
        post(
            "/password/reset/request",
            &json!({ "email": "nobody@example.test" }),
            Some(&open_csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _, _) = send(
        &open,
        post("/invitations", &json!({}), Some(&open_csrf), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "mounted, so the body is checked"
    );
}

#[cfg(feature = "session")]
#[tokio::test]
async fn invitation_issue_delivers_the_token_and_returns_none() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let issued: Arc<Mutex<Vec<(String, TokenKind, String)>>> = Arc::default();
    let sink = Arc::clone(&issued);
    let app = router(&database, tenant, false)
        .on_proof(move |email, kind, token| {
            sink.lock()
                .expect("hook")
                .push((email.to_owned(), kind, token.expose().to_owned()));
        })
        .into_router();

    let (_, headers, _) = send(&app, get("/session", None)).await;
    let csrf = set_cookie(&headers, "neotales.csrf").expect("csrf cookie");

    let expires = (Timestamp::now_utc() + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("timestamp");
    let body = json!({ "email": "invite@example.test", "expires_at": expires });
    let (status, _, bytes) = send(&app, post("/invitations", &body, Some(&csrf), None)).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "the same accepted body as a proof"
    );

    let received = issued.lock().expect("hook");
    assert_eq!(received.len(), 1, "the hook receives the invitation token");
    assert_eq!(received[0].0, "invite@example.test");
    assert_eq!(received[0].1, TokenKind::Invitation);
    assert_ne!(received[0].2, "");

    let text = String::from_utf8(bytes).expect("utf-8");
    let parsed: Value = serde_json::from_str(&text).expect("json");
    assert!(
        parsed.get("token").is_none(),
        "the body has no token: {text}"
    );
    assert!(
        !text.contains(&received[0].2),
        "the token never reaches the body: {text}"
    );
    assert_eq!(
        parsed.get("status").and_then(Value::as_str),
        Some("accepted")
    );
}

#[cfg(feature = "email-signin")]
async fn email_user(database: &Database, tenant: Id) -> Id {
    let id = Id::now_v7();
    let user = vaelspire_core::User {
        id,
        tenant_id: tenant,
        email: "signin@example.test".to_owned(),
    };
    database
        .store
        .create_user(
            &user,
            "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA",
            None,
            Timestamp::now_utc(),
        )
        .await
        .expect("user");
    id
}

#[cfg(feature = "email-signin")]
type IssuedProofs = Arc<Mutex<Vec<(String, TokenKind, String)>>>;

#[cfg(feature = "email-signin")]
fn proof_recorder() -> (
    IssuedProofs,
    impl Fn(&str, TokenKind, &vaelspire_auth::Secret) + Send + Sync,
) {
    let issued: IssuedProofs = Arc::default();
    let sink = Arc::clone(&issued);
    (issued, move |email, kind, token| {
        sink.lock()
            .expect("hook")
            .push((email.to_owned(), kind, token.expose().to_owned()));
    })
}

#[cfg(feature = "email-signin")]
#[tokio::test]
async fn email_sign_in_issues_a_session_once_and_keeps_the_token_out_of_the_body() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let user = email_user(&database, tenant).await;
    let (issued, sink) = proof_recorder();
    let app = router(&database, tenant, false)
        .on_proof(sink)
        .into_router();
    let csrf = csrf(&app).await;

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "not-an-email" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a malformed email is invalid input, not a conflict"
    );

    let (status, _, bytes) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "  SignIn@Example.Test  " }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let text = String::from_utf8(bytes).expect("utf-8");
    let token = {
        let received = issued.lock().expect("hook");
        assert_eq!(received.len(), 1, "the hook receives the proof");
        assert_eq!(
            received[0].0, "signin@example.test",
            "the hook receives the normalized address, not the raw body"
        );
        assert_eq!(received[0].1, TokenKind::EmailSignIn);
        let token = received[0].2.clone();
        assert_ne!(token, "");
        assert!(
            !text.contains(&token),
            "the proof token never reaches the response body: {text}"
        );
        token
    };

    let (status, headers, bytes) = send(
        &app,
        post(
            "/email/sign-in",
            &json!({ "token": token }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session_token = set_cookie(&headers, "neotales.session").expect("session cookie");
    assert_ne!(session_token, "");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body.get("user_id").and_then(Value::as_str),
        Some(user.to_string().as_str())
    );
    assert!(
        !String::from_utf8_lossy(&bytes).contains(&token),
        "the proof token is not echoed"
    );
    assert!(
        !String::from_utf8_lossy(&bytes).contains(&session_token),
        "the session token is only in the cookie"
    );

    let cookie = format!("neotales.session={session_token}");
    let (status, _, _) = send(&app, get("/session", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK, "the issued session resolves");

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in",
            &json!({ "token": token }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a proof is spent once");
}

#[cfg(feature = "email-signin")]
#[tokio::test]
async fn email_sign_in_paths_move_and_the_defaults_stop_answering() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    email_user(&database, tenant).await;
    let (issued, sink) = proof_recorder();
    let app = router(&database, tenant, false)
        .paths(
            Paths::new()
                .email_signin_request("/auth/email/start")
                .email_signin("/auth/email/finish"),
        )
        .on_proof(sink)
        .into_router();
    let csrf = csrf(&app).await;

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "signin@example.test" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default issue path is not registered"
    );
    let (status, _, _) = send(
        &app,
        post(
            "/auth/email/start",
            &json!({ "email": "signin@example.test" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let token = issued.lock().expect("hook")[0].2.clone();

    let (status, _, _) = send(
        &app,
        post(
            "/auth/email/finish",
            &json!({ "token": token }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in",
            &json!({ "token": token }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default spend path is not registered either"
    );
}

#[cfg(feature = "email-signin")]
async fn custom_email_sign_in() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom email sign in")
}

#[cfg(feature = "email-signin")]
#[tokio::test]
async fn email_sign_in_handler_is_overridable() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .email_signin(custom_email_sign_in)
        .into_router();

    let (status, _, bytes) = send(
        &app,
        post("/email/sign-in", &json!({ "token": "unused" }), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "custom email sign in"
    );
}

#[cfg(feature = "email-signin")]
#[tokio::test]
async fn the_email_sign_in_issue_route_is_absent_without_a_proof_hook() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "signin@example.test" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the issue route needs the hook"
    );
    let (status, _, _) = send(&app, post("/email/sign-in", &json!({}), Some(&csrf), None)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the spend route is mounted and checks its body"
    );
}

#[cfg(all(feature = "email-signin", not(feature = "password")))]
#[tokio::test]
async fn email_sign_in_works_with_password_compiled_out() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    email_user(&database, tenant).await;
    let (issued, sink) = proof_recorder();
    let app = router(&database, tenant, false)
        .on_proof(sink)
        .into_router();
    let csrf = csrf(&app).await;

    let (status, _, _) = send(&app, post("/sign-in", &json!({}), Some(&csrf), None)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "password sign-in is not compiled in"
    );

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "signin@example.test" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let token = issued.lock().expect("hook")[0].2.clone();
    let (status, headers, _) = send(
        &app,
        post(
            "/email/sign-in",
            &json!({ "token": token }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(set_cookie(&headers, "neotales.session").is_some());
}

#[cfg(feature = "apikeys")]
async fn key_user(database: &Database, tenant: Id) -> Id {
    let id = Id::now_v7();
    let user = vaelspire_core::User {
        id,
        tenant_id: tenant,
        email: "key@example.test".to_owned(),
    };
    database
        .store
        .create_user(
            &user,
            "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA",
            None,
            Timestamp::now_utc(),
        )
        .await
        .expect("user");
    id
}

#[cfg(feature = "apikeys")]
#[tokio::test]
async fn api_key_route_issues_the_key_once() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let user = key_user(&database, tenant).await;
    let app = router(&database, tenant, false)
        .api_keys(None)
        .expect("api-key prefix")
        .csrf_disabled()
        .into_router();

    let expires = (Timestamp::now_utc() + Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("timestamp");
    let (status, _, bytes) = send(
        &app,
        post(
            "/api-keys",
            &json!({ "user_id": user.to_string(), "scopes": ["read"], "expires_at": expires }),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    let key = body.get("key").and_then(Value::as_str).expect("key");
    assert!(
        key.starts_with("nak_"),
        "presented key uses the default prefix"
    );

    let (status, _, bytes) = send(&app, get("/api-keys/verify", None).layer_request(key)).await;
    assert_eq!(status, StatusCode::OK);
    let verified: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        verified.get("user_id").and_then(Value::as_str),
        Some(user.to_string().as_str())
    );
}

/// A tiny extension trait so the API-key lookup test can attach a bearer header.
#[cfg(feature = "apikeys")]
trait WithKey {
    fn layer_request(self, key: &str) -> Self;
}

#[cfg(feature = "apikeys")]
impl WithKey for Request<Body> {
    fn layer_request(mut self, key: &str) -> Self {
        self.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {key}").parse().expect("header"),
        );
        self
    }
}

#[cfg(all(feature = "apikeys", feature = "session", feature = "password"))]
async fn issue_key(app: &Router, user_id: &str, csrf: &str) -> String {
    let expires = (Timestamp::now_utc() + Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("timestamp");
    let (status, _, bytes) = send(
        app,
        post(
            "/api-keys",
            &json!({ "user_id": user_id, "scopes": [], "expires_at": expires }),
            Some(csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    body.get("key")
        .and_then(Value::as_str)
        .expect("presented key")
        .to_owned()
}

#[cfg(all(feature = "apikeys", feature = "session", feature = "password"))]
async fn verified_key_id(app: &Router, key: &str) -> String {
    let (status, _, bytes) = send(app, get("/api-keys/verify", None).layer_request(key)).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    body.get("id")
        .and_then(Value::as_str)
        .expect("key id")
        .to_owned()
}

#[cfg(all(feature = "apikeys", feature = "session", feature = "password"))]
async fn session_user(app: &Router, session: &str) -> String {
    let cookie = format!("neotales.session={session}");
    let (status, _, bytes) = send(app, get("/session", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    body.get("user_id")
        .and_then(Value::as_str)
        .expect("user id")
        .to_owned()
}

#[cfg(all(feature = "apikeys", feature = "session", feature = "password"))]
#[tokio::test]
async fn api_key_revoke_is_owner_scoped_and_not_repeatable() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, true)
        .api_keys(None)
        .expect("api-key prefix")
        .into_router();
    let csrf = csrf(&app).await;
    register(&app, "key-owner@example.test", &csrf).await;
    register(&app, "key-stranger@example.test", &csrf).await;
    let session = sign_in(&app, "key-owner@example.test", &csrf).await;
    let stranger = sign_in(&app, "key-stranger@example.test", &csrf).await;
    let owner = session_user(&app, &session).await;
    let stranger_id = session_user(&app, &stranger).await;

    let key = issue_key(&app, &owner, &csrf).await;
    let key_id = verified_key_id(&app, &key).await;
    let stranger_key = issue_key(&app, &stranger_id, &csrf).await;
    let stranger_key_id = verified_key_id(&app, &stranger_key).await;

    // CSRF guards the revoke, and the caller must be signed in.
    let (status, _, _) = send(
        &app,
        delete(&format!("/api-keys/{key_id}"), Some(&session), None, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no CSRF pair, no revoke");
    let (status, _, _) = send(
        &app,
        delete(&format!("/api-keys/{key_id}"), None, Some(&csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no session, no revoke");

    // Another account's identifier is not a revoke, and its key stays usable.
    let (status, _, _) = send(
        &app,
        delete(
            &format!("/api-keys/{stranger_key_id}"),
            Some(&session),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &app,
        get("/api-keys/verify", None).layer_request(&stranger_key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a stranger's key stays live");

    // The caller's own identifier is revoked, and the response carries no secret.
    let (status, _, bytes) = send(
        &app,
        delete(
            &format!("/api-keys/{key_id}"),
            Some(&session),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(bytes.is_empty(), "the revoke response has no body");
    assert!(!String::from_utf8_lossy(&bytes).contains(&key));

    let (status, _, _) = send(&app, get("/api-keys/verify", None).layer_request(&key)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a revoked key fails");
    let (status, _, _) = send(
        &app,
        delete(
            &format!("/api-keys/{key_id}"),
            Some(&session),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a second revoke is not found"
    );

    let rows = sqlx::query(
        "SELECT actor_id, outcome FROM auth_audit WHERE action = 'auth.api_key.revoked'",
    )
    .fetch_all(&database.pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 1, "one successful revoke writes one row");
    assert_eq!(rows[0].get::<String, _>("outcome"), "ok");
    let actor: Vec<u8> = sqlx::query_scalar("SELECT id FROM auth_user WHERE email = ?")
        .bind("key-owner@example.test")
        .fetch_one(&database.pool)
        .await
        .expect("owner id");
    assert_eq!(rows[0].get::<Vec<u8>, _>("actor_id"), actor);
    let recorded: String = sqlx::query_scalar(
        "SELECT action || coalesce(ip, '') || coalesce(user_agent, '') FROM auth_audit \
         WHERE action = 'auth.api_key.revoked'",
    )
    .fetch_one(&database.pool)
    .await
    .expect("audit text");
    assert!(!recorded.contains(&key), "the row has no presented key");
}

#[cfg(all(feature = "apikeys", feature = "session", feature = "password"))]
#[tokio::test]
async fn api_key_revoke_path_moves_and_the_default_stops_answering() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .api_keys(None)
        .expect("api-key prefix")
        .paths(Paths::new().api_keys_revoke("/auth/api-keys/{id}"))
        .into_router();
    let csrf = csrf(&app).await;
    register(&app, "key-moved@example.test", &csrf).await;
    let session = sign_in(&app, "key-moved@example.test", &csrf).await;
    let owner = session_user(&app, &session).await;
    let key = issue_key(&app, &owner, &csrf).await;
    let key_id = verified_key_id(&app, &key).await;

    let (status, _, _) = send(
        &app,
        delete(
            &format!("/api-keys/{key_id}"),
            Some(&session),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default revoke path is not registered"
    );
    let (status, _, _) = send(
        &app,
        delete(
            &format!("/auth/api-keys/{key_id}"),
            Some(&session),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(&app, get("/api-keys/verify", None).layer_request(&key)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the moved route revoked");
}

#[cfg(all(feature = "apikeys", feature = "session"))]
async fn custom_api_key_revoke() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom api key revoke")
}

#[cfg(all(feature = "apikeys", feature = "session"))]
#[tokio::test]
async fn the_api_key_revoke_handler_is_overridable() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .api_key_revoke(custom_api_key_revoke)
        .into_router();

    let (status, _, bytes) = send(&app, delete("/api-keys/anything", None, None, None)).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "custom api key revoke"
    );
}

#[cfg(all(feature = "apikeys", not(feature = "password")))]
#[tokio::test]
async fn a_disabled_feature_route_is_not_registered() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let user = key_user(&database, tenant).await;
    let app = router(&database, tenant, false)
        .api_keys(None)
        .expect("api-key prefix")
        .csrf_disabled()
        .into_router();

    let (status, _, _) = send(&app, post("/sign-in", &json!({}), None, None)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "sign-in is not compiled in this build"
    );

    let expires = (Timestamp::now_utc() + Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("timestamp");
    let (status, _, _) = send(
        &app,
        post(
            "/api-keys",
            &json!({ "user_id": user.to_string(), "scopes": [], "expires_at": expires }),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the API-key route is present");
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn change_password_keeps_the_cookie_and_revokes_the_other_sessions() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, true).into_router();
    let csrf = csrf(&app).await;
    register(&app, "change-password@example.test", &csrf).await;
    let first = sign_in(&app, "change-password@example.test", &csrf).await;
    let second = sign_in(&app, "change-password@example.test", &csrf).await;

    let (status, headers, _) = send(
        &app,
        post_signed(
            "/password/change",
            &json!({ "current_password": PASSWORD, "new_password": "a replacement password" }),
            &first,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_none(),
        "the presented cookie is neither replaced nor cleared"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={first}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the presented session survives");
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={second}"))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the other session is revoked"
    );

    let old = json!({ "email": "change-password@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-in", &old, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old password fails");
    let new = json!({
        "email": "change-password@example.test",
        "password": "a replacement password",
    });
    let (status, _, _) = send(&app, post("/sign-in", &new, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::OK, "the new password signs in");

    let rows = sqlx::query(
        "SELECT outcome, ip, user_agent FROM auth_audit WHERE action = 'auth.password.changed'",
    )
    .fetch_all(&database.pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 1, "one change writes one row");
    let row = &rows[0];
    assert_eq!(row.get::<String, _>("outcome"), "ok");
    let text = format!(
        "{}{}{}",
        row.get::<String, _>("outcome"),
        row.get::<Option<String>, _>("ip").unwrap_or_default(),
        row.get::<Option<String>, _>("user_agent")
            .unwrap_or_default(),
    );
    assert!(!text.contains(PASSWORD), "the row has no current password");
    assert!(
        !text.contains("a replacement password"),
        "the row has no new password"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn a_wrong_current_password_leaves_the_stored_hash() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "wrong-current@example.test", &csrf).await;
    let session = sign_in(&app, "wrong-current@example.test", &csrf).await;

    let stored: String = sqlx::query_scalar(
        "SELECT p.password_hash FROM auth_password p JOIN auth_user u ON u.id = p.user_id WHERE u.email = ?",
    )
    .bind("wrong-current@example.test")
    .fetch_one(&database.pool)
    .await
    .expect("stored hash");

    let (status, _, _) = send(
        &app,
        post_signed(
            "/password/change",
            &json!({ "current_password": "not the password", "new_password": "another password" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let after: String = sqlx::query_scalar(
        "SELECT p.password_hash FROM auth_password p JOIN auth_user u ON u.id = p.user_id WHERE u.email = ?",
    )
    .bind("wrong-current@example.test")
    .fetch_one(&database.pool)
    .await
    .expect("stored hash");
    assert_eq!(after, stored, "a wrong current password changes nothing");
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={session}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the session stays signed in");
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn change_email_moves_the_address_and_clears_verification() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;
    register(&app, "before@example.test", &csrf).await;
    register(&app, "taken@example.test", &csrf).await;
    let session = sign_in(&app, "before@example.test", &csrf).await;

    let (status, _, _) = send(
        &app,
        post_signed(
            "/email/change",
            &json!({ "email": "not-an-email" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = send(
        &app,
        post_signed(
            "/email/change",
            &json!({ "email": "taken@example.test" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, headers, _) = send(
        &app,
        post_signed(
            "/email/change",
            &json!({ "email": "  Moved@Example.Test  " }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_none(),
        "the presented cookie is untouched"
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={session}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the presented session survives");

    let old = json!({ "email": "before@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-in", &old, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old address is gone");
    let new = json!({ "email": "moved@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-in", &new, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::OK, "the new address signs in");
    let unverified: bool =
        sqlx::query_scalar("SELECT email_verified_at IS NULL FROM auth_user WHERE email = ?")
            .bind("moved@example.test")
            .fetch_one(&database.pool)
            .await
            .expect("verification state");
    assert!(unverified, "a changed address is unverified");
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn delete_marks_the_account_revokes_every_session_and_clears_the_cookie() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, true).into_router();
    let csrf = csrf(&app).await;
    register(&app, "delete-me@example.test", &csrf).await;
    let first = sign_in(&app, "delete-me@example.test", &csrf).await;
    let second = sign_in(&app, "delete-me@example.test", &csrf).await;

    let (status, headers, _) = send(&app, delete("/user", Some(&first), Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_some_and(|text| text.contains("Max-Age=0")),
        "the presented cookie is cleared"
    );
    for token in [&first, &second] {
        let (status, _, _) = send(
            &app,
            get("/session", Some(&format!("neotales.session={token}"))),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "every session is revoked");
    }

    let credentials = json!({ "email": "delete-me@example.test", "password": PASSWORD });
    let (status, _, _) = send(&app, post("/sign-in", &credentials, Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a later sign-in fails");
    let retained: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM auth_user WHERE email = ?")
            .bind("delete-me@example.test")
            .fetch_one(&database.pool)
            .await
            .expect("the row is kept and marked");
    assert!(retained, "the account is marked deleted, not hard-deleted");

    let rows = sqlx::query("SELECT outcome FROM auth_audit WHERE action = 'auth.user.deleted'")
        .fetch_all(&database.pool)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<String, _>("outcome"), "ok");
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn the_account_routes_need_csrf_and_a_live_session() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false).into_router();
    let csrf = csrf(&app).await;

    for (method, path, body) in [
        ("POST", "/password/change", json!({})),
        ("POST", "/email/change", json!({})),
        ("DELETE", "/user", json!({})),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "http://localhost")
            .body(Body::from(body.to_string()))
            .expect("request");
        let (status, _, _) = send(&app, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} checks CSRF first");

        let request = if method == "DELETE" {
            delete(path, None, Some(&csrf), None)
        } else {
            post(path, &json!({}), Some(&csrf), None)
        };
        let (status, _, _) = send(&app, request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{path} needs a signed-in caller"
        );
    }

    register(&app, "csrf-change@example.test", &csrf).await;
    let session = sign_in(&app, "csrf-change@example.test", &csrf).await;
    let request = Request::builder()
        .method("POST")
        .uri("/email/change")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, format!("neotales.session={session}"))
        .body(Body::from(
            json!({ "email": "csrf-error@example.test" }).to_string(),
        ))
        .expect("request");
    let (status, _, _) = send(&app, request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a signed-in caller still needs the pair"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
async fn custom_password_change() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom password change")
}

#[cfg(all(feature = "password", feature = "session"))]
async fn custom_email_change() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom email change")
}

#[cfg(all(feature = "password", feature = "session"))]
async fn custom_delete_user() -> (StatusCode, &'static str) {
    (StatusCode::IM_A_TEAPOT, "custom delete user")
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn the_account_handlers_are_overridable() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .password_change(custom_password_change)
        .email_change(custom_email_change)
        .delete_user(custom_delete_user)
        .into_router();

    let (status, _, bytes) = send(&app, post("/password/change", &json!({}), None, None)).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "custom password change"
    );
    let (status, _, bytes) = send(&app, post("/email/change", &json!({}), None, None)).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "custom email change"
    );
    let (status, _, bytes) = send(&app, delete("/user", None, None, None)).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "custom delete user"
    );
}

#[cfg(all(feature = "password", feature = "session"))]
#[tokio::test]
async fn account_change_paths_move_and_the_defaults_stop_answering() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    let app = router(&database, tenant, false)
        .paths(
            Paths::new()
                .password_change("/auth/password")
                .email_change("/auth/email")
                .user("/auth/account"),
        )
        .into_router();
    let csrf = csrf(&app).await;
    register(&app, "moved-change@example.test", &csrf).await;
    let session = sign_in(&app, "moved-change@example.test", &csrf).await;

    let (status, _, _) = send(
        &app,
        post_signed(
            "/password/change",
            &json!({ "current_password": PASSWORD, "new_password": "another password" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the default change-password path is not registered"
    );
    let (status, _, _) = send(
        &app,
        post_signed(
            "/auth/password",
            &json!({ "current_password": PASSWORD, "new_password": "another password" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(
        &app,
        post_signed(
            "/email/change",
            &json!({ "email": "moved-address@example.test" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &app,
        post_signed(
            "/auth/email",
            &json!({ "email": "moved-address@example.test" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(&app, delete("/user", Some(&session), Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &app,
        delete("/auth/account", Some(&session), Some(&csrf), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// With `password` compiled out the address and deletion routes still exist, because they
/// only need `session`; the password route does not.
#[cfg(all(
    feature = "session",
    feature = "email-signin",
    not(feature = "password")
))]
#[tokio::test]
async fn the_account_changes_work_with_password_compiled_out() {
    let database = database().await;
    let tenant = tenant(&database.store).await;
    email_user(&database, tenant).await;
    let (issued, sink) = proof_recorder();
    let app = router(&database, tenant, false)
        .on_proof(sink)
        .into_router();
    let csrf = csrf(&app).await;

    let (status, _, _) = send(
        &app,
        post(
            "/email/sign-in/request",
            &json!({ "email": "signin@example.test" }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let proof = issued.lock().expect("hook")[0].2.clone();
    let (status, headers, _) = send(
        &app,
        post(
            "/email/sign-in",
            &json!({ "token": proof }),
            Some(&csrf),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session = set_cookie(&headers, "neotales.session").expect("session cookie");

    let (status, _, _) = send(
        &app,
        post("/password/change", &json!({}), Some(&csrf), None),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the password route needs the password feature"
    );

    let (status, headers, _) = send(
        &app,
        post_signed(
            "/email/change",
            &json!({ "email": "moved@example.test" }),
            &session,
            &csrf,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(cookie_header(&headers, "neotales.session").is_none());

    let (status, headers, _) = send(&app, delete("/user", Some(&session), Some(&csrf), None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        cookie_header(&headers, "neotales.session").is_some_and(|text| text.contains("Max-Age=0"))
    );
    let (status, _, _) = send(
        &app,
        get("/session", Some(&format!("neotales.session={session}"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
