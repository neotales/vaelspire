//! End-to-end HTTP integration tests for OIDC 1.0 `IdP`, stateless `vaelspire-verify`,
//! SCIM 2.0 user provisioning, and SAML 2.0 `IdP` metadata in `crates/vaelspire`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use vaelspire::bootstrap::{bootstrap_admin, ensure_tenant};
use vaelspire::config::{ServerConfig, UiMode};
use vaelspire::server::build_router;
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
use vaelspire_store_sqlite::open;
use vaelspire_verify::TokenVerifier;
use zeroize::Zeroizing;

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    (status, headers, body.to_vec())
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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn oidc_idp_http_scim_and_saml_metadata_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("oidc.sqlite");
    let key = [11u8; 32];
    let store = Arc::new(open(&db_path).await.expect("sqlite"));
    vaelspire::ext_store::ensure_extended_schema(&store)
        .await
        .expect("ext schema");
    let tenant_id = ensure_tenant(&store, "default").await.expect("tenant");
    bootstrap_admin(
        &store,
        tenant_id,
        "admin@vaelspire.test",
        Zeroizing::new("correct horse battery staple".to_owned()),
        key,
    )
    .await
    .expect("bootstrap");

    let cfg = ServerConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        sqlite_path: db_path,
        tenant_name: "default".to_owned(),
        digest_key: Zeroizing::new(key),
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
        issuer_url: "https://auth.vaelspire.test".to_owned(),
        ui_mode: UiMode::ApiOnly,
        pii_log_mode: vaelspire_core::privacy::PiiLogMode::Masked,
        audit_ip_mode: vaelspire_core::privacy::AuditIpMode::Full,
        ip_source: vaelspire::security::IpSource::Direct,
        trusted_proxies: Vec::new(),
        session_sliding: true,
        session_idle_ttl: Duration::from_hours(24),
        session_max_lifetime: Some(Duration::from_hours(168)),
        rp_id: None,
        rp_origin: None,
        alerts: None,
    };

    let app = build_router(store, tenant_id, &cfg).expect("router");

    // 1. OIDC Discovery & JWKS
    let (status, _, body) = send(
        &app,
        Request::get("/.well-known/openid-configuration")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let disc: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(disc["issuer"], "https://auth.vaelspire.test");

    let (status, _, jwks_bytes) = send(
        &app,
        Request::get("/.well-known/jwks.json")
            .body(Body::empty())
            .expect("req"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let jwks_str = String::from_utf8(jwks_bytes).expect("utf8");
    let verifier = TokenVerifier::from_jwks_json(&jwks_str)
        .expect("verifier")
        .require_issuer("https://auth.vaelspire.test")
        .require_audience("vaelsgard");

    // 2. Sign in admin to get a session cookie
    let (_, h, _) = send(
        &app,
        Request::get("/session").body(Body::empty()).expect("r"),
    )
    .await;
    let csrf = cookie_value(&h, DEFAULT_CSRF_COOKIE).expect("csrf");
    let (status, h, _) = send(
        &app,
        Request::post("/sign-in")
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
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session = cookie_value(&h, DEFAULT_SESSION_COOKIE).expect("session");

    // 3. Register Vaelsgard OIDC client via Admin API
    let (status, _, body) = send(
        &app,
        Request::post("/admin/oidc/clients")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                format!("{DEFAULT_SESSION_COOKIE}={session}"),
            )
            .body(Body::from(
                json!({
                    "client_id": "vaelsgard",
                    "name": "Vaelsgard Vault",
                    "redirect_uris": ["https://vault.local/cb"],
                    "allowed_scopes": ["openid", "email", "offline_access", "vault:read"],
                    "confidential": true
                })
                .to_string(),
            ))
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: Value = serde_json::from_slice(&body).expect("json");
    let secret = created["client_secret"].as_str().expect("secret");

    // 4. Authorize with PKCE S256 + approve=1
    let code_verifier = "vaelspire-http-pkce-verifier-0123456789abcdefghijk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let uri = format!(
        "/oauth2/authorize?response_type=code&client_id=vaelsgard&redirect_uri=https%3A%2F%2Fvault.local%2Fcb&scope=openid%20email%20offline_access&code_challenge={challenge}&code_challenge_method=S256&approve=1"
    );
    let (status, _, body) = send(
        &app,
        Request::get(&uri)
            .header(
                header::COOKIE,
                format!("{DEFAULT_SESSION_COOKIE}={session}"),
            )
            .body(Body::empty())
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let authz: Value = serde_json::from_slice(&body).expect("json");
    let code = authz["code"].as_str().expect("code");

    // 5. Exchange code at POST /oauth2/token -> verify via vaelspire-verify + UserInfo + Revoke
    let (status, _, body) = send(
        &app,
        Request::post("/oauth2/token")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "grant_type": "authorization_code",
                    "client_id": "vaelsgard",
                    "client_secret": secret,
                    "code": code,
                    "redirect_uri": "https://vault.local/cb",
                    "code_verifier": code_verifier
                })
                .to_string(),
            ))
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tok: Value = serde_json::from_slice(&body).expect("json");
    let access_token = tok["access_token"].as_str().expect("access_token");
    let claims = verifier
        .verify(access_token, vaelspire_core::Timestamp::now_utc())
        .expect("stateless verify");
    assert_eq!(claims.email.as_deref(), Some("admin@vaelspire.test"));

    let (status, _, body) = send(
        &app,
        Request::get("/oauth2/userinfo")
            .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ui: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(ui["email"], "admin@vaelspire.test");

    // 6. SCIM 2.0 ServiceProviderConfig + Create/List/Delete User
    let (status, _, _) = send(
        &app,
        Request::get("/scim/v2/ServiceProviderConfig")
            .body(Body::empty())
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = send(
        &app,
        Request::post("/scim/v2/Users")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                format!("{DEFAULT_SESSION_COOKIE}={session}"),
            )
            .body(Body::from(
                json!({ "userName": "scim-user@vaelspire.test" }).to_string(),
            ))
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let scim_user: Value = serde_json::from_slice(&body).expect("json");
    let scim_id = scim_user["id"].as_str().expect("id");

    let (status, _, body) = send(
        &app,
        Request::get("/scim/v2/Users")
            .header(
                header::COOKIE,
                format!("{DEFAULT_SESSION_COOKIE}={session}"),
            )
            .body(Body::empty())
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(list["totalResults"], 2);

    let (status, _, _) = send(
        &app,
        Request::delete(format!("/scim/v2/Users/{scim_id}"))
            .header(
                header::COOKIE,
                format!("{DEFAULT_SESSION_COOKIE}={session}"),
            )
            .body(Body::empty())
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 7. SAML 2.0 Metadata XML
    let (status, headers, body) = send(
        &app,
        Request::get("/saml/metadata")
            .body(Body::empty())
            .expect("r"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .expect("ct")
            .contains("samlmetadata+xml")
    );
    let xml = String::from_utf8(body).expect("xml");
    assert!(xml.contains("entityID=\"https://auth.vaelspire.test\""));
}
