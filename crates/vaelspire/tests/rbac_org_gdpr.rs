//! End-to-end integration tests for M3.5 & M4 features:
//! - Org-wide & per-app RBAC (roles, permissions, groups, group-to-role grants, effective projection)
//! - Self-service org policy (`business_domains_only` / `verified_domains_only`), DNS domains, upstream `IdP` dry-run test, Home Realm Discovery
//! - Per-org SCIM 2.0 bearer tokens & `/scim/v2/Groups` directory sync
//! - GDPR Right of Access (`/account/export`) & Right to Erasure (`/admin/gdpr/erase/{id}`)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use vaelspire::bootstrap::{bootstrap_admin, ensure_tenant};
use vaelspire::config::{ServerConfig, UiMode};
use vaelspire::ext_store::ensure_extended_schema;
use vaelspire::security::IpSource;
use vaelspire::server::build_router;
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
use vaelspire_core::privacy::{AuditIpMode, PiiLogMode};
use vaelspire_store_sqlite::open;
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
async fn per_app_rbac_self_service_org_idp_scim_groups_and_gdpr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("m35_m4.sqlite");
    let key = [0x42; 32];
    let store = Arc::new(open(&db_path).await.expect("sqlite"));
    ensure_extended_schema(&store).await.expect("ext schema");
    let tenant_id = ensure_tenant(&store, "acme").await.expect("tenant");
    let vaelspire::bootstrap::BootstrapOutcome::Created(admin_id) = bootstrap_admin(
        &store,
        tenant_id,
        "admin@acme.com",
        Zeroizing::new("correct-horse-battery-staple".to_owned()),
        key,
    )
    .await
    .expect("admin") else {
        panic!("expected Created");
    };

    let cfg = ServerConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        sqlite_path: db_path,
        tenant_name: "acme".to_owned(),
        digest_key: Zeroizing::new(key),
        cookie_secure: false,
        allowed_origins: Some(vec!["http://localhost".to_owned()]),
        trust_proxy: false,
        session_cookie: DEFAULT_SESSION_COOKIE.to_owned(),
        csrf_cookie: DEFAULT_CSRF_COOKIE.to_owned(),
        api_key_prefix: "vsp".to_owned(),
        auditing: true,
        roles: true,
        rate_limit: (1000, Duration::from_secs(60)),
        forward_auth_login_url: None,
        issuer_url: "https://auth.acme.test".to_owned(),
        ui_mode: UiMode::ApiOnly,
        pii_log_mode: PiiLogMode::Masked,
        audit_ip_mode: AuditIpMode::Truncated,
        ip_source: IpSource::Direct,
        trusted_proxies: Vec::new(),
        session_sliding: true,
        session_idle_ttl: Duration::from_hours(24),
        session_max_lifetime: Some(Duration::from_hours(168)),
        rp_id: None,
        rp_origin: None,
        alerts: None,
    };
    let app = build_router(Arc::clone(&store), tenant_id, &cfg).expect("router");

    // 1. Prime CSRF and sign in as admin@acme.com
    let (_, h, _) = send(&app, Request::get("/session").body(Body::empty()).unwrap()).await;
    let csrf = cookie_value(&h, DEFAULT_CSRF_COOKIE).expect("csrf");
    let (status, sh, _) = send(
        &app,
        Request::post("/sign-in")
            .header(header::ORIGIN, "http://localhost")
            .header(header::COOKIE, format!("{DEFAULT_CSRF_COOKIE}={csrf}"))
            .header("x-csrf-token", &csrf)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"email":"admin@acme.com","password":"correct-horse-battery-staple"})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sess = cookie_value(&sh, DEFAULT_SESSION_COOKIE).expect("session cookie");
    let cookie_hdr = format!("{DEFAULT_SESSION_COOKIE}={sess}; {DEFAULT_CSRF_COOKIE}={csrf}");

    // 2. Configure org policy -> business_domains_only
    let (status, _, _) = send(
        &app,
        Request::put("/org/portal/policy")
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email_policy": "business_domains_only",
                    "session_sliding": true,
                    "session_idle_secs": 3600,
                    "session_absolute_secs": 86400,
                    "break_glass_enabled": true
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 3. Mint per-org SCIM bearer token and verify gmail.com is blocked under business_domains_only
    let (status, _, body) = send(
        &app,
        Request::post("/org/portal/scim-tokens")
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"name": "Okta Sync"}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let scim_token = serde_json::from_slice::<Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(scim_token.starts_with("vs_scim_"));

    let (status, _, _) = send(
        &app,
        Request::post("/scim/v2/Users")
            .header(header::AUTHORIZATION, format!("Bearer {scim_token}"))
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(
                json!({"userName": "blocked@gmail.com", "password": "long-enough-password"})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Provision business user via SCIM token
    let (status, _, ubody) = send(
        &app,
        Request::post("/scim/v2/Users")
            .header(header::AUTHORIZATION, format!("Bearer {scim_token}"))
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(
                json!({"userName": "alice@acme.com", "password": "alice-password-123!"})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let alice_id = serde_json::from_slice::<Value>(&ubody).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // 4. Create SCIM Group "engineering" and add Alice via RFC 7644 PatchOp
    let (status, _, gbody) = send(
        &app,
        Request::post("/scim/v2/Groups")
            .header(header::AUTHORIZATION, format!("Bearer {scim_token}"))
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(
                json!({"displayName": "engineering", "externalId": "okta-grp-1"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = serde_json::from_slice::<Value>(&gbody).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, _, _) = send(
        &app,
        Request::patch(format!("/scim/v2/Groups/{group_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {scim_token}"))
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(
                json!({
                    "Operations": [{ "op": "add", "path": "members", "value": [{ "value": alice_id }] }]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 5. Create per-app role ("vaelsgard":"vault-editor") + permission ("vaelsgard":"secrets:rotate"), grant perm -> role, assign role -> group
    let (status, _, rbody) = send(
        &app,
        Request::post("/admin/rbac/roles")
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"app_id": "vaelsgard", "name": "vault-editor"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let role_id = serde_json::from_slice::<Value>(&rbody).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, _, pbody) = send(
        &app,
        Request::post("/admin/rbac/permissions")
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"app_id": "vaelsgard", "name": "secrets:rotate"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let perm_id = serde_json::from_slice::<Value>(&pbody).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, _, _) = send(
        &app,
        Request::post(format!("/admin/rbac/roles/{role_id}/permissions/{perm_id}"))
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(
        &app,
        Request::post(format!("/admin/rbac/groups/{group_id}/roles/{role_id}"))
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify Alice inherits vaelsgard:vault-editor & vaelsgard:secrets:rotate via SCIM group!
    let (status, _, eff_body) = send(
        &app,
        Request::get(format!(
            "/admin/rbac/users/{alice_id}/effective?app_id=vaelsgard"
        ))
        .header(header::COOKIE, &cookie_hdr)
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let eff: Value = serde_json::from_slice(&eff_body).unwrap();
    assert_eq!(eff["groups"], json!(["engineering"]));
    assert_eq!(eff["roles"], json!(["vaelsgard:vault-editor"]));
    assert_eq!(eff["permissions"], json!(["vaelsgard:secrets:rotate"]));

    // Also assign role to admin and verify /forward-auth emits X-Vaelspire-Roles!
    let _ = send(
        &app,
        Request::post(format!("/admin/rbac/users/{admin_id}/roles/{role_id}"))
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let (status, fh, _) = send(
        &app,
        Request::get("/forward-auth")
            .header(header::COOKIE, &cookie_hdr)
            .header("x-vaelspire-app-id", "vaelsgard")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        fh.get("x-vaelspire-roles").unwrap().to_str().unwrap(),
        "vaelsgard:vault-editor"
    );

    // 6. Self-service domain verification + upstream IdP + dry-run test + Home Realm Discovery
    let (status, _, dbody) = send(
        &app,
        Request::post("/org/portal/domains")
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"domain": "acme.com"}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let dom: Value = serde_json::from_slice(&dbody).unwrap();
    let dom_id = dom["id"].as_str().unwrap();
    let txt_val = dom["verification_token"].as_str().unwrap();

    let (status, _, _) = send(
        &app,
        Request::post(format!("/org/portal/domains/{dom_id}/verify"))
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"txt_value": txt_val}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, ibody) = send(
        &app,
        Request::post("/org/portal/idps")
            .header(header::COOKIE, &cookie_hdr)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": "Acme Okta",
                    "protocol": "oidc",
                    "issuer_url": "https://acme.okta.com",
                    "client_id": "okta-client-123",
                    "enabled": true
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let idp_id = serde_json::from_slice::<Value>(&ibody).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, _, tbody) = send(
        &app,
        Request::post(format!("/org/portal/idps/{idp_id}/test"))
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<Value>(&tbody).unwrap()["ok"], true);

    // Home Realm Discovery routes alice@acme.com -> SSO!
    let (status, _, hbody) = send(
        &app,
        Request::post("/auth/discover")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"email": "alice@acme.com"}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let hrd: Value = serde_json::from_slice(&hbody).unwrap();
    assert_eq!(hrd["mode"], "sso");
    assert_eq!(hrd["idp"]["name"], "Acme Okta");

    // 7. GDPR Right of Access (/account/export) + Right to Erasure (/admin/gdpr/erase/{alice_id})
    let (status, _, exp_body) = send(
        &app,
        Request::get("/account/export")
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let export: Value = serde_json::from_slice(&exp_body).unwrap();
    assert_eq!(export["schema"], "vaelspire.gdpr.export.v1");
    assert_eq!(export["user"]["email"], "admin@acme.com");

    let (status, _, _) = send(
        &app,
        Request::post(format!("/admin/gdpr/erase/{alice_id}"))
            .header(header::COOKIE, &cookie_hdr)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Confirm Alice no longer shows up as an active SCIM user after GDPR erasure.
    let (status, _, _) = send(
        &app,
        Request::get(format!("/scim/v2/Users/{alice_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {scim_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
