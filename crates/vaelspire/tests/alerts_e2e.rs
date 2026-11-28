//! End-to-end test verifying `vaelspire` server wires `vaelspire-alerts` into
//! discovery metadata and non-blocking anomaly webhook delivery with masked PII.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::post;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt as _;
use vaelspire::bootstrap::{bootstrap_admin, ensure_tenant};
use vaelspire::config::{ServerConfig, UiMode};
use vaelspire::ext_store::ensure_extended_schema;
use vaelspire::security::IpSource;
use vaelspire::server::build_router;
use vaelspire_alerts::sinks::webhook::verify_hmac_sha256;
use vaelspire_alerts::{AlertsConfig, Severity, SinkConfig, SinkRuleConfig};
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
use vaelspire_core::privacy::{AuditIpMode, PiiLogMode};
use vaelspire_store_sqlite::open;
use zeroize::Zeroizing;

#[derive(Clone)]
struct ReceivedWebhook {
    sig: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone, Default)]
struct ReceiverState {
    received: Arc<Mutex<Vec<ReceivedWebhook>>>,
}

#[allow(clippy::unused_async)]
async fn webhook_sink_handler(
    State(state): State<ReceiverState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let sig = headers
        .get("x-signature-256")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    state.received.lock().unwrap().push(ReceivedWebhook {
        sig,
        body: body.to_vec(),
    });
    StatusCode::OK
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
    let prefix = format!("{name}=");
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            raw.strip_prefix(&prefix)
                .and_then(|rest| rest.split(';').next())
                .map(ToOwned::to_owned)
        })
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn server_emits_masked_hmac_webhook_alert_on_session_anomaly() {
    let rx_state = ReceiverState::default();
    let rx_app = Router::new()
        .route("/hook", post(webhook_sink_handler))
        .with_state(rx_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, rx_app).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("alerts-e2e.sqlite");
    let store = Arc::new(open(&db_path).await.unwrap());
    ensure_extended_schema(&store).await.unwrap();
    let tenant_id = ensure_tenant(&store, "acme").await.unwrap();
    let key = [0x99u8; 32];
    bootstrap_admin(
        &store,
        tenant_id,
        "wfischer@acme.com",
        Zeroizing::new("correct-horse-battery-staple".to_owned()),
        key,
    )
    .await
    .unwrap();

    let alerts_cfg = AlertsConfig {
        dedupe_window_secs: 60,
        sinks: vec![SinkRuleConfig {
            min_severity: Severity::Warn,
            categories: Vec::new(),
            max_retries: 1,
            sink: SinkConfig::Webhook {
                name: "ops-webhook".to_owned(),
                url: format!("http://{hook_addr}/hook"),
                signing_secret: Some("wh-secret-42".to_owned()),
                headers: BTreeMap::new(),
            },
        }],
    };

    let cfg = ServerConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
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
        issuer_url: "http://127.0.0.1:8080".to_owned(),
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
        alerts: Some(alerts_cfg),
    };

    let app = build_router(store, tenant_id, &cfg).expect("router");

    // 1. Discovery lists active alert sinks.
    let (status, _, body) = send(
        &app,
        Request::get("/.well-known/vaelspire")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let disc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(disc["alerts"]["enabled"], true);
    assert_eq!(disc["alerts"]["sinks"], json!(["ops-webhook"]));

    // 2. Sign in and call /forward-auth with two different User-Agents to trigger NewDeviceOrIp.
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
                json!({"email":"wfischer@acme.com","password":"correct-horse-battery-staple"})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session = cookie_value(&sh, DEFAULT_SESSION_COOKIE).expect("session");

    for ua in ["Mozilla/5.0 FirstDevice", "curl/8.0 UnexpectedDevice"] {
        let (st, _, _) = send(
            &app,
            Request::get("/forward-auth")
                .header(
                    header::COOKIE,
                    format!("{DEFAULT_SESSION_COOKIE}={session}"),
                )
                .header(header::USER_AGENT, ua)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    // Wait briefly for the background AlertHandle worker to deliver the webhook.
    for _ in 0..40 {
        if !rx_state.received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let delivered = rx_state.received.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    let item = &delivered[0];
    assert!(verify_hmac_sha256(
        b"wh-secret-42",
        &item.body,
        item.sig.as_deref().unwrap_or("")
    ));
    let payload: Value = serde_json::from_slice(&item.body).unwrap();
    assert_eq!(payload["severity"], "warn");
    assert_eq!(payload["category"], "security.anomaly");
    assert_eq!(payload["fields"]["email"], "wf******@acme.com");
}
