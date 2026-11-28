//! End-to-end integration tests verifying all HTTP sinks, HMAC signing,
//! deduplication, severity/category filtering, retries, and declarative config.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use tokio::net::TcpListener;

use vaelspire_alerts::sinks::discord::{DiscordConfig, DiscordSink};
use vaelspire_alerts::sinks::gotify::{GotifyConfig, GotifySink};
use vaelspire_alerts::sinks::ntfy::{NtfyConfig, NtfySink};
use vaelspire_alerts::sinks::slack::{SlackConfig, SlackSink};
use vaelspire_alerts::sinks::sms::{
    GenericSmsConfig, GenericSmsSink, TwilioSmsConfig, TwilioSmsSink,
};
use vaelspire_alerts::sinks::teams::{TeamsConfig, TeamsSink};
use vaelspire_alerts::sinks::webhook::{WebhookConfig, WebhookSink, verify_hmac_sha256};
use vaelspire_alerts::{AlertEvent, AlertRouter, AlertsConfig, MemorySink, Severity, SinkRule};

#[derive(Debug, Clone)]
struct CapturedRequest {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Default, Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    fail_once: Arc<Mutex<bool>>,
}

#[allow(clippy::unused_async)]
async fn capture(
    path: &'static str,
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let hdrs = headers
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    state.requests.lock().unwrap().push(CapturedRequest {
        path: path.to_owned(),
        headers: hdrs,
        body: body.to_vec(),
    });
    StatusCode::OK
}

async fn flaky_webhook(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let should_fail = {
        let mut guard = state.fail_once.lock().unwrap();
        if *guard {
            *guard = false;
            true
        } else {
            false
        }
    };
    if should_fail {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    capture("/flaky", State(state), headers, body).await
}

async fn spawn_mock_server() -> (String, MockState) {
    let state = MockState {
        requests: Arc::new(Mutex::new(Vec::new())),
        fail_once: Arc::new(Mutex::new(true)),
    };
    let app = Router::new()
        .route("/webhook", post(|s, h, b| capture("/webhook", s, h, b)))
        .route("/flaky", post(flaky_webhook))
        .route("/slack", post(|s, h, b| capture("/slack", s, h, b)))
        .route("/discord", post(|s, h, b| capture("/discord", s, h, b)))
        .route("/teams", post(|s, h, b| capture("/teams", s, h, b)))
        .route(
            "/gotify/message",
            post(|s, h, b| capture("/gotify/message", s, h, b)),
        )
        .route("/ntfy/ops", post(|s, h, b| capture("/ntfy/ops", s, h, b)))
        .route(
            "/twilio/2010-04-01/Accounts/AC123/Messages.json",
            post(|s, h, b| capture("/twilio", s, h, b)),
        )
        .route("/sms", post(|s, h, b| capture("/sms", s, h, b)))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), state)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn all_http_sinks_deliver_expected_payloads_and_headers() {
    let (base, state) = spawn_mock_server().await;

    let webhook = WebhookSink::new(
        WebhookConfig::new(format!("{base}/webhook"))
            .with_signing_secret("top-secret-hmac")
            .with_header("x-custom-tenant", "acme"),
    )
    .unwrap();
    let slack = SlackSink::new(SlackConfig::new(format!("{base}/slack"))).unwrap();
    let discord = DiscordSink::new(DiscordConfig::new(format!("{base}/discord"))).unwrap();
    let teams = TeamsSink::new(TeamsConfig::new(format!("{base}/teams"))).unwrap();
    let gotify =
        GotifySink::new(GotifyConfig::new(format!("{base}/gotify"), "app-tok-99")).unwrap();
    let ntfy =
        NtfySink::new(NtfyConfig::new(format!("{base}/ntfy/ops")).with_bearer_token("tk_secret"))
            .unwrap();
    let twilio = TwilioSmsSink::new(
        TwilioSmsConfig::new(
            "AC123",
            "tok_abc",
            "+15550001111",
            vec!["+15550002222".into()],
        )
        .with_api_base_url(format!("{base}/twilio")),
    )
    .unwrap();
    let generic_sms = GenericSmsSink::new(
        GenericSmsConfig::new(
            format!("{base}/sms"),
            "+15550001111",
            vec!["+15550003333".into()],
        )
        .with_bearer_token("sms-tok"),
    )
    .unwrap();

    let router = AlertRouter::new()
        .with_dedupe_window(Duration::from_secs(60))
        .with_rule(SinkRule::new(Arc::new(webhook)))
        .with_rule(SinkRule::new(Arc::new(slack)))
        .with_rule(SinkRule::new(Arc::new(discord)))
        .with_rule(SinkRule::new(Arc::new(teams)))
        .with_rule(SinkRule::new(Arc::new(gotify)))
        .with_rule(SinkRule::new(Arc::new(ntfy)))
        .with_rule(SinkRule::new(Arc::new(twilio)))
        .with_rule(SinkRule::new(Arc::new(generic_sms)));

    let event = AlertEvent::new(
        Severity::Critical,
        "security.anomaly",
        "Password spray detected",
        "Burst of failed sign-ins from 203.0.113.0/24",
    )
    .with_source("vaelspire")
    .with_field("email", "wf******@acme.com")
    .with_dedupe_key("spray:203.0.113.0/24");

    let report = router.dispatch(&event).await;
    assert!(!report.deduplicated);
    assert_eq!(report.succeeded(), 8);
    assert_eq!(report.failed(), 0);

    // Second identical event within dedupe window must be suppressed.
    let dup = router.dispatch(&event).await;
    assert!(dup.deduplicated);
    assert_eq!(dup.outcomes.len(), 0);

    let captured = state.requests.lock().unwrap().clone();
    assert_eq!(captured.len(), 8);

    // Verify HMAC-SHA256 signature on generic webhook.
    let wh = captured.iter().find(|r| r.path == "/webhook").unwrap();
    let sig = wh
        .headers
        .iter()
        .find(|(k, _)| k == "x-signature-256")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert!(verify_hmac_sha256(b"top-secret-hmac", &wh.body, sig));
    assert!(
        wh.headers
            .iter()
            .any(|(k, v)| k == "x-custom-tenant" && v == "acme")
    );

    // Verify Gotify key + priority 9 for Critical.
    let gf = captured
        .iter()
        .find(|r| r.path == "/gotify/message")
        .unwrap();
    assert!(
        gf.headers
            .iter()
            .any(|(k, v)| k == "x-gotify-key" && v == "app-tok-99")
    );
    let gf_json: serde_json::Value = serde_json::from_slice(&gf.body).unwrap();
    assert_eq!(gf_json["priority"], 9);

    // Verify ntfy priority + auth.
    let nf = captured.iter().find(|r| r.path == "/ntfy/ops").unwrap();
    assert!(
        nf.headers
            .iter()
            .any(|(k, v)| k == "priority" && v == "urgent")
    );
    assert!(
        nf.headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer tk_secret")
    );

    // Verify Teams Adaptive Card 1.4.
    let tm = captured.iter().find(|r| r.path == "/teams").unwrap();
    let tm_json: serde_json::Value = serde_json::from_slice(&tm.body).unwrap();
    assert_eq!(tm_json["attachments"][0]["content"]["type"], "AdaptiveCard");

    // Verify Discord embed uses crimson (0xC0392B, never cyan).
    let dc = captured.iter().find(|r| r.path == "/discord").unwrap();
    let dc_json: serde_json::Value = serde_json::from_slice(&dc.body).unwrap();
    assert_eq!(dc_json["embeds"][0]["color"], 0x00C0_392B);

    // Verify Twilio form body & Basic auth.
    let tw = captured.iter().find(|r| r.path == "/twilio").unwrap();
    assert!(
        tw.headers
            .iter()
            .any(|(k, v)| k == "authorization" && v.starts_with("Basic "))
    );
    let tw_body = String::from_utf8(tw.body.clone()).unwrap();
    assert!(tw_body.contains("To=%2B15550002222"));
    assert!(tw_body.contains("From=%2B15550001111"));
}

#[tokio::test]
async fn router_filters_by_severity_and_category_and_retries_transient_503() {
    let (base, state) = spawn_mock_server().await;
    let mem_crit = Arc::new(MemorySink::new("crit-only"));
    let flaky = WebhookSink::new(WebhookConfig::new(format!("{base}/flaky"))).unwrap();

    let router = AlertRouter::new()
        .with_dedupe_window(Duration::ZERO)
        .with_rule(
            SinkRule::new(Arc::clone(&mem_crit) as Arc<dyn vaelspire_alerts::AlertSink>)
                .min_severity(Severity::Critical)
                .categories(vec!["security.".to_owned()]),
        )
        .with_rule(
            SinkRule::new(Arc::new(flaky))
                .max_retries(2)
                .retry_base_delay(Duration::from_millis(10)),
        );

    let info_ev = AlertEvent::new(Severity::Info, "security.login", "Login", "Normal login");
    let r1 = router.dispatch(&info_ev).await;
    assert_eq!(r1.succeeded(), 1); // flaky succeeded on retry #2; crit-only skipped Info
    assert_eq!(r1.outcomes[0].attempts, 2);
    assert_eq!(mem_crit.events().len(), 0);
    assert_eq!(state.requests.lock().unwrap().len(), 1);

    let crit_ev = AlertEvent::new(
        Severity::Critical,
        "security.token_reuse",
        "Refresh token reuse",
        "Family revoked",
    );
    let r2 = router.dispatch(&crit_ev).await;
    assert_eq!(r2.succeeded(), 2);
    assert_eq!(mem_crit.events().len(), 1);
}

#[tokio::test]
async fn declarative_json_config_builds_working_router() {
    let (base, state) = spawn_mock_server().await;
    let cfg_json = serde_json::json!({
        "dedupe_window_secs": 30,
        "sinks": [
            {
                "min_severity": "warn",
                "sink": { "type": "slack", "webhook_url": format!("{base}/slack") }
            },
            {
                "min_severity": "critical",
                "sink": {
                    "type": "gotify",
                    "base_url": format!("{base}/gotify"),
                    "app_token": "tok123"
                }
            }
        ]
    });
    let cfg: AlertsConfig = serde_json::from_value(cfg_json).unwrap();
    let router = cfg.build_router().unwrap();
    assert_eq!(router.sink_count(), 2);

    let warn_ev = AlertEvent::new(
        Severity::Warn,
        "security.new_ip",
        "New IP",
        "Observed new /24",
    );
    let report = router.dispatch(&warn_ev).await;
    assert_eq!(report.succeeded(), 1); // slack only
    assert_eq!(state.requests.lock().unwrap().len(), 1);
}
