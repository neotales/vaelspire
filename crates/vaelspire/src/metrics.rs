//! Lightweight, lock-free Prometheus text exposition metrics for Vaelspire Core.
//!
//! All label values are strictly bounded low-cardinality enums (never `user_id`,
//! `email`, or `ip`) to protect Prometheus from cardinality explosion and prevent
//! PII leakage into metrics scrapers.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::security::AnomalyKind;

/// Authentication method observed on `/forward-auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardAuthMethod {
    /// Browser session cookie.
    Session,
    /// `Authorization: Bearer` or `X-API-Key` header.
    ApiKey,
    /// No credential presented.
    None,
}

/// Atomic server metrics exposed at `GET /metrics` (always free in Core).
#[derive(Debug)]
pub struct Metrics {
    started_at: Instant,
    http_requests_total: AtomicU64,
    http_2xx_total: AtomicU64,
    http_4xx_total: AtomicU64,
    http_5xx_total: AtomicU64,
    forward_auth_allow_session: AtomicU64,
    forward_auth_allow_api_key: AtomicU64,
    forward_auth_deny_session: AtomicU64,
    forward_auth_deny_api_key: AtomicU64,
    forward_auth_deny_none: AtomicU64,
    oidc_token_auth_code: AtomicU64,
    oidc_token_refresh: AtomicU64,
    oidc_token_client_credentials: AtomicU64,
    oidc_token_denied: AtomicU64,
    anomaly_password_spray: AtomicU64,
    anomaly_new_device: AtomicU64,
    anomaly_refresh_reuse: AtomicU64,
    gdpr_exports_total: AtomicU64,
    gdpr_erasures_total: AtomicU64,
    scim_ops_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Create a fresh metrics collector anchored at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            http_requests_total: AtomicU64::new(0),
            http_2xx_total: AtomicU64::new(0),
            http_4xx_total: AtomicU64::new(0),
            http_5xx_total: AtomicU64::new(0),
            forward_auth_allow_session: AtomicU64::new(0),
            forward_auth_allow_api_key: AtomicU64::new(0),
            forward_auth_deny_session: AtomicU64::new(0),
            forward_auth_deny_api_key: AtomicU64::new(0),
            forward_auth_deny_none: AtomicU64::new(0),
            oidc_token_auth_code: AtomicU64::new(0),
            oidc_token_refresh: AtomicU64::new(0),
            oidc_token_client_credentials: AtomicU64::new(0),
            oidc_token_denied: AtomicU64::new(0),
            anomaly_password_spray: AtomicU64::new(0),
            anomaly_new_device: AtomicU64::new(0),
            anomaly_refresh_reuse: AtomicU64::new(0),
            gdpr_exports_total: AtomicU64::new(0),
            gdpr_erasures_total: AtomicU64::new(0),
            scim_ops_total: AtomicU64::new(0),
        }
    }

    /// Record one completed HTTP response status.
    pub fn record_http_status(&self, status_code: u16) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        match status_code {
            200..=299 => {
                self.http_2xx_total.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.http_4xx_total.fetch_add(1, Ordering::Relaxed);
            }
            500..=599 => {
                self.http_5xx_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a `/forward-auth` decision.
    pub fn record_forward_auth(&self, allowed: bool, method: ForwardAuthMethod) {
        match (allowed, method) {
            (true, ForwardAuthMethod::Session) => {
                self.forward_auth_allow_session
                    .fetch_add(1, Ordering::Relaxed);
            }
            (true, ForwardAuthMethod::ApiKey) => {
                self.forward_auth_allow_api_key
                    .fetch_add(1, Ordering::Relaxed);
            }
            (false, ForwardAuthMethod::Session) => {
                self.forward_auth_deny_session
                    .fetch_add(1, Ordering::Relaxed);
            }
            (false, ForwardAuthMethod::ApiKey) => {
                self.forward_auth_deny_api_key
                    .fetch_add(1, Ordering::Relaxed);
            }
            (_, ForwardAuthMethod::None) => {
                self.forward_auth_deny_none.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record an OIDC `/oauth2/token` grant outcome.
    pub fn record_oidc_token(&self, grant_type: &str, ok: bool) {
        if !ok {
            self.oidc_token_denied.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match grant_type {
            "authorization_code" => {
                self.oidc_token_auth_code.fetch_add(1, Ordering::Relaxed);
            }
            "refresh_token" => {
                self.oidc_token_refresh.fetch_add(1, Ordering::Relaxed);
            }
            "client_credentials" => {
                self.oidc_token_client_credentials
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a detected security anomaly.
    pub fn record_anomaly(&self, kind: AnomalyKind) {
        match kind {
            AnomalyKind::PasswordSpray => {
                self.anomaly_password_spray.fetch_add(1, Ordering::Relaxed);
            }
            AnomalyKind::NewDeviceOrIp => {
                self.anomaly_new_device.fetch_add(1, Ordering::Relaxed);
            }
            AnomalyKind::RefreshTokenReuse => {
                self.anomaly_refresh_reuse.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a GDPR data export.
    pub fn record_gdpr_export(&self) {
        self.gdpr_exports_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a GDPR account erasure.
    pub fn record_gdpr_erasure(&self) {
        self.gdpr_erasures_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a SCIM 2.0 directory operation.
    pub fn record_scim_op(&self) {
        self.scim_ops_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Render Prometheus text exposition format (version 0.0.4).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);
        let uptime = self.started_at.elapsed().as_secs();
        let version = env!("CARGO_PKG_VERSION");

        let _ = writeln!(
            out,
            "# HELP vaelspire_build_info Build metadata for Vaelspire."
        );
        let _ = writeln!(out, "# TYPE vaelspire_build_info gauge");
        let _ = writeln!(
            out,
            "vaelspire_build_info{{version=\"{version}\",edition=\"core\"}} 1"
        );

        let _ = writeln!(
            out,
            "# HELP vaelspire_uptime_seconds Seconds since Vaelspire started."
        );
        let _ = writeln!(out, "# TYPE vaelspire_uptime_seconds gauge");
        let _ = writeln!(out, "vaelspire_uptime_seconds {uptime}");

        let _ = writeln!(
            out,
            "# HELP vaelspire_http_requests_total Total HTTP requests handled."
        );
        let _ = writeln!(out, "# TYPE vaelspire_http_requests_total counter");
        let _ = writeln!(
            out,
            "vaelspire_http_requests_total {}",
            self.http_requests_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_http_responses_total{{class=\"2xx\"}} {}",
            self.http_2xx_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_http_responses_total{{class=\"4xx\"}} {}",
            self.http_4xx_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_http_responses_total{{class=\"5xx\"}} {}",
            self.http_5xx_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP vaelspire_forward_auth_total Total forward-auth decisions by outcome and method."
        );
        let _ = writeln!(out, "# TYPE vaelspire_forward_auth_total counter");
        let _ = writeln!(
            out,
            "vaelspire_forward_auth_total{{outcome=\"allow\",method=\"session\"}} {}",
            self.forward_auth_allow_session.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_forward_auth_total{{outcome=\"allow\",method=\"api_key\"}} {}",
            self.forward_auth_allow_api_key.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_forward_auth_total{{outcome=\"deny\",method=\"session\"}} {}",
            self.forward_auth_deny_session.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_forward_auth_total{{outcome=\"deny\",method=\"api_key\"}} {}",
            self.forward_auth_deny_api_key.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_forward_auth_total{{outcome=\"deny\",method=\"none\"}} {}",
            self.forward_auth_deny_none.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP vaelspire_oidc_tokens_total Total OIDC token endpoint outcomes."
        );
        let _ = writeln!(out, "# TYPE vaelspire_oidc_tokens_total counter");
        let _ = writeln!(
            out,
            "vaelspire_oidc_tokens_total{{grant_type=\"authorization_code\",outcome=\"ok\"}} {}",
            self.oidc_token_auth_code.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_oidc_tokens_total{{grant_type=\"refresh_token\",outcome=\"ok\"}} {}",
            self.oidc_token_refresh.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_oidc_tokens_total{{grant_type=\"client_credentials\",outcome=\"ok\"}} {}",
            self.oidc_token_client_credentials.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_oidc_tokens_total{{grant_type=\"any\",outcome=\"denied\"}} {}",
            self.oidc_token_denied.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP vaelspire_anomalies_total Detected security anomalies by kind."
        );
        let _ = writeln!(out, "# TYPE vaelspire_anomalies_total counter");
        let _ = writeln!(
            out,
            "vaelspire_anomalies_total{{kind=\"password_spray\"}} {}",
            self.anomaly_password_spray.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_anomalies_total{{kind=\"new_device_or_ip\"}} {}",
            self.anomaly_new_device.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_anomalies_total{{kind=\"refresh_token_reuse\"}} {}",
            self.anomaly_refresh_reuse.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP vaelspire_gdpr_actions_total GDPR data portability exports and erasures."
        );
        let _ = writeln!(out, "# TYPE vaelspire_gdpr_actions_total counter");
        let _ = writeln!(
            out,
            "vaelspire_gdpr_actions_total{{action=\"export\"}} {}",
            self.gdpr_exports_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "vaelspire_gdpr_actions_total{{action=\"erasure\"}} {}",
            self.gdpr_erasures_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP vaelspire_scim_operations_total SCIM 2.0 directory operations."
        );
        let _ = writeln!(out, "# TYPE vaelspire_scim_operations_total counter");
        let _ = writeln!(
            out,
            "vaelspire_scim_operations_total {}",
            self.scim_ops_total.load(Ordering::Relaxed)
        );

        out
    }
}
