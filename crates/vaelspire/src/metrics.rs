//! Lightweight, lock-free Prometheus text exposition metrics for Vaelspire Core.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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

    /// Render Prometheus text exposition format (version 0.0.4).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);
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

        out
    }
}
