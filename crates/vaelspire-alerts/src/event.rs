//! Alert severity levels and structured event payloads.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Severity of an [`AlertEvent`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational notification (audit highlight, lifecycle event).
    #[default]
    Info,
    /// Actionable warning (new IP/device sign-in, elevated failures).
    Warn,
    /// High-priority security or availability incident (password spray, token reuse).
    Critical,
}

impl Severity {
    /// Canonical lowercase string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }

    /// Uppercase badge text for chat and email subjects.
    #[must_use]
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Critical => "CRITICAL",
        }
    }

    /// RGB hex integer color used by embed-capable sinks (warm gold / amber / crimson).
    #[must_use]
    pub const fn accent_rgb(self) -> u32 {
        match self {
            Self::Info => 0x00D4_A017,     // Molten gold
            Self::Warn => 0x00E6_7E22,     // Ember orange
            Self::Critical => 0x00C0_392B, // Dragon crimson
        }
    }

    /// Gotify priority integer (`0..=10`).
    #[must_use]
    pub const fn gotify_priority(self) -> u8 {
        match self {
            Self::Info => 3,
            Self::Warn => 6,
            Self::Critical => 9,
        }
    }

    /// ntfy priority string (`default`, `high`, `urgent`).
    #[must_use]
    pub const fn ntfy_priority(self) -> &'static str {
        match self {
            Self::Info => "default",
            Self::Warn => "high",
            Self::Critical => "urgent",
        }
    }

    /// ntfy default tag list.
    #[must_use]
    pub const fn ntfy_tags(self) -> &'static str {
        match self {
            Self::Info => "information_source",
            Self::Warn => "warning",
            Self::Critical => "rotating_light",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "low" => Ok(Self::Info),
            "warn" | "warning" | "medium" => Ok(Self::Warn),
            "critical" | "crit" | "high" | "error" => Ok(Self::Critical),
            other => Err(format!(
                "invalid severity '{other}' (expected info, warn, or critical)"
            )),
        }
    }
}

/// Structured, service-agnostic alert payload routed to one or more sinks.
///
/// Callers should pass already-redacted PII (for example `wf******@acme.com` and
/// truncated IP subnets) so alert channels never leak raw personal data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertEvent {
    /// Severity level governing routing, priority, and visual styling.
    pub severity: Severity,
    /// Dot-delimited category (e.g. `"security.anomaly"`, `"gdpr.erasure"`).
    pub category: String,
    /// Short headline for notifications and subjects.
    pub title: String,
    /// Human-readable description of what happened.
    pub summary: String,
    /// Name of the emitting application or service (e.g. `"vaelspire"`).
    pub source: String,
    /// RFC 3339 UTC timestamp when the event was created.
    pub occurred_at: String,
    /// Ordered key-value context fields rendered as structured facts in sinks.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// Optional deduplication key for burst suppression within the router window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<String>,
}

impl AlertEvent {
    /// Creates a new alert event stamped with the current UTC time.
    #[must_use]
    pub fn new(
        severity: Severity,
        category: impl Into<String>,
        title: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        let occurred_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        Self {
            severity,
            category: category.into(),
            title: title.into(),
            summary: summary.into(),
            source: "application".to_owned(),
            occurred_at,
            fields: BTreeMap::new(),
            dedupe_key: None,
        }
    }

    /// Sets the emitting service/source identifier.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// Attaches a structured key-value context field.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Sets an explicit deduplication key for router burst suppression.
    #[must_use]
    pub fn with_dedupe_key(mut self, key: impl Into<String>) -> Self {
        self.dedupe_key = Some(key.into());
        self
    }

    /// Renders a concise single-message plain-text representation suitable for SMS,
    /// Gotify, ntfy, and email bodies.
    #[must_use]
    pub fn format_plain_text(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        let _ = writeln!(
            out,
            "[{}] {} ({})",
            self.severity.badge(),
            self.title,
            self.source
        );
        let _ = writeln!(out, "{}", self.summary);
        let _ = writeln!(out, "category: {}", self.category);
        let _ = writeln!(out, "occurred_at: {}", self.occurred_at);
        for (k, v) in &self.fields {
            let _ = writeln!(out, "{k}: {v}");
        }
        out.trim_end().to_owned()
    }

    /// Renders a compact SMS-friendly summary (kept concise for carrier segments).
    #[must_use]
    pub fn format_sms_text(&self) -> String {
        let mut msg = format!(
            "[{}] {}: {} - {}",
            self.severity.badge(),
            self.source,
            self.title,
            self.summary
        );
        if msg.len() > 300 {
            msg.truncate(297);
            msg.push_str("...");
        }
        msg
    }
}
