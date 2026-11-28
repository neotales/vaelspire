//! Reusable multi-sink alerting router with severity filtering, burst deduplication,
//! retries, and feature-gated sinks (Webhook, Slack, Discord, Microsoft Teams, Gotify,
//! ntfy, Twilio/Generic SMS, and SMTP Email).
//!
//! This crate intentionally has **zero Vaelspire-specific dependencies** so it can be
//! reused across other services and extracted cleanly into a standalone `neotales-alerts`
//! crate in the future.

pub mod config;
pub mod error;
pub mod event;
pub mod router;
pub mod sink;
pub mod sinks;

pub use config::{AlertsConfig, SinkConfig, SinkRuleConfig};
pub use error::AlertError;
pub use event::{AlertEvent, Severity};
pub use router::{AlertHandle, AlertRouter, DispatchReport, SinkOutcome, SinkRule};
pub use sink::{AlertSink, LogSink, MemorySink};
