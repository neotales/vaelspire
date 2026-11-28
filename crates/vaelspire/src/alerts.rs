//! Vaelspire server & CLI integration with the reusable [`vaelspire_alerts`] crate.
//!
//! Supports both declarative JSON config files (`--alerts-config /path/to/alerts.json`)
//! and quick CLI/env flags for Webhook, Slack, Discord, Microsoft Teams, Gotify, and ntfy.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use vaelspire_alerts::{
    AlertError, AlertEvent, AlertHandle, AlertsConfig, Severity, SinkConfig, SinkRuleConfig,
};
use vaelspire_core::Id;
use vaelspire_core::privacy::{AuditIpMode, PiiLogMode, format_email_for_log, format_ip_for_audit};

use crate::security::AnomalyKind;

/// Reusable clap argument group for configuring alert sinks in `vaelspire serve` and `vaelspire alert test`.
#[derive(Debug, Clone, Args)]
pub struct AlertCliArgs {
    /// Optional path to a declarative `AlertsConfig` JSON file (supports all sinks including SMS & SMTP email).
    #[arg(long, env = "VAELSPIRE_ALERTS_CONFIG")]
    pub alerts_config: Option<PathBuf>,

    /// Minimum severity for CLI/env-configured sinks (`info`, `warn`, `critical`).
    #[arg(long, env = "VAELSPIRE_ALERT_MIN_SEVERITY", default_value = "warn")]
    pub alert_min_severity: String,

    /// Deduplication cooldown window in seconds (default 60; 0 disables deduplication).
    #[arg(long, env = "VAELSPIRE_ALERT_DEDUPE_SECS", default_value_t = 60)]
    pub alert_dedupe_secs: u64,

    /// Generic JSON webhook URL for security alerts.
    #[arg(long, env = "VAELSPIRE_ALERT_WEBHOOK_URL")]
    pub alert_webhook_url: Option<String>,

    /// Optional HMAC-SHA256 signing secret for `--alert-webhook-url` (`X-Signature-256`).
    #[arg(long, env = "VAELSPIRE_ALERT_WEBHOOK_SECRET")]
    pub alert_webhook_secret: Option<String>,

    /// Slack Incoming Webhook URL.
    #[arg(long, env = "VAELSPIRE_ALERT_SLACK_URL")]
    pub alert_slack_url: Option<String>,

    /// Discord Webhook URL.
    #[arg(long, env = "VAELSPIRE_ALERT_DISCORD_URL")]
    pub alert_discord_url: Option<String>,

    /// Microsoft Teams Workflows Adaptive Card webhook URL.
    #[arg(long, env = "VAELSPIRE_ALERT_TEAMS_URL")]
    pub alert_teams_url: Option<String>,

    /// Gotify server base URL (e.g. `https://gotify.example.com`).
    #[arg(long, env = "VAELSPIRE_ALERT_GOTIFY_URL")]
    pub alert_gotify_url: Option<String>,

    /// Gotify application token (used with `--alert-gotify-url`).
    #[arg(long, env = "VAELSPIRE_ALERT_GOTIFY_TOKEN")]
    pub alert_gotify_token: Option<String>,

    /// ntfy topic URL (e.g. `https://ntfy.sh/my-vaelspire-alerts` or self-hosted ntfy).
    #[arg(long, env = "VAELSPIRE_ALERT_NTFY_URL")]
    pub alert_ntfy_url: Option<String>,

    /// Optional Bearer token for `--alert-ntfy-url`.
    #[arg(long, env = "VAELSPIRE_ALERT_NTFY_TOKEN")]
    pub alert_ntfy_token: Option<String>,
}

impl AlertCliArgs {
    /// Builds an [`AlertsConfig`] by loading `--alerts-config` (if supplied) and appending
    /// any sinks specified via CLI/env flags. Returns `Ok(None)` when no sinks are configured.
    ///
    /// # Errors
    /// Returns [`AlertError::InvalidConfig`] if the config file cannot be read/parsed or
    /// if a sink pair (such as Gotify URL without token) is incomplete.
    pub fn to_alerts_config(&self) -> Result<Option<AlertsConfig>, AlertError> {
        let mut cfg = if let Some(path) = &self.alerts_config {
            let raw = fs::read_to_string(path).map_err(|err| {
                AlertError::InvalidConfig(format!(
                    "failed to read alerts config '{}': {err}",
                    path.display()
                ))
            })?;
            serde_json::from_str::<AlertsConfig>(&raw).map_err(|err| {
                AlertError::InvalidConfig(format!(
                    "failed to parse alerts config '{}': {err}",
                    path.display()
                ))
            })?
        } else {
            AlertsConfig {
                dedupe_window_secs: self.alert_dedupe_secs,
                sinks: Vec::new(),
            }
        };

        let min_severity: Severity = self
            .alert_min_severity
            .parse()
            .map_err(AlertError::InvalidConfig)?;

        let mut push_sink = |sink: SinkConfig| {
            cfg.sinks.push(SinkRuleConfig {
                min_severity,
                categories: Vec::new(),
                max_retries: 2,
                sink,
            });
        };

        if let Some(url) = self.alert_webhook_url.clone() {
            push_sink(SinkConfig::Webhook {
                name: "webhook".to_owned(),
                url,
                signing_secret: self.alert_webhook_secret.clone(),
                headers: std::collections::BTreeMap::new(),
            });
        }
        if let Some(webhook_url) = self.alert_slack_url.clone() {
            push_sink(SinkConfig::Slack {
                name: "slack".to_owned(),
                webhook_url,
                channel: None,
            });
        }
        if let Some(webhook_url) = self.alert_discord_url.clone() {
            push_sink(SinkConfig::Discord {
                name: "discord".to_owned(),
                webhook_url,
                username: Some("Vaelspire".to_owned()),
            });
        }
        if let Some(webhook_url) = self.alert_teams_url.clone() {
            push_sink(SinkConfig::Teams {
                name: "teams".to_owned(),
                webhook_url,
            });
        }
        if let Some(base_url) = self.alert_gotify_url.clone() {
            let app_token = self.alert_gotify_token.clone().ok_or_else(|| {
                AlertError::InvalidConfig(
                    "--alert-gotify-token (or VAELSPIRE_ALERT_GOTIFY_TOKEN) is required with --alert-gotify-url"
                        .to_owned(),
                )
            })?;
            push_sink(SinkConfig::Gotify {
                name: "gotify".to_owned(),
                base_url,
                app_token,
            });
        }
        if let Some(topic_url) = self.alert_ntfy_url.clone() {
            push_sink(SinkConfig::Ntfy {
                name: "ntfy".to_owned(),
                topic_url,
                bearer_token: self.alert_ntfy_token.clone(),
            });
        }

        if cfg.sinks.is_empty() {
            Ok(None)
        } else {
            Ok(Some(cfg))
        }
    }
}

/// CLI subcommands under `vaelspire alert`.
#[derive(Debug, Subcommand)]
pub enum AlertCommand {
    /// Send a synthetic test alert through all configured alert sinks and print delivery results.
    Test(Box<AlertTestArgs>),
}

/// Arguments for `vaelspire alert test`.
#[derive(Debug, Args)]
pub struct AlertTestArgs {
    /// Alert severity to emit (`info`, `warn`, or `critical`).
    #[arg(long, default_value = "warn")]
    pub severity: String,

    /// Custom title for the test alert.
    #[arg(long, default_value = "Vaelspire test alert")]
    pub title: String,

    /// Custom summary body for the test alert.
    #[arg(
        long,
        default_value = "Synthetic test notification from `vaelspire alert test`"
    )]
    pub summary: String,

    /// Shared alert sink configuration flags.
    #[command(flatten)]
    pub alerts: AlertCliArgs,
}

/// Executes `vaelspire alert ...` subcommands.
pub async fn run_alert_command(cmd: AlertCommand) -> ExitCode {
    match cmd {
        AlertCommand::Test(args) => {
            let severity: Severity = match args.severity.parse() {
                Ok(s) => s,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let cfg = match args.alerts.to_alerts_config() {
                Ok(Some(cfg)) => cfg,
                Ok(None) => {
                    eprintln!(
                        "error: no alert sinks configured (pass --alerts-config or e.g. --alert-webhook-url / --alert-gotify-url)"
                    );
                    return ExitCode::FAILURE;
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let router = match cfg.build_router() {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            let event = AlertEvent::new(severity, "vaelspire.test", args.title, args.summary)
                .with_source("vaelspire")
                .with_field("mode", "cli-test");
            let report = router.dispatch(&event).await;
            for outcome in &report.outcomes {
                match &outcome.result {
                    Ok(()) => println!("ok\t{}\tattempts={}", outcome.sink, outcome.attempts),
                    Err(err) => {
                        eprintln!(
                            "fail\t{}\tattempts={}\t{err}",
                            outcome.sink, outcome.attempts
                        );
                    }
                }
            }
            if report.failed() == 0 && report.succeeded() > 0 {
                ExitCode::SUCCESS
            } else {
                if report.outcomes.is_empty() {
                    eprintln!("warning: no sinks matched severity '{severity}'");
                }
                ExitCode::FAILURE
            }
        }
    }
}

/// Emits a PII-safe anomaly alert when an [`AlertHandle`] is active.
pub fn notify_anomaly(
    alerts: Option<&AlertHandle>,
    kind: AnomalyKind,
    user_id: Option<Id>,
    email: Option<&str>,
    client_ip: Option<&str>,
    pii_mode: PiiLogMode,
    audit_ip_mode: AuditIpMode,
) {
    let Some(handle) = alerts else {
        return;
    };
    let (severity, title, summary) = match kind {
        AnomalyKind::PasswordSpray => (
            Severity::Critical,
            "Password spray detected",
            "Repeated authentication failures observed from a single source.",
        ),
        AnomalyKind::NewDeviceOrIp => (
            Severity::Warn,
            "New device or network observed",
            "An authenticated session appeared from a previously unseen IP or User-Agent.",
        ),
        AnomalyKind::RefreshTokenReuse => (
            Severity::Critical,
            "OIDC refresh token reuse detected",
            "A rotated refresh token was replayed; the token family was invalidated.",
        ),
    };

    let mut event = AlertEvent::new(severity, "security.anomaly", title, summary)
        .with_source("vaelspire")
        .with_field("anomaly", kind.as_str());

    if let Some(uid) = user_id {
        event = event.with_field("user_id", uid.to_string());
    }
    if let Some(raw_email) = email {
        event = event.with_field("email", format_email_for_log(raw_email, pii_mode));
    }
    if let Some(ip) = format_ip_for_audit(client_ip, audit_ip_mode) {
        event = event.with_field("client_ip", ip);
    }

    let dedupe_subject = user_id
        .map(|id| id.to_string())
        .or_else(|| client_ip.map(ToOwned::to_owned))
        .unwrap_or_else(|| "global".to_owned());
    event = event.with_dedupe_key(format!("{}:{dedupe_subject}", kind.as_str()));

    let _ = handle.try_notify(event);
}

/// Emits a pseudonymous GDPR erasure notification (contains user ID only, zero raw PII).
pub fn notify_gdpr_erasure(alerts: Option<&AlertHandle>, user_id: Id, trigger: &str) {
    let Some(handle) = alerts else {
        return;
    };
    let event = AlertEvent::new(
        Severity::Info,
        "gdpr.erasure",
        "GDPR account erasure completed",
        "User PII was anonymized and active credentials were revoked.",
    )
    .with_source("vaelspire")
    .with_field("user_id", user_id.to_string())
    .with_field("trigger", trigger)
    .with_dedupe_key(format!("gdpr_erase:{user_id}"));
    let _ = handle.try_notify(event);
}
