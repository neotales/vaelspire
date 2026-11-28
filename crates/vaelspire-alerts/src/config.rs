//! Declarative multi-sink alert configuration (`AlertsConfig`) for easy CLI, env, or JSON loading.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AlertError;
use crate::event::Severity;
use crate::router::{AlertRouter, SinkRule};
use crate::sink::LogSink;

/// Declarative sink configuration deserializable from JSON or TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SinkConfig {
    /// Built-in structured `tracing` log sink.
    Log {
        /// Logical sink name.
        #[serde(default = "default_log_name")]
        name: String,
    },
    /// Generic JSON HTTP webhook with optional HMAC-SHA256 signing.
    #[cfg(feature = "webhook")]
    Webhook {
        /// Logical sink name.
        #[serde(default = "default_webhook_name")]
        name: String,
        /// Target URL.
        url: String,
        /// Optional HMAC-SHA256 secret.
        #[serde(default)]
        signing_secret: Option<String>,
        /// Extra HTTP headers.
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
    /// Slack Incoming Webhook.
    #[cfg(feature = "slack")]
    Slack {
        /// Logical sink name.
        #[serde(default = "default_slack_name")]
        name: String,
        /// Slack Incoming Webhook URL.
        webhook_url: String,
        /// Optional channel override.
        #[serde(default)]
        channel: Option<String>,
    },
    /// Discord Webhook.
    #[cfg(feature = "discord")]
    Discord {
        /// Logical sink name.
        #[serde(default = "default_discord_name")]
        name: String,
        /// Discord webhook URL.
        webhook_url: String,
        /// Optional username override.
        #[serde(default)]
        username: Option<String>,
    },
    /// Microsoft Teams Workflows Adaptive Card webhook.
    #[cfg(feature = "teams")]
    Teams {
        /// Logical sink name.
        #[serde(default = "default_teams_name")]
        name: String,
        /// Teams Workflows webhook URL.
        webhook_url: String,
    },
    /// Gotify server push notification sink.
    #[cfg(feature = "gotify")]
    Gotify {
        /// Logical sink name.
        #[serde(default = "default_gotify_name")]
        name: String,
        /// Gotify server base URL.
        base_url: String,
        /// Gotify application token.
        app_token: String,
    },
    /// ntfy push notification sink.
    #[cfg(feature = "ntfy")]
    Ntfy {
        /// Logical sink name.
        #[serde(default = "default_ntfy_name")]
        name: String,
        /// Full topic URL (e.g. `https://ntfy.example.com/ops`).
        topic_url: String,
        /// Optional Bearer token.
        #[serde(default)]
        bearer_token: Option<String>,
    },
    /// Twilio SMS sink.
    #[cfg(feature = "sms")]
    TwilioSms {
        /// Logical sink name.
        #[serde(default = "default_twilio_name")]
        name: String,
        /// Twilio Account SID.
        account_sid: String,
        /// Twilio Auth Token.
        auth_token: String,
        /// Sender phone number (E.164).
        from: String,
        /// Recipient phone numbers (E.164).
        to: Vec<String>,
        /// Optional base URL override.
        #[serde(default)]
        api_base_url: Option<String>,
    },
    /// Generic HTTP JSON SMS gateway sink.
    #[cfg(feature = "sms")]
    GenericSms {
        /// Logical sink name.
        #[serde(default = "default_sms_name")]
        name: String,
        /// Gateway HTTP(S) URL.
        endpoint_url: String,
        /// Sender phone number or ID.
        from: String,
        /// Recipient phone numbers.
        to: Vec<String>,
        /// Optional Bearer token.
        #[serde(default)]
        bearer_token: Option<String>,
    },
    /// SMTP Email sink (requires `email` crate feature).
    #[cfg(feature = "email")]
    Email {
        /// Logical sink name.
        #[serde(default = "default_email_name")]
        name: String,
        /// SMTP hostname.
        smtp_host: String,
        /// SMTP port (default `587`).
        #[serde(default = "default_smtp_port")]
        smtp_port: u16,
        /// Transport mode: `starttls`, `tls`, or `plain`.
        #[serde(default)]
        security: Option<String>,
        /// Optional SMTP username.
        #[serde(default)]
        username: Option<String>,
        /// Optional SMTP password.
        #[serde(default)]
        password: Option<String>,
        /// Sender mailbox.
        from: String,
        /// Recipient mailboxes.
        to: Vec<String>,
    },
}

fn default_log_name() -> String {
    "log".to_owned()
}
#[cfg(feature = "webhook")]
fn default_webhook_name() -> String {
    "webhook".to_owned()
}
#[cfg(feature = "slack")]
fn default_slack_name() -> String {
    "slack".to_owned()
}
#[cfg(feature = "discord")]
fn default_discord_name() -> String {
    "discord".to_owned()
}
#[cfg(feature = "teams")]
fn default_teams_name() -> String {
    "teams".to_owned()
}
#[cfg(feature = "gotify")]
fn default_gotify_name() -> String {
    "gotify".to_owned()
}
#[cfg(feature = "ntfy")]
fn default_ntfy_name() -> String {
    "ntfy".to_owned()
}
#[cfg(feature = "sms")]
fn default_twilio_name() -> String {
    "twilio-sms".to_owned()
}
#[cfg(feature = "sms")]
fn default_sms_name() -> String {
    "sms".to_owned()
}
#[cfg(feature = "email")]
fn default_email_name() -> String {
    "email".to_owned()
}
#[cfg(feature = "email")]
const fn default_smtp_port() -> u16 {
    587
}

/// Declarative routing rule binding a [`SinkConfig`] to severity and category filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkRuleConfig {
    /// Minimum severity required to trigger this sink (default `warn`).
    #[serde(default = "default_min_severity")]
    pub min_severity: Severity,
    /// Optional category prefixes; empty means all categories.
    #[serde(default)]
    pub categories: Vec<String>,
    /// Maximum retry attempts on transient errors (default `2`).
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Concrete sink configuration.
    pub sink: SinkConfig,
}

const fn default_min_severity() -> Severity {
    Severity::Warn
}

const fn default_max_retries() -> u32 {
    2
}

/// Top-level declarative alert router configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    /// Deduplication window in seconds (default `60`; `0` disables deduplication).
    #[serde(default = "default_dedupe_secs")]
    pub dedupe_window_secs: u64,
    /// Configured sink rules.
    #[serde(default)]
    pub sinks: Vec<SinkRuleConfig>,
}

const fn default_dedupe_secs() -> u64 {
    60
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            dedupe_window_secs: default_dedupe_secs(),
            sinks: Vec::new(),
        }
    }
}

impl AlertsConfig {
    /// Compiles this declarative configuration into a ready-to-use [`AlertRouter`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] if any sink has invalid settings.
    pub fn build_router(&self) -> Result<AlertRouter, AlertError> {
        let mut router =
            AlertRouter::new().with_dedupe_window(Duration::from_secs(self.dedupe_window_secs));
        for rule_cfg in &self.sinks {
            let sink = build_sink(&rule_cfg.sink)?;
            let rule = SinkRule::new(sink)
                .min_severity(rule_cfg.min_severity)
                .categories(rule_cfg.categories.clone())
                .max_retries(rule_cfg.max_retries);
            router.add_rule(rule);
        }
        Ok(router)
    }
}

#[allow(clippy::too_many_lines)]
fn build_sink(cfg: &SinkConfig) -> Result<Arc<dyn crate::AlertSink>, AlertError> {
    match cfg {
        SinkConfig::Log { name } => Ok(Arc::new(LogSink::new(name))),
        #[cfg(feature = "webhook")]
        SinkConfig::Webhook {
            name,
            url,
            signing_secret,
            headers,
        } => {
            let mut c = crate::sinks::webhook::WebhookConfig::new(url).with_name(name);
            if let Some(secret) = signing_secret {
                c = c.with_signing_secret(secret);
            }
            c.headers.clone_from(headers);
            Ok(Arc::new(crate::sinks::webhook::WebhookSink::new(c)?))
        }
        #[cfg(feature = "slack")]
        SinkConfig::Slack {
            name,
            webhook_url,
            channel,
        } => {
            let mut c = crate::sinks::slack::SlackConfig::new(webhook_url).with_name(name);
            c.channel.clone_from(channel);
            Ok(Arc::new(crate::sinks::slack::SlackSink::new(c)?))
        }
        #[cfg(feature = "discord")]
        SinkConfig::Discord {
            name,
            webhook_url,
            username,
        } => {
            let mut c = crate::sinks::discord::DiscordConfig::new(webhook_url).with_name(name);
            c.username.clone_from(username);
            Ok(Arc::new(crate::sinks::discord::DiscordSink::new(c)?))
        }
        #[cfg(feature = "teams")]
        SinkConfig::Teams { name, webhook_url } => {
            let c = crate::sinks::teams::TeamsConfig::new(webhook_url).with_name(name);
            Ok(Arc::new(crate::sinks::teams::TeamsSink::new(c)?))
        }
        #[cfg(feature = "gotify")]
        SinkConfig::Gotify {
            name,
            base_url,
            app_token,
        } => {
            let c = crate::sinks::gotify::GotifyConfig::new(base_url, app_token).with_name(name);
            Ok(Arc::new(crate::sinks::gotify::GotifySink::new(c)?))
        }
        #[cfg(feature = "ntfy")]
        SinkConfig::Ntfy {
            name,
            topic_url,
            bearer_token,
        } => {
            let mut c = crate::sinks::ntfy::NtfyConfig::new(topic_url).with_name(name);
            if let Some(tok) = bearer_token {
                c = c.with_bearer_token(tok);
            }
            Ok(Arc::new(crate::sinks::ntfy::NtfySink::new(c)?))
        }
        #[cfg(feature = "sms")]
        SinkConfig::TwilioSms {
            name,
            account_sid,
            auth_token,
            from,
            to,
            api_base_url,
        } => {
            let mut c =
                crate::sinks::sms::TwilioSmsConfig::new(account_sid, auth_token, from, to.clone())
                    .with_name(name);
            if let Some(base) = api_base_url {
                c = c.with_api_base_url(base);
            }
            Ok(Arc::new(crate::sinks::sms::TwilioSmsSink::new(c)?))
        }
        #[cfg(feature = "sms")]
        SinkConfig::GenericSms {
            name,
            endpoint_url,
            from,
            to,
            bearer_token,
        } => {
            let mut c = crate::sinks::sms::GenericSmsConfig::new(endpoint_url, from, to.clone());
            c.name.clone_from(name);
            if let Some(tok) = bearer_token {
                c = c.with_bearer_token(tok);
            }
            Ok(Arc::new(crate::sinks::sms::GenericSmsSink::new(c)?))
        }
        #[cfg(feature = "email")]
        SinkConfig::Email {
            name,
            smtp_host,
            smtp_port,
            security,
            username,
            password,
            from,
            to,
        } => {
            let mut c = crate::sinks::email::EmailConfig::new(smtp_host, from, to.clone());
            c.name.clone_from(name);
            c.smtp_port = *smtp_port;
            c.security = match security.as_deref() {
                Some("tls" | "smtps" | "implicit") => {
                    crate::sinks::email::SmtpSecurity::ImplicitTls
                }
                Some("plain" | "none") => crate::sinks::email::SmtpSecurity::Plain,
                _ => crate::sinks::email::SmtpSecurity::StartTls,
            };
            c.username.clone_from(username);
            c.password = password.clone().map(zeroize::Zeroizing::new);
            Ok(Arc::new(crate::sinks::email::EmailSink::new(c)?))
        }
    }
}
