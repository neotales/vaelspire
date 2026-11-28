//! Discord Webhook sink (severity-colored Embeds).

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

/// Configuration for [`DiscordSink`].
#[derive(Debug, Clone)]
pub struct DiscordConfig {
    /// Logical sink name (default `"discord"`).
    pub name: String,
    /// Discord webhook URL.
    pub webhook_url: Zeroizing<String>,
    /// Optional webhook username override.
    pub username: Option<String>,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl DiscordConfig {
    /// Creates a Discord webhook config.
    #[must_use]
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            name: "discord".to_owned(),
            webhook_url: Zeroizing::new(webhook_url.into()),
            username: None,
            timeout_secs: 10,
        }
    }

    /// Sets a custom logical name for this sink.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

/// Builds a Discord Webhook Embed JSON payload for `event`.
#[must_use]
pub fn build_discord_payload(event: &AlertEvent, config: &DiscordConfig) -> Value {
    let mut fields = vec![
        json!({"name": "Source", "value": event.source, "inline": true}),
        json!({"name": "Category", "value": event.category, "inline": true}),
    ];
    for (k, v) in &event.fields {
        fields.push(json!({"name": k, "value": v, "inline": true}));
    }
    let embed = json!({
        "title": format!("[{}] {}", event.severity.badge(), event.title),
        "description": event.summary,
        "color": event.severity.accent_rgb(),
        "timestamp": event.occurred_at,
        "fields": fields,
        "footer": { "text": format!("{} alerts", event.source) }
    });

    let mut payload = json!({ "embeds": [embed] });
    if let Some(username) = &config.username
        && let Some(obj) = payload.as_object_mut()
    {
        obj.insert("username".to_owned(), json!(username));
    }
    payload
}

/// Delivers alerts to a Discord channel via Webhook.
pub struct DiscordSink {
    config: DiscordConfig,
    client: reqwest::Client,
}

impl DiscordSink {
    /// Validates `config` and constructs a new [`DiscordSink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when `webhook_url` is invalid.
    pub fn new(config: DiscordConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.webhook_url, "discord webhook_url")?;
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl AlertSink for DiscordSink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let payload = build_discord_payload(event, &self.config);
        let resp = self
            .client
            .post(self.config.webhook_url.as_str())
            .json(&payload)
            .send()
            .await
            .map_err(|source| AlertError::Http {
                sink: self.config.name.clone(),
                source,
            })?;
        check_http_response(&self.config.name, resp).await
    }
}
