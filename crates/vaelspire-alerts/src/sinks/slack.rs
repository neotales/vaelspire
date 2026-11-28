//! Slack Incoming Webhook sink (Block Kit payload).

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

/// Configuration for [`SlackSink`].
#[derive(Debug, Clone)]
pub struct SlackConfig {
    /// Logical sink name (default `"slack"`).
    pub name: String,
    /// Slack Incoming Webhook URL.
    pub webhook_url: Zeroizing<String>,
    /// Optional channel override (for legacy webhooks that accept `channel`).
    pub channel: Option<String>,
    /// Optional display username override.
    pub username: Option<String>,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl SlackConfig {
    /// Creates a Slack config targeting an Incoming Webhook URL.
    #[must_use]
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            name: "slack".to_owned(),
            webhook_url: Zeroizing::new(webhook_url.into()),
            channel: None,
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

/// Builds a Slack Block Kit JSON payload for `event`.
#[must_use]
pub fn build_slack_payload(event: &AlertEvent, config: &SlackConfig) -> Value {
    let mut blocks = vec![
        json!({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": format!("[{}] {}", event.severity.badge(), event.title),
                "emoji": true
            }
        }),
        json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": event.summary
            }
        }),
    ];

    let mut fields = vec![
        json!({"type": "mrkdwn", "text": format!("*Source:*\n`{}`", event.source)}),
        json!({"type": "mrkdwn", "text": format!("*Category:*\n`{}`", event.category)}),
    ];
    for (k, v) in &event.fields {
        fields.push(json!({"type": "mrkdwn", "text": format!("*{k}:*\n`{v}`")}));
    }
    for chunk in fields.chunks(10) {
        blocks.push(json!({
            "type": "section",
            "fields": chunk
        }));
    }
    blocks.push(json!({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": format!("Occurred at `{}`", event.occurred_at)
        }]
    }));

    let mut payload = json!({
        "text": format!("[{}] {}: {}", event.severity.badge(), event.title, event.summary),
        "blocks": blocks
    });
    if let Some(obj) = payload.as_object_mut() {
        if let Some(channel) = &config.channel {
            obj.insert("channel".to_owned(), json!(channel));
        }
        if let Some(username) = &config.username {
            obj.insert("username".to_owned(), json!(username));
        }
    }
    payload
}

/// Delivers alerts to Slack via an Incoming Webhook.
pub struct SlackSink {
    config: SlackConfig,
    client: reqwest::Client,
}

impl SlackSink {
    /// Validates `config` and constructs a new [`SlackSink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when `webhook_url` is invalid.
    pub fn new(config: SlackConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.webhook_url, "slack webhook_url")?;
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl AlertSink for SlackSink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let payload = build_slack_payload(event, &self.config);
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
