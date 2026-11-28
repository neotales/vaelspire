//! Microsoft Teams Workflows webhook sink (Adaptive Card 1.4 JSON).

use async_trait::async_trait;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::{AlertEvent, Severity};
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

/// Configuration for [`TeamsSink`].
#[derive(Debug, Clone)]
pub struct TeamsConfig {
    /// Logical sink name (default `"teams"`).
    pub name: String,
    /// Microsoft Teams Workflows / Power Automate webhook URL.
    pub webhook_url: Zeroizing<String>,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl TeamsConfig {
    /// Creates a Microsoft Teams Workflows config.
    #[must_use]
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            name: "teams".to_owned(),
            webhook_url: Zeroizing::new(webhook_url.into()),
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

/// Builds a Microsoft Teams Adaptive Card 1.4 webhook envelope for `event`.
#[must_use]
pub fn build_teams_payload(event: &AlertEvent) -> Value {
    let color = match event.severity {
        Severity::Info => "Default",
        Severity::Warn => "Warning",
        Severity::Critical => "Attention",
    };

    let mut facts = vec![
        json!({"title": "Severity", "value": event.severity.badge()}),
        json!({"title": "Source", "value": event.source}),
        json!({"title": "Category", "value": event.category}),
        json!({"title": "Time", "value": event.occurred_at}),
    ];
    for (k, v) in &event.fields {
        facts.push(json!({"title": k, "value": v}));
    }

    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": Value::Null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "size": "Medium",
                        "weight": "Bolder",
                        "color": color,
                        "wrap": true,
                        "text": format!("[{}] {}", event.severity.badge(), event.title)
                    },
                    {
                        "type": "TextBlock",
                        "wrap": true,
                        "text": event.summary
                    },
                    {
                        "type": "FactSet",
                        "facts": facts
                    }
                ]
            }
        }]
    })
}

/// Delivers alerts to Microsoft Teams via Workflows Adaptive Card webhook.
pub struct TeamsSink {
    config: TeamsConfig,
    client: reqwest::Client,
}

impl TeamsSink {
    /// Validates `config` and constructs a new [`TeamsSink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when `webhook_url` is invalid.
    pub fn new(config: TeamsConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.webhook_url, "teams webhook_url")?;
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl AlertSink for TeamsSink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let payload = build_teams_payload(event);
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
