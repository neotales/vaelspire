//! Gotify push notification sink (`POST /message` with `X-Gotify-Key`).

use async_trait::async_trait;
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

/// Configuration for [`GotifySink`].
#[derive(Debug, Clone)]
pub struct GotifyConfig {
    /// Logical sink name (default `"gotify"`).
    pub name: String,
    /// Gotify server base URL (e.g. `https://gotify.example.com`).
    pub base_url: String,
    /// Gotify application token sent in the `X-Gotify-Key` header.
    pub app_token: Zeroizing<String>,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl GotifyConfig {
    /// Creates a Gotify configuration from server base URL and application token.
    #[must_use]
    pub fn new(base_url: impl Into<String>, app_token: impl Into<String>) -> Self {
        Self {
            name: "gotify".to_owned(),
            base_url: base_url.into(),
            app_token: Zeroizing::new(app_token.into()),
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

/// Delivers push notifications to a self-hosted Gotify server.
pub struct GotifySink {
    config: GotifyConfig,
    endpoint: String,
    client: reqwest::Client,
}

impl GotifySink {
    /// Validates `config` and constructs a new [`GotifySink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when `base_url` is invalid or `app_token` is empty.
    pub fn new(config: GotifyConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.base_url, "gotify base_url")?;
        if config.app_token.trim().is_empty() {
            return Err(AlertError::InvalidConfig(
                "gotify app_token must not be empty".to_owned(),
            ));
        }
        let endpoint = format!("{}/message", config.base_url.trim_end_matches('/'));
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self {
            config,
            endpoint,
            client,
        })
    }
}

#[async_trait]
impl AlertSink for GotifySink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let payload = json!({
            "title": format!("[{}] {}", event.severity.badge(), event.title),
            "message": event.format_plain_text(),
            "priority": event.severity.gotify_priority(),
            "extras": {
                "client::display": { "contentType": "text/plain" },
                "vaelspire::alert": {
                    "source": event.source,
                    "category": event.category,
                    "severity": event.severity.as_str(),
                    "occurred_at": event.occurred_at,
                }
            }
        });
        let resp = self
            .client
            .post(&self.endpoint)
            .header("x-gotify-key", self.config.app_token.as_str())
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
