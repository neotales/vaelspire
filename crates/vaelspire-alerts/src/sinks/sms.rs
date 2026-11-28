//! SMS alert sinks (Twilio REST API and generic HTTP SMS gateway).

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

/// Configuration for [`TwilioSmsSink`].
#[derive(Debug, Clone)]
pub struct TwilioSmsConfig {
    /// Logical sink name (default `"twilio-sms"`).
    pub name: String,
    /// Twilio Account SID (`AC...`).
    pub account_sid: String,
    /// Twilio Auth Token (or API Key Secret).
    pub auth_token: Zeroizing<String>,
    /// Sender phone number in E.164 format (e.g. `+15550001111`).
    pub from: String,
    /// Recipient phone numbers in E.164 format.
    pub to: Vec<String>,
    /// Optional base URL override (defaults to `https://api.twilio.com`; handy for local tests).
    pub api_base_url: String,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl TwilioSmsConfig {
    /// Creates a Twilio SMS configuration targeting `api.twilio.com`.
    #[must_use]
    pub fn new(
        account_sid: impl Into<String>,
        auth_token: impl Into<String>,
        from: impl Into<String>,
        to: Vec<String>,
    ) -> Self {
        Self {
            name: "twilio-sms".to_owned(),
            account_sid: account_sid.into(),
            auth_token: Zeroizing::new(auth_token.into()),
            from: from.into(),
            to,
            api_base_url: "https://api.twilio.com".to_owned(),
            timeout_secs: 10,
        }
    }

    /// Overrides the Twilio API base URL (useful for testing or private proxies).
    #[must_use]
    pub fn with_api_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.api_base_url = base_url.into();
        self
    }

    /// Sets a custom logical name for this sink.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

/// Sends SMS alerts via the Twilio REST Messages API.
pub struct TwilioSmsSink {
    config: TwilioSmsConfig,
    endpoint: String,
    auth_header: Zeroizing<String>,
    client: reqwest::Client,
}

impl TwilioSmsSink {
    /// Validates `config` and constructs a new [`TwilioSmsSink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when required credentials, URL, or recipients are missing.
    pub fn new(config: TwilioSmsConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.api_base_url, "twilio api_base_url")?;
        if config.account_sid.trim().is_empty() || config.auth_token.trim().is_empty() {
            return Err(AlertError::InvalidConfig(
                "twilio account_sid and auth_token are required".to_owned(),
            ));
        }
        if config.from.trim().is_empty() || config.to.is_empty() {
            return Err(AlertError::InvalidConfig(
                "twilio requires a non-empty 'from' number and at least one 'to' recipient"
                    .to_owned(),
            ));
        }
        let endpoint = format!(
            "{}/2010-04-01/Accounts/{}/Messages.json",
            config.api_base_url.trim_end_matches('/'),
            config.account_sid.trim()
        );
        let raw_creds = format!(
            "{}:{}",
            config.account_sid.trim(),
            config.auth_token.as_str()
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_creds.as_bytes());
        let auth_header = Zeroizing::new(format!("Basic {encoded}"));
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self {
            config,
            endpoint,
            auth_header,
            client,
        })
    }
}

fn form_encode_pairs(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        serializer.append_pair(k, v);
    }
    serializer.finish()
}

#[async_trait]
impl AlertSink for TwilioSmsSink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let body_text = event.format_sms_text();
        for recipient in &self.config.to {
            let form_body = form_encode_pairs(&[
                ("To", recipient.as_str()),
                ("From", self.config.from.as_str()),
                ("Body", body_text.as_str()),
            ]);
            let resp = self
                .client
                .post(&self.endpoint)
                .header("authorization", self.auth_header.as_str())
                .header("content-type", "application/x-www-form-urlencoded")
                .body(form_body)
                .send()
                .await
                .map_err(|source| AlertError::Http {
                    sink: self.config.name.clone(),
                    source,
                })?;
            check_http_response(&self.config.name, resp).await?;
        }
        Ok(())
    }
}

/// Configuration for [`GenericSmsSink`] (works with Telnyx, Vonage, Plivo, or custom SMS bridges).
#[derive(Debug, Clone)]
pub struct GenericSmsConfig {
    /// Logical sink name (default `"sms"`).
    pub name: String,
    /// HTTP(S) endpoint accepting JSON `{ "from", "to", "message", "severity", "source" }`.
    pub endpoint_url: String,
    /// Optional Bearer token sent in `Authorization: Bearer <token>`.
    pub bearer_token: Option<Zeroizing<String>>,
    /// Sender ID or E.164 phone number.
    pub from: String,
    /// Recipient phone numbers.
    pub to: Vec<String>,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl GenericSmsConfig {
    /// Creates a generic HTTP SMS gateway configuration.
    #[must_use]
    pub fn new(endpoint_url: impl Into<String>, from: impl Into<String>, to: Vec<String>) -> Self {
        Self {
            name: "sms".to_owned(),
            endpoint_url: endpoint_url.into(),
            bearer_token: None,
            from: from.into(),
            to,
            timeout_secs: 10,
        }
    }

    /// Sets an optional Bearer API token.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(Zeroizing::new(token.into()));
        self
    }
}

/// Sends compact SMS alerts via a generic JSON HTTP SMS gateway.
pub struct GenericSmsSink {
    config: GenericSmsConfig,
    client: reqwest::Client,
}

impl GenericSmsSink {
    /// Validates `config` and constructs a new [`GenericSmsSink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when the URL or recipient list is invalid.
    pub fn new(config: GenericSmsConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.endpoint_url, "sms endpoint_url")?;
        if config.to.is_empty() {
            return Err(AlertError::InvalidConfig(
                "generic sms sink requires at least one recipient".to_owned(),
            ));
        }
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl AlertSink for GenericSmsSink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let payload = json!({
            "from": self.config.from,
            "to": self.config.to,
            "message": event.format_sms_text(),
            "severity": event.severity.as_str(),
            "source": event.source,
            "category": event.category,
        });
        let mut req = self.client.post(&self.config.endpoint_url).json(&payload);
        if let Some(tok) = &self.config.bearer_token {
            req = req.header("authorization", format!("Bearer {}", tok.as_str()));
        }
        let resp = req.send().await.map_err(|source| AlertError::Http {
            sink: self.config.name.clone(),
            source,
        })?;
        check_http_response(&self.config.name, resp).await
    }
}
