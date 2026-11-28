//! Generic HTTP JSON webhook sink with optional HMAC-SHA256 payload signing.

use std::collections::BTreeMap;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

type HmacSha256 = Hmac<Sha256>;

/// Configuration for [`WebhookSink`].
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Logical sink name (default `"webhook"`).
    pub name: String,
    /// Target HTTP(S) webhook URL.
    pub url: String,
    /// Optional shared HMAC-SHA256 signing secret sent as `X-Signature-256: sha256=<hex>`.
    pub signing_secret: Option<Zeroizing<String>>,
    /// Optional extra HTTP headers (e.g. `Authorization: Bearer ...`).
    pub headers: BTreeMap<String, String>,
    /// HTTP request timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl WebhookConfig {
    /// Creates a webhook config targeting `url`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            name: "webhook".to_owned(),
            url: url.into(),
            signing_secret: None,
            headers: BTreeMap::new(),
            timeout_secs: 10,
        }
    }

    /// Sets a custom logical name for this sink.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Configures an HMAC-SHA256 signing secret (`X-Signature-256: sha256=<hex>`).
    #[must_use]
    pub fn with_signing_secret(mut self, secret: impl Into<String>) -> Self {
        self.signing_secret = Some(Zeroizing::new(secret.into()));
        self
    }

    /// Adds a custom HTTP header sent on every webhook delivery.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

/// Computes `sha256=<lowercase-hex>` HMAC signature for raw webhook bytes.
///
/// # Errors
///
/// Returns [`AlertError::InvalidConfig`] if `secret` is empty.
pub fn sign_hmac_sha256(secret: &[u8], body: &[u8]) -> Result<String, AlertError> {
    if secret.is_empty() {
        return Err(AlertError::InvalidConfig(
            "webhook signing secret must not be empty".to_owned(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| AlertError::InvalidConfig("invalid hmac key".to_owned()))?;
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    Ok(format!("sha256={}", hex::encode(digest)))
}

/// Verifies a `sha256=<hex>` HMAC signature in constant time.
#[must_use]
pub fn verify_hmac_sha256(secret: &[u8], body: &[u8], signature_header: &str) -> bool {
    let Some(hex_sig) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Delivers raw [`AlertEvent`] JSON payloads to an HTTP(S) webhook endpoint.
pub struct WebhookSink {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookSink {
    /// Validates `config` and constructs a new [`WebhookSink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when the URL or client setup is invalid.
    pub fn new(config: WebhookConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.url, "webhook url")?;
        if let Some(secret) = &config.signing_secret
            && secret.is_empty()
        {
            return Err(AlertError::InvalidConfig(
                "webhook signing_secret must not be empty when set".to_owned(),
            ));
        }
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl AlertSink for WebhookSink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let body = serde_json::to_vec(event)?;
        let mut req = self
            .client
            .post(&self.config.url)
            .header("content-type", "application/json");
        if let Some(secret) = &self.config.signing_secret {
            let sig = sign_hmac_sha256(secret.as_bytes(), &body)?;
            req = req.header("x-signature-256", sig);
        }
        for (k, v) in &self.config.headers {
            req = req.header(k, v);
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|source| AlertError::Http {
                sink: self.config.name.clone(),
                source,
            })?;
        check_http_response(&self.config.name, resp).await
    }
}
