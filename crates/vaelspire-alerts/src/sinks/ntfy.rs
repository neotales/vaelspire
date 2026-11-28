//! ntfy push notification sink (`POST /{topic}` — works with `ntfy.sh` or self-hosted ntfy).

use async_trait::async_trait;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;
use crate::sinks::{build_http_client, check_http_response, validate_http_url};

/// Optional authentication mode for [`NtfySink`].
#[derive(Debug, Clone)]
pub enum NtfyAuth {
    /// Bearer access token (`Authorization: Bearer tk_...`).
    Bearer(Zeroizing<String>),
    /// HTTP Basic auth (`username`, `password`).
    Basic {
        /// Account username.
        username: String,
        /// Account password.
        password: Zeroizing<String>,
    },
}

/// Configuration for [`NtfySink`].
#[derive(Debug, Clone)]
pub struct NtfyConfig {
    /// Logical sink name (default `"ntfy"`).
    pub name: String,
    /// Full topic URL (e.g. `https://ntfy.example.com/vaelspire-alerts`).
    pub topic_url: String,
    /// Optional Bearer or Basic authentication.
    pub auth: Option<NtfyAuth>,
    /// HTTP timeout in seconds (default `10`).
    pub timeout_secs: u64,
}

impl NtfyConfig {
    /// Creates an ntfy sink config targeting `topic_url`.
    #[must_use]
    pub fn new(topic_url: impl Into<String>) -> Self {
        Self {
            name: "ntfy".to_owned(),
            topic_url: topic_url.into(),
            auth: None,
            timeout_secs: 10,
        }
    }

    /// Sets a custom logical name for this sink.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Configures Bearer token authentication.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.auth = Some(NtfyAuth::Bearer(Zeroizing::new(token.into())));
        self
    }

    /// Configures HTTP Basic authentication.
    #[must_use]
    pub fn with_basic_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.auth = Some(NtfyAuth::Basic {
            username: username.into(),
            password: Zeroizing::new(password.into()),
        });
        self
    }
}

/// Delivers push notifications to an `ntfy` topic endpoint.
pub struct NtfySink {
    config: NtfyConfig,
    client: reqwest::Client,
}

impl NtfySink {
    /// Validates `config` and constructs a new [`NtfySink`].
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when `topic_url` is invalid.
    pub fn new(config: NtfyConfig) -> Result<Self, AlertError> {
        let _ = validate_http_url(&config.topic_url, "ntfy topic_url")?;
        let client = build_http_client(config.timeout_secs)?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl AlertSink for NtfySink {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let mut req = self
            .client
            .post(&self.config.topic_url)
            .header(
                "title",
                format!("[{}] {}", event.severity.badge(), event.title),
            )
            .header("priority", event.severity.ntfy_priority())
            .header("tags", event.severity.ntfy_tags())
            .header("content-type", "text/plain; charset=utf-8");

        if let Some(auth) = &self.config.auth {
            let header_val = match auth {
                NtfyAuth::Bearer(tok) => format!("Bearer {}", tok.as_str()),
                NtfyAuth::Basic { username, password } => {
                    let raw = format!("{username}:{}", password.as_str());
                    let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                    format!("Basic {b64}")
                }
            };
            req = req.header("authorization", header_val);
        }

        let resp = req
            .body(event.format_plain_text())
            .send()
            .await
            .map_err(|source| AlertError::Http {
                sink: self.config.name.clone(),
                source,
            })?;
        check_http_response(&self.config.name, resp).await
    }
}
