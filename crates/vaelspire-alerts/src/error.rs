//! Error types for alert configuration and sink delivery.

use thiserror::Error;

/// Errors returned while constructing or delivering alerts.
#[derive(Debug, Error)]
pub enum AlertError {
    /// Sink configuration failed validation (for example, an invalid URL or missing recipient).
    #[error("invalid alert sink configuration: {0}")]
    InvalidConfig(String),

    /// Underlying HTTP transport error.
    #[cfg(feature = "http")]
    #[error("http delivery failed for sink '{sink}': {source}")]
    Http {
        /// Name of the sink that failed.
        sink: String,
        /// Underlying `reqwest` transport error.
        #[source]
        source: reqwest::Error,
    },

    /// Remote HTTP endpoint returned a non-2xx status code.
    #[error("sink '{sink}' rejected alert with HTTP {status}: {body}")]
    HttpStatus {
        /// Name of the sink that rejected the request.
        sink: String,
        /// HTTP status code returned by the remote server.
        status: u16,
        /// Truncated response body for troubleshooting (never includes sink credentials).
        body: String,
    },

    /// Email delivery failed.
    #[cfg(feature = "email")]
    #[error("email delivery failed for sink '{sink}': {message}")]
    Email {
        /// Name of the email sink.
        sink: String,
        /// Human-readable error summary.
        message: String,
    },

    /// Payload serialization failed.
    #[error("failed to serialize alert payload: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Custom error returned by user-provided [`crate::AlertSink`] implementations.
    #[error("{0}")]
    Custom(String),
}

impl AlertError {
    /// Returns `true` when retrying the delivery with backoff is likely to succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            #[cfg(feature = "http")]
            Self::Http { .. } => true,
            Self::HttpStatus { status, .. } => *status == 429 || *status >= 500,
            #[cfg(feature = "email")]
            Self::Email { .. } => true,
            Self::InvalidConfig(_) | Self::Serialization(_) | Self::Custom(_) => false,
        }
    }
}
