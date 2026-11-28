//! Built-in alert sink implementations (feature-gated by transport/provider).

#[cfg(feature = "discord")]
pub mod discord;
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "gotify")]
pub mod gotify;
#[cfg(feature = "ntfy")]
pub mod ntfy;
#[cfg(feature = "slack")]
pub mod slack;
#[cfg(feature = "sms")]
pub mod sms;
#[cfg(feature = "teams")]
pub mod teams;
#[cfg(feature = "webhook")]
pub mod webhook;

#[cfg(feature = "http")]
pub(crate) fn build_http_client(timeout_secs: u64) -> Result<reqwest::Client, crate::AlertError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .user_agent("vaelspire-alerts/0.0.0-alpha.0")
        .build()
        .map_err(|err| {
            crate::AlertError::InvalidConfig(format!("failed to build http client: {err}"))
        })
}

#[cfg(feature = "http")]
pub(crate) fn validate_http_url(raw: &str, field: &str) -> Result<url::Url, crate::AlertError> {
    let parsed = url::Url::parse(raw.trim()).map_err(|err| {
        crate::AlertError::InvalidConfig(format!("{field} is not a valid URL: {err}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(crate::AlertError::InvalidConfig(format!(
            "{field} must use http or https scheme, got '{other}'"
        ))),
    }
}

#[cfg(feature = "http")]
pub(crate) async fn check_http_response(
    sink_name: &str,
    resp: reqwest::Response,
) -> Result<(), crate::AlertError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    let truncated = if body.len() > 256 {
        format!("{}...", &body[..256])
    } else {
        body
    };
    Err(crate::AlertError::HttpStatus {
        sink: sink_name.to_owned(),
        status: status.as_u16(),
        body: truncated,
    })
}
