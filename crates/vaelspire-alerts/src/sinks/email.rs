//! SMTP email alert sink powered by `lettre` (feature `email`).

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor};
use zeroize::Zeroizing;

use crate::error::AlertError;
use crate::event::AlertEvent;
use crate::sink::AlertSink;

/// SMTP TLS transport mode for [`EmailSink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpSecurity {
    /// Upgrade plaintext connection via `STARTTLS` (port 587).
    #[default]
    StartTls,
    /// Implicit TLS / SMTPS (port 465).
    ImplicitTls,
    /// Unencrypted SMTP (local development / Mailpit / internal relay only).
    Plain,
}

/// Configuration for [`EmailSink`].
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// Logical sink name (default `"email"`).
    pub name: String,
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (default `587`).
    pub smtp_port: u16,
    /// Transport encryption mode.
    pub security: SmtpSecurity,
    /// Optional SMTP username.
    pub username: Option<String>,
    /// Optional SMTP password.
    pub password: Option<Zeroizing<String>>,
    /// Sender mailbox (e.g. `alerts@example.com` or `Vaelspire Alerts <alerts@example.com>`).
    pub from: String,
    /// Recipient mailboxes.
    pub to: Vec<String>,
}

impl EmailConfig {
    /// Creates an SMTP email alert config using `STARTTLS` on port `587`.
    #[must_use]
    pub fn new(smtp_host: impl Into<String>, from: impl Into<String>, to: Vec<String>) -> Self {
        Self {
            name: "email".to_owned(),
            smtp_host: smtp_host.into(),
            smtp_port: 587,
            security: SmtpSecurity::StartTls,
            username: None,
            password: None,
            from: from.into(),
            to,
        }
    }
}

/// Delivers alerts over SMTP to one or more recipients.
pub struct EmailSink {
    name: String,
    from: Mailbox,
    to: Vec<Mailbox>,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailSink {
    /// Validates mailboxes and constructs an async SMTP transport.
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::InvalidConfig`] when addresses or SMTP host configuration are invalid.
    pub fn new(config: EmailConfig) -> Result<Self, AlertError> {
        if config.smtp_host.trim().is_empty() {
            return Err(AlertError::InvalidConfig(
                "email smtp_host must not be empty".to_owned(),
            ));
        }
        if config.to.is_empty() {
            return Err(AlertError::InvalidConfig(
                "email sink requires at least one recipient".to_owned(),
            ));
        }
        let from: Mailbox = config.from.parse().map_err(|err| {
            AlertError::InvalidConfig(format!("invalid email 'from' address: {err}"))
        })?;
        let mut to = Vec::with_capacity(config.to.len());
        for addr in &config.to {
            let mb: Mailbox = addr.parse().map_err(|err| {
                AlertError::InvalidConfig(format!("invalid email 'to' address '{addr}': {err}"))
            })?;
            to.push(mb);
        }

        let mut builder = match config.security {
            SmtpSecurity::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host).map_err(
                    |err| AlertError::InvalidConfig(format!("invalid smtp starttls host: {err}")),
                )?
            }
            SmtpSecurity::ImplicitTls => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host).map_err(|err| {
                    AlertError::InvalidConfig(format!("invalid smtp tls host: {err}"))
                })?
            }
            SmtpSecurity::Plain => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
            }
        }
        .port(config.smtp_port);

        if let (Some(user), Some(pass)) = (config.username, config.password) {
            builder = builder.credentials(Credentials::new(user, pass.as_str().to_owned()));
        }

        Ok(Self {
            name: config.name,
            from,
            to,
            transport: builder.build(),
        })
    }
}

#[async_trait]
impl AlertSink for EmailSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        let subject = format!(
            "[{}] {}: {}",
            event.severity.badge(),
            event.source,
            event.title
        );
        let body = event.format_plain_text();
        for recipient in &self.to {
            let msg = Message::builder()
                .from(self.from.clone())
                .to(recipient.clone())
                .subject(subject.clone())
                .body(body.clone())
                .map_err(|err| AlertError::Email {
                    sink: self.name.clone(),
                    message: format!("failed to build email: {err}"),
                })?;
            self.transport
                .send(msg)
                .await
                .map_err(|err| AlertError::Email {
                    sink: self.name.clone(),
                    message: err.to_string(),
                })?;
        }
        Ok(())
    }
}
