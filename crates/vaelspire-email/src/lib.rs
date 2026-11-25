//! Vendor-neutral email delivery hook; SMTP is an explicit, optional feature.

use vaelspire_core::Purpose;
use zeroize::Zeroizing;

/// Application-rendered proof email. Contains the token exactly once.
/// Debug redacts the entire payload; drop clears the token buffer.
pub struct Message {
    /// Destination email address.
    pub recipient: String,
    /// Stable template name matching the proof purpose.
    pub template: &'static str,
    token: Zeroizing<String>,
}

impl Message {
    /// Token template field. Put it in the delivered message once, never in diagnostics.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Message([REDACTED])")
    }
}

/// Application-provided asynchronous sender. A function/closure returning a future
/// can be supplied directly. Delivery begins when polled. Errors must not echo the
/// payload. Cancellation or failure may occur after delivery; retries can duplicate mail.
#[async_trait::async_trait]
pub trait Sender: Send + Sync {
    /// Deliver the owned message without logging its token.
    ///
    /// # Errors
    /// Returns an opaque delivery failure. The proof is not invalidated.
    async fn send(&self, message: Message) -> Result<(), SendError>;
}

#[async_trait::async_trait]
impl<F, Fut> Sender for F
where
    F: Fn(Message) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<(), SendError>> + Send,
{
    async fn send(&self, message: Message) -> Result<(), SendError> {
        self(message).await
    }
}

/// Opaque delivery failure; contains no message content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendError;

/// Connection security for [`SmtpSender`].
#[cfg(feature = "smtp")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Connect without TLS. Use only on a trusted network.
    Plain,
    /// Upgrade the connection with STARTTLS before sending credentials or mail.
    StartTls,
}

/// Credentials supplied by the application, never logged by this crate.
#[cfg(feature = "smtp")]
pub struct SmtpCredentials {
    username: String,
    password: String,
}

#[cfg(feature = "smtp")]
impl std::fmt::Debug for SmtpCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SmtpCredentials([REDACTED])")
    }
}

#[cfg(feature = "smtp")]
impl SmtpCredentials {
    /// Construct credentials from caller-owned values.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// SMTP implementation of the existing delivery hook.
///
/// Host, port, sender address, security mode, and optional credentials are supplied by the caller.
/// STARTTLS is verified using the platform-independent web PKI roots provided by rustls.
#[cfg(feature = "smtp")]
pub struct SmtpSender {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

#[cfg(feature = "smtp")]
impl std::fmt::Debug for SmtpSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SmtpSender([REDACTED])")
    }
}

#[cfg(feature = "smtp")]
impl SmtpSender {
    /// Create an SMTP sender for a caller-supplied host and port.
    ///
    /// # Errors
    /// Returns [`SendError`] if the sender address or SMTP transport configuration is invalid.
    pub fn new(
        host: &str,
        port: u16,
        from: &str,
        security: SmtpSecurity,
        credentials: Option<SmtpCredentials>,
    ) -> Result<Self, SendError> {
        use lettre::transport::smtp::authentication::Credentials;
        let from = from.parse().map_err(|_| SendError)?;
        let mut builder = match security {
            SmtpSecurity::Plain => {
                lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(host)
            }
            SmtpSecurity::StartTls => {
                lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(host)
                    .map_err(|_| SendError)?
            }
        }
        .port(port);
        if let Some(credentials) = credentials {
            builder =
                builder.credentials(Credentials::new(credentials.username, credentials.password));
        }
        Ok(Self {
            transport: builder.build(),
            from,
        })
    }
}

#[cfg(feature = "smtp")]
#[async_trait::async_trait]
impl Sender for SmtpSender {
    async fn send(&self, message: Message) -> Result<(), SendError> {
        use lettre::{AsyncTransport, message::header::ContentType};
        let to = message.recipient.parse().map_err(|_| SendError)?;
        let email = lettre::Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(message.template)
            .header(ContentType::TEXT_PLAIN)
            .body(format!("Your proof token is: {}", message.token()))
            .map_err(|_| SendError)?;
        self.transport
            .send(email)
            .await
            .map(|_| ())
            .map_err(|_| SendError)
    }
}

/// Build and deliver a verification, reset, or OTP email from an issued proof.
/// The application chooses the recipient and renders the purpose-specific template.
/// No hash or other credential is included. The token appears in one field only.
///
/// # Errors
/// Returns the sender's opaque failure, which the workflow may retry with the same proof.
pub async fn send_proof(
    sender: &impl Sender,
    recipient: &str,
    purpose: Purpose,
    token: &str,
) -> Result<(), SendError> {
    sender
        .send(Message {
            recipient: recipient.to_owned(),
            template: purpose.as_str(),
            token: Zeroizing::new(token.to_owned()),
        })
        .await
}
