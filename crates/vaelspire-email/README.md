# ✉️ `vaelspire-email`

Vendor-neutral email delivery hook for **Vaelspire** one-time proof tokens (`VerifyEmail`, `ResetPassword`, `EmailOtp`).

- 🔒 `Message` wraps its token in `Zeroizing<String>` and redacts `Debug` output completely (`Message([REDACTED])`).
- 🧩 Implement [`Sender`](src/lib.rs) directly — or pass any `async` closure.
- 📬 Opt into `feature = "smtp"` for a ready-to-use `SmtpSender` built on `lettre` + `rustls` (STARTTLS or local plaintext for dev/Mailpit).

## 🧪 Example

```rust
use vaelspire_email::{Message, SendError, Sender};

async fn send_with_closure() {
    let sender = |msg: Message| async move {
        // Hand `msg.recipient`, `msg.template`, and `msg.token()` to your mail provider.
        // Never log `msg.token()`.
        let _ = (msg.recipient.as_str(), msg.template, msg.token());
        Ok::<(), SendError>(())
    };
    let _ = &sender as &dyn Sender;
}
```

With SMTP (`features = ["smtp"]`):

```rust
#[cfg(feature = "smtp")]
fn smtp_example() -> Result<vaelspire_email::SmtpSender, vaelspire_email::SendError> {
    use vaelspire_email::{SmtpCredentials, SmtpSecurity, SmtpSender};

    SmtpSender::new(
        "smtp.example.com",
        587,
        "Vaelspire <no-reply@example.com>",
        SmtpSecurity::StartTls,
        Some(SmtpCredentials::new("smtp-user", "smtp-pass")),
    )
}
```
