# 🔔 `vaelspire-alerts`

Reusable, multi-sink alerting router in pure Rust (MIT-licensed, zero `unsafe`).

> **Note on future extraction:** `vaelspire-alerts` intentionally has **zero Vaelspire-specific dependencies** so it can be extracted cleanly into a standalone generic **`neotales-alerts`** crate shared across Vaelspire, Vaelsgard, and other Neotales services.

## Supported Sinks

All external sinks are feature-gated so binaries only compile what they enable:

| Feature | Sink | Delivery Protocol |
|---|---|---|
| `webhook` | `WebhookSink` | JSON `POST` + optional HMAC-SHA256 (`X-Signature-256`) + custom headers |
| `slack` | `SlackSink` | Slack Incoming Webhook (Block Kit payload) |
| `discord` | `DiscordSink` | Discord Webhook (severity-colored Embeds) |
| `teams` | `TeamsSink` | Microsoft Teams Workflows (Adaptive Card 1.4 JSON) |
| `gotify` | `GotifySink` | Gotify `POST /message` with `X-Gotify-Key` and priority mapping |
| `ntfy` | `NtfySink` | Self-hosted / `ntfy.sh` `POST /{topic}` with priority, tags, and auth |
| `sms` | `TwilioSmsSink` / `GenericSmsSink` | Twilio REST Messages API + generic HTTP SMS gateway hook |
| `email` | `EmailSink` | SMTP delivery via `lettre` (`STARTTLS`, `SMTPS`, or local relay) |
| *(always)* | `LogSink` / `MemorySink` | Structured `tracing` output and in-memory test collector |

## Quick Example

```rust
use std::sync::Arc;
use std::time::Duration;
use vaelspire_alerts::{AlertEvent, AlertRouter, Severity, SinkRule};
use vaelspire_alerts::sinks::gotify::{GotifyConfig, GotifySink};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let gotify = GotifySink::new(GotifyConfig::new(
    "https://gotify.example.com",
    "app-token-here",
))?;

let router = Arc::new(
    AlertRouter::new()
        .with_dedupe_window(Duration::from_secs(60))
        .with_rule(SinkRule::new(Arc::new(gotify)).min_severity(Severity::Warn)),
);

// Non-blocking bounded background dispatcher (never slows down HTTP requests)
let handle = router.spawn_dispatcher(256);

handle.try_notify(
    AlertEvent::new(
        Severity::Critical,
        "security.anomaly",
        "Password spray detected",
        "Multiple failed logins from 203.0.113.0/24",
    )
    .with_source("vaelspire")
    .with_field("email", "wf******@acme.com")
    .with_dedupe_key("spray:203.0.113.0/24"),
);
# Ok(())
# }
```
