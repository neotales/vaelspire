//! Hook contract and real Mailpit delivery; the latter requires Docker.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use testcontainers::{
    GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tracing::instrument::WithSubscriber;
use vaelspire_core::Purpose;
use vaelspire_email::{Message, SendError, send_proof};

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn captured_delivery(sender: &impl vaelspire_email::Sender, token: &str) {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    async {
        tracing::info!("capture active");
        send_proof(sender, "user@example.test", Purpose::VerifyEmail, token)
            .await
            .expect("delivery");
    }
    .with_subscriber(subscriber)
    .await;
    let captured =
        String::from_utf8(logs.0.lock().expect("capture lock").clone()).expect("UTF-8 logs");
    assert!(
        captured.contains("capture active"),
        "capture must not pass vacuously"
    );
    assert!(
        !captured.contains(token),
        "proof must never appear in captured logs"
    );
}

#[tokio::test]
async fn hook_redacts_payload_and_preserves_delivery_errors() {
    let token = "synthetic-test-proof";
    let messages = Arc::new(Mutex::new(Vec::new()));
    let inbox = messages.clone();
    let sender = move |message: Message| {
        assert!(!format!("{message:?}").contains(message.token()));
        inbox.lock().expect("inbox lock").push(message);
        std::future::ready(Ok(()))
    };
    captured_delivery(&sender, token).await;
    {
        let received = messages.lock().expect("inbox lock");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].token(), token);
        assert_eq!(received[0].recipient, "user@example.test");
        assert_eq!(received[0].template, "verify_email");
    }
    let rejected = |_: Message| std::future::ready(Err(SendError));
    assert_eq!(
        send_proof(
            &rejected,
            "user@example.test",
            Purpose::ResetPassword,
            token
        )
        .await,
        Err(SendError)
    );
}

#[tokio::test]
async fn mailpit_receives_message_without_library_token_logging() {
    let container = GenericImage::new("axllent/mailpit", "v1.21.0")
        .with_wait_for(WaitFor::message_on_either_std("accessible"))
        .with_exposed_port(8025.tcp())
        .start()
        .await
        .expect("Mailpit container");
    let port = container
        .get_host_port_ipv4(8025.tcp())
        .await
        .expect("mapped port");
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let endpoint = format!("{base}/api/v1/send");
    let send_client = client.clone();
    let sender = move |message: Message| {
        let client = send_client.clone();
        let endpoint = endpoint.clone();
        async move {
            client
                .post(endpoint)
                .json(&serde_json::json!({
                    "From": {"Email": "auth@example.test"},
                    "To": [{"Email": message.recipient}],
                    "Subject": message.template,
                    "Text": format!("Verify using {}", message.token())
                }))
                .send()
                .await
                .map_err(|_| SendError)?
                .error_for_status()
                .map_err(|_| SendError)?;
            Ok(())
        }
    };
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).expect("random test proof");
    let mut token = String::new();
    for byte in random {
        use std::fmt::Write as _;
        write!(token, "{byte:02x}").expect("format test proof");
    }
    captured_delivery(&sender, &token).await;
    let inbox: serde_json::Value = client
        .get(format!("{base}/api/v1/messages"))
        .send()
        .await
        .expect("inbox")
        .error_for_status()
        .expect("inbox status")
        .json()
        .await
        .expect("inbox JSON");
    assert_eq!(inbox["messages"].as_array().expect("messages").len(), 1);
    let message: serde_json::Value = client
        .get(format!("{base}/api/v1/message/latest"))
        .send()
        .await
        .expect("received message")
        .error_for_status()
        .expect("message status")
        .json()
        .await
        .expect("message JSON");
    assert_eq!(message["Subject"], "verify_email");
    let text = message["Text"].as_str().expect("received body");
    assert_eq!(
        text.matches(&token).count(),
        1,
        "proof delivered exactly once"
    );
    assert_eq!(message["To"][0]["Address"], "user@example.test");
}

#[cfg(feature = "smtp")]
#[tokio::test]
async fn smtp_sender_delivers_to_mailpit_without_logging_token() {
    use vaelspire_email::{SmtpSecurity, SmtpSender};

    let container = GenericImage::new("axllent/mailpit", "v1.21.0")
        .with_wait_for(WaitFor::message_on_either_std("accessible"))
        .with_exposed_port(8025.tcp())
        .with_exposed_port(1025.tcp())
        .start()
        .await
        .expect("Mailpit container");
    let api_port = container
        .get_host_port_ipv4(8025.tcp())
        .await
        .expect("API port");
    let smtp_port = container
        .get_host_port_ipv4(1025.tcp())
        .await
        .expect("SMTP port");
    let sender = SmtpSender::new(
        "127.0.0.1",
        smtp_port,
        "auth@example.test",
        SmtpSecurity::Plain,
        None,
    )
    .expect("SMTP sender");
    let token = "smtp-integration-proof-not-for-logs";
    captured_delivery(&sender, token).await;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{api_port}");
    let inbox: serde_json::Value = client
        .get(format!("{base}/api/v1/messages"))
        .send()
        .await
        .expect("inbox")
        .error_for_status()
        .expect("inbox status")
        .json()
        .await
        .expect("inbox JSON");
    assert_eq!(inbox["messages"].as_array().expect("messages").len(), 1);
    let message: serde_json::Value = client
        .get(format!("{base}/api/v1/message/latest"))
        .send()
        .await
        .expect("message")
        .error_for_status()
        .expect("message status")
        .json()
        .await
        .expect("message JSON");
    assert_eq!(message["Subject"], "verify_email");
    assert_eq!(
        message["Text"]
            .as_str()
            .expect("body")
            .matches(token)
            .count(),
        1
    );
    assert_eq!(message["To"][0]["Address"], "user@example.test");
}
