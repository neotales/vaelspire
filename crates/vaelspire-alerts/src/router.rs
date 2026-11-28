//! Multi-sink alert router with filtering, deduplication, retries, and bounded async dispatch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::event::{AlertEvent, Severity};
use crate::sink::AlertSink;

/// Routing policy binding a single [`AlertSink`] to severity, category, and retry rules.
pub struct SinkRule {
    sink: Arc<dyn AlertSink>,
    min_severity: Severity,
    categories: Vec<String>,
    max_retries: u32,
    retry_base_delay: Duration,
}

impl SinkRule {
    /// Creates a rule accepting all severities and categories with 2 retries.
    #[must_use]
    pub fn new(sink: Arc<dyn AlertSink>) -> Self {
        Self {
            sink,
            min_severity: Severity::Info,
            categories: Vec::new(),
            max_retries: 2,
            retry_base_delay: Duration::from_millis(250),
        }
    }

    /// Sets the minimum [`Severity`] required for this sink to fire.
    #[must_use]
    pub const fn min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Restricts delivery to events whose `category` matches any prefix in `categories`.
    /// An empty list allows all categories.
    #[must_use]
    pub fn categories(mut self, categories: Vec<String>) -> Self {
        self.categories = categories;
        self
    }

    /// Configures maximum retry attempts for transient errors.
    #[must_use]
    pub const fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the initial exponential backoff delay before the first retry.
    #[must_use]
    pub const fn retry_base_delay(mut self, delay: Duration) -> Self {
        self.retry_base_delay = delay;
        self
    }

    /// Returns whether `event` matches this rule's severity and category filters.
    #[must_use]
    pub fn matches(&self, event: &AlertEvent) -> bool {
        if event.severity < self.min_severity {
            return false;
        }
        if self.categories.is_empty() {
            return true;
        }
        self.categories
            .iter()
            .any(|prefix| event.category == *prefix || event.category.starts_with(prefix))
    }

    /// Returns the underlying sink name.
    #[must_use]
    pub fn sink_name(&self) -> &str {
        self.sink.name()
    }
}

/// Outcome of delivering an event to a single sink.
#[derive(Debug, Clone)]
pub struct SinkOutcome {
    /// Name of the target sink.
    pub sink: String,
    /// `Ok(())` on successful delivery, or the final error message.
    pub result: Result<(), String>,
    /// Number of attempts executed (`1` = succeeded or failed on first try).
    pub attempts: u32,
}

/// Aggregate report returned by [`AlertRouter::dispatch`].
#[derive(Debug, Clone, Default)]
pub struct DispatchReport {
    /// `true` when the event was suppressed by the router's deduplication window.
    pub deduplicated: bool,
    /// Per-sink outcomes for all rules that matched the event.
    pub outcomes: Vec<SinkOutcome>,
}

impl DispatchReport {
    /// Number of sinks that successfully accepted the event.
    #[must_use]
    pub fn succeeded(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_ok()).count()
    }

    /// Number of sinks that failed after retries.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.outcomes.iter().filter(|o| o.result.is_err()).count()
    }
}

/// Routes [`AlertEvent`]s to zero or more configured sinks with burst deduplication.
pub struct AlertRouter {
    rules: Vec<SinkRule>,
    dedupe_window: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl Default for AlertRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertRouter {
    /// Creates an empty router with a default 60-second deduplication window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            dedupe_window: Duration::from_secs(60),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Sets the deduplication cooldown window. Pass [`Duration::ZERO`] to disable deduplication.
    #[must_use]
    pub const fn with_dedupe_window(mut self, window: Duration) -> Self {
        self.dedupe_window = window;
        self
    }

    /// Appends a [`SinkRule`] to the router.
    #[must_use]
    pub fn with_rule(mut self, rule: SinkRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Appends a [`SinkRule`] in place.
    pub fn add_rule(&mut self, rule: SinkRule) {
        self.rules.push(rule);
    }

    /// Returns the number of configured sink rules.
    #[must_use]
    pub fn sink_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns the configured sink names in registration order.
    #[must_use]
    pub fn sink_names(&self) -> Vec<&str> {
        self.rules.iter().map(SinkRule::sink_name).collect()
    }

    fn check_and_record_dedupe(&self, key: &str) -> bool {
        if self.dedupe_window.is_zero() {
            return false;
        }
        let now = Instant::now();
        let mut guard = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() > 2048 {
            guard.retain(|_, ts| now.duration_since(*ts) < self.dedupe_window);
        }
        if let Some(prev) = guard.get(key)
            && now.duration_since(*prev) < self.dedupe_window
        {
            return true;
        }
        guard.insert(key.to_owned(), now);
        false
    }

    /// Dispatches `event` concurrently to every matching sink rule.
    pub async fn dispatch(&self, event: &AlertEvent) -> DispatchReport {
        if let Some(key) = event.dedupe_key.as_deref()
            && self.check_and_record_dedupe(key)
        {
            return DispatchReport {
                deduplicated: true,
                outcomes: Vec::new(),
            };
        }

        let matching: Vec<&SinkRule> = self.rules.iter().filter(|r| r.matches(event)).collect();
        if matching.is_empty() {
            return DispatchReport::default();
        }

        let mut handles = Vec::with_capacity(matching.len());
        for rule in matching {
            let sink = Arc::clone(&rule.sink);
            let ev = event.clone();
            let max_retries = rule.max_retries;
            let base_delay = rule.retry_base_delay;
            handles.push(tokio::spawn(async move {
                deliver_with_retry(sink, ev, max_retries, base_delay).await
            }));
        }

        let mut outcomes = Vec::with_capacity(handles.len());
        for h in handles {
            match h.await {
                Ok(outcome) => outcomes.push(outcome),
                Err(err) => outcomes.push(SinkOutcome {
                    sink: "unknown".to_owned(),
                    result: Err(format!("alert task failed: {err}")),
                    attempts: 1,
                }),
            }
        }

        DispatchReport {
            deduplicated: false,
            outcomes,
        }
    }

    /// Spawns a bounded background dispatcher task so hot request paths can enqueue
    /// alerts without awaiting network I/O.
    #[must_use]
    pub fn spawn_dispatcher(self: Arc<Self>, capacity: usize) -> AlertHandle {
        let (tx, mut rx) = mpsc::channel::<AlertEvent>(capacity.max(1));
        let router = Arc::clone(&self);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let report = router.dispatch(&event).await;
                for outcome in report.outcomes {
                    if let Err(err) = outcome.result {
                        tracing::warn!(
                            sink = %outcome.sink,
                            attempts = outcome.attempts,
                            category = %event.category,
                            error = %err,
                            "alert delivery failed"
                        );
                    }
                }
            }
        });
        AlertHandle { tx, router: self }
    }
}

async fn deliver_with_retry(
    sink: Arc<dyn AlertSink>,
    event: AlertEvent,
    max_retries: u32,
    base_delay: Duration,
) -> SinkOutcome {
    let sink_name = sink.name().to_owned();
    let mut attempts = 0_u32;
    loop {
        attempts += 1;
        match sink.send(&event).await {
            Ok(()) => {
                return SinkOutcome {
                    sink: sink_name,
                    result: Ok(()),
                    attempts,
                };
            }
            Err(err) => {
                if !err.is_retryable() || attempts > max_retries {
                    return SinkOutcome {
                        sink: sink_name,
                        result: Err(err.to_string()),
                        attempts,
                    };
                }
                let factor = 1_u32.checked_shl(attempts.saturating_sub(1)).unwrap_or(16);
                let sleep_for = base_delay.saturating_mul(factor);
                tokio::time::sleep(sleep_for).await;
            }
        }
    }
}

/// Non-blocking cloneable handle to a background [`AlertRouter`] dispatcher.
#[derive(Clone)]
pub struct AlertHandle {
    tx: mpsc::Sender<AlertEvent>,
    router: Arc<AlertRouter>,
}

impl AlertHandle {
    /// Attempts to enqueue `event` without blocking. Returns `false` if the bounded
    /// queue is full or closed (drops gracefully instead of stalling callers).
    pub fn try_notify(&self, event: AlertEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("alert dispatcher queue full; dropping alert event");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Dispatches an event directly and awaits the full [`DispatchReport`]
    /// (useful for `alert test` CLI commands or health checks).
    pub async fn dispatch_now(&self, event: &AlertEvent) -> DispatchReport {
        self.router.dispatch(event).await
    }

    /// Number of configured sinks on the underlying router.
    #[must_use]
    pub fn sink_count(&self) -> usize {
        self.router.sink_count()
    }

    /// Names of configured sinks on the underlying router.
    #[must_use]
    pub fn sink_names(&self) -> Vec<&str> {
        self.router.sink_names()
    }
}
