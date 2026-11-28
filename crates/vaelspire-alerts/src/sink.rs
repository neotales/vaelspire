//! Core [`AlertSink`] trait and built-in local sinks (`LogSink`, `MemorySink`).

use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::AlertError;
use crate::event::{AlertEvent, Severity};

/// Destination capable of delivering an [`AlertEvent`].
#[async_trait]
pub trait AlertSink: Send + Sync {
    /// Human-readable sink identifier (e.g. `"slack"`, `"gotify-ops"`, `"webhook-pager"`).
    fn name(&self) -> &str;

    /// Delivers a single alert event to this sink.
    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError>;
}

/// Built-in sink that emits alerts via `tracing` without network I/O.
#[derive(Debug, Clone)]
pub struct LogSink {
    name: String,
}

impl Default for LogSink {
    fn default() -> Self {
        Self::new("log")
    }
}

impl LogSink {
    /// Creates a named tracing sink.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl AlertSink for LogSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        match event.severity {
            Severity::Info => tracing::info!(
                sink = %self.name,
                source = %event.source,
                category = %event.category,
                title = %event.title,
                summary = %event.summary,
                "alert emitted"
            ),
            Severity::Warn => tracing::warn!(
                sink = %self.name,
                source = %event.source,
                category = %event.category,
                title = %event.title,
                summary = %event.summary,
                "alert emitted"
            ),
            Severity::Critical => tracing::error!(
                sink = %self.name,
                source = %event.source,
                category = %event.category,
                title = %event.title,
                summary = %event.summary,
                "alert emitted"
            ),
        }
        Ok(())
    }
}

/// Thread-safe in-memory sink for testing alert pipelines without external services.
#[derive(Debug, Default)]
pub struct MemorySink {
    name: String,
    events: Mutex<Vec<AlertEvent>>,
}

impl MemorySink {
    /// Creates a new in-memory collector sink.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Returns a snapshot of all events delivered so far.
    #[must_use]
    pub fn events(&self) -> Vec<AlertEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clears all collected events.
    pub fn clear(&self) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

#[async_trait]
impl AlertSink for MemorySink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, event: &AlertEvent) -> Result<(), AlertError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
        Ok(())
    }
}
