//! Copyright (c) Neotales. Proprietary — governed by `LICENSE-ENTERPRISE`.
//!
//! Bounded, non-blocking [`TelemetrySink`] with OpenTelemetry (OTLP JSON),
//! Splunk HEC NDJSON, and Datadog Logs batch formatters for SIEM ingestion.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use vaelspire_core::extensions::{TelemetrySignal, TelemetrySink};

/// SIEM / observability export target format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// OpenTelemetry OTLP/HTTP JSON log record batch.
    OtlpJson,
    /// Splunk HTTP Event Collector (HEC) newline-delimited JSON.
    SplunkHecNdjson,
    /// Datadog HTTP Logs Intake JSON array.
    DatadogLogsJson,
}

/// Snapshot of queue & drop telemetry metrics for operational alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryStats {
    /// Signals accepted into the bounded export buffer.
    pub accepted: u64,
    /// Signals dropped because the bounded buffer reached capacity (backpressure).
    pub dropped: u64,
    /// Signals currently buffered awaiting flush.
    pub buffered: usize,
}

/// Bounded in-memory [`TelemetrySink`] that formats SIEM/OTLP batches cleanly
/// without ever blocking or failing authentication paths.
#[derive(Debug)]
pub struct SiemTelemetrySink {
    service_name: String,
    capacity: usize,
    queue: Mutex<VecDeque<TelemetrySignal>>,
    accepted: AtomicU64,
    dropped: AtomicU64,
}

impl SiemTelemetrySink {
    /// Create a bounded SIEM sink holding at most `capacity` buffered signals.
    #[must_use]
    pub fn new(service_name: impl Into<String>, capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            service_name: service_name.into(),
            capacity: cap,
            queue: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Return current buffer & drop counters.
    ///
    /// # Panics
    /// Never panics unless the internal mutex was poisoned.
    #[must_use]
    pub fn stats(&self) -> TelemetryStats {
        let buffered = self.queue.lock().expect("telemetry mutex poisoned").len();
        TelemetryStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            buffered,
        }
    }

    /// Drain up to `max_batch` buffered signals and format them for `format`.
    ///
    /// # Panics
    /// Never panics unless the internal mutex was poisoned.
    #[must_use]
    pub fn drain_formatted(&self, max_batch: usize, format: ExportFormat) -> String {
        let batch = self.drain_batch(max_batch);
        match format {
            ExportFormat::OtlpJson => format_otlp_json(&self.service_name, &batch),
            ExportFormat::SplunkHecNdjson => format_splunk_hec(&self.service_name, &batch),
            ExportFormat::DatadogLogsJson => format_datadog_logs(&self.service_name, &batch),
        }
    }

    fn drain_batch(&self, max_batch: usize) -> Vec<TelemetrySignal> {
        let mut guard = self.queue.lock().expect("telemetry mutex poisoned");
        let n = max_batch.min(guard.len());
        guard.drain(..n).collect()
    }
}

impl TelemetrySink for SiemTelemetrySink {
    fn record(&self, signal: TelemetrySignal) {
        if let Ok(mut guard) = self.queue.lock() {
            if guard.len() >= self.capacity {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            guard.push_back(signal);
            self.accepted.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn format_otlp_json(service_name: &str, signals: &[TelemetrySignal]) -> String {
    let records: Vec<Value> = signals
        .iter()
        .map(|s| {
            let mut attrs: Vec<Value> = vec![
                json!({ "key": "vaelspire.outcome", "value": { "stringValue": s.outcome } }),
                json!({ "key": "vaelspire.region", "value": { "stringValue": s.region } }),
                json!({ "key": "vaelspire.latency_us", "value": { "intValue": s.latency_us.to_string() } }),
            ];
            if let Some(tid) = s.tenant_id {
                attrs.push(json!({ "key": "vaelspire.tenant_id", "value": { "stringValue": tid.to_string() } }));
            }
            for (k, v) in &s.attributes {
                attrs.push(json!({ "key": k, "value": { "stringValue": v } }));
            }
            json!({
                "severityText": if s.outcome == "ok" { "INFO" } else { "WARN" },
                "body": { "stringValue": s.name },
                "attributes": attrs,
            })
        })
        .collect();

    let payload = json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [{
                    "key": "service.name",
                    "value": { "stringValue": service_name }
                }]
            },
            "scopeLogs": [{
                "scope": { "name": "vaelspire.enterprise.telemetry" },
                "logRecords": records
            }]
        }]
    });
    payload.to_string()
}

fn format_splunk_hec(service_name: &str, signals: &[TelemetrySignal]) -> String {
    let mut out = String::new();
    for s in signals {
        let attrs: serde_json::Map<String, Value> = s
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let line = json!({
            "sourcetype": "vaelspire:auth",
            "source": service_name,
            "event": {
                "name": s.name,
                "outcome": s.outcome,
                "region": s.region,
                "latency_us": s.latency_us,
                "tenant_id": s.tenant_id.map(|id| id.to_string()),
                "attributes": attrs,
            }
        });
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

fn format_datadog_logs(service_name: &str, signals: &[TelemetrySignal]) -> String {
    let records: Vec<Value> = signals
        .iter()
        .map(|s| {
            let mut obj = serde_json::Map::new();
            obj.insert("ddsource".into(), Value::String("vaelspire".into()));
            obj.insert("service".into(), Value::String(service_name.into()));
            obj.insert("status".into(), Value::String(s.outcome.clone()));
            obj.insert("message".into(), Value::String(s.name.clone()));
            obj.insert("region".into(), Value::String(s.region.clone()));
            obj.insert(
                "latency_us".into(),
                Value::Number(serde_json::Number::from(s.latency_us)),
            );
            if let Some(tid) = s.tenant_id {
                obj.insert("tenant_id".into(), Value::String(tid.to_string()));
            }
            for (k, v) in &s.attributes {
                obj.insert(k.clone(), Value::String(v.clone()));
            }
            Value::Object(obj)
        })
        .collect();
    Value::Array(records).to_string()
}

#[cfg(test)]
mod tests {
    use vaelspire_core::Id;

    use super::*;

    fn signal(name: &str) -> TelemetrySignal {
        TelemetrySignal {
            name: name.into(),
            outcome: "ok".into(),
            tenant_id: Some(Id::now_v7()),
            region: "eu-central-1".into(),
            latency_us: 420,
            attributes: vec![("client".into(), "vaelsgard".into())],
        }
    }

    #[test]
    fn siem_sink_formats_otlp_splunk_datadog_and_enforces_backpressure() {
        let sink = SiemTelemetrySink::new("vaelspire-prod", 2);
        sink.record(signal("vaelspire.auth.sign_in"));
        sink.record(signal("vaelspire.oidc.token.issued"));
        sink.record(signal("vaelspire.overflow.dropped"));

        let stats = sink.stats();
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.buffered, 2);

        let otlp = sink.drain_formatted(1, ExportFormat::OtlpJson);
        let parsed: Value = serde_json::from_str(&otlp).expect("valid otlp json");
        assert_eq!(
            parsed["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"],
            "vaelspire.auth.sign_in"
        );

        let splunk = sink.drain_formatted(1, ExportFormat::SplunkHecNdjson);
        let line: Value = serde_json::from_str(splunk.trim()).expect("valid splunk json");
        assert_eq!(line["sourcetype"], "vaelspire:auth");
        assert_eq!(line["event"]["name"], "vaelspire.oidc.token.issued");

        sink.record(signal("vaelspire.scim.user.created"));
        let dd = sink.drain_formatted(1, ExportFormat::DatadogLogsJson);
        let arr: Value = serde_json::from_str(&dd).expect("valid datadog json");
        assert_eq!(arr[0]["service"], "vaelspire-prod");
        assert_eq!(arr[0]["message"], "vaelspire.scim.user.created");
    }
}
