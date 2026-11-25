# Vaelspire Enterprise

This directory contains proprietary commercial and enterprise modules for
**Vaelspire**, governed by the [Vaelspire Enterprise License](../LICENSE-ENTERPRISE).

## Enterprise Scope

Core security capabilities always belong in the MIT-licensed Open-Core engine.
Modules in `enterprise/` focus on global scale, regulated storage, governance,
and compliance:

- Multi-region active-active geo-replication and regional data-residency pinning
- WORM (Write-Once-Read-Many) immutable audit storage (S3 Object Lock, Azure
  Immutable Blob, GCS Bucket Lock)
- Extended multi-year audit log retention, hash-chaining, and auditor exports
- Enterprise telemetry pipelines and real-time SIEM streaming (OpenTelemetry,
  Splunk, Datadog, Sentinel, CrowdStrike, Kafka)
- Offline-verifiable license key management (seats, regions, feature flags)
- FIPS 140-3 validated builds and enterprise compliance packaging
