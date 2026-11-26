# Vaelspire Enterprise (`enterprise/`)

> **License Notice:** Everything under `enterprise/` is proprietary software governed by [`LICENSE-ENTERPRISE`](../LICENSE-ENTERPRISE), completely isolated in its own Cargo workspace from the MIT-licensed Open-Core crates in `crates/`.

## Philosophy: Zero SSO Tax

Core security — Argon2id passwords, TOTP/Passkey MFA, OIDC 1.0 IdP with Ed25519 JWKS, PKCE, Refresh Token Rotation, SCIM 2.0, Non-Human Identity (`client_credentials`), SAML metadata, RBAC, and `/forward-auth` — is **100% free and MIT-licensed forever**.

Vaelspire Enterprise implements the extension trait seams defined in `vaelspire-core::extensions` (`LicenseGate`, `AuditSink`, `TelemetrySink`, `RegionPolicy`, `ReplicationHook`) for large-scale compliance, global resiliency, and regulated enterprises.

## Workspace Crates

| Crate | Core Trait Implemented | Capability |
| --- | --- | --- |
| `vaelspire-license` | `LicenseGate` | Offline Ed25519 `.vlic` signed license issuance & verification. **Non-bricking guarantee:** expired or invalid licenses NEVER block user logins (`allows_login() == true` always). |
| `vaelspire-worm` | `AuditSink` | SHA-256 tamper-evident hash-chained audit records + cloud Object Lock archive framing (`S3ObjectLock`, `AzureImmutableBlob`, `GcsBucketLock`). |
| `vaelspire-telemetry` | `TelemetrySink` | Bounded, non-blocking SIEM & observability exporter with OpenTelemetry OTLP JSON, Splunk HEC NDJSON, and Datadog Logs batch formatters. |
| `vaelspire-georep` | `RegionPolicy`, `ReplicationHook` | Lock-free EU/US/APAC tenant data-residency pinning and ordered cross-region replication outbox envelopes. |

## Local Verification

```bash
cd enterprise
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
