# Vaelspire

Open-core identity and authentication platform by **Neotales**.

**Security is free. Scale, compliance storage, and global operations are enterprise.**

## Editions

Vaelspire is designed around one ultra-lightweight core engine that scales cleanly
from a single binary to a globally distributed enterprise deployment:

| Area               | Vaelspire Core (MIT)                                                  | Vaelspire Enterprise (Commercial)                                                    |
| ------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **Security**       | 100% free: OIDC, OAuth 2.0, SAML, Passkeys/WebAuthn, MFA, RBAC/ABAC   | Everything in Core (no SSO tax)                                                      |
| **Footprint**      | Ultra-lightweight single binary, high throughput, 1 region            | Multi-node HA clusters, multi-region active-active geo-replication, residency pinning |
| **Audit Data**     | Short-term local audit logs                                           | Multi-year retention, cryptographic hash-chaining, auditor exports                   |
| **WORM Storage**   | —                                                                     | Immutable WORM backends (S3 Object Lock, Azure Immutable Blob, GCS Bucket Lock)      |
| **Telemetry**      | Prometheus `/metrics` and structured stdout logs                      | OpenTelemetry tracing, real-time SIEM streaming, anomaly telemetry                   |
| **Compliance**     | Standard audited crypto libraries and OIDC conformance testing        | FIPS 140-3 builds, third-party audit/pen-test packages, dedicated SLAs               |

## Licensing

Vaelspire uses an open-core licensing split:

- **Open-Core (`/` outside `enterprise/`):** Licensed under the [MIT License](LICENSE).
- **Enterprise (`enterprise/`):** Proprietary — governed by the [Vaelspire Enterprise License](LICENSE-ENTERPRISE).

## Status

Early architecture and repository bootstrap.
