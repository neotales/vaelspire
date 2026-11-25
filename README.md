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

## Workspace Crates (MIT Open-Core)

Vaelspire's base crates can be embedded directly into Rust applications (no separate auth server
required) or composed by the upcoming `vaelspire` single-binary CLI/server:

- `vaelspire-core` — Domain types, `AuthStore` trait, error codes, and core contracts
- `vaelspire-auth` — Password hashing (Argon2id + bcrypt upgrade), keyed BLAKE3 digests, sessions,
  TOTP MFA, Passkeys/WebAuthn, API keys, email sign-in, social/OIDC client
- `vaelspire-axum` — Axum 0.8 routers, CSRF/origin protection, `spawn_blocking` Argon2, social/OIDC
  and passkey handlers
- `vaelspire-email` — Email delivery hook and optional SMTP (`lettre`) transport
- `vaelspire-store-sqlite` — SQLite adapter over `neotales-dbapi` and `neotales-migration`
- `vaelspire-store-postgres` — PostgreSQL adapter over `neotales-dbapi` and `neotales-migration`

## Status

Base MIT crates (`vaelspire-*`) imported from `neotales-x-auth*` and passing full workspace
conformance tests on SQLite and compilation/clippy gates across SQLite and Postgres. Next up:
`vaelspire` single-binary CLI/server, OIDC Identity Provider (IdP), Forward-Auth, embedded
SvelteKit UI, and the Rune desktop app.
