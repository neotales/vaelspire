# 🗺️ Vaelspire Roadmap

Vaelspire ships in tight, verifiable milestones — dogfooding **Vaelsgard** and Neotales apps first, keeping all core security **100% free and MIT-licensed**, and building Enterprise scale & regulated compliance cleanly on top.

> 📚 Full documentation & marketing site: [**`neotales/vaelspire-site`**](https://github.com/neotales/vaelspire-site)
> 🚨 Release rule: Documentation in `neotales/vaelspire-site` must be updated and verified **before** every release tag. See [RELEASING.md](RELEASING.md).

---

## ✅ M1 — Embeddable Rust Crates *(Complete)*
- 6 MIT Open-Core crates over `neotales-dbapi` + `neotales-migration`:
  `vaelspire-core`, `vaelspire-auth`, `vaelspire-axum`, `vaelspire-email`, `vaelspire-store-sqlite`, `vaelspire-store-postgres`
- Argon2id + bcrypt auto-upgrade, keyed BLAKE3 digests, `Zeroizing` secret hygiene, TOTP MFA (AES-256-GCM), Passkeys/WebAuthn, API keys, email sign-in, social/OIDC client, RBAC, transactional append-only audit rows, shared `conformance.rs` suite

## ✅ M2 — Single-Binary CLI/Server, Setup Tooling & Docs Site *(Complete)*
- `crates/vaelspire` single-binary `clap` CLI (`serve`, `migrate`, `keygen`, `admin bootstrap`) + Axum HTTP server
- `/forward-auth` (session cookies + API keys + `X-Vaelspire-*` headers), Prometheus `/metrics`, `/health`, `/ready`, `/.well-known/vaelspire`
- One-command setup scripts (`scripts/dev-setup.sh`, `scripts/quickstart.sh`, `scripts/smoke-test.sh`, `scripts/demo.sh`), Docker/Compose, Caddy / Traefik / Nginx configs
- Dedicated Astro Starlight marketing & docs repo (`neotales/vaelspire-site`) with human guides, comparisons, crate reference, Roadmap, Enterprise architecture, and dense AI agent pages (`/agents/`, `/llms.txt`, `/llms-full.txt`)

## ✅ M3 — OIDC 1.0 Identity Provider, Stateless Verifier & Embedded Core UI *(Core Shipped)*
- `vaelspire-oidc` OIDC 1.0 / OAuth 2.0 Identity Provider (Discovery, rotating Ed25519 JWKS with RFC 7638 thumbprints, exact-URI Auth Code + PKCE `S256`, Refresh Token Rotation + family reuse detection, UserInfo, Introspect, Revoke, `/admin/oidc/clients`) for **Vaelsgard** and third-party SSO
- `vaelspire-verify` zero-DB stateless `EdDSA` JWKS verifier crate
- Embedded SvelteKit (`adapter-static` + Tailwind) web console (`ui/`, `--features embed-ui`) + runtime `--ui-mode embedded|external|api-only` toggle
- Isolated native desktop companion spec in `apps/vaelspire-desktop/` for **Rune** (`anomalyco/rune`)
- *Pre-`v0.1.0` polish:* Wire `--database-url postgres://...` directly into `vaelspire serve` / `migrate` alongside SQLite

## 🔨 M4 — SCIM 2.0, Non-Human Identity (NHI), SAML & Standards Conformance *(Core Shipped, Hardening Next)*
- ✅ SCIM 2.0 Directory Sync (`/scim/v2/ServiceProviderConfig`, `/scim/v2/Users` CRUD)
- ✅ Non-Human Identity (NHI) / AI agent scoped delegation (`client_credentials` with strict scope attenuation)
- ✅ SAML 2.0 IdP metadata (`/saml/metadata`)
- 🧭 Next: Full SAML 2.0 signed assertions, OpenID Foundation OIDC Conformance Suite in CI, delegated multi-org admin portals, and commissioning the official fantasy **Spire & Dragon** logo

## ✅ M5 — Vaelspire Enterprise Foundations (`enterprise/`) *(Core Modules Implemented)*
Isolated proprietary Cargo workspace (`enterprise/Cargo.toml`, governed by `LICENSE-ENTERPRISE`) implementing `vaelspire-core::extensions`:
- ✅ `vaelspire-license`: Offline Ed25519 `.vlic` signing & verification (`LicenseGate`) with guaranteed **never-brick-logins** graceful expiry
- ✅ `vaelspire-worm`: Tamper-evident SHA-256 hash-chained `AuditSink` + S3 Object Lock / Azure Immutable Blob / GCS Bucket Lock archive framing
- ✅ `vaelspire-telemetry`: Bounded non-blocking `TelemetrySink` with OTLP JSON, Splunk HEC NDJSON, and Datadog Logs batch formatters
- ✅ `vaelspire-georep`: EU/US/APAC tenant data-residency pinning (`RegionPolicy`) + ordered cross-region replication outbox envelopes (`ReplicationHook`)
- 🧭 Next: Wire live cloud bucket uploaders, SIEM push workers, and peer-region active-active mTLS sync daemons

## ☁️ M6 — Managed Cloud, Formal Audits & FIPS 140-3 *(Revenue-Funded)*
- **Vaelspire Cloud** (managed multi-region SaaS)
- Independent third-party penetration tests & security audit packages (under NDA)
- **FIPS 140-3** validated builds (`aws-lc-rs`), SOC 2 Type II, ISO 27001, and dedicated enterprise SLAs
