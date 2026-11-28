# 🗺️ Vaelspire Roadmap

Vaelspire ships in tight, verifiable milestones — dogfooding **Vaelsgard** and Neotales apps first, keeping all core security **100% free and MIT-licensed**, and building low-cost edge, Kubernetes, and Enterprise compliance cleanly on top.

> 📚 Full documentation & marketing site: [**`neotales/vaelspire-site`**](https://github.com/neotales/vaelspire-site)
> 🚨 Release rule: Documentation in `neotales/vaelspire-site` must be updated and verified **before** every release tag. See [RELEASING.md](RELEASING.md).

---

## ✅ M1 — Embeddable Rust Crates *(Complete)*
- 6 MIT Open-Core crates over `neotales-dbapi` + `neotales-migration`:
  `vaelspire-core`, `vaelspire-auth`, `vaelspire-axum`, `vaelspire-email`, `vaelspire-store-sqlite`, `vaelspire-store-postgres`
- Argon2id + bcrypt auto-upgrade, keyed BLAKE3 digests, `Zeroizing` secret hygiene, TOTP MFA (AES-256-GCM), Passkeys/WebAuthn library workflows, API keys, email sign-in, social/OIDC client, RBAC schema foundations, transactional append-only audit rows, shared `conformance.rs` suite

## ✅ M2 — Single-Binary CLI/Server, Setup Tooling & Docs Site *(Complete)*
- `crates/vaelspire` single-binary `clap` CLI (`serve`, `migrate`, `keygen`, `admin bootstrap`) + Axum HTTP server
- `/forward-auth` (session cookies + API keys + `X-Vaelspire-*` headers), Prometheus `/metrics`, `/health`, `/ready`, `/.well-known/vaelspire`
- One-command setup scripts (`scripts/dev-setup.sh`, `scripts/quickstart.sh`, `scripts/smoke-test.sh`, `scripts/demo.sh`), Docker/Compose, Caddy / Traefik / Nginx configs
- Dedicated Astro Starlight marketing & docs repo (`neotales/vaelspire-site`) with human guides, comparisons, crate reference, Roadmap, Enterprise architecture, and dense AI agent pages (`/agents/`, `/llms.txt`, `/llms-full.txt`)

## ✅ M3 — OIDC 1.0 Identity Provider, Stateless Verifier & Embedded Core UI *(Core Shipped)*
- `vaelspire-oidc` OIDC 1.0 / OAuth 2.0 Identity Provider (Discovery, rotating Ed25519 JWKS with RFC 7638 thumbprints, exact-URI Auth Code + PKCE `S256`, Refresh Token Rotation + family reuse detection, UserInfo, Introspect, Revoke, `/admin/oidc/clients`) for **Vaelsgard** and third-party SSO
- `vaelspire-verify` zero-DB stateless `EdDSA` JWKS verifier crate (`wasm32`-clean)
- Embedded SvelteKit (`adapter-static` + Tailwind) web console (`ui/`, `--features embed-ui`) + runtime `--ui-mode embedded|external|api-only` toggle
- Isolated native desktop companion spec in `apps/vaelspire-desktop/` for **Rune** (`anomalyco/rune`)

## ✅ M3.5 — Pre-`v0.1.0` Production Hardening, Passkeys, RBAC & Management CLI *(Shipped)*

### Security, Sessions, Auditing, GDPR & Observability
- ✅ **GDPR-Safe Logging & Redaction:** Centralized `vaelspire_core::privacy` email redactor (`user_id` + `wf******@domain.com`) with `--pii-log-mode masked|id-only|full` and strict log-level hygiene
- ✅ **GDPR Data Rights:** Right to Erasure (`DELETE /account/erase`, `POST /admin/gdpr/erase/{id}`, `vaelspire user gdpr-erase`) anonymizing PII (`erased-<id>@deleted.invalid`) while preserving append-only `auth_audit` integrity; Right of Access JSON export (`GET /account/export`, `vaelspire user export`); IP subnet truncation (`--audit-ip-mode full|truncated|none`, `/24` IPv4, `/48` IPv6)
- ✅ **Sliding & Hard Session Expirations:** Configurable `session_sliding` / `--session-fixed`, `--session-idle-secs`, and `--session-max-secs` (enforced via `UUIDv7` creation timestamp in `vaelspire-auth::Policy`)
- ✅ **Trusted IP Collection & Anomaly Detection:** Explicit `--ip-source` (`direct`, `x-forwarded-for`, `cf-connecting-ip`, `forwarded`) + `--trusted-proxies` CIDR allow-list; Core `AnomalyDetector` (password spray, new device/subnet, OIDC refresh-token reuse)
- ✅ **Reusable Multi-Sink Alerting (`crates/vaelspire-alerts`):** Zero-Vaelspire-coupling MIT alert router with severity/category filters, burst deduplication, retries, and feature-gated sinks (**Webhook + HMAC-SHA256**, **Slack**, **Discord**, **Microsoft Teams Adaptive Cards**, **Gotify**, **ntfy**, **Twilio / Generic SMS**, **SMTP Email**), wired into `vaelspire` anomaly/GDPR hooks and `vaelspire alert test` *(planned for future extraction into a generic standalone `neotales-alerts` crate)*
- ✅ **Expanded Bounded-Cardinality Metrics:** OIDC grants, anomalies, GDPR exports/erasures, SCIM ops, HTTP status classes, and `/forward-auth` decisions on `/metrics`

### End-to-End Passkeys, Full Per-App RBAC, Persistence & Operator CLI
- ✅ **End-to-End Passkeys (WebAuthn):** Wired `--features passkey`, `--rp-id` / `--rp-origin`, and browser `navigator.credentials.{create,get}` flows in `/ui/account` & `/ui/login`
- ✅ **Full RBAC (Global & Per-App Roles, Groups & Permissions):** Nullable `app_id` on `vs_app_role` & `vs_app_permission`, permission-to-role grants, group-to-role grants, `/admin/rbac/*` endpoints, `/ui/rbac` console, and automatic projection into OIDC UserInfo & `/forward-auth` (`X-Vaelspire-Roles`, `X-Vaelspire-Groups`)
- ✅ **Persistent OIDC Clients & Full Operator CLI (`vaelspire`):** Persisted OIDC clients in `vs_oidc_client` + full CLI subcommands (`user`, `org`, `rbac`, `audit`, `admin`, `serve`, `migrate`, `keygen`)
- 🧭 *Remaining polish:* Wire `--database-url postgres://...` directly into `vaelspire serve` / `migrate` alongside SQLite

## ✅ M4 — Self-Service Org IdP, Domain Policies, Directory Sync & NHI *(Core Shipped)*
- ✅ **Self-Service Organization / Client IdP Portal:** `/org/portal/{policy,domains,idps,scim-tokens}` API + `/ui/org` console for upstream **OIDC** and **SAML 2.0** IdPs, dry-run `/org/portal/idps/{id}/test` validation, JIT provisioning & group claim mapping, and break-glass local admin toggle
- ✅ **Organization Domain Policies & Home Realm Discovery (HRD):** DNS TXT domain verification (`_vaelspire-verify.<domain>`) + per-org email policies (`allow_public`, `business_domains_only`, `verified_domains_only`) + `POST /auth/discover`
- ✅ **Directory Sync (SCIM 2.0 Users & Groups):** `/scim/v2/ServiceProviderConfig`, `/scim/v2/Users` (with `PATCH active=false` immediate session revocation), `/scim/v2/Groups` (RFC 7644 `PatchOp` member sync), and per-org scoped `vs_scim_...` bearer tokens
- ✅ **Non-Human Identity (NHI) / AI Agents & SAML Metadata:** OAuth 2.0 `client_credentials` with strict `allowed_scopes` attenuation + `/saml/metadata`
- 🧭 *Next:* Full signed SAML 2.0 assertions, OpenID Foundation OIDC Conformance Suite in CI, and commissioning the official fantasy **Spire & Dragon** logo

## ✅ M4.5 — Low-Cost Edge (Cloudflare D1 / Workers / Containers) & Kubernetes *(Foundations Shipped)*
- ✅ **Cloudflare D1 Store Crate (`crates/vaelspire-store-d1`):** Pure-Rust, zero-native-C, `wasm32`-clean `AuthStore` adapter (`D1Store`, `D1Client`, `D1_SCHEMA_SQL`)
- ✅ **Cloudflare Edge Templates (`deploy/cloudflare/`):** Workers + D1 template (`wrangler.toml`, `schema.sql`, edge gateway) and Cloudflare Containers template (`wrangler.jsonc` running `deploy/Dockerfile` with `--ip-source cf-connecting-ip`)
- ✅ **Kubernetes Helm Chart (`deploy/helm/vaelspire/`):** Hardened non-root Deployment, Service, Ingress, HPA (`autoscaling/v2`), PodDisruptionBudget, NetworkPolicy, Secret, and Prometheus `ServiceMonitor`

## ✅ M5 — Vaelspire Enterprise Foundations *(Separate Private Repo: `neotales/vaelspire-enterprise`)*
Proprietary commercial Cargo workspace maintained outside this MIT repository, implementing `vaelspire-core::extensions`:
- ✅ `vaelspire-license`: Offline Ed25519 `.vlic` signing & verification (`LicenseGate`) with guaranteed **never-brick-logins** graceful expiry
- ✅ `vaelspire-worm`: Tamper-evident SHA-256 hash-chained `AuditSink` + S3 Object Lock / Azure Immutable Blob / GCS Bucket Lock archive framing
- ✅ `vaelspire-telemetry`: Bounded non-blocking `TelemetrySink` with OTLP JSON, Splunk HEC NDJSON, and Datadog Logs batch formatters
- ✅ `vaelspire-georep`: EU/US/APAC tenant data-residency pinning (`RegionPolicy`) + ordered cross-region replication outbox envelopes (`ReplicationHook`)
- 🧭 Next: Wire live cloud bucket uploaders, SIEM push workers, cross-region anomaly feeds, and peer-region active-active mTLS sync daemons

## ☁️ M6 — Managed Cloud, Formal Audits & FIPS 140-3 *(Revenue-Funded)*
- **Vaelspire Cloud** (managed multi-region SaaS with generous free/low-cost tier)
- Independent third-party penetration tests & security audit packages (under NDA)
- **FIPS 140-3** validated builds (`aws-lc-rs`), SOC 2 Type II, ISO 27001, and dedicated enterprise SLAs
