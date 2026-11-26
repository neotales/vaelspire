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

## 🔨 M3.5 — Pre-`v0.1.0` Production Hardening, Passkeys, RBAC & Management CLI *(Next — Required Before First Release)*

### Security, Sessions, Auditing, GDPR & Observability
- **GDPR-Safe Logging & Redaction:** Centralized email redactor (`user_id` + `wf******@domain.com` showing only leading characters + domain) with configurable PII log mode (`masked`, `id-only`, `full` dev-only) and strict log-level hygiene (`ERROR`, `WARN`, `INFO`, `DEBUG`/`TRACE` — zero secrets/tokens ever)
- **GDPR Data Rights:** Right to Erasure (`DELETE /user` + `vaelspire user gdpr-erase`) anonymizing PII while preserving append-only `auth_audit` integrity via pseudonymous `actor_id`; Right of Access JSON export (`GET /account/export`); configurable IP retention/truncation (`/24` IPv4, `/48` IPv6)
- **Sliding & Hard Session Expirations:** Configurable `session_idle_timeout` (sliding window with throttled `session_refresh_window` DB writes) + `session_absolute_timeout` (hard cap from `created_at`) + toggleable `fixed` vs `sliding` mode
- **Trusted IP Collection & Anomaly Detection:** Explicit `--ip-source` (`direct`, `x-forwarded-for`, `cf-connecting-ip`, `forwarded`) + `--trusted-proxies` CIDR allow-list; per-IP password-spray/stuffing detection, new-device/IP alerts, refresh-token reuse alerts, and optional local GeoLite2 impossible-travel flagging
- **Expanded Bounded-Cardinality Metrics:** Auth attempt outcomes, OIDC grants, lockouts, anomaly triggers, Argon2 latency histograms, and active session gauges on `/metrics`

### End-to-End Passkeys, Full Per-App RBAC, Persistence & Operator CLI
- **End-to-End Passkeys (WebAuthn):** Wire `passkey` feature + `--rp-id` / `--rp-origin` into `crates/vaelspire` and browser `navigator.credentials.{create,get}` flows into `/ui/account` and `/ui/login`
- **Full RBAC (Global & Per-App Roles, Groups & Permissions):** Nullable `app_id` on roles & permissions (org-wide + per-OIDC-app roles), permission-to-role grants (`auth_role_permission`), group-to-role grants (`auth_group_role`), and effective role/group/permission projection into OIDC JWTs & `/forward-auth`
- **Persistent OIDC Clients & PostgreSQL CLI Parity:** Persist OIDC clients in `AuthStore` and wire `--database-url postgres://...` into `vaelspire serve` / `migrate` alongside SQLite
- **Full Management CLI (`vaelspire`):** Dual-mode (local direct-DB OR remote API profiles) subcommands for `user`, `org`, `client`, `role`, `perm`, `group`, `api-key`, `audit`, and `status`

## 🧭 M4 — Self-Service Org IdP, Domain Policies, Directory Sync & Standards Conformance
- **Self-Service Organization / Client IdP Portal:** Delegated org admin setup portal (`/ui/org/sso`) to configure upstream **OIDC** and **SAML 2.0** IdPs, run live test-mode verification, configure JIT provisioning & claim-to-role mappings, and retain a break-glass local admin path
- **Organization Domain Policies & Home Realm Discovery (HRD):** DNS TXT domain verification (`_vaelspire-verify.<domain>`) + per-org email policies (`allow_public` e.g. Gmail/Outlook, `business_domains_only`, or `verified_domains_only`) + automatic email-domain IdP routing
- **Directory Sync (SCIM 2.0):** Already shipped `/scim/v2/ServiceProviderConfig` & `/scim/v2/Users` CRUD; expand with `/scim/v2/Groups` sync, per-org scoped SCIM bearer tokens (Okta, Entra ID, Google Workspace, JumpCloud), and instant session/token revocation on deprovisioning
- **Non-Human Identity (NHI) / AI Agents:** Already shipped `client_credentials` with strict `allowed_scopes` attenuation; add fine-grained delegation chains and workload policies
- **SAML 2.0 & Standards Conformance:** Already shipped `/saml/metadata`; add signed SAML 2.0 assertions + OpenID Foundation OIDC Conformance Suite in CI
- **Brand Identity:** Commission official fantasy **Spire & Dragon** logo & wordmark lockups

## 🌐 M4.5 — Low-Cost Edge (Cloudflare D1 / Workers / Containers) & Kubernetes
- **Cloudflare Workers + D1 (`vaelspire-store-d1`):** Keep `vaelspire-core` & `vaelspire-verify` strictly `wasm32`-clean; build a Cloudflare D1 `AuthStore` adapter and edge Worker runtime (with WebCrypto/configurable KDF or hybrid hashing offload to fit Worker CPU/memory ceilings) for ultra-low-cost global deployments
- **Cloudflare Containers & Hybrid Edge:** First-class deployment template running the native static `vaelspire` Docker image on **Cloudflare Containers** (full SIMD Argon2id + Passkeys + embedded UI) paired with an optional `vaelspire-verify` Wasm Worker for sub-millisecond edge JWT validation
- **Containers & Kubernetes (K8s):** Hardened OCI images (distroless/scratch), official **Helm chart** (PostgreSQL HA, HPA autoscaling, PodDisruptionBudgets, NetworkPolicies, Prometheus `ServiceMonitor`), and optional Kubernetes operator for declarative org/client CRDs

## ✅ M5 — Vaelspire Enterprise Foundations (`enterprise/`) *(Core Modules Implemented)*
Isolated proprietary Cargo workspace (`enterprise/Cargo.toml`, governed by `LICENSE-ENTERPRISE`) implementing `vaelspire-core::extensions`:
- ✅ `vaelspire-license`: Offline Ed25519 `.vlic` signing & verification (`LicenseGate`) with guaranteed **never-brick-logins** graceful expiry
- ✅ `vaelspire-worm`: Tamper-evident SHA-256 hash-chained `AuditSink` + S3 Object Lock / Azure Immutable Blob / GCS Bucket Lock archive framing
- ✅ `vaelspire-telemetry`: Bounded non-blocking `TelemetrySink` with OTLP JSON, Splunk HEC NDJSON, and Datadog Logs batch formatters
- ✅ `vaelspire-georep`: EU/US/APAC tenant data-residency pinning (`RegionPolicy`) + ordered cross-region replication outbox envelopes (`ReplicationHook`)
- 🧭 Next: Wire live cloud bucket uploaders, SIEM push workers, cross-region anomaly feeds, and peer-region active-active mTLS sync daemons

## ☁️ M6 — Managed Cloud, Formal Audits & FIPS 140-3 *(Revenue-Funded)*
- **Vaelspire Cloud** (managed multi-region SaaS with generous free/low-cost tier)
- Independent third-party penetration tests & security audit packages (under NDA)
- **FIPS 140-3** validated builds (`aws-lc-rs`), SOC 2 Type II, ISO 27001, and dedicated enterprise SLAs
