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
- One-command setup scripts (`scripts/dev-setup.sh`, `scripts/quickstart.sh`, `scripts/smoke-test.sh`), Docker/Compose, Caddy / Traefik / Nginx configs
- Dedicated Astro Starlight marketing & docs repo (`neotales/vaelspire-site`) with human guides, Roadmap, Enterprise pitch, and dense AI agent pages (`/agents/`, `/llms.txt`, `/llms-full.txt`)

## 🔨 M3 — OIDC Identity Provider, Embedded Core UI & Rune Desktop *(Next)*
- OIDC / OAuth 2.0 Identity Provider (Discovery, rotating Ed25519/ES256 JWKS, Auth Code + PKCE, Token/UserInfo/Introspect/Revoke, Client Registry) for first-class **Vaelsgard** SSO
- Thin stateless JWKS verifier crate (`vaelspire-verify`)
- Embedded SvelteKit (`adapter-static` + `shadcn-svelte` + Tailwind) web login/admin UI (`--features embed-ui`) + `--ui=external` mode for Enterprise
- Isolated native desktop admin companion app in **Rune** (`anomalyco/rune`)
- PostgreSQL CLI parity (`--database-url postgres://...`) in `vaelspire serve` / `migrate`

## 🧭 M4 — Standards Conformance, SAML 2.0, SCIM 2.0 & Organizations
- OpenID Foundation OIDC Conformance Suite in CI
- SAML 2.0 IdP & SCIM 2.0 Directory Sync
- Multi-tenant Organizations & delegated org admin portals
- Non-Human Identity (NHI) / AI agent scoped credential delegation
- Official fantasy **Spire & Dragon** logo & wordmark lockups

## 🏢 M5 — Vaelspire Enterprise (`enterprise/`)
- Multi-region active-active **geo-replication** & EU/US/APAC data-residency pinning
- **WORM immutable audit storage** (S3 Object Lock, Azure Immutable Blob, GCS Bucket Lock) + multi-year hash-chained retention
- Real-time **SIEM & OpenTelemetry** pipelines (Splunk, Datadog, Sentinel, CrowdStrike, Kafka)
- **Offline Ed25519 license verification** (air-gapped workforce seat packs + separate CIAM MAU packs; graceful enforcement that never bricks logins)

## ☁️ M6 — Managed Cloud, Formal Audits & FIPS 140-3 *(Revenue-Funded)*
- **Vaelspire Cloud** (managed multi-region SaaS)
- Independent third-party penetration tests & security audit packages (under NDA)
- **FIPS 140-3** validated builds (`aws-lc-rs`), SOC 2 Type II, ISO 27001, and dedicated enterprise SLAs
