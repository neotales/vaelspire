# Vaelspire Desktop Companion (`apps/vaelspire-desktop`)

Vaelspire's optional desktop companion application is built with **[Rune](https://github.com/anomalyco/rune)** (`anomalyco/rune`, currently pre-release on its `dev` branch) and communicates exclusively with a running Vaelspire server over HTTP/HTTPS (the same OpenAPI/OIDC/SCIM/Admin endpoints used by the web console and CLI).

## Why Isolated?

1. **Zero UI bloat in the core server binary:** `vaelspire` stays a lean, headless single binary (with optional `--features embed-ui` for the static SvelteKit web console) that deploys cleanly into containers, systemd units, and air-gapped servers without GUI or WebView system dependencies.
2. **Pre-release isolation:** Because Rune is actively evolving on `dev`, isolating the desktop app in `apps/vaelspire-desktop` guarantees that breaking changes in upstream GUI frameworks never block `vaelspire` server releases or crate publishing.
3. **API-first parity:** Every action in the desktop companion maps 1:1 to Vaelspire's REST API:
   - Session management (`/session`, `/sessions`, `/sign-in`, `/sign-out`)
   - One-time API key issuance (`/api-keys`)
   - OIDC client registration & JWKS inspection (`/admin/oidc/clients`, `/.well-known/jwks.json`)
   - SCIM 2.0 user directory management (`/scim/v2/Users`)
   - Live health, readiness, and Prometheus metrics monitoring (`/health`, `/ready`, `/metrics`)

## Planned Capabilities

- Connect to one or more Vaelspire Core or Enterprise instances (local, homelab, staging, production) with OS keychain credential storage.
- Local passkey / OIDC PKCE loopback login against your Vaelspire IdP (`http://127.0.0.1:<ephemeral>/callback`).
- Live audit & metrics dashboard without opening a browser.
- Offline `.vlic` Enterprise license inspector and WORM audit chain verifier.

## Visual Palette

Matches the Vaelspire Core & Docs theme — **warm obsidian, dragon-ember crimson, and molten amber-gold** (zero cyan), with Neotales purple reserved for the `by Neotales` parent brand badge.
