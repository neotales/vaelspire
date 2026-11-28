# Deploying Vaelspire on Cloudflare (Low-Cost Edge & Containers)

Vaelspire supports two Cloudflare deployment architectures so you can start at **$0–$5/month** on the global edge and scale seamlessly without rewriting your identity layer:

## Option 1: Cloudflare Containers (Full Native Static Binary — Recommended)

Runs the exact Linux `vaelspire` binary ([`deploy/Dockerfile`](../Dockerfile)) natively on Cloudflare Containers with:
- Full native SIMD **Argon2id** password hashing (no Wasm CPU ceiling)
- Full **OIDC 1.0 IdP**, **Passkeys (WebAuthn)**, **SCIM 2.0**, **Per-App RBAC**, and optional **Embedded SvelteKit UI**
- `--ip-source cf-connecting-ip` honoring Cloudflare's edge `CF-Connecting-IP` header safely

See [`containers/wrangler.jsonc`](containers/wrangler.jsonc).

## Option 2: Cloudflare Workers + D1 Edge Gateway (Ultra-Low Cost)

Pair **Cloudflare D1** (using `crates/vaelspire-store-d1` + [`worker/schema.sql`](worker/schema.sql)) with a tiny edge **Cloudflare Worker** ([`worker/src/index.ts`](worker/src/index.ts)) that:
1. Verifies Vaelspire `Ed25519` (`EdDSA`) JWTs statelessly at 300+ global Cloudflare PoPs via `/.well-known/jwks.json` (sub-millisecond, zero origin hop!).
2. Stores sessions, users, and append-only audit rows in **Cloudflare D1** (`wrangler d1 execute vaelspire-db --file=worker/schema.sql`).
3. Optionally forwards heavy Argon2id / Passkey endpoints to a Cloudflare Container or small regional Vaelspire server.

```bash
cd deploy/cloudflare/worker
wrangler d1 create vaelspire-db
wrangler d1 execute vaelspire-db --file=schema.sql
wrangler deploy
```
