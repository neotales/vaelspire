# `vaelspire-store-d1`

Pure-Rust, zero-native-C, `wasm32`-clean **Cloudflare D1** [`AuthStore`](../vaelspire-core) adapter for low-cost serverless edge deployments of Vaelspire Core.

## Why `vaelspire-store-d1`?

- **Zero native C / OpenSSL / `libsqlite3-sys`:** Compiles cleanly for `wasm32-unknown-unknown` (Cloudflare Workers) as well as native Linux/macOS (Cloudflare Containers or D1 REST API).
- **Minimal [`D1Client`](src/lib.rs) bridge:** Implement two methods (`query` and `execute`) over Cloudflare Workers' `worker::D1Database` JS binding *or* the Cloudflare D1 HTTPS REST API.
- **Included D1 DDL (`D1_SCHEMA_SQL`):** Ready to run with `wrangler d1 execute vaelspire-db --file=schema.sql`, complete with append-only `auth_audit` triggers.

See [`deploy/cloudflare/`](../../deploy/cloudflare/) for ready-to-deploy **Cloudflare Workers + D1** and **Cloudflare Containers** templates.
