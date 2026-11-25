//! Single-binary Open-Core identity and authentication server + CLI for **Vaelspire**.
//!
//! Combines the modular `vaelspire-*` crates (`vaelspire-core`, `vaelspire-auth`,
//! `vaelspire-axum`, `vaelspire-store-sqlite`) into one static binary exposing:
//!
//! - Fail-closed authentication HTTP endpoints (`/sign-up`, `/sign-in`, `/sign-out`, `/session`, `/api-keys`, RBAC)
//! - Reverse-proxy `/forward-auth` for Caddy, Traefik, and Nginx (session cookie or API key)
//! - Prometheus `/metrics` and `/health` + `/ready` probes
//! - Scriptable `clap` CLI (`serve`, `migrate`, `keygen`, `admin bootstrap`)

pub mod bootstrap;
pub mod config;
pub mod metrics;
pub mod server;
