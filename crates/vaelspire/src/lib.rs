//! Single-binary Open-Core identity and authentication server + CLI for **Vaelspire**.
//!
//! Combines the modular `vaelspire-*` crates (`vaelspire-core`, `vaelspire-auth`,
//! `vaelspire-axum`, `vaelspire-oidc`, `vaelspire-verify`, `vaelspire-store-sqlite`)
//! into one static binary exposing:
//!
//! - Fail-closed authentication HTTP endpoints (`/sign-up`, `/sign-in`, `/sign-out`, `/session`, `/api-keys`, RBAC)
//! - `OpenID` Connect 1.0 & OAuth 2.0 Identity Provider (`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/oauth2/*`)
//! - SCIM 2.0 directory provisioning (`/scim/v2/*`) and SAML 2.0 metadata (`/saml/metadata`)
//! - Reverse-proxy `/forward-auth` for Caddy, Traefik, and Nginx (session cookie or API key)
//! - Prometheus `/metrics`, `/health`, `/ready`, and optional embedded `SvelteKit` UI (`--features embed-ui`)
//! - Scriptable `clap` CLI (`serve`, `migrate`, `keygen`, `admin bootstrap`)

pub mod bootstrap;
pub mod config;
pub mod metrics;
pub mod oidc_http;
pub mod scim;
pub mod server;
pub mod ui;
