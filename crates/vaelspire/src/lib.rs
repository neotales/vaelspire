//! Vaelspire single-binary Open-Core identity server and CLI library.
//!
//! Combines the embeddable `vaelspire-*` crates into a ready-to-deploy HTTP server
//! with:
//! - Authentication, sessions (sliding + hard absolute timeouts), MFA, Passkeys (`--features passkey`), API keys, and RBAC via `vaelspire-axum`
//! - Org-wide and per-application RBAC (roles, permissions, groups) via `/admin/rbac/*`
//! - Self-service organization `IdP` configuration, domain policies, Home Realm Discovery, and per-org SCIM tokens via `/org/portal/*` and `/auth/discover`
//! - GDPR Right of Access (`/account/export`), Right to Erasure (`/account/erase`, `/admin/gdpr/erase/{id}`), and redacted logging (`wf******@domain.com`)
//! - Full OIDC 1.0 / OAuth 2.0 `IdP` (Discovery, rotating `Ed25519` JWKS, PKCE, Refresh Rotation, NHI `client_credentials`)
//! - SCIM 2.0 Users & Groups provisioning (`/scim/v2/*`) and SAML 2.0 metadata (`/saml/metadata`)
//! - Reverse-proxy `/forward-auth` with `X-Vaelspire-*` identity & RBAC headers
//! - CIDR-guarded trusted IP extraction, Core anomaly detection, Prometheus `/metrics`, `/health`, `/ready`, and optional embedded `SvelteKit` UI (`--features embed-ui`)

pub mod alerts;
pub mod bootstrap;
pub mod cli_mgmt;
pub mod config;
pub mod ext_store;
pub mod gdpr;
pub mod metrics;
pub mod oidc_http;
pub mod org;
pub mod rbac;
pub mod scim;
pub mod security;
pub mod server;
pub mod ui;
