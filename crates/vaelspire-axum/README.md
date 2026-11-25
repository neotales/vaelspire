# 🌐 `vaelspire-axum`

Fail-closed **Axum 0.8** HTTP routes, cookies, origin allow-lists, CSRF protection, and `spawn_blocking` password verification for [`vaelspire-auth`](../vaelspire-auth/README.md).

## 🛡️ Security-First Defaults (Fail Closed)

- **`cookie_secure` is required** at construction — no accidental cleartext cookies in production.
- **Explicit `Origin` allow-list** on every state-changing route (`localhost` / `127.0.0.1` / `[::1]` only by default; empty list refuses all).
- **Double-submit CSRF** (`neotales.csrf` cookie echoed in `x-csrf-token` header).
- **Proof routes fail closed:** `/email/verify/request`, `/password/reset/request`, `/email/sign-in/request`, and `/invitations` return `404` unless `.on_proof(...)` is explicitly wired.
- **Built-in fixed-window rate limiting** on state-changing routes (30 req / 60s default, configurable).
- **Zero-leak `Arc<S>` sharing:** Share one `Arc<Store>` across your app and `AuthRouter` cleanly.

## 🛣️ Mounted Routes

| Group | Routes | Feature / Flag |
| :--- | :--- | :--- |
| **Core Auth** | `POST /sign-up`, `POST /sign-in`, `POST /sign-out`, `GET /session` | `password`, `session` (default) |
| **Session Mgmt** | `GET /sessions`, `DELETE /sessions/{id}`, `DELETE /sessions`, `DELETE /sessions/all` | `session` |
| **Account** | `POST /password/change`, `POST /email/change`, `DELETE /user` | `password`, `session` |
| **Proofs** | `POST /email/verify/request`, `POST /email/verify`, `POST /password/reset/request`, `POST /password/reset` | Always (`request` needs `.on_proof`) |
| **Email Sign-In** | `POST /email/sign-in/request`, `POST /email/sign-in` | `email-signin` |
| **Passkeys** | `POST /passkey/register/{begin,finish}`, `POST /passkey/login/{begin,finish}` | `passkey` |
| **API Keys** | `POST /api-keys`, `GET /api-keys/verify`, `DELETE /api-keys/{id}` | `apikeys` |
| **Tenancy & RBAC** | `POST /memberships`, `POST /invitations`, `POST /invitations/accept`, `POST /roles`, `POST /permissions`, `POST /groups` | `.roles(true)` for catalogue writes |
| **Social / OIDC** | `GET /social/{provider}/{start,callback}`, `GET /oidc/{provider}/{start,callback}` | `social`, `oidc` |

## 🧪 Mount Example

```rust
use std::sync::Arc;
use axum::Router;
use vaelspire_axum::AuthRouter;
use vaelspire_core::{AuthStore, Id, Timestamp};
use vaelspire_store_sqlite::open;

async fn build_app(digest_key: [u8; 32]) -> Result<Router, Box<dyn std::error::Error>> {
    let store = Arc::new(open("app.sqlite").await?);
    let tenant = Id::now_v7();
    store.create_tenant(tenant, "app", Timestamp::now_utc()).await?;

    let auth = AuthRouter::new(Arc::clone(&store), tenant, digest_key, true)
        .allowed_origins(["https://app.example.com"])
        .auditing(true)
        .roles(true)
        .on_proof(|email, kind, token| {
            // Send via vaelspire-email; never log `token`.
            let _ = (email, kind, token);
        })
        .into_router();

    Ok(Router::new().nest("/auth", auth))
}
```

> Want a turnkey server binary with `/forward-auth` and Prometheus `/metrics`? Use [**`vaelspire`**](../vaelspire/README.md).
