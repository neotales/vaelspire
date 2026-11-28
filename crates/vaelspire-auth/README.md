# 🔐 `vaelspire-auth`

Embeddable, **Better-Auth-style** authentication workflows in pure Rust — built over any [`AuthStore`](../vaelspire-core/README.md) with `#![forbid(unsafe_code)]` and zero runtime logging.

## ✨ Highlights

- 🔑 **Argon2id + Legacy bcrypt Auto-Upgrade:** CPU-bound hashing (`hash_password` / `verify_password`) is split cleanly from async store calls (`begin_sign_in` / `finish_sign_in`) so your web server runs Argon2 on `spawn_blocking` without stalling async workers.
- 🍪 **Keyed BLAKE3 Session & Token Digests:** Bearer tokens never touch the database — only versioned 256-bit keyed digests are stored. All returned secrets are wrapped in `Secret` (`Zeroizing<String>` + redacted `Debug`).
- 📱 **TOTP MFA & Recovery Codes** (`feature = "mfa"`): AES-256-GCM encrypted TOTP secrets + constant-time verification + one-use recovery codes.
- 🪪 **Passkeys / WebAuthn** (`feature = "passkey"`): Full registration and login ceremonies via `webauthn-rs`.
- 🗝️ **API Keys** (`feature = "apikeys"`): Prefixed keys (`{prefix}_{id12}_{secret}`), scoped, revocable, with `last_used_at` tracking.
- 📝 **Transactional Audit Trail:** Enable `.auditing(true)` and every identity mutation commits its append-only `auth_audit` row in the **same database transaction**.

## 📦 Feature Flags

| Feature | Default | Capabilities |
| :--- | :---: | :--- |
| `password` | ✅ | Argon2id hashing, legacy bcrypt verify & rehash, sign-up/sign-in/reset |
| `session` | ✅ | Opaque sessions, `SessionCache`, sliding expiry, session listing & revocation |
| `apikeys` | No | `ApiKeys` issuer, verifier, revocation |
| `mfa` | No | TOTP enrollment/confirmation, AES-256-GCM secret encryption, recovery codes |
| `passkey` | No | WebAuthn passkey registration and sign-in ceremonies |
| `email-signin` | No | Passwordless email OTP / magic-link sign-in |
| `social` | No | GitHub, Google, and Microsoft OAuth state & sign-in flows |
| `oidc` | No | Self-hosted OIDC client flows (implies `social`) |

## 🧪 Quick Example (Argon2 Off the Async Worker)

```rust
use vaelspire_auth::{Auth, Policy, SignInOutcome, hash_password, verify_password};
use vaelspire_core::{AuthStore, Id, Timestamp};
use vaelspire_store_sqlite::open;

async fn register_and_sign_in() -> Result<(), Box<dyn std::error::Error>> {
    let store = open(":memory:").await?;
    let tenant = Id::now_v7();
    let now = Timestamp::now_utc();
    store.create_tenant(tenant, "demo", now).await?;

    let digest_key = [7u8; 32]; // Load from a secret store in production!
    let auth = Auth::new(&store, digest_key, Policy::default()).auditing(true);

    // 1. Hash password on a blocking thread, then persist user
    let hash = tokio::task::spawn_blocking(|| hash_password(b"correct horse battery staple"))
        .await??;
    auth.sign_up(tenant, "ada@example.test", &hash, now).await?;

    // 2. Begin sign-in (async DB read), verify password off-worker, then finish
    let attempt = auth.begin_sign_in(tenant, "ada@example.test", now).await?;
    let stored_hash = attempt.password_hash().to_owned();
    let valid = tokio::task::spawn_blocking(move || {
        verify_password(b"correct horse battery staple", &stored_hash)
    })
    .await??;

    let outcome = if valid {
        SignInOutcome::Verified { rehash: None }
    } else {
        SignInOutcome::WrongPassword
    };

    let issued = auth.finish_sign_in(attempt, outcome, now).await?;
    let session = auth.resolve_session(issued.token().expose(), now).await?;
    assert_eq!(session.tenant_id, tenant);
    Ok(())
}
```

> Need multi-region geo-replication, WORM audit storage, or SIEM streaming? Check out [**Vaelspire Enterprise**](https://vaelspire.dev/enterprise/overview/).
