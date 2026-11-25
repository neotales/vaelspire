# 🧱 `vaelspire-core`

Zero-I/O domain types, error codes, and the [`AuthStore`](src/lib.rs) storage contract for **Vaelspire** (MIT Open-Core).

`vaelspire-core` contains **no database driver, no HTTP framework, and no logging** — making it safe to share across stores, web servers, CLIs, and desktop apps (including Rune).

## ✨ What's Inside

- 🆔 **Identifiers & Time:** `Id` (`UUIDv7`) and `Timestamp` (`time::OffsetDateTime`, UTC)
- ⚠️ **Stable Error Codes:** `AuthError` (`Unauthorized`, `NotFound`, `Invalid`, `Conflict`, `Store`, `Unsupported`) — opaque by design, never leaks submitted credentials
- 👤 **Identity Models:** `User`, `Session`, `PasswordCredential` (redacted `Debug`), `OneTime` (`Purpose`), `ApiKey`, `ApiKeyPrefix`, `MfaFactor`, `PasskeyRecord`, `Membership`, `MembershipStatus`, `Invitation`, `AuditEvent`
- 🔌 **Storage Port:** `#[async_trait] pub trait AuthStore` implemented by [`vaelspire-store-sqlite`](../vaelspire-store-sqlite/README.md) and [`vaelspire-store-postgres`](../vaelspire-store-postgres/README.md)
- 🏷️ **Seeded Tenant Roles:** `SEEDED_ROLES = ["owner", "admin", "member"]`

## 📦 Feature Flags

| Feature | Default | Enables |
| :--- | :---: | :--- |
| `password` | No | Password feature marker |
| `session` | No | Session feature marker |
| `social` | No | `SocialProvider` (`GitHub`, `Google`, `Microsoft`) |
| `oidc` | No | `OidcProvider` (`Authentik`, `Zitadel`, `Keycloak`) + `social` |

## 🧪 Usage Example

```rust
use vaelspire_core::{ApiKeyPrefix, AuthError, Id, Purpose, SEEDED_ROLES};

fn inspect_core_types() -> Result<(), AuthError> {
    let tenant_id = Id::now_v7();
    let prefix = ApiKeyPrefix::new(Some("vsp"))?;
    assert_eq!(prefix.as_str(), "vsp");
    assert_eq!(Purpose::ResetPassword.as_str(), "reset_password");
    assert_eq!(SEEDED_ROLES, ["owner", "admin", "member"]);
    let _ = tenant_id;
    Ok(())
}
```

> Part of [**Vaelspire**](../../README.md) by Neotales — MIT Open-Core, with [Vaelspire Enterprise](../../enterprise/README.md) for multi-region geo-replication, WORM audit storage, and FIPS 140-3.
