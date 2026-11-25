# 🪶 `vaelspire-store-sqlite`

Zero-dependency embedded **SQLite** implementation of [`AuthStore`](../vaelspire-core/README.md), built over **`neotales-dbapi`** and **`neotales-migration-sqlite`**.

## ✨ Highlights

- 🚀 **Single-file persistence:** Ideal for `Vaelspire Core` single-binary deployments, local dev, homelabs, and embedded apps.
- 🔒 **Transactional security transitions:** Multi-row writes (password reset + session revocation + audit row) execute atomically.
- 📜 **Append-only audit triggers:** SQLite triggers (`auth_audit_no_update`, `auth_audit_no_delete`) enforce audit immutability at the database layer.
- 🛡️ **Net-new migration safety:** Refuses to adopt unowned pre-existing tables without a matching `auth_schema_history` ledger.
- 🔌 **Pluggable SQLite driver:** Default `sqlx-compat` feature uses `neotales-dbapi-sqlite`; disable default features to pass any `neotales-dbapi::SqlitePool` (such as `neotales-dbapi-sqlite-direct` on `rusqlite`).

## 🧪 Quick Example

```rust
use std::sync::Arc;
use vaelspire_store_sqlite::open;

async fn init_sqlite() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(open("./vaelspire.sqlite").await?);
    let _ = store;
    Ok(())
}
```
