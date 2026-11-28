# 🐘 `vaelspire-store-postgres`

Production **PostgreSQL 17+** implementation of [`AuthStore`](../vaelspire-core/README.md), built over **`neotales-dbapi-postgres`** and **`neotales-migration-postgres`**.

## ✨ Highlights

- 🔒 **Advisory-locked transactional migrations:** Safe for concurrent startup across multiple replicas in single-region HA.
- ✅ **100% SQLite parity:** Verified against the exact same shared [`crates/conformance.rs`](../conformance.rs) black-box test suite.
- 🛡️ **Net-new schema guard:** Refuses to adopt unowned application tables without a matching `auth_schema_history` ledger.
- 🧱 **Driver-neutral contract:** Uses `neotales-dbapi` typed parameters (`bytea` UUIDv7s, microsecond UTC timestamps) without exposing `sqlx` in the public API.

## 🧪 Quick Example

```rust
use neotales_dbapi_postgres::PostgresPool;
use vaelspire_store_postgres::open;

async fn init_postgres(pool: PostgresPool) -> Result<(), Box<dyn std::error::Error>> {
    // Runs advisory-locked migrations and returns a cloneable PostgresStore
    let store = open(pool).await?;
    let _ = store;
    Ok(())
}
```

> Need active-active **multi-region geo-replication**, data-residency pinning, or **WORM immutable audit archival**? See [**Vaelspire Enterprise**](https://vaelspire.dev/enterprise/overview/).
