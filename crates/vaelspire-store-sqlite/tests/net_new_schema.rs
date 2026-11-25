//! The schema is net-new: application tables without a matching ledger are refused.
#![cfg(feature = "sqlx-compat")]

use sqlx::SqlitePool;
use vaelspire_store_sqlite::{OpenError, open};

#[tokio::test]
async fn unowned_tables_are_not_adopted() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    {
        let pool = SqlitePool::connect(path).await.expect("raw pool");
        sqlx::query("CREATE TABLE auth_tenant(id BLOB PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("legacy table");
        pool.close().await;
    }
    let error = open(path)
        .await
        .expect_err("unowned schema must be refused");
    assert!(
        matches!(error, OpenError::Migration(_)),
        "expected a migration refusal, got {error:?}"
    );
}
