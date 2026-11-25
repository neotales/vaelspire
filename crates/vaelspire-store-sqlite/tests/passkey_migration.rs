//! The net-new schema installs the complete ceremony state once and is idempotent.
#![cfg(feature = "sqlx-compat")]

#[tokio::test]
async fn ceremony_column_is_installed_once() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    vaelspire_store_sqlite::open(path).await.unwrap();
    let pool = sqlx::SqlitePool::connect(path).await.unwrap();
    let columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pragma_table_info('auth_webauthn_challenge') WHERE name='ceremony'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(columns, 1);
    pool.close().await;
    // A second open finds the applied migration in the ledger and does not rerun it.
    vaelspire_store_sqlite::open(path).await.unwrap();
    let pool = sqlx::SqlitePool::connect(path).await.unwrap();
    let columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pragma_table_info('auth_webauthn_challenge') WHERE name='ceremony'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(columns, 1);
}
