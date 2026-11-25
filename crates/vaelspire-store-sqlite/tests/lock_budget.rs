//! Finite lock budgets, pool admission, and isolated security-transition concurrency.

use std::time::{Duration, Instant};

use neotales_dbapi::{ErrorKind, QueryOptions, SqlitePool, TxOptions, Value};
use vaelspire_auth::{Auth, Policy, SignInOutcome, hash_password_with};
use vaelspire_core::{AuthError, AuthStore, Id, Purpose, Timestamp};
use vaelspire_store_sqlite::{SqliteStore, migrate_with_pool};

async fn single_writer_admission(pool: &dyn SqlitePool) {
    pool.execute_async("CREATE TABLE admission(value INTEGER)", QueryOptions::new())
        .await
        .unwrap();
    let mut session = pool.acquire_sqlite_async().await.unwrap();
    let mut holder = session.begin_immediate_async().await.unwrap();
    holder
        .execute_async("INSERT INTO admission VALUES(1)", QueryOptions::new())
        .await
        .unwrap();
    let mut waiting = pool.execute_async("INSERT INTO admission VALUES(2)", QueryOptions::new());
    // Admission waits beyond the 40ms SQLite lock budget because no second connection or
    // statement has been dispatched. Keep this same future: do not abandon or replay a write.
    assert!(
        tokio::time::timeout(Duration::from_millis(80), waiting.as_mut())
            .await
            .is_err()
    );
    holder.commit_async().await.unwrap();
    drop(session);
    assert_eq!(waiting.await.unwrap(), 1);
    assert_eq!(
        pool.fetch_scalar_async("SELECT count(*) FROM admission", QueryOptions::new())
            .await
            .unwrap(),
        Value::I64(2)
    );
}

#[tokio::test]
async fn sqlx_single_writer_admission_is_not_a_sqlite_lock_wait_or_retry() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite::SqlitePoolProvider::connect(
        neotales_dbapi_sqlite::SqliteConfig::new(file.path())
            .max_connections(1)
            .busy_timeout(Duration::from_millis(40)),
    )
    .await
    .unwrap();
    single_writer_admission(&pool).await;
}

#[tokio::test]
async fn direct_single_writer_admission_is_not_a_sqlite_lock_wait_or_retry() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite_direct::SqlitePoolProvider::connect(
        neotales_dbapi_sqlite_direct::SqliteConfig::new(file.path())
            .max_connections(1)
            .busy_timeout(Duration::from_millis(40)),
    )
    .await
    .unwrap();
    single_writer_admission(&pool).await;
    pool.close();
    pool.wait_for_cleanup().await.unwrap();
}

async fn concurrent_transitions<P: SqlitePool>(pool: P) {
    migrate_with_pool(&pool).await.unwrap();
    let store = SqliteStore::new(pool);
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "concurrency", now)
        .await
        .unwrap();
    let auth = Auth::new(&store, [42; 32], Policy::default());
    // The contract here is the store transition, not password verification or KDF throughput.
    // A small explicit test cost avoids contending with SQLite workers for CPU and memory.
    let hash = hash_password_with(b"synthetic fixture", 32, 1, 1).unwrap();
    let user = auth
        .sign_up(tenant, "concurrency@example.test", &hash, now)
        .await
        .unwrap();
    let mut attempts = Vec::new();
    for _ in 0..5 {
        attempts.push(auth.begin_sign_in(tenant, &user.email, now).await.unwrap());
    }
    let mut attempts = attempts.into_iter();
    let results = tokio::join!(
        auth.finish_sign_in(attempts.next().unwrap(), SignInOutcome::Failed, now),
        auth.finish_sign_in(attempts.next().unwrap(), SignInOutcome::Failed, now),
        auth.finish_sign_in(attempts.next().unwrap(), SignInOutcome::Failed, now),
        auth.finish_sign_in(attempts.next().unwrap(), SignInOutcome::Failed, now),
        auth.finish_sign_in(attempts.next().unwrap(), SignInOutcome::Failed, now),
    );
    for result in [results.0, results.1, results.2, results.3, results.4] {
        assert!(matches!(result, Err(AuthError::Unauthorized)));
    }
    let credential = store.password(user.id).await.unwrap();
    assert_eq!(credential.failed_attempts, 5);
    assert!(credential.locked_until.is_some());
    let proof = auth
        .issue_proof(tenant, &user.email, Purpose::ResetPassword, now)
        .await
        .unwrap();
    let results = tokio::join!(
        auth.reset_password(proof.expose(), &hash, now),
        auth.reset_password(proof.expose(), &hash, now),
    );
    assert!(matches!(
        results,
        (Ok(()), Err(AuthError::Unauthorized)) | (Err(AuthError::Unauthorized), Ok(()))
    ));
    assert_eq!(store.password(user.id).await.unwrap().failed_attempts, 0);
}

#[tokio::test]
async fn sqlx_default_pool_concurrent_security_transitions_without_kdf_load() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite::SqlitePoolProvider::connect(
        neotales_dbapi_sqlite::SqliteConfig::new(file.path()),
    )
    .await
    .unwrap();
    concurrent_transitions(pool).await;
}

#[tokio::test]
async fn direct_default_pool_concurrent_security_transitions_without_kdf_load() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite_direct::SqlitePoolProvider::connect(
        neotales_dbapi_sqlite_direct::SqliteConfig::new(file.path()),
    )
    .await
    .unwrap();
    concurrent_transitions(pool.clone()).await;
    pool.close();
    pool.wait_for_cleanup().await.unwrap();
}

async fn lock_budget(pool: &dyn SqlitePool) {
    migrate_with_pool(pool).await.unwrap();
    pool.execute_async(
        "CREATE TABLE budget_probe(value INTEGER)",
        QueryOptions::new(),
    )
    .await
    .unwrap();
    // Hold both physical checkouts. Migration's 5,000ms override must not escape its lease.
    let mut first = pool.acquire_sqlite_async().await.unwrap();
    let mut second = pool.acquire_sqlite_async().await.unwrap();
    for session in [&mut first, &mut second] {
        assert_eq!(
            session
                .fetch_scalar_async("PRAGMA busy_timeout", QueryOptions::new())
                .await
                .unwrap(),
            Value::I64(40),
        );
    }
    first
        .execute_async("PRAGMA busy_timeout = 1", QueryOptions::new())
        .await
        .unwrap();
    drop(first);
    let mut first = pool.acquire_sqlite_async().await.unwrap();
    let mut holder = first.begin_immediate_async().await.unwrap();
    assert_eq!(
        holder
            .fetch_scalar_async("PRAGMA busy_timeout", QueryOptions::new())
            .await
            .unwrap(),
        Value::I64(40),
        "checkout must restore the configured budget inside transactions too",
    );
    holder
        .execute_async("INSERT INTO budget_probe VALUES(1)", QueryOptions::new())
        .await
        .unwrap();
    // The holder cannot finish until this await returns: contention is guaranteed, not a sleep.
    let mut contender = second.begin_async(TxOptions::default()).await.unwrap();
    let started = Instant::now();
    let error = contender
        .execute_async("INSERT INTO budget_probe VALUES(2)", QueryOptions::new())
        .await
        .unwrap_err();
    eprintln!(
        "sqlite lock-budget stage: Execute, kind: {:?}, elapsed_ms: {}",
        error.kind(),
        started.elapsed().as_millis()
    );
    assert_eq!(error.kind(), ErrorKind::Busy);
    // No upper wall-clock assertion: a descheduled worker is not an incorrect busy handler.
    assert!(started.elapsed() >= Duration::from_millis(40));
    drop(contender);
    drop(second);
    holder.rollback_async().await.unwrap();
    drop(first);
    assert_eq!(
        pool.fetch_scalar_async("SELECT count(*) FROM budget_probe", QueryOptions::new())
            .await
            .unwrap(),
        Value::I64(0),
        "no attempt is retried and the explicitly rolled-back holder leaves no row",
    );
}

#[tokio::test]
async fn sqlx_checkout_and_transaction_restore_the_finite_lock_budget() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite::SqlitePoolProvider::connect(
        neotales_dbapi_sqlite::SqliteConfig::new(file.path())
            .max_connections(2)
            .busy_timeout(Duration::from_millis(40)),
    )
    .await
    .unwrap();
    lock_budget(&pool).await;
}

#[tokio::test]
async fn direct_checkout_and_transaction_restore_the_finite_lock_budget() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite_direct::SqlitePoolProvider::connect(
        neotales_dbapi_sqlite_direct::SqliteConfig::new(file.path())
            .max_connections(2)
            .busy_timeout(Duration::from_millis(40)),
    )
    .await
    .unwrap();
    lock_budget(&pool).await;
    pool.close();
    pool.wait_for_cleanup().await.unwrap();
}

#[tokio::test]
async fn direct_sync_checkout_restores_the_transaction_lock_budget() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let pool = neotales_dbapi_sqlite_direct::SqlitePoolProvider::connect_sync(
        neotales_dbapi_sqlite_direct::SqliteConfig::new(file.path())
            .max_connections(1)
            .busy_timeout(Duration::from_millis(40)),
    )
    .unwrap();
    let mut session = pool.acquire_sync_sqlite().unwrap();
    neotales_dbapi::sync::Session::execute(
        &mut session,
        "PRAGMA busy_timeout = 1",
        QueryOptions::new(),
    )
    .unwrap();
    drop(session);
    let mut session = pool.acquire_sync_sqlite().unwrap();
    let mut tx = session.begin_immediate().unwrap();
    assert_eq!(
        tx.fetch_scalar("PRAGMA busy_timeout", QueryOptions::new())
            .unwrap(),
        Value::I64(40),
    );
    tx.rollback().unwrap();
    drop(session);
    pool.close();
    pool.wait_for_cleanup().await.unwrap();
}
