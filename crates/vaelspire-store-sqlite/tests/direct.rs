//! The shared auth contract through the direct SQLite provider.

#[path = "../../conformance.rs"]
mod shared;

use neotales_dbapi::{PoolPolicy, SqlitePolicyPool, TelemetryOutcome};
use neotales_dbapi_sqlite_direct::{SqliteConfig, SqlitePoolProvider};
use vaelspire_store_sqlite::{SqliteStore, migrate_with_pool};

#[tokio::test]
async fn direct_conformance() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    // Test the security transition under concurrent API calls, without assuming SQLite's
    // finite, non-FIFO writer wait always succeeds under host load. lock_budget.rs separately
    // covers default-pool security races, exhausted budgets, and single-writer admission.
    let pool = SqlitePoolProvider::connect(SqliteConfig::new(file.path()).max_connections(1))
        .await
        .expect("connect");
    migrate_with_pool(&pool).await.expect("schema");
    let store = SqliteStore::new(SqlitePolicyPool::new(
        pool.clone(),
        PoolPolicy {
            telemetry_enabled: true,
            observer: Some(std::sync::Arc::new(|event| {
                if let TelemetryOutcome::Error(kind) = event.outcome {
                    eprintln!(
                        "auth direct stage: {:?}, kind: {kind:?}, elapsed_ms: {}",
                        event.operation,
                        event.duration.as_millis(),
                    );
                }
            })),
            ..PoolPolicy::default()
        },
    ));
    shared::conformance(&store).await;
    #[cfg(feature = "social")]
    {
        let now =
            vaelspire_core::Timestamp::from_unix_timestamp(1_800_000_000).expect("test instant");
        let _ = shared::social(&store, now).await;
    }
    drop(store);
    pool.close();
    pool.wait_for_cleanup().await.expect("worker cleanup");
}
