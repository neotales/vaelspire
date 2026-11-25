//! Relations are schema-qualified, so a hostile `search_path` cannot redirect the store.
//!
//! The provider is configured with `search_path=decoy` only: `public` is absent. A decoy
//! schema holds same-shaped copies of every auth relation, so an unqualified statement
//! would succeed against the wrong schema instead of failing. The full contract still has
//! to operate on the migrated `public` relations.

#[path = "../../conformance.rs"]
// The shared module also carries a `social` helper that each runner calls under its own
// `social` test; this runner only needs the main contract.
#[allow(dead_code)]
mod shared;

use neotales_dbapi::{Pool, QueryOptions};
use neotales_dbapi_postgres::{Config, PoolOptions, PostgresPool, Profile};
use std::time::Duration;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use vaelspire_store_postgres::open;

/// A plaintext loopback provider whose sessions only see `search_path`.
fn provider(port: u16, search_path: &str) -> PostgresPool {
    let mut config = Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user("auth_test")
        .password("test-password")
        .dbname("auth_test")
        .options(format!("-c search_path={search_path}"));
    PostgresPool::loopback_plaintext_for_tests(
        config,
        PoolOptions::new(
            8,
            // Live tests are not testing deadline policy; a shared or loaded runner can
            // exceed a short budget and surface a sanitized unknown write outcome.
            Profile::normal(Duration::from_secs(60), Duration::from_secs(5)).expect("profile"),
            Duration::from_mins(15),
        )
        .expect("pool options"),
    )
    .expect("loopback provider")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_operations_stay_in_the_migrated_schema_with_public_absent() {
    let container = GenericImage::new("postgres", "17-alpine")
        .with_wait_for(WaitFor::log(
            LogWaitStrategy::stdout_or_stderr("database system is ready to accept connections")
                .with_times(2),
        ))
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_PASSWORD", "test-password")
        .with_env_var("POSTGRES_USER", "auth_test")
        .with_env_var("POSTGRES_DB", "auth_test")
        .start()
        .await
        .expect("Postgres container");
    let port = container
        .get_host_port_ipv4(5432.tcp())
        .await
        .expect("mapped port");
    let url = format!("postgres://auth_test:test-password@127.0.0.1:{port}/auth_test");
    let inspection = sqlx::PgPool::connect(&url).await.expect("inspection pool");
    sqlx::query("CREATE SCHEMA decoy")
        .execute(&inspection)
        .await
        .expect("decoy schema");

    // The migration is schema-qualified too, so it succeeds while `public` is not on
    // the provider's path.
    let connection = provider(port, "decoy");
    let store = open(connection.clone())
        .await
        .expect("migrate with public absent");

    // Same shape, same constraints; an unqualified statement would silently use these.
    sqlx::query(
        r"DO $$ DECLARE r record; BEGIN
            FOR r IN SELECT tablename FROM pg_tables
                WHERE schemaname='public' AND tablename LIKE 'auth\_%'
                AND tablename NOT LIKE 'auth\_schema\_history%'
            LOOP
                EXECUTE format(
                    'CREATE TABLE decoy.%I (LIKE public.%I INCLUDING ALL)',
                    r.tablename, r.tablename
                );
            END LOOP;
        END $$",
    )
    .execute(&inspection)
    .await
    .expect("decoy relations");

    shared::conformance(&store).await;

    let public_users: i64 = sqlx::query_scalar("SELECT count(*) FROM public.auth_user")
        .fetch_one(&inspection)
        .await
        .expect("public users");
    assert!(public_users > 0, "the migrated schema holds the accounts");
    for (relation, sql) in [
        ("auth_tenant", "SELECT count(*) FROM decoy.auth_tenant"),
        ("auth_user", "SELECT count(*) FROM decoy.auth_user"),
        ("auth_password", "SELECT count(*) FROM decoy.auth_password"),
        ("auth_session", "SELECT count(*) FROM decoy.auth_session"),
        ("auth_one_time", "SELECT count(*) FROM decoy.auth_one_time"),
        ("auth_role", "SELECT count(*) FROM decoy.auth_role"),
        (
            "auth_membership",
            "SELECT count(*) FROM decoy.auth_membership",
        ),
        ("auth_audit", "SELECT count(*) FROM decoy.auth_audit"),
    ] {
        let decoy_rows: i64 = sqlx::query_scalar(sql)
            .fetch_one(&inspection)
            .await
            .expect("decoy rows");
        assert_eq!(
            decoy_rows, 0,
            "{relation} must not be read or written through the decoy schema"
        );
    }

    // Prove the provider really hides `public`: the same unqualified name resolves to the
    // empty decoy relation on a store connection, while the qualified one has rows.
    let mut session = connection.acquire_async().await.expect("probe session");
    let path: String = session
        .fetch_one_async(
            "SELECT current_setting('search_path') AS path",
            QueryOptions::new(),
        )
        .await
        .expect("search path")
        .read("path")
        .expect("path text");
    assert_eq!(path, "decoy", "the provider session must not see public");
    let unqualified: i64 = session
        .fetch_one_async(
            "SELECT count(*) AS rows FROM auth_tenant",
            QueryOptions::new(),
        )
        .await
        .expect("decoy relation resolves")
        .read("rows")
        .expect("row count");
    let qualified: i64 = session
        .fetch_one_async(
            "SELECT count(*) AS rows FROM public.auth_tenant",
            QueryOptions::new(),
        )
        .await
        .expect("public relation resolves")
        .read("rows")
        .expect("row count");
    assert_eq!(unqualified, 0, "the decoy relation stays empty");
    assert!(qualified > 0, "the migrated relation holds the tenants");
}
