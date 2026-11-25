//! PostgreSQL runs the same contract as SQLite; requires Docker and is not ignored.

#[path = "../../conformance.rs"]
mod shared;

use neotales_dbapi_postgres::{Config, PoolOptions, PostgresPool, Profile};
use std::time::Duration;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::LogWaitStrategy},
    runners::AsyncRunner,
};
use vaelspire_auth::{Auth, Policy};
use vaelspire_core::{AuthStore, Id, Timestamp};
use vaelspire_store_postgres::open;

/// A plaintext loopback provider over the disposable container. The provider is only
/// insecure because every host is a numeric loopback address.
fn provider(port: u16) -> PostgresPool {
    let mut config = Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user("auth_test")
        .password("test-password")
        .dbname("auth_test");
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
async fn postgres_conformance() {
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
    let connection = provider(port);
    let store = open(connection.clone()).await.expect("schema");
    let pool = sqlx::PgPool::connect(&url).await.expect("inspection pool");
    shared::conformance(&store).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit")
        .fetch_one(&pool)
        .await
        .expect("audit count");
    assert_eq!(
        count, 14,
        "one safe row, three reserved ids, three email sign-in rows, three revoked sessions, three account changes, and one API-key revoke"
    );
    let revoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE action='auth.session.revoked' AND outcome='ok'",
    )
    .fetch_one(&pool)
    .await
    .expect("revoked-session rows");
    assert_eq!(revoked, 3, "each revoke writes one row");
    let key_revoked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE action='auth.api_key.revoked' AND outcome='ok'",
    )
    .fetch_one(&pool)
    .await
    .expect("revoked-key row");
    assert_eq!(key_revoked, 1, "the API-key revoke commits its row");
    let email_issue: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE action='auth.proof.issued' AND outcome='ok'",
    )
    .fetch_one(&pool)
    .await
    .expect("email sign-in issue row");
    assert_eq!(email_issue, 1, "issue writes one audit row");
    let email_denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE action='auth.session.denied' AND outcome='denied'",
    )
    .fetch_one(&pool)
    .await
    .expect("email sign-in denial row");
    assert_eq!(email_denied, 1, "a second spend writes one denial row");
    #[cfg(feature = "social")]
    {
        let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("instant");
        let raw_state = shared::social(&store, now).await;
        let states: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_social_state")
            .fetch_one(&pool)
            .await
            .expect("social states");
        assert!(states >= 5, "each start stores a state");
        let undigested: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_social_state WHERE octet_length(token_digest) <> 33",
        )
        .fetch_one(&pool)
        .await
        .expect("state digest width");
        assert_eq!(undigested, 0, "a state row is a versioned digest");
        let leaked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_social_state WHERE token_digest=$1")
                .bind(&raw_state)
                .fetch_one(&pool)
                .await
                .expect("raw state lookup");
        assert_eq!(leaked, 0, "the raw state is never stored");
        let identity: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_social_identity WHERE subject='subject-1'",
        )
        .fetch_one(&pool)
        .await
        .expect("social identity");
        assert_eq!(identity, 1, "one subject maps to one account");
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_audit a JOIN auth_user u ON u.id=a.actor_id \
             WHERE u.email='social-created@example.test' AND a.action='auth.session.issued'",
        )
        .fetch_one(&pool)
        .await
        .expect("social audit rows");
        assert_eq!(audited, 2, "each social session commits its audit row");
        let quiet: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_audit a JOIN auth_user u ON u.id=a.actor_id \
             WHERE u.email='social-quiet@example.test'",
        )
        .fetch_one(&pool)
        .await
        .expect("quiet audit rows");
        assert_eq!(quiet, 0, "auditing off writes no row");
    }
    let assigned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_membership_role mr JOIN auth_role r ON r.id=mr.role_id WHERE r.name=$1",
    )
    .bind(shared::ATOMIC_ROLE)
    .fetch_one(&pool)
    .await
    .expect("atomic role assignment");
    assert_eq!(
        assigned, 0,
        "a failed audit insert leaves no role assignment"
    );
    // A tenant is created with three role names; the suite adds only `conformance.`
    // names on top, and no permission is seeded.
    let tenants: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_tenant")
        .fetch_one(&pool)
        .await
        .expect("tenant count");
    let seeded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT tenant_id FROM auth_role \
         WHERE name IN ('owner','admin','member') \
         GROUP BY tenant_id HAVING count(DISTINCT name)=3) seeded",
    )
    .fetch_one(&pool)
    .await
    .expect("seeded role count");
    assert_eq!(
        seeded, tenants,
        "every tenant was created with the three role names"
    );
    let unseeded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_role \
         WHERE name NOT LIKE 'conformance.%' AND name NOT IN ('owner','admin','member')",
    )
    .fetch_one(&pool)
    .await
    .expect("caller-named role");
    assert_eq!(unseeded, 0, "a role outside the seed is the caller's");
    let permissions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_permission WHERE name NOT LIKE 'conformance.%'",
    )
    .fetch_one(&pool)
    .await
    .expect("permission catalogue");
    assert_eq!(permissions, 0, "no permission is seeded");
    assert!(
        sqlx::query("UPDATE auth_audit SET outcome='error'")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM auth_audit")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("INSERT INTO auth_audit(password) VALUES('refused')")
            .execute(&pool)
            .await
            .is_err()
    );
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("instant");
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "legacy", now)
        .await
        .expect("tenant");
    let auth = Auth::new(&store, [42; 32], Policy::default());
    let password = b"legacy password";
    let user = auth
        .sign_up(
            tenant,
            "legacy@example.test",
            &shared::hashed(password),
            now,
        )
        .await
        .expect("user");
    let legacy = bcrypt::hash(password, 4).expect("legacy fixture");
    sqlx::query("UPDATE auth_password SET password_hash=$1,algorithm='bcrypt' WHERE user_id=$2")
        .bind(&legacy)
        .bind(user.id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .expect("import fixture");
    shared::sign_in(&auth, tenant, &user.email, password, now)
        .await
        .expect("legacy login");
    assert!(
        store
            .password(user.id)
            .await
            .expect("upgraded hash")
            .password_hash
            .starts_with("$argon2id$")
    );
    let algorithm: String =
        sqlx::query_scalar("SELECT algorithm FROM auth_password WHERE user_id=$1")
            .bind(user.id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .expect("algorithm");
    assert_eq!(algorithm, "argon2id");

    // A changed address clears verification. The port does not expose that column, so it
    // is written and read here.
    sqlx::query("UPDATE auth_user SET email_verified_at=$1 WHERE id=$2")
        .bind(1_800_000_000_000_000_i64)
        .bind(user.id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .expect("verified instant");
    let session = shared::sign_in(&auth, tenant, &user.email, password, now)
        .await
        .expect("session for the change");
    let presented = auth
        .resolve_session(session.token().expose(), now)
        .await
        .expect("presented session");
    auth.change_email(&presented, "legacy-new@example.test", now)
        .await
        .expect("change the address");
    let unverified: bool =
        sqlx::query_scalar("SELECT email_verified_at IS NULL FROM auth_user WHERE id=$1")
            .bind(user.id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .expect("verification state");
    assert!(unverified, "a changed address is unverified");
    shared::session_extension(
        &store,
        Timestamp::from_unix_timestamp(1_800_000_000).unwrap(),
    )
    .await;
    drop(store);
    pool.close().await;
    drop(open(connection).await.expect("reopen"));
}
