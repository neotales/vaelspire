//! SQLite contract against a real temporary database file.
#![cfg(feature = "sqlx-compat")]

#[path = "../../conformance.rs"]
mod shared;

use neotales_dbapi::{ErrorKind, PoolPolicy, SqlitePolicyPool, TelemetryOutcome};
use neotales_dbapi_sqlite::{SqliteConfig, SqlitePoolProvider};
use sqlx::Connection;
use vaelspire_auth::{Auth, Policy};
use vaelspire_core::{AuthError, AuthStore, Id, Purpose, Timestamp};
use vaelspire_store_sqlite::{SqliteStore, migrate_with_pool, open};

#[tokio::test]
async fn reset_password_reports_store_when_writer_exceeds_configured_lock_budget() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    let provider = SqlitePoolProvider::connect(
        SqliteConfig::new(file.path()).busy_timeout(std::time::Duration::from_millis(20)),
    )
    .await
    .unwrap();
    migrate_with_pool(&provider).await.unwrap();
    let errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = std::sync::Arc::clone(&errors);
    let store = SqliteStore::new(SqlitePolicyPool::new(
        provider,
        PoolPolicy {
            telemetry_enabled: true,
            observer: Some(std::sync::Arc::new(move |event| {
                if let TelemetryOutcome::Error(kind) = event.outcome {
                    observed.lock().unwrap().push(kind);
                }
            })),
            ..PoolPolicy::default()
        },
    ));
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "lock-budget", now)
        .await
        .unwrap();
    let auth = Auth::new(&store, [42; 32], Policy::default());
    let hash = shared::hashed(b"synthetic lock-budget fixture");
    let user = auth
        .sign_up(tenant, "budget@example.test", &hash, now)
        .await
        .unwrap();
    let proof = auth
        .issue_proof(tenant, &user.email, Purpose::ResetPassword, now)
        .await
        .unwrap();
    let mut blocker = sqlx::SqliteConnection::connect(path).await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut blocker)
        .await
        .unwrap();
    assert_eq!(
        auth.reset_password(proof.expose(), &hash, now).await,
        Err(AuthError::Store)
    );
    assert_eq!(errors.lock().unwrap().as_slice(), &[ErrorKind::Busy]);
    sqlx::query("ROLLBACK").execute(&mut blocker).await.unwrap();
    // Only the controlled, authoritative Busy result is repeated. Unknown outcomes must not
    // enter this path; successful consumption proves the blocked attempt did not spend the proof.
    assert_eq!(
        auth.reset_password(proof.expose(), &hash, now).await,
        Ok(())
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqlite_conformance() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    // Keep overlapping API calls, but admit one SQLite writer at a time. Security outcomes
    // must not depend on the host completing several disk commits within one busy wait.
    // lock_budget.rs separately checks the default multi-connection policy and finite waits.
    let provider = SqlitePoolProvider::connect(SqliteConfig::new(file.path()).max_connections(1))
        .await
        .expect("provider");
    migrate_with_pool(&provider).await.expect("schema");
    let store = SqliteStore::new(provider);
    // Only stable operation/error categories: never SQL, values, or driver messages.
    let store = SqliteStore::new(SqlitePolicyPool::new(
        store.provider().clone(),
        PoolPolicy {
            telemetry_enabled: true,
            observer: Some(std::sync::Arc::new(|event| {
                if let TelemetryOutcome::Error(kind) = event.outcome {
                    eprintln!(
                        "auth sqlite stage: {:?}, kind: {kind:?}, elapsed_ms: {}",
                        event.operation,
                        event.duration.as_millis()
                    );
                }
            })),
            ..PoolPolicy::default()
        },
    ));
    let pool = sqlx::SqlitePool::connect(path)
        .await
        .expect("inspection pool");
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
            "SELECT count(*) FROM auth_social_state WHERE length(token_digest) <> 33",
        )
        .fetch_one(&pool)
        .await
        .expect("state digest width");
        assert_eq!(undigested, 0, "a state row is a versioned digest");
        let leaked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_social_state WHERE token_digest=?")
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
        "SELECT count(*) FROM auth_membership_role mr JOIN auth_role r ON r.id=mr.role_id WHERE r.name=?",
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

    // Legacy import is a fixture only. New registrations and resets cannot write bcrypt.
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
    sqlx::query("UPDATE auth_password SET password_hash=?,algorithm='bcrypt' WHERE user_id=?")
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
        sqlx::query_scalar("SELECT algorithm FROM auth_password WHERE user_id=?")
            .bind(user.id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .expect("algorithm");
    assert_eq!(algorithm, "argon2id");

    // The public proof digest is exactly what the one-time row stores, version byte and all.
    let proof = auth
        .issue_proof(tenant, "legacy@example.test", Purpose::VerifyEmail, now)
        .await
        .expect("verification proof");
    let (keyed, digest_hex) = auth.proof_digest(Purpose::VerifyEmail, proof.expose());
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT token_digest FROM auth_one_time WHERE purpose='verify_email' AND user_id=?",
    )
    .bind(user.id.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("stored proof digest");
    assert_eq!(stored.len(), 33, "version byte plus 32 bytes");
    assert_eq!(stored[0], 1);
    assert_eq!(&stored[1..], keyed.as_slice());
    assert_eq!(
        digest_hex.len(),
        64,
        "the hex column excludes the version byte"
    );

    // A changed address clears verification. The port does not expose that column, so it
    // is written and read here.
    sqlx::query("UPDATE auth_user SET email_verified_at=? WHERE id=?")
        .bind("2027-01-01T00:00:00.000000000Z")
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
        sqlx::query_scalar("SELECT email_verified_at IS NULL FROM auth_user WHERE id=?")
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
    drop(open(path).await.expect("reopen without rerunning DDL"));
}
