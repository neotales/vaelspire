//! The audit switch and invitation acceptance against a real SQLite file.
#![cfg(feature = "sqlx-compat")]

use sqlx::{Row, SqlitePool};
use time::Duration;
use vaelspire_auth::{Auth, IssuedSession, Policy, SignInOutcome, hash_password, verify_password};
use vaelspire_core::{AuthError, AuthStore, Id, MembershipStatus, Purpose, Timestamp};
use vaelspire_store_sqlite::{SqliteStore, open};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Hash where the application does: before the async workflow, not inside it.
fn hashed(password: &[u8]) -> String {
    hash_password(password).expect("hash")
}

/// Sign in through the split workflow: load, verify here, then finish.
async fn sign_in<S: AuthStore>(
    auth: &Auth<'_, S>,
    tenant: Id,
    email: &str,
    password: &[u8],
    now: Timestamp,
) -> Result<IssuedSession, AuthError> {
    let attempt = auth.begin_sign_in(tenant, email, now).await?;
    let verified = verify_password(password, attempt.password_hash()).unwrap_or(false);
    let replacement_hash = if verified && attempt.needs_rehash() {
        Some(hash_password(password)?)
    } else {
        None
    };
    let outcome = if verified {
        SignInOutcome::Verified {
            replacement_hash: replacement_hash.as_deref(),
        }
    } else {
        SignInOutcome::Failed
    };
    let result = auth.finish_sign_in(attempt, outcome, now).await?;
    #[cfg(feature = "mfa")]
    let result = match result {
        vaelspire_auth::SignInResult::Session(session) => session,
        vaelspire_auth::SignInResult::Pending(_) => panic!("unexpected MFA challenge"),
    };
    Ok(result)
}

struct Database {
    file: tempfile::NamedTempFile,
    pool: SqlitePool,
    store: SqliteStore,
}

async fn database() -> Database {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let path = file.path().to_str().expect("UTF-8 path");
    let store = open(path).await.expect("schema");
    let pool = SqlitePool::connect(path).await.expect("inspection pool");
    Database { file, pool, store }
}

async fn tenant(store: &SqliteStore, now: Timestamp) -> Id {
    let id = Id::now_v7();
    store.create_tenant(id, "audit", now).await.expect("tenant");
    id
}

/// `(action, outcome, actor, ip, user_agent)` for every audit row, oldest first.
async fn events(
    pool: &SqlitePool,
) -> Vec<(
    String,
    String,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
)> {
    sqlx::query("SELECT action,outcome,actor_id,ip,user_agent FROM auth_audit ORDER BY created_at")
        .fetch_all(pool)
        .await
        .expect("audit rows")
        .into_iter()
        .map(|row| {
            (
                row.try_get("action").expect("action"),
                row.try_get("outcome").expect("outcome"),
                row.try_get::<Option<Vec<u8>>, _>("actor_id")
                    .expect("actor"),
                row.try_get("ip").expect("ip"),
                row.try_get("user_agent").expect("user agent"),
            )
        })
        .collect()
}

#[tokio::test]
async fn audit_off_writes_nothing() {
    let database = database().await;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("instant");
    let tenant = tenant(&database.store, now).await;
    let auth = Auth::new(&database.store, [21; 32], Policy::default());
    let user = auth
        .sign_up(tenant, "quiet@example.test", &hashed(PASSWORD), now)
        .await
        .expect("register");
    sign_in(&auth, tenant, &user.email, PASSWORD, now)
        .await
        .expect("sign in");
    assert!(matches!(
        sign_in(&auth, tenant, &user.email, b"wrong", now).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        sign_in(&auth, tenant, "missing@example.test", PASSWORD, now).await,
        Err(AuthError::Unauthorized)
    ));
    let proof = auth
        .issue_proof(tenant, &user.email, Purpose::EmailOtp, now)
        .await
        .expect("email sign-in proof");
    auth.sign_in_with_email_proof(proof.expose(), now)
        .await
        .expect("email sign-in");
    assert!(matches!(
        auth.sign_in_with_email_proof(proof.expose(), now).await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        events(&database.pool).await.is_empty(),
        "audit is off unless the caller turns it on"
    );
    drop(database.store);
    database.pool.close().await;
    drop(database.file);
}

#[tokio::test]
async fn audit_on_records_issued_and_denied() {
    let database = database().await;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("instant");
    let tenant = tenant(&database.store, now).await;
    let auth = Auth::new(&database.store, [22; 32], Policy::default()).auditing(true);
    let user = auth
        .sign_up(tenant, "loud@example.test", &hashed(PASSWORD), now)
        .await
        .expect("register");
    let issued = sign_in(
        &auth,
        tenant,
        &user.email,
        PASSWORD,
        now + Duration::seconds(1),
    )
    .await
    .expect("sign in");
    assert!(matches!(
        sign_in(
            &auth,
            tenant,
            &user.email,
            b"wrong",
            now + Duration::seconds(2)
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        sign_in(
            &auth,
            tenant,
            "missing@example.test",
            PASSWORD,
            now + Duration::seconds(3)
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    auth.call()
        .ip("203.0.113.7")
        .user_agent("sqlite-test/1")
        .sign_out(issued.token().expose(), now + Duration::seconds(4))
        .await
        .expect("sign out");

    let rows = events(&database.pool).await;
    let summary: Vec<(&str, &str)> = rows
        .iter()
        .map(|(action, outcome, ..)| (action.as_str(), outcome.as_str()))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("auth.user.created", "ok"),
            ("auth.session.issued", "ok"),
            ("auth.session.denied", "denied"),
            ("auth.session.denied", "denied"),
            ("auth.session.revoked", "ok"),
        ]
    );
    assert_eq!(rows[1].2.as_deref(), Some(user.id.as_bytes().as_slice()));
    assert_eq!(
        rows[2].2.as_deref(),
        Some(user.id.as_bytes().as_slice()),
        "a wrong password names the account"
    );
    assert_eq!(rows[3].2, None, "an unknown account has no actor");
    assert_eq!(rows[1].3, None, "no carrier means a null ip");
    assert_eq!(rows[1].4, None);
    assert_eq!(rows[4].3.as_deref(), Some("203.0.113.7"));
    assert_eq!(rows[4].4.as_deref(), Some("sqlite-test/1"));
    drop(database.store);
    database.pool.close().await;
    drop(database.file);
}

#[tokio::test]
async fn invitation_accepts_once_and_the_seed_is_roles_only() {
    let database = database().await;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("instant");
    let tenant = tenant(&database.store, now).await;
    let auth = Auth::new(&database.store, [23; 32], Policy::default());
    let invitee = auth
        .sign_up(tenant, "invitee@example.test", &hashed(PASSWORD), now)
        .await
        .expect("register");
    let token = auth
        .issue_invitation(
            tenant,
            " Invitee@Example.Test ",
            now + Duration::hours(1),
            vec![],
            now,
        )
        .await
        .expect("invitation");

    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_digest FROM auth_invitation")
        .fetch_one(&database.pool)
        .await
        .expect("stored digest");
    assert_ne!(
        stored,
        token.expose().as_bytes(),
        "the raw token is never stored"
    );
    let email: String = sqlx::query_scalar("SELECT email FROM auth_invitation")
        .fetch_one(&database.pool)
        .await
        .expect("stored email");
    assert_eq!(email, "invitee@example.test");

    let membership = auth
        .accept_invitation(token.expose(), now)
        .await
        .expect("first acceptance");
    assert_eq!(membership.user_id, invitee.id);
    assert_eq!(membership.status, MembershipStatus::Active);
    assert_eq!(
        auth.accept_invitation(token.expose(), now).await,
        Err(AuthError::Unauthorized),
        "an invitation is spent once"
    );

    let seeded: Vec<String> = sqlx::query_scalar("SELECT name FROM auth_role ORDER BY name")
        .fetch_all(&database.pool)
        .await
        .expect("role catalogue");
    assert_eq!(
        seeded,
        ["admin", "member", "owner"],
        "the tenant was created with the three role names"
    );
    let permissions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_permission")
        .fetch_one(&database.pool)
        .await
        .expect("permission catalogue");
    assert_eq!(permissions, 0, "the library inserts no permission name");
    assert!(
        events(&database.pool).await.is_empty(),
        "audit stays off by default"
    );
    drop(database.store);
    database.pool.close().await;
    drop(database.file);
}
