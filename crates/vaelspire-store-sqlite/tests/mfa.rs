//! MFA enrollment storage against a real SQLite database.
#![cfg(feature = "mfa")]
#![cfg(feature = "sqlx-compat")]

use vaelspire_auth::{Auth, Policy, SignInOutcome, SignInResult, hash_password, mfa};
use vaelspire_core::{AuthError, AuthStore, Id, Timestamp};
use vaelspire_store_sqlite::open;

#[tokio::test]
#[allow(clippy::too_many_lines)] // One enrollment, challenge, replay, and recovery scenario.
async fn enrollment_confirms_only_the_current_code_and_denies_password_only_login() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    let store = open(path).await.unwrap();
    let pool = sqlx::SqlitePool::connect(path).await.unwrap();
    let now = Timestamp::from_unix_timestamp(59).unwrap();
    let tenant = Id::now_v7();
    store.create_tenant(tenant, "mfa", now).await.unwrap();
    let auth = Auth::new(&store, [1; 32], Policy::default());
    let hash = hash_password(b"a sufficient password").unwrap();
    let user = auth
        .sign_up(tenant, "user@example.test", &hash, now)
        .await
        .unwrap();
    let key = [2; 32];
    let secret = b"12345678901234567890";
    let ciphertext = mfa::encrypt_secret(&key, secret, user.id.as_bytes()).unwrap();
    store
        .save_mfa(user.id, &ciphertext, "test-key")
        .await
        .unwrap();
    assert!(store.load_mfa(user.id).await.unwrap().enabled_at.is_none());
    assert_eq!(
        auth.confirm_totp(user.id, "test-key", &key, "000000", now)
            .await,
        Err(AuthError::Unauthorized)
    );
    auth.confirm_totp(user.id, "test-key", &key, "287082", now)
        .await
        .unwrap();
    assert_eq!(store.load_mfa(user.id).await.unwrap().enabled_at, Some(now));
    let attempt = auth.begin_sign_in(tenant, &user.email, now).await.unwrap();
    let SignInResult::Pending(pending) = auth
        .finish_sign_in(
            attempt,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .unwrap()
    else {
        panic!("expected pending login")
    };
    assert!(matches!(
        auth.finish_mfa(pending.token().expose(), "000000", "test-key", &key, now)
            .await,
        Err(AuthError::Unauthorized)
    ));
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
    let session = auth
        .finish_mfa(pending.token().expose(), "287082", "test-key", &key, now)
        .await
        .unwrap();
    auth.resolve_session(session.token().expose(), now)
        .await
        .unwrap();
    assert!(
        auth.finish_mfa(pending.token().expose(), "287082", "test-key", &key, now)
            .await
            .is_err()
    );

    let recovery = auth.issue_recovery_code(user.id).await.unwrap();
    assert_ne!(recovery.expose(), "");
    assert!(!format!("{recovery:?}").contains(recovery.expose()));
    let attempt = auth.begin_sign_in(tenant, &user.email, now).await.unwrap();
    let SignInResult::Pending(pending) = auth
        .finish_sign_in(
            attempt,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .unwrap()
    else {
        panic!("expected pending")
    };
    auth.finish_mfa(
        pending.token().expose(),
        recovery.expose(),
        "test-key",
        &key,
        now,
    )
    .await
    .unwrap();
    let attempt = auth.begin_sign_in(tenant, &user.email, now).await.unwrap();
    let SignInResult::Pending(pending) = auth
        .finish_sign_in(
            attempt,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .unwrap()
    else {
        panic!("expected pending")
    };
    assert!(matches!(
        auth.finish_mfa(
            pending.token().expose(),
            recovery.expose(),
            "test-key",
            &key,
            now
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    assert!(
        auth.finish_mfa(
            pending.token().expose(),
            "287082",
            "test-key",
            &key,
            now + std::time::Duration::from_secs(360)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn recovery_digest_is_consumed_once_for_its_owner() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = open(file.path().to_str().unwrap()).await.unwrap();
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();
    let tenant = Id::now_v7();
    store.create_tenant(tenant, "mfa", now).await.unwrap();
    let auth = Auth::new(&store, [1; 32], Policy::default());
    let hash = hash_password(b"a sufficient password").unwrap();
    let user = auth
        .sign_up(tenant, "user@example.test", &hash, now)
        .await
        .unwrap();
    let digest = [3; 32];
    store
        .insert_recovery_code(Id::now_v7(), user.id, &digest)
        .await
        .unwrap();
    assert_eq!(
        store
            .consume_recovery_code(Id::now_v7(), &digest, now)
            .await,
        Err(AuthError::Unauthorized)
    );
    store
        .consume_recovery_code(user.id, &digest, now)
        .await
        .unwrap();
    assert_eq!(
        store.consume_recovery_code(user.id, &digest, now).await,
        Err(AuthError::Unauthorized)
    );
}

#[tokio::test]
async fn enroll_does_not_store_plaintext_and_cannot_replace_factor() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let store = open(file.path().to_str().unwrap()).await.unwrap();
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();
    let tenant = Id::now_v7();
    store.create_tenant(tenant, "mfa", now).await.unwrap();
    let auth = Auth::new(&store, [1; 32], Policy::default());
    let hash = hash_password(b"a sufficient password").unwrap();
    let user = auth
        .sign_up(tenant, "user@example.test", &hash, now)
        .await
        .unwrap();
    let secret = auth
        .enroll_totp(user.id, "test-key", &[2; 32])
        .await
        .unwrap();
    let factor = store.load_mfa(user.id).await.unwrap();
    assert!(
        !factor
            .secret_crypt
            .windows(secret.expose().len())
            .any(|w| w == secret.expose().as_bytes())
    );
    assert!(matches!(
        auth.enroll_totp(user.id, "test-key", &[2; 32]).await,
        Err(AuthError::Conflict)
    ));
}

#[tokio::test]
async fn password_change_invalidates_pending_mfa() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    let store = open(path).await.unwrap();
    let pool = sqlx::SqlitePool::connect(path).await.unwrap();
    let now = Timestamp::from_unix_timestamp(59).unwrap();
    let tenant = Id::now_v7();
    store.create_tenant(tenant, "mfa", now).await.unwrap();
    let auth = Auth::new(&store, [1; 32], Policy::default());
    let hash = hash_password(b"a sufficient password").unwrap();
    let user = auth
        .sign_up(tenant, "user@example.test", &hash, now)
        .await
        .unwrap();
    let key = [2; 32];
    let ciphertext =
        mfa::encrypt_secret(&key, b"12345678901234567890", user.id.as_bytes()).unwrap();
    store
        .save_mfa(user.id, &ciphertext, "test-key")
        .await
        .unwrap();
    auth.confirm_totp(user.id, "test-key", &key, "287082", now)
        .await
        .unwrap();
    let attempt = auth.begin_sign_in(tenant, &user.email, now).await.unwrap();
    let SignInResult::Pending(pending) = auth
        .finish_sign_in(
            attempt,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .unwrap()
    else {
        panic!("expected pending")
    };
    let new_hash = hash_password(b"a different sufficient password").unwrap();
    sqlx::query("UPDATE auth_password SET password_hash=? WHERE user_id=?")
        .bind(new_hash)
        .bind(user.id.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        auth.finish_mfa(pending.token().expose(), "287082", "test-key", &key, now)
            .await,
        Err(AuthError::Unauthorized)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_session")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
