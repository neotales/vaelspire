// Shared black-box contract: both real database adapters run this exact suite.
use time::Duration;
use vaelspire_auth::{
    ApiKeys, Auth, IssuedSession, Policy, SignInOutcome, hash_password, verify_password,
};
use vaelspire_core::{
    AuditEvent, AuthError, AuthStore, Id, Invitation, Membership, MembershipStatus, OneTime,
    Purpose, Session, Timestamp, User,
};

const PASSWORD: &[u8] = b"correct horse battery staple";
const KEY: [u8; 32] = [42; 32]; // Synthetic fixture, not an application credential.

/// Hash where the application does: before the async workflow, not inside it.
pub(crate) fn hashed(password: &[u8]) -> String {
    hash_password(password).expect("hash")
}

/// Sign in through the split workflow: load, verify here, then finish.
pub(crate) async fn sign_in<S: AuthStore>(
    auth: &Auth<'_, S>,
    tenant: Id,
    email: &str,
    password: &[u8],
    now: Timestamp,
) -> Result<IssuedSession, AuthError> {
    let attempt = auth.begin_sign_in(tenant, email, now).await?;
    // Password hashing is CPU-bound. Do not block the async executor while another
    // sign-in may be holding a database transaction open.
    let password = password.to_vec();
    let encoded_hash = attempt.password_hash().to_owned();
    let needs_rehash = attempt.needs_rehash();
    let (verified, replacement_hash) = tokio::task::spawn_blocking(move || {
        let verified = verify_password(&password, &encoded_hash).unwrap_or(false);
        let replacement_hash = if verified && needs_rehash {
            Some(hash_password(&password)?)
        } else {
            None
        };
        Ok::<_, AuthError>((verified, replacement_hash))
    })
    .await
    .expect("password worker")?;
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

pub(crate) async fn conformance<S: AuthStore>(store: &S) {
    let now = Timestamp::from_unix_timestamp(1_800_000_000).expect("test instant");
    let auth = Auth::new(store, KEY, Policy::default());
    let user = registration_and_sessions(store, &auth, now).await;
    let live = lockout(store, &auth, &user, now).await;
    proofs(&auth, &user, now, &live).await;
    email_sign_in(store, &user, now).await;
    reset_invalidates_email_sign_in(store, &user, now).await;
    api_keys(store, &user, now).await;
    audit(store, &user, now).await;
    atomic_audit(store, now).await;
    unsupported_defaults(now).await;
    let (role, other_role, other) = catalogue(store, &auth, user.tenant_id, now).await;
    seeded_roles(store, &auth, now).await;
    memberships(&auth, &user, other, role, other_role, now).await;
    groups(&auth, &user, other, now).await;
    let accepted = invitations(&auth, &user, role, other_role, now).await;
    reinvitation(&auth, &user, accepted, now).await;
    suspended_tenant(store, &auth, now).await;
    fractional_expiry(&auth, &user, now + Duration::hours(1)).await;
    policy(store, now).await;
    session_management(store, now).await;
    signed_in_account_changes(store, now).await;
    #[cfg(feature = "mfa")]
    second_factor(store).await;
    #[cfg(feature = "mfa")]
    enrolled_second_factor(store).await;
}

/// Second-factor enrollment and login. The TOTP vector is the RFC 6238 SHA-1 sample for
/// T = 59 with the 20-byte ASCII secret, so the expected code is the same on every backend.
#[cfg(feature = "mfa")]
#[allow(clippy::too_many_lines)] // One enrollment, challenge, replay, and recovery scenario.
async fn second_factor<S: AuthStore>(store: &S) {
    use vaelspire_auth::mfa as totp;

    let now = Timestamp::from_unix_timestamp(59).expect("TOTP instant");
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "mfa", now)
        .await
        .expect("MFA tenant");
    let auth = Auth::new(store, KEY, Policy::default());
    let user = auth
        .sign_up(tenant, "mfa@example.test", &hashed(PASSWORD), now)
        .await
        .expect("MFA account");
    let key = [7u8; 32];
    let secret = b"12345678901234567890";
    let ciphertext = totp::encrypt_secret(&key, secret, user.id.as_bytes()).expect("enrollment");
    store
        .save_mfa(user.id, &ciphertext, "conformance-key")
        .await
        .expect("factor");
    let factor = store.load_mfa(user.id).await.expect("factor");
    assert!(factor.enabled_at.is_none(), "enrollment starts unconfirmed");
    assert!(
        !factor
            .secret_crypt
            .windows(secret.len())
            .any(|window| window == secret),
        "the stored factor is ciphertext"
    );
    assert!(matches!(
        auth.confirm_totp(user.id, "conformance-key", &key, "000000", now)
            .await,
        Err(AuthError::Unauthorized)
    ));
    auth.confirm_totp(user.id, "conformance-key", &key, "287082", now)
        .await
        .expect("confirmed factor");
    assert_eq!(
        store.load_mfa(user.id).await.expect("factor").enabled_at,
        Some(now)
    );

    let pending = pending_login(&auth, tenant, &user.email, now).await;
    assert!(matches!(
        auth.finish_mfa(
            pending.token().expose(),
            "000000",
            "conformance-key",
            &key,
            now
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
    let session = auth
        .finish_mfa(
            pending.token().expose(),
            "287082",
            "conformance-key",
            &key,
            now,
        )
        .await
        .expect("second factor");
    auth.resolve_session(session.token().expose(), now)
        .await
        .expect("MFA session");
    assert!(
        auth.finish_mfa(
            pending.token().expose(),
            "287082",
            "conformance-key",
            &key,
            now
        )
        .await
        .is_err(),
        "a consumed challenge cannot be replayed"
    );

    let recovery = auth.issue_recovery_code(user.id).await.expect("recovery");
    assert_ne!(recovery.expose(), "");
    assert!(!format!("{recovery:?}").contains(recovery.expose()));
    let pending = pending_login(&auth, tenant, &user.email, now).await;
    auth.finish_mfa(
        pending.token().expose(),
        recovery.expose(),
        "conformance-key",
        &key,
        now,
    )
    .await
    .expect("recovery sign-in");
    let pending = pending_login(&auth, tenant, &user.email, now).await;
    assert!(matches!(
        auth.finish_mfa(
            pending.token().expose(),
            recovery.expose(),
            "conformance-key",
            &key,
            now
        )
        .await,
        Err(AuthError::Unauthorized)
    ));
}

/// Public enrollment through [`Auth::enroll_totp`]: the caller-visible secret is decoded and
/// must match the key the store holds, and the confirmation code is derived from that decoded
/// value at a fixed instant so the check stays deterministic without a hard-coded code.
#[cfg(feature = "mfa")]
async fn enrolled_second_factor<S: AuthStore>(store: &S) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use vaelspire_auth::mfa as totp;

    let now = Timestamp::from_unix_timestamp(59).expect("TOTP instant");
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "mfa-enrolled", now)
        .await
        .expect("tenant");
    let auth = Auth::new(store, KEY, Policy::default());
    let user = auth
        .sign_up(tenant, "enrolled@example.test", &hashed(PASSWORD), now)
        .await
        .expect("account");
    let key = [9u8; 32];
    let secret = auth
        .enroll_totp(user.id, "enrolled-key", &key)
        .await
        .expect("enrollment");
    assert_ne!(secret.expose(), "");
    assert!(!format!("{secret:?}").contains(secret.expose()));
    // Decode the caller-visible value exactly as an application would before showing it to
    // an authenticator or computing a code.
    let decoded = URL_SAFE_NO_PAD
        .decode(secret.expose())
        .expect("unpadded URL-safe base64 enrollment secret");
    let factor = store.load_mfa(user.id).await.expect("factor");
    assert!(factor.enabled_at.is_none(), "enrollment starts unconfirmed");
    assert_eq!(factor.key_id, "enrolled-key");
    let stored = totp::decrypt_secret(&key, &factor.secret_crypt, user.id.as_bytes())
        .expect("stored plaintext");
    assert_eq!(
        decoded.as_slice(),
        stored.as_slice(),
        "the returned secret decodes to the key the store holds"
    );
    assert_eq!(decoded.len(), 20, "the enrolled TOTP secret is 160 bits");
    let code = totp::totp_code(&decoded, 59);
    let (first, rest) = code.split_at(1);
    let wrong = format!("{}{rest}", if first == "0" { "1" } else { "0" });
    assert!(matches!(
        auth.confirm_totp(user.id, "enrolled-key", &key, &wrong, now)
            .await,
        Err(AuthError::Unauthorized)
    ));
    auth.confirm_totp(user.id, "enrolled-key", &key, &code, now)
        .await
        .expect("confirmed factor");
    assert_eq!(
        store.load_mfa(user.id).await.expect("factor").enabled_at,
        Some(now)
    );

    let pending = pending_login(&auth, tenant, &user.email, now).await;
    let session = auth
        .finish_mfa(pending.token().expose(), &code, "enrolled-key", &key, now)
        .await
        .expect("second factor");
    auth.resolve_session(session.token().expose(), now)
        .await
        .expect("MFA session");
    assert!(
        auth.finish_mfa(pending.token().expose(), &code, "enrolled-key", &key, now)
            .await
            .is_err(),
        "a consumed challenge cannot be replayed"
    );
}

/// The first factor of an MFA-enabled account must produce a pending challenge.
#[cfg(feature = "mfa")]
async fn pending_login<S: AuthStore>(
    auth: &Auth<'_, S>,
    tenant: Id,
    email: &str,
    now: Timestamp,
) -> vaelspire_auth::PendingSignIn {
    let attempt = auth
        .begin_sign_in(tenant, email, now)
        .await
        .expect("attempt");
    match auth
        .finish_sign_in(
            attempt,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .expect("first factor")
    {
        vaelspire_auth::SignInResult::Pending(pending) => pending,
        vaelspire_auth::SignInResult::Session(_) => panic!("an MFA account must challenge"),
    }
}

/// The signed-in account's own password, address, and deletion. Each mutation commits its
/// audit row in the same transaction, so a failed insert leaves the account as it was.
async fn signed_in_account_changes<S: AuthStore>(store: &S, now: Timestamp) {
    change_password_keeps_the_presented_session(store, now).await;
    change_password_needs_the_current_hash(store, now).await;
    change_email_replaces_the_address(store, now).await;
    delete_marks_the_account_and_revokes_every_session(store, now).await;
    changes_roll_back_with_their_audit(store, now).await;
}

/// A password change writes the new hash, spends outstanding email sign-in proofs, and
/// revokes every session except the presented one.
async fn change_password_keeps_the_presented_session<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "password-change", "change@example.test", 3, now).await;
    let audited = Auth::new(store, [23; 32], Policy::default()).auditing(true);
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");
    let proof = auth
        .issue_proof(user.tenant_id, &user.email, Purpose::EmailOtp, now)
        .await
        .expect("email sign-in proof");
    let credential = store.password(user.id).await.expect("credential");
    let replacement = b"a replacement password";
    audited
        .change_password(
            &current,
            &credential.password_hash,
            &hashed(replacement),
            now,
        )
        .await
        .expect("change the password");

    assert!(
        matches!(
            sign_in(&auth, user.tenant_id, &user.email, PASSWORD, now).await,
            Err(AuthError::Unauthorized)
        ),
        "the old password no longer signs in"
    );
    sign_in(&auth, user.tenant_id, &user.email, replacement, now)
        .await
        .expect("the new password signs in");
    for session in [&signed[1], &signed[2]] {
        assert_eq!(
            auth.resolve_session(session.token().expose(), now).await,
            Err(AuthError::Unauthorized),
            "every other live session is revoked"
        );
    }
    auth.resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session survives");
    assert!(
        matches!(
            auth.sign_in_with_email_proof(proof.expose(), now).await,
            Err(AuthError::Unauthorized)
        ),
        "outstanding email sign-in proofs are consumed"
    );
}

/// The change is a compare-and-swap: a hash the caller no longer holds is refused, and the
/// stored hash and every session stay.
async fn change_password_needs_the_current_hash<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "password-guard", "guard@example.test", 2, now).await;
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");
    let credential = store.password(user.id).await.expect("credential");
    let stale = hashed(b"the password the caller thought");
    assert_eq!(
        auth.change_password(&current, &stale, &hashed(b"a new password"), now)
            .await,
        Err(AuthError::Unauthorized),
        "a wrong current password is unauthorized"
    );
    assert_eq!(
        store.password(user.id).await.expect("credential"),
        credential,
        "a wrong current password does not change the hash"
    );
    for session in &signed {
        auth.resolve_session(session.token().expose(), now)
            .await
            .expect("no session is revoked");
    }
}

/// An address change keeps the account and its sessions, refuses a live duplicate, and
/// clears the verification instant.
async fn change_email_replaces_the_address<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "email-change", "old@example.test", 2, now).await;
    let audited = Auth::new(store, [23; 32], Policy::default()).auditing(true);
    auth.sign_up(user.tenant_id, "taken@example.test", &hashed(PASSWORD), now)
        .await
        .expect("another account");
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");

    assert_eq!(
        audited
            .change_email(&current, "  Taken@Example.Test  ", now)
            .await,
        Err(AuthError::Conflict),
        "a live address in the tenant is a duplicate"
    );
    assert_eq!(
        audited.change_email(&current, "not-an-email", now).await,
        Err(AuthError::Invalid),
        "a malformed address is the caller's mistake"
    );
    audited
        .change_email(&current, "  New@Example.Test  ", now)
        .await
        .expect("change the address");

    assert_eq!(
        store
            .find_user(user.tenant_id, "new@example.test")
            .await
            .expect("the normalized new address")
            .id,
        user.id
    );
    assert_eq!(
        store.find_user(user.tenant_id, "old@example.test").await,
        Err(AuthError::NotFound),
        "the old address no longer finds the account"
    );
    for session in &signed {
        auth.resolve_session(session.token().expose(), now)
            .await
            .expect("the presented session and the others stay");
    }
    assert!(matches!(
        sign_in(&auth, user.tenant_id, "old@example.test", PASSWORD, now).await,
        Err(AuthError::Unauthorized)
    ));
    sign_in(&auth, user.tenant_id, "new@example.test", PASSWORD, now)
        .await
        .expect("the new address signs in");
}

/// Deletion marks the account, revokes every session including the presented one, and
/// keeps the row.
async fn delete_marks_the_account_and_revokes_every_session<S: AuthStore>(
    store: &S,
    now: Timestamp,
) {
    let (auth, user, signed) =
        sessions_fixture(store, "delete-account", "delete@example.test", 3, now).await;
    let audited = Auth::new(store, [23; 32], Policy::default()).auditing(true);
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");

    audited
        .delete_user(&current, now)
        .await
        .expect("delete the account");
    for session in &signed {
        assert_eq!(
            auth.resolve_session(session.token().expose(), now).await,
            Err(AuthError::Unauthorized),
            "every session is revoked, including the presented one"
        );
    }
    assert_eq!(
        store.find_user(user.tenant_id, &user.email).await,
        Err(AuthError::NotFound),
        "a deleted account is not found"
    );
    assert!(matches!(
        sign_in(&auth, user.tenant_id, &user.email, PASSWORD, now).await,
        Err(AuthError::Unauthorized)
    ));
    assert_eq!(
        audited.delete_user(&current, now).await,
        Err(AuthError::NotFound),
        "a repeated deletion is not a second success"
    );
}

/// Each account change and its audit row commit together: a failed insert leaves the old
/// hash, the old address, the account, and every session as they were.
async fn changes_roll_back_with_their_audit<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "password-rollback", "rollback@example.test", 2, now).await;
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");
    let before = store.password(user.id).await.expect("credential");
    let blocked = reserve_audit(store, user.tenant_id, now).await;
    assert_eq!(
        store
            .change_password(
                user.id,
                current.id,
                &before.password_hash,
                &hashed(b"a replacement password"),
                Some(collision(
                    blocked,
                    user.tenant_id,
                    user.id,
                    "auth.password.changed"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.password(user.id).await.expect("credential"),
        before,
        "a failed audit insert leaves the old hash"
    );
    for session in &signed {
        auth.resolve_session(session.token().expose(), now)
            .await
            .expect("a failed audit insert leaves every session live");
    }
    sign_in(&auth, user.tenant_id, &user.email, PASSWORD, now)
        .await
        .expect("the old password still signs in");

    // The address change commits its row the same way.
    assert_eq!(
        store
            .change_email(
                user.id,
                user.tenant_id,
                "rollback-new@example.test",
                Some(collision(
                    blocked,
                    user.tenant_id,
                    user.id,
                    "auth.email.changed"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store
            .find_user(user.tenant_id, &user.email)
            .await
            .expect("account")
            .id,
        user.id,
        "a failed audit insert leaves the old address"
    );

    // So does the deletion.
    assert_eq!(
        store
            .delete_user(
                user.id,
                Some(collision(
                    blocked,
                    user.tenant_id,
                    user.id,
                    "auth.user.deleted"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    store
        .find_user(user.tenant_id, &user.email)
        .await
        .expect("a failed audit insert leaves the account");
    for session in &signed {
        auth.resolve_session(session.token().expose(), now)
            .await
            .expect("a failed audit insert leaves every session live");
    }
}

/// The caller's own sessions: list, revoke one, revoke others, revoke all, and the
/// audit insert that rolls a revoke back.
async fn session_management<S: AuthStore>(store: &S, now: Timestamp) {
    session_listing(store, now).await;
    session_revoke_one(store, now).await;
    session_revoke_others_and_all(store, now).await;
}

/// One tenant, one registered account, and `count` sessions signed in for it.
async fn sessions_fixture<'s, S: AuthStore>(
    store: &'s S,
    name: &str,
    email: &str,
    count: usize,
    now: Timestamp,
) -> (Auth<'s, S>, User, Vec<IssuedSession>) {
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, name, now)
        .await
        .expect("tenant");
    let auth = Auth::new(store, [23; 32], Policy::default());
    let user = auth
        .sign_up(tenant, email, &hashed(PASSWORD), now)
        .await
        .expect("account");
    let mut signed = Vec::with_capacity(count);
    for _ in 0..count {
        signed.push(
            sign_in(&auth, tenant, &user.email, PASSWORD, now)
                .await
                .expect("session"),
        );
    }
    (auth, user, signed)
}

/// The list is a store read of the caller's live sessions only.
async fn session_listing<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "sessions-list", "sessions@example.test", 3, now).await;
    let outsider = auth
        .sign_up(
            user.tenant_id,
            "sessions-other@example.test",
            &hashed(PASSWORD),
            now,
        )
        .await
        .expect("other account");
    let other = sign_in(&auth, user.tenant_id, &outsider.email, PASSWORD, now)
        .await
        .expect("other account's session");
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");
    let other_session = auth
        .resolve_session(other.token().expose(), now)
        .await
        .expect("the other account's session");

    let listed = auth.list_sessions(&current, now).await.expect("list");
    assert_eq!(listed.len(), 3, "the caller's three sessions");
    assert!(
        !listed.iter().any(|info| info.id == other_session.id),
        "another account's session is not listed"
    );
    assert_eq!(
        listed.iter().filter(|info| info.current).count(),
        1,
        "only the presented session is current"
    );
    for session in [&current, &other_session] {
        let found = listed.iter().find(|info| info.id == session.id);
        if session.id == current.id {
            assert_eq!(
                found.map(|info| (info.expires_at, info.current)),
                Some((session.expires_at, true)),
                "the presented session is listed as current, with its expiry"
            );
        } else {
            assert!(found.is_none(), "another account's session is absent");
        }
    }
    let second = auth
        .resolve_session(signed[1].token().expose(), now)
        .await
        .expect("the second session");
    assert_eq!(
        listed
            .iter()
            .find(|info| info.id == second.id)
            .map(|info| info.expires_at),
        Some(second.expires_at),
        "the listed expiry is the stored one"
    );
}

/// One identifier revokes one session, and only when the caller owns it.
async fn session_revoke_one<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "sessions-revoke-one", "revoke@example.test", 2, now).await;
    let audited = Auth::new(store, [23; 32], Policy::default()).auditing(true);
    let outsider = auth
        .sign_up(
            user.tenant_id,
            "stranger@example.test",
            &hashed(PASSWORD),
            now,
        )
        .await
        .expect("other account");
    let other = sign_in(&auth, user.tenant_id, &outsider.email, PASSWORD, now)
        .await
        .expect("other account's session");
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");
    let retired = auth
        .resolve_session(signed[1].token().expose(), now)
        .await
        .expect("the second session");
    let other_session = auth
        .resolve_session(other.token().expose(), now)
        .await
        .expect("the other account's session");

    // Another account's identifier is not a revoke.
    assert_eq!(
        audited
            .revoke_session(&current, other_session.id, now)
            .await,
        Err(AuthError::NotFound)
    );
    auth.resolve_session(other.token().expose(), now)
        .await
        .expect("another account's session stays live");

    assert_eq!(
        audited.revoke_session(&current, retired.id, now).await,
        Ok(())
    );
    assert_eq!(
        auth.resolve_session(signed[1].token().expose(), now).await,
        Err(AuthError::Unauthorized)
    );
    assert_eq!(
        audited.revoke_session(&current, retired.id, now).await,
        Err(AuthError::NotFound),
        "a repeated revoke is not a second success"
    );
    auth.resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session survives");
    assert_eq!(
        auth.list_sessions(&current, now)
            .await
            .expect("list after one revoke")
            .len(),
        1
    );
}

/// Revoke-others keeps the presented session; revoke-all removes it too; a failed audit
/// insert leaves every session live.
async fn session_revoke_others_and_all<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "sessions-revoke-all", "all@example.test", 3, now).await;
    let audited = Auth::new(store, [23; 32], Policy::default()).auditing(true);
    let other = sign_in(&auth, user.tenant_id, &user.email, PASSWORD, now)
        .await
        .expect("a session after revoke-others");
    let current = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session");

    assert_eq!(audited.revoke_other_sessions(&current, now).await, Ok(()));
    assert_eq!(
        auth.resolve_session(signed[1].token().expose(), now).await,
        Err(AuthError::Unauthorized)
    );
    assert_eq!(
        auth.resolve_session(signed[2].token().expose(), now).await,
        Err(AuthError::Unauthorized)
    );
    auth.resolve_session(signed[0].token().expose(), now)
        .await
        .expect("the presented session survives revoke-others");
    let remaining = auth
        .list_sessions(&current, now)
        .await
        .expect("list after others");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, current.id);
    assert!(remaining[0].current);

    assert_eq!(audited.revoke_all_sessions(&current, now).await, Ok(()));
    for session in [&signed[0], &other] {
        assert_eq!(
            auth.resolve_session(session.token().expose(), now).await,
            Err(AuthError::Unauthorized),
            "revoke-all includes the presented session"
        );
    }
    assert_eq!(
        auth.list_sessions(&current, now)
            .await
            .expect("list after all")
            .len(),
        0
    );

    // A mutation and its audit row commit in one transaction.
    let blocked = reserve_audit(store, user.tenant_id, now).await;
    let fifth = sign_in(&auth, user.tenant_id, &user.email, PASSWORD, now)
        .await
        .expect("fifth session");
    let live = auth
        .resolve_session(fifth.token().expose(), now)
        .await
        .expect("the fifth session");
    assert_eq!(
        store
            .revoke_session_by_id(
                live.user_id,
                live.id,
                Some(collision(
                    blocked,
                    user.tenant_id,
                    live.user_id,
                    "auth.session.revoked"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    auth.resolve_session(fifth.token().expose(), now)
        .await
        .expect("a failed audit insert leaves the session live");

    let sixth = sign_in(&auth, user.tenant_id, &user.email, PASSWORD, now)
        .await
        .expect("sixth session");
    assert_eq!(
        store
            .revoke_sessions(
                live.user_id,
                None,
                Some(collision(
                    blocked,
                    user.tenant_id,
                    live.user_id,
                    "auth.session.revoked"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    for session in [&fifth, &sixth] {
        auth.resolve_session(session.token().expose(), now)
            .await
            .expect("a failed audit insert leaves every session live");
    }
}

async fn fractional_expiry<S: AuthStore>(auth: &Auth<'_, S>, user: &User, now: Timestamp) {
    let issued = (now + Duration::milliseconds(500))
        .to_offset(time::UtcOffset::from_hms(5, 30, 0).expect("offset"));
    let session = sign_in(
        auth,
        user.tenant_id,
        &user.email,
        b"a different strong password",
        issued,
    )
    .await
    .expect("fractional login");
    let before_expiry = now + Duration::hours(24);
    auth.resolve_session(session.token().expose(), before_expiry)
        .await
        .expect("half second before expiry");
    auth.resolve_session(session.token().expose(), issued + Duration::hours(24))
        .await
        .expect("sliding the near-expiry session keeps it live");
    let proof = auth
        .issue_proof(user.tenant_id, &user.email, Purpose::VerifyEmail, issued)
        .await
        .expect("fractional proof");
    assert_eq!(
        auth.verify_email(proof.expose(), now + Duration::minutes(30))
            .await,
        Ok(user.id)
    );
}

async fn registration_and_sessions<S: AuthStore>(
    store: &S,
    auth: &Auth<'_, S>,
    now: Timestamp,
) -> User {
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "test", now)
        .await
        .expect("tenant");
    let other_tenant = Id::now_v7();
    store
        .create_tenant(other_tenant, "other", now)
        .await
        .expect("other tenant");
    let password = PASSWORD;
    let user = auth
        .sign_up(tenant, "  User@Example.Test  ", &hashed(password), now)
        .await
        .expect("register");
    assert_eq!(user.email, "user@example.test");
    assert_eq!(user.id.get_version_num(), 7);
    assert_eq!(
        auth.sign_up(tenant, "USER@example.test", &hashed(password), now)
            .await,
        Err(AuthError::Conflict)
    );
    assert_eq!(
        auth.sign_up(tenant, "not-an-email", &hashed(password), now)
            .await,
        Err(AuthError::Invalid)
    );
    let other_user = auth
        .sign_up(other_tenant, "user@example.test", &hashed(password), now)
        .await
        .expect("tenant-scoped email");
    assert_ne!(user.id, other_user.id);
    assert!(
        store
            .password(user.id)
            .await
            .expect("credential")
            .password_hash
            .starts_with("$argon2id$")
    );
    assert!(matches!(
        sign_in(auth, tenant, "missing@example.test", password, now).await,
        Err(AuthError::Unauthorized)
    ));

    let session = sign_in(auth, tenant, "user@example.test", password, now)
        .await
        .expect("login");
    let resolved = auth
        .resolve_session(session.token().expose(), now)
        .await
        .expect("resolve");
    assert_eq!(resolved.user_id, user.id);
    assert_eq!(resolved.tenant_id, tenant);
    assert_ne!(resolved.token_digest, session.token().expose().as_bytes());
    assert!(matches!(
        Auth::new(store, [7; 32], Policy::default())
            .resolve_session(session.token().expose(), now)
            .await,
        Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
        auth.resolve_session(session.token().expose(), now + Duration::hours(24))
            .await,
        Err(AuthError::Unauthorized)
    ));
    auth.sign_out(session.token().expose(), now)
        .await
        .expect("logout");
    auth.sign_out(session.token().expose(), now)
        .await
        .expect("idempotent logout");
    assert_eq!(
        auth.resolve_session(session.token().expose(), now).await,
        Err(AuthError::Unauthorized)
    );
    user
}

async fn lockout<S: AuthStore>(
    store: &S,
    auth: &Auth<'_, S>,
    user: &User,
    now: Timestamp,
) -> IssuedSession {
    let tenant = user.tenant_id;
    let password = PASSWORD;
    // Concurrent failed attempts cannot overwrite one another.
    let (first, second, third, fourth, fifth) = tokio::join!(
        sign_in(auth, tenant, &user.email, b"wrong", now),
        sign_in(auth, tenant, &user.email, b"wrong", now),
        sign_in(auth, tenant, &user.email, b"wrong", now),
        sign_in(auth, tenant, &user.email, b"wrong", now),
        sign_in(auth, tenant, &user.email, b"wrong", now)
    );
    for result in [first, second, third, fourth, fifth] {
        match result {
            Err(AuthError::Unauthorized) => {}
            Err(error) => panic!("concurrent failed sign-in returned error variant: {error:?}"),
            Ok(_) => panic!("concurrent failed sign-in unexpectedly succeeded"),
        }
    }
    assert_eq!(
        store
            .password(user.id)
            .await
            .expect("locked credential")
            .failed_attempts,
        5
    );
    assert!(matches!(
        sign_in(auth, tenant, &user.email, password, now).await,
        Err(AuthError::Unauthorized)
    ));
    let later = now + Duration::minutes(15);
    let live = sign_in(auth, tenant, &user.email, password, later)
        .await
        .expect("lock expires");
    assert_eq!(
        store
            .password(user.id)
            .await
            .expect("reset failures")
            .failed_attempts,
        0
    );
    live
}

async fn proofs<S: AuthStore>(
    auth: &Auth<'_, S>,
    user: &User,
    now: Timestamp,
    live: &IssuedSession,
) {
    let tenant = user.tenant_id;
    let later = now + Duration::minutes(15);
    let password = PASSWORD;
    let verify = auth
        .issue_proof(tenant, &user.email, Purpose::VerifyEmail, later)
        .await
        .expect("verification");
    assert_eq!(
        auth.reset_password(verify.expose(), &hashed(b"not accepted"), later)
            .await,
        Err(AuthError::Unauthorized)
    );
    assert_eq!(auth.verify_email(verify.expose(), later).await, Ok(user.id));
    assert_eq!(
        auth.verify_email(verify.expose(), later).await,
        Err(AuthError::Unauthorized)
    );
    let otp = auth
        .issue_proof(tenant, &user.email, Purpose::EmailOtp, later)
        .await
        .expect("OTP");
    assert_eq!(auth.verify_otp(otp.expose(), later).await, Ok(user.id));
    assert_eq!(
        auth.verify_otp(otp.expose(), later).await,
        Err(AuthError::Unauthorized)
    );
    let expired = auth
        .issue_proof(tenant, &user.email, Purpose::ResetPassword, now)
        .await
        .expect("expired reset");
    assert_eq!(
        auth.reset_password(
            expired.expose(),
            &hashed(b"replacement"),
            now + Duration::minutes(30)
        )
        .await,
        Err(AuthError::Unauthorized)
    );
    let reset = auth
        .issue_proof(tenant, &user.email, Purpose::ResetPassword, later)
        .await
        .expect("reset");
    let replacement = b"a different strong password";
    let first_hash = hashed(replacement);
    let second_hash = hashed(replacement);
    let (first, second) = tokio::join!(
        auth.reset_password(reset.expose(), &first_hash, later),
        auth.reset_password(reset.expose(), &second_hash, later)
    );
    assert!(
        matches!(
            (first, second),
            (Ok(()), Err(AuthError::Unauthorized)) | (Err(AuthError::Unauthorized), Ok(()))
        ),
        "concurrent reset outcomes: {first:?}, {second:?}"
    );
    assert_eq!(
        auth.resolve_session(live.token().expose(), later).await,
        Err(AuthError::Unauthorized)
    );
    assert!(matches!(
        sign_in(auth, tenant, &user.email, password, later).await,
        Err(AuthError::Unauthorized)
    ));
    sign_in(auth, tenant, &user.email, replacement, later)
        .await
        .expect("new password");
    assert!(!format!("{reset:?}").contains(reset.expose()));

    // The digest a caller hashes matches the shape of the session digest and is
    // domain-separated by purpose, so one token cannot satisfy another purpose.
    let token = "unwritten-proof-token";
    let (keyed, digest_hex) = auth.proof_digest(Purpose::VerifyEmail, token);
    assert_eq!(digest_hex.len(), 64);
    assert!(
        digest_hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );
    assert_eq!(
        auth.proof_digest(Purpose::VerifyEmail, token),
        (keyed, digest_hex.clone())
    );
    assert_ne!(
        auth.proof_digest(Purpose::ResetPassword, token).1,
        digest_hex
    );
    assert_ne!(auth.proof_digest(Purpose::EmailOtp, token).1, digest_hex);
    assert_ne!(auth.session_digest(token).1, digest_hex);
}

/// One `EmailOtp` proof signs in once, issues a session, and cannot be spent again.
async fn email_sign_in<S: AuthStore>(store: &S, user: &User, now: Timestamp) {
    let auth = Auth::new(store, [17; 32], Policy::default()).auditing(true);
    let tenant = user.tenant_id;
    assert!(
        matches!(
            auth.issue_proof(tenant, "not-an-email", Purpose::EmailOtp, now)
                .await,
            Err(AuthError::Invalid)
        ),
        "a bad email is invalid input, not a duplicate"
    );
    let proof = auth
        .issue_proof(tenant, &user.email, Purpose::EmailOtp, now)
        .await
        .expect("email sign-in proof");
    let issued = auth
        .sign_in_with_email_proof(proof.expose(), now)
        .await
        .expect("email sign-in");
    let session = auth
        .resolve_session(issued.token().expose(), now)
        .await
        .expect("the proof's session resolves");
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.tenant_id, tenant);
    assert_eq!(issued.digest_hex().len(), 64);
    assert!(!format!("{proof:?}").contains(proof.expose()));
    assert!(
        matches!(
            auth.sign_in_with_email_proof(proof.expose(), now).await,
            Err(AuthError::Unauthorized)
        ),
        "a proof is spent once"
    );
}

/// A password reset consumes outstanding email sign-in proofs, so a proof minted
/// before the reset cannot issue a session afterward.
async fn reset_invalidates_email_sign_in<S: AuthStore>(store: &S, user: &User, now: Timestamp) {
    let auth = Auth::new(store, [19; 32], Policy::default());
    let tenant = user.tenant_id;
    let email_proof = auth
        .issue_proof(tenant, &user.email, Purpose::EmailOtp, now)
        .await
        .expect("email sign-in proof");
    let reset = auth
        .issue_proof(tenant, &user.email, Purpose::ResetPassword, now)
        .await
        .expect("reset proof");
    auth.reset_password(reset.expose(), &hashed(b"a different strong password"), now)
        .await
        .expect("reset the password");
    assert!(
        matches!(
            auth.sign_in_with_email_proof(email_proof.expose(), now)
                .await,
            Err(AuthError::Unauthorized)
        ),
        "a reset consumes the outstanding email sign-in proof and issues no session"
    );
}

async fn api_keys<S: AuthStore>(store: &S, user: &User, later: Timestamp) {
    let keys = ApiKeys::new(store, KEY, Some("custom")).expect("custom prefix");
    let token = keys
        .issue(
            user,
            vec!["application.scope".to_owned()],
            later + Duration::hours(1) + Duration::milliseconds(500),
            later,
        )
        .await
        .expect("issue key");
    assert!(token.expose().starts_with("custom_"));
    let changed = ApiKeys::new(store, KEY, None).expect("default prefix");
    let record = changed
        .lookup(token.expose(), later)
        .await
        .expect("old prefix still parses");
    assert_eq!(record.prefix, "custom");
    assert_eq!(record.scopes, vec!["application.scope"]);
    assert_eq!(record.user_id, user.id);
    assert_ne!(record.secret_digest, token.expose().as_bytes());
    assert_eq!(
        record.last_used_at,
        Some(later),
        "a successful lookup records the lookup instant"
    );
    let wrong_prefix = token.expose().replacen("custom_", "nak_", 1);
    assert_eq!(
        keys.lookup(&wrong_prefix, later + Duration::minutes(5))
            .await,
        Err(AuthError::Unauthorized)
    );
    assert_eq!(
        stored_key(store, token.expose(), later).await.last_used_at,
        Some(later),
        "a wrong prefix does not move last_used_at"
    );
    keys.lookup(token.expose(), later + Duration::hours(1))
        .await
        .expect("fractional key expiry");
    assert_eq!(
        keys.lookup(
            token.expose(),
            later + Duration::hours(1) + Duration::milliseconds(500)
        )
        .await,
        Err(AuthError::Unauthorized)
    );
    assert_eq!(
        stored_key(store, token.expose(), later).await.last_used_at,
        Some(later + Duration::hours(1)),
        "an expired lookup does not move last_used_at"
    );
    let default_key = changed
        .issue(user, vec![], later + Duration::hours(1), later)
        .await
        .expect("default key");
    assert!(default_key.expose().starts_with("nak_"));
    assert_eq!(
        keys.lookup(default_key.expose(), later)
            .await
            .expect("default lookup")
            .prefix,
        "nak"
    );
    assert!(!format!("{token:?}").contains(token.expose()));

    api_key_revocation(store, user, later, token.expose(), record.id).await;
}

/// Revoke is scoped to the account the live session names and is not repeatable.
async fn api_key_revocation<S: AuthStore>(
    store: &S,
    user: &User,
    later: Timestamp,
    token: &str,
    owned: Id,
) {
    let keys = ApiKeys::new(store, KEY, Some("custom")).expect("custom prefix");
    let session = Session {
        id: Id::now_v7(),
        user_id: user.id,
        tenant_id: user.tenant_id,
        token_digest: vec![9; 33],
        expires_at: later + Duration::hours(1),
    };
    let stranger = User {
        id: Id::now_v7(),
        tenant_id: user.tenant_id,
        email: "api-key-stranger@example.test".to_owned(),
    };
    store
        .create_user(&stranger, &hashed(PASSWORD), None, later)
        .await
        .expect("stranger account");
    let stranger_key = keys
        .issue(&stranger, vec![], later + Duration::hours(1), later)
        .await
        .expect("stranger key");
    let stranger_id = keys
        .lookup(stranger_key.expose(), later)
        .await
        .expect("stranger key is live")
        .id;
    assert_eq!(
        keys.revoke(&session, stranger_id, later).await,
        Err(AuthError::NotFound),
        "another account's key identifier is not found"
    );
    keys.lookup(stranger_key.expose(), later)
        .await
        .expect("another account's key stays usable");

    keys.revoke(&session, owned, later)
        .await
        .expect("revoke an owned key");
    assert_eq!(
        keys.lookup(token, later).await,
        Err(AuthError::Unauthorized),
        "a revoked key does not verify"
    );
    assert_eq!(
        keys.revoke(&session, owned, later).await,
        Err(AuthError::NotFound),
        "a second revoke is not a second success"
    );
}

/// Read one key without recording a use, so the last-used column can be observed.
async fn stored_key<S: AuthStore>(
    store: &S,
    token: &str,
    now: Timestamp,
) -> vaelspire_core::ApiKey {
    let (keyed, _) = vaelspire_auth::token_digest(&KEY, "api_key", token);
    let mut digest = Vec::with_capacity(33);
    digest.push(1);
    digest.extend_from_slice(&keyed);
    store
        .find_api_key(&digest, "custom", now)
        .await
        .expect("the key is still live")
}

async fn audit<S: AuthStore>(store: &S, user: &User, later: Timestamp) {
    let mut audit = AuditEvent {
        id: Id::now_v7(),
        tenant_id: Some(user.tenant_id),
        actor_id: Some(user.id),
        action: "auth.session.issued".to_owned(),
        outcome: "ok".to_owned(),
        fields: vec![],
    };
    store.insert_audit(&audit, later).await.expect("safe audit");
    for name in [
        "password",
        "password_hash",
        "token",
        "token_digest",
        "otp",
        "api_key_secret",
        "secret",
        "API_KEY_SECRET",
    ] {
        audit.id = Id::now_v7();
        audit.fields = vec![(name.to_owned(), "must not persist".to_owned())];
        assert_eq!(
            store.insert_audit(&audit, later).await,
            Err(AuthError::Conflict)
        );
    }
    assert!(
        !format!("{:?}", store.password(user.id).await.expect("credential")).contains("$argon2")
    );
}

/// The role the role-assignment case tries to attach. The store tests count its links
/// after the suite, because the port exposes no role read.
pub(crate) const ATOMIC_ROLE: &str = "conformance.atomic-role";

/// A mutation and its audit row commit in one transaction. A forced insert failure
/// leaves neither the new row nor the mutation behind.
async fn atomic_audit<S: AuthStore>(store: &S, now: Timestamp) {
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "atomic-audit", now)
        .await
        .expect("tenant");
    let blocked = reserve_audit(store, tenant, now).await;
    let user = atomic_sign_up_and_login(store, tenant, blocked, now).await;
    atomic_failure_and_revoke(store, tenant, &user, blocked, now).await;
    atomic_api_key_revoke(store, tenant, &user, blocked, now).await;
    atomic_membership_and_roles(store, tenant, &user, blocked, now).await;
    atomic_proofs(store, tenant, &user, blocked, now).await;
    atomic_email_sign_in(store, tenant, &user, blocked, now).await;
    atomic_invitations(store, tenant, blocked, now).await;
}

/// Reserve an audit id so a later insert with the same id fails in the database rather
/// than in validation.
async fn reserve_audit<S: AuthStore>(store: &S, tenant: Id, now: Timestamp) -> Id {
    let event = AuditEvent {
        id: Id::now_v7(),
        tenant_id: Some(tenant),
        actor_id: None,
        action: "conformance.atomic".to_owned(),
        outcome: "ok".to_owned(),
        fields: vec![],
    };
    store
        .insert_audit(&event, now)
        .await
        .expect("reserved audit id");
    event.id
}

fn collision(id: Id, tenant: Id, actor: Id, action: &str) -> AuditEvent {
    AuditEvent {
        id,
        tenant_id: Some(tenant),
        actor_id: Some(actor),
        action: action.to_owned(),
        outcome: "ok".to_owned(),
        fields: vec![],
    }
}

async fn atomic_sign_up_and_login<S: AuthStore>(
    store: &S,
    tenant: Id,
    blocked: Id,
    now: Timestamp,
) -> User {
    // Sign-up: the account must not exist when its audit row cannot be written.
    let pending = User {
        id: Id::now_v7(),
        tenant_id: tenant,
        email: "atomic@example.test".to_owned(),
    };
    assert_eq!(
        store
            .create_user(
                &pending,
                &hashed(PASSWORD),
                Some(collision(blocked, tenant, pending.id, "auth.user.created")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.find_user(tenant, "atomic@example.test").await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no account"
    );

    // Login: the session must not exist when its audit row cannot be written.
    let auth = Auth::new(store, [14; 32], Policy::default());
    let user = auth
        .sign_up(tenant, "atomic@example.test", &hashed(PASSWORD), now)
        .await
        .expect("register without the failing row");
    let credential = store.password(user.id).await.expect("credential");
    let session = Session {
        id: Id::now_v7(),
        user_id: user.id,
        tenant_id: tenant,
        token_digest: vec![7; 33],
        expires_at: now + Duration::hours(1),
    };
    assert_eq!(
        store
            .complete_login(
                &session,
                &credential.password_hash,
                None,
                Some(collision(blocked, tenant, user.id, "auth.session.issued")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.find_session(&session.token_digest, now).await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no session"
    );
    user
}

async fn atomic_failure_and_revoke<S: AuthStore>(
    store: &S,
    tenant: Id,
    user: &User,
    blocked: Id,
    now: Timestamp,
) {
    // Failure recording: a failed audit insert leaves the credential row unchanged.
    let credential = store.password(user.id).await.expect("credential");
    assert_eq!(
        store
            .record_failure(
                user.id,
                Some(collision(blocked, tenant, user.id, "auth.session.denied")),
                now,
                now + Duration::minutes(15),
                5,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.password(user.id).await.expect("credential"),
        credential,
        "a failed audit insert leaves the failure count and lock unchanged"
    );

    // Sign-out: the revocation and its row commit together, so a failed insert leaves
    // the session live.
    let session = Session {
        id: Id::now_v7(),
        user_id: user.id,
        tenant_id: tenant,
        token_digest: vec![8; 33],
        expires_at: now + Duration::hours(1),
    };
    store
        .complete_login(&session, &credential.password_hash, None, None, now)
        .await
        .expect("session without audit");
    assert_eq!(
        store
            .revoke_session(
                &session.token_digest,
                Some(collision(blocked, tenant, user.id, "auth.session.revoked")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    store
        .find_session(&session.token_digest, now)
        .await
        .expect("a failed audit insert leaves the session live");
}

/// Extension and its audit insert are one transaction.
#[allow(dead_code)]
pub(crate) async fn session_extension<S: AuthStore>(store: &S, now: Timestamp) {
    let (auth, user, signed) =
        sessions_fixture(store, "extension", "extension@example.test", 1, now).await;
    let session = auth
        .resolve_session(signed[0].token().expose(), now)
        .await
        .unwrap();
    let blocked = reserve_audit(store, user.tenant_id, now).await;
    let later = now + Duration::hours(48);
    assert_eq!(
        store
            .extend_session(
                &session.token_digest,
                later,
                Some(collision(
                    blocked,
                    user.tenant_id,
                    user.id,
                    "auth.session.extended"
                )),
                now
            )
            .await,
        Err(AuthError::Conflict)
    );
    assert_eq!(
        store
            .find_session(&session.token_digest, now)
            .await
            .unwrap()
            .expires_at,
        session.expires_at
    );
    store
        .extend_session(&session.token_digest, later, None, now)
        .await
        .expect("extend");
    assert_eq!(
        store
            .find_session(&session.token_digest, now)
            .await
            .unwrap()
            .expires_at,
        later
    );
}

/// A key revoke and its audit row commit together, so a failed insert leaves the key
/// usable; the successful revoke makes the key stop verifying.
async fn atomic_api_key_revoke<S: AuthStore>(
    store: &S,
    tenant: Id,
    user: &User,
    blocked: Id,
    now: Timestamp,
) {
    let key = vaelspire_core::ApiKey {
        id: Id::now_v7(),
        tenant_id: tenant,
        user_id: user.id,
        prefix: "atomic".to_owned(),
        secret_digest: vec![0xA1; 33],
        scopes: vec![],
        expires_at: now + Duration::hours(1),
        last_used_at: None,
    };
    store
        .create_api_key(&key, now)
        .await
        .expect("key without audit");
    assert_eq!(
        store
            .revoke_api_key(
                user.id,
                key.id,
                Some(collision(blocked, tenant, user.id, "auth.api_key.revoked")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    store
        .find_api_key(&key.secret_digest, "atomic", now)
        .await
        .expect("a failed audit insert leaves the key usable");
    let audit = AuditEvent {
        id: Id::now_v7(),
        tenant_id: Some(tenant),
        actor_id: Some(user.id),
        action: "auth.api_key.revoked".to_owned(),
        outcome: "ok".to_owned(),
        fields: vec![],
    };
    store
        .revoke_api_key(user.id, key.id, Some(audit), now)
        .await
        .expect("revoke and its audit row commit together");
    assert_eq!(
        store.find_api_key(&key.secret_digest, "atomic", now).await,
        Err(AuthError::NotFound),
        "the revoked key no longer resolves"
    );
}

async fn atomic_membership_and_roles<S: AuthStore>(
    store: &S,
    tenant: Id,
    user: &User,
    blocked: Id,
    now: Timestamp,
) {
    // Membership: the row must not exist when its audit row cannot be written.
    let membership = Membership {
        id: Id::now_v7(),
        tenant_id: tenant,
        user_id: user.id,
        status: MembershipStatus::Active,
    };
    assert_eq!(
        store
            .create_membership(
                &membership,
                Some(collision(
                    blocked,
                    tenant,
                    user.id,
                    "auth.membership.created"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.find_membership(tenant, user.id).await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no membership"
    );
    store
        .create_membership(&membership, None, now)
        .await
        .expect("membership without audit");

    // Membership status: the prior row keeps its status when the insert fails.
    assert_eq!(
        store
            .set_membership_status(
                membership.id,
                MembershipStatus::Suspended,
                Some(collision(
                    blocked,
                    tenant,
                    user.id,
                    "auth.membership.updated"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store
            .find_membership(tenant, user.id)
            .await
            .expect("membership")
            .status,
        MembershipStatus::Active,
        "a failed audit insert leaves the membership status unchanged"
    );

    // Role assignment: the port exposes no role read, so the store tests count the
    // links to `ATOMIC_ROLE` after the suite.
    let role = Id::now_v7();
    store
        .create_role(role, tenant, ATOMIC_ROLE)
        .await
        .expect("role");
    assert_eq!(
        store
            .assign_role(
                membership.id,
                role,
                Some(collision(
                    blocked,
                    tenant,
                    user.id,
                    "auth.membership.updated"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
}

async fn atomic_proofs<S: AuthStore>(
    store: &S,
    tenant: Id,
    user: &User,
    blocked: Id,
    now: Timestamp,
) {
    // Proof issue: the proof must not exist when its audit row cannot be written.
    let digest = vec![9_u8; 33];
    let proof = OneTime {
        id: Id::now_v7(),
        user_id: user.id,
        purpose: Purpose::VerifyEmail,
        token_digest: digest.clone(),
        expires_at: now + Duration::minutes(30),
    };
    assert_eq!(
        store
            .create_one_time(
                &proof,
                Some(collision(blocked, tenant, user.id, "auth.proof.issued")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store
            .consume_one_time(Purpose::VerifyEmail, &digest, None, None, now)
            .await,
        Err(AuthError::Unauthorized),
        "a failed audit insert leaves no proof"
    );

    // Proof consumption: the stored proof stays unspent when its audit row fails.
    store
        .create_one_time(&proof, None, now)
        .await
        .expect("proof without audit");
    assert_eq!(
        store
            .consume_one_time(
                Purpose::VerifyEmail,
                &digest,
                None,
                Some(collision(blocked, tenant, user.id, "auth.email.verified")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store
            .consume_one_time(Purpose::VerifyEmail, &digest, None, None, now)
            .await,
        Ok(user.id),
        "a failed audit insert leaves the proof unspent"
    );
}

/// Email sign-in consumes the proof and inserts the session in one transaction, so a
/// failed audit insert leaves neither behind.
async fn atomic_email_sign_in<S: AuthStore>(
    store: &S,
    tenant: Id,
    user: &User,
    blocked: Id,
    now: Timestamp,
) {
    let auth = Auth::new(store, [18; 32], Policy::default());
    let proof = auth
        .issue_proof(tenant, &user.email, Purpose::EmailOtp, now)
        .await
        .expect("email sign-in proof");
    let (keyed, _) = auth.proof_digest(Purpose::EmailOtp, proof.expose());
    let mut digest = Vec::with_capacity(33);
    digest.push(1);
    digest.extend_from_slice(&keyed);
    let session_id = Id::now_v7();
    let session_digest = vec![5_u8; 33];
    let expires_at = now + Duration::hours(1);
    assert_eq!(
        store
            .complete_email_sign_in(
                &digest,
                session_id,
                &session_digest,
                expires_at,
                Some(collision(blocked, tenant, user.id, "auth.session.issued")),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.find_session(&session_digest, now).await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no session"
    );
    let session = store
        .complete_email_sign_in(&digest, session_id, &session_digest, expires_at, None, now)
        .await
        .expect("a failed audit insert leaves the proof unspent");
    assert_eq!(session.id, session_id);
    assert_eq!(session.user_id, user.id);
    store
        .find_session(&session_digest, now)
        .await
        .expect("the session insert committed");
}

async fn atomic_invitations<S: AuthStore>(store: &S, tenant: Id, blocked: Id, now: Timestamp) {
    // Invitation issue: the invitation must not exist when its audit row cannot be
    // written.
    let digest = vec![3_u8; 33];
    let invitation = Invitation {
        id: Id::now_v7(),
        tenant_id: tenant,
        email: "atomic-invitee@example.test".to_owned(),
        token_digest: digest.clone(),
        expires_at: now + Duration::hours(1),
        role_ids: vec![],
    };
    assert_eq!(
        store
            .create_invitation(
                &invitation,
                Some(collision(
                    blocked,
                    tenant,
                    Id::now_v7(),
                    "auth.invitation.issued"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store
            .accept_invitation(Id::now_v7(), &digest, None, now)
            .await,
        Err(AuthError::Unauthorized),
        "a failed audit insert leaves no invitation"
    );

    // Invitation accept: the new membership must be absent and the invitation unspent
    // when the acceptance's audit row cannot be written.
    let invitee = Auth::new(store, [15; 32], Policy::default())
        .sign_up(
            tenant,
            "atomic-invitee@example.test",
            &hashed(PASSWORD),
            now,
        )
        .await
        .expect("invitee");
    store
        .create_invitation(&invitation, None, now)
        .await
        .expect("invitation without audit");
    assert_eq!(
        store
            .accept_invitation(
                Id::now_v7(),
                &digest,
                Some(collision(
                    blocked,
                    tenant,
                    invitee.id,
                    "auth.invitation.accepted"
                )),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit id is already taken"
    );
    assert_eq!(
        store.find_membership(tenant, invitee.id).await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no membership"
    );
    store
        .accept_invitation(Id::now_v7(), &digest, None, now)
        .await
        .expect("a failed audit insert leaves the invitation unspent");
}

/// Every optional default body reports `Unsupported`, never a storage failure.
async fn unsupported_defaults(now: Timestamp) {
    let store = RequiredOnly;
    let id = Id::now_v7();
    assert_eq!(
        store.suspend_tenant(id, now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store
            .create_membership(
                &Membership {
                    id,
                    tenant_id: id,
                    user_id: id,
                    status: MembershipStatus::Active,
                },
                None,
                now,
            )
            .await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.find_membership(id, id).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store
            .set_membership_status(id, MembershipStatus::Active, None, now)
            .await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.create_permission(id, id, "name").await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.create_role(id, id, "name").await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.create_group(id, id, "name", now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.add_group_member(id, id, id).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.remove_group_member(id, id, id).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.assign_role(id, id, None, now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.create_invitation(&invitation(id), None, now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.accept_invitation(id, &[1], None, now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store
            .change_password(id, id, "expected", "hash", None, now)
            .await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store
            .change_email(id, id, "person@example.test", None, now)
            .await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.delete_user(id, None, now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.revoke_api_key(id, id, None, now).await,
        Err(AuthError::Unsupported)
    );
    assert_eq!(
        store.record_api_key_use(id, now).await,
        Err(AuthError::Unsupported)
    );
}

fn invitation(id: Id) -> vaelspire_core::Invitation {
    vaelspire_core::Invitation {
        id,
        tenant_id: id,
        email: "invitee@example.test".to_owned(),
        token_digest: vec![1],
        expires_at: Timestamp::from_unix_timestamp(1_900_000_000).expect("instant"),
        role_ids: vec![],
    }
}

/// Implements only the methods the port requires, so every optional default body is
/// the one under test.
struct RequiredOnly;

#[async_trait::async_trait]
impl AuthStore for RequiredOnly {
    async fn create_tenant(&self, _id: Id, _name: &str, _now: Timestamp) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn create_user(
        &self,
        _user: &User,
        _hash: &str,
        _audit: Option<AuditEvent>,
        _now: Timestamp,
    ) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn find_user(&self, _tenant: Id, _email: &str) -> Result<User, AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn password(&self, _user: Id) -> Result<vaelspire_core::PasswordCredential, AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn record_failure(
        &self,
        _user: Id,
        _audit: Option<AuditEvent>,
        _now: Timestamp,
        _until: Timestamp,
        _limit: i32,
    ) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn complete_login(
        &self,
        _session: &Session,
        _expected_hash: &str,
        _replacement: Option<&str>,
        _audit: Option<AuditEvent>,
        _now: Timestamp,
    ) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn find_session(&self, _digest: &[u8], _now: Timestamp) -> Result<Session, AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn revoke_session(
        &self,
        _digest: &[u8],
        _audit: Option<AuditEvent>,
        _now: Timestamp,
    ) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn create_one_time(
        &self,
        _proof: &vaelspire_core::OneTime,
        _audit: Option<AuditEvent>,
        _now: Timestamp,
    ) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn consume_one_time(
        &self,
        _purpose: Purpose,
        _digest: &[u8],
        _hash: Option<&str>,
        _audit: Option<AuditEvent>,
        _now: Timestamp,
    ) -> Result<Id, AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn create_api_key(
        &self,
        _key: &vaelspire_core::ApiKey,
        _now: Timestamp,
    ) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn find_api_key(
        &self,
        _digest: &[u8],
        _prefix: &str,
        _now: Timestamp,
    ) -> Result<vaelspire_core::ApiKey, AuthError> {
        Err(AuthError::Unsupported)
    }
    async fn insert_audit(&self, _event: &AuditEvent, _now: Timestamp) -> Result<(), AuthError> {
        Err(AuthError::Unsupported)
    }
}

/// A tenant is created with `owner`, `admin`, and `member`. The port exposes no role
/// read, so the suite proves each name exists through the conflict a second insert of
/// that name produces.
async fn seeded_roles<S: AuthStore>(store: &S, auth: &Auth<'_, S>, now: Timestamp) {
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "seeded-roles", now)
        .await
        .expect("tenant");
    for name in ["owner", "admin", "member"] {
        assert_eq!(
            auth.create_role(tenant, name).await,
            Err(AuthError::Conflict),
            "{name} arrived with the tenant"
        );
    }
    auth.create_role(tenant, "conformance.first-role")
        .await
        .expect("a name outside the seed is still the caller's");
}

/// Catalogue writes: a tenant arrives with three role names; every other name is the
/// caller's.
async fn catalogue<S: AuthStore>(
    store: &S,
    auth: &Auth<'_, S>,
    tenant: Id,
    now: Timestamp,
) -> (Id, Id, Id) {
    let other = Id::now_v7();
    store
        .create_tenant(other, "membership-other", now)
        .await
        .expect("other tenant");
    let other_role = auth
        .create_role(other, "conformance.other-role")
        .await
        .expect("role in the other tenant");

    // An empty name is refused; every other name is stored as the caller wrote it.
    assert_eq!(
        auth.create_role(tenant, "   ").await,
        Err(AuthError::Invalid)
    );
    assert_eq!(
        auth.create_permission(tenant, "").await,
        Err(AuthError::Invalid)
    );
    let role = auth
        .create_role(tenant, "conformance.role")
        .await
        .expect("role name from the caller");
    let permission = auth
        .create_permission(tenant, "conformance.permission")
        .await
        .expect("permission name from the caller");
    assert_ne!(role, permission);
    assert_eq!(
        auth.create_role(tenant, "conformance.role").await,
        Err(AuthError::Conflict),
        "duplicate name in one tenant"
    );
    assert_eq!(
        auth.create_permission(tenant, "conformance.permission")
            .await,
        Err(AuthError::Conflict)
    );
    (role, other_role, other)
}

/// Membership creates an active membership for a user already in the tenant, and
/// only an active one is authority.
async fn memberships<S: AuthStore>(
    auth: &Auth<'_, S>,
    user: &User,
    other: Id,
    role: Id,
    other_role: Id,
    now: Timestamp,
) {
    let tenant = user.tenant_id;
    let outsider = auth
        .sign_up(other, "outsider@example.test", &hashed(PASSWORD), now)
        .await
        .expect("outsider");

    let membership = auth
        .create_membership(tenant, user.id, MembershipStatus::Invited, now)
        .await
        .expect("membership");
    assert_eq!(membership.status, MembershipStatus::Invited);
    assert!(
        !membership.status.is_authority(),
        "invited is not authority"
    );
    assert_eq!(
        auth.membership(tenant, user.id)
            .await
            .expect("read invited membership"),
        membership
    );
    assert_eq!(
        auth.create_membership(tenant, user.id, MembershipStatus::Active, now)
            .await,
        Err(AuthError::Conflict),
        "one membership per user and tenant"
    );
    assert_eq!(
        auth.create_membership(other, user.id, MembershipStatus::Active, now)
            .await,
        Err(AuthError::Conflict),
        "the user is not in that tenant"
    );
    assert_eq!(
        auth.membership(tenant, outsider.id).await,
        Err(AuthError::NotFound)
    );

    let active = auth
        .set_membership_status(membership.id, MembershipStatus::Active, now)
        .await
        .expect("activate membership");
    assert!(active.status.is_authority());
    let suspended = auth
        .set_membership_status(membership.id, MembershipStatus::Suspended, now)
        .await
        .expect("suspend membership");
    assert!(!suspended.status.is_authority());
    assert_eq!(
        auth.set_membership_status(Id::now_v7(), MembershipStatus::Active, now)
            .await,
        Err(AuthError::NotFound)
    );

    assert_eq!(
        auth.assign_role(membership.id, role, now)
            .await
            .expect("assign role")
            .id,
        membership.id
    );
    auth.assign_role(membership.id, role, now)
        .await
        .expect("repeated assignment");
    assert_eq!(
        auth.assign_role(membership.id, other_role, now).await,
        Err(AuthError::Conflict),
        "a role from another tenant"
    );
}

/// A group belongs to one tenant and holds memberships of that tenant. The caller
/// passes that tenant: a group in another tenant is `NotFound`. A repeated add
/// succeeds, and a membership of another tenant is refused. Both adapters run this.
async fn groups<S: AuthStore>(auth: &Auth<'_, S>, user: &User, other: Id, now: Timestamp) {
    let tenant = user.tenant_id;
    assert_eq!(
        auth.create_group(tenant, "   ", now).await,
        Err(AuthError::Invalid),
        "an empty name is refused"
    );
    let group = auth
        .create_group(tenant, " conformance.group ", now)
        .await
        .expect("group from the caller");
    assert_eq!(
        auth.create_group(tenant, "conformance.group", now).await,
        Err(AuthError::Conflict),
        "duplicate name in one tenant"
    );
    let other_group = auth
        .create_group(other, "conformance.group", now)
        .await
        .expect("the same name in another tenant");

    let membership = auth
        .membership(tenant, user.id)
        .await
        .expect("the membership the group holds");
    assert_eq!(
        auth.add_group_member(tenant, other_group, membership.id)
            .await,
        Err(AuthError::NotFound),
        "a group in another tenant looks missing"
    );
    auth.add_group_member(tenant, group, membership.id)
        .await
        .expect("add a membership");
    auth.add_group_member(tenant, group, membership.id)
        .await
        .expect("a repeated add succeeds");

    let foreign = auth
        .sign_up(other, "group-foreign@example.test", &hashed(PASSWORD), now)
        .await
        .expect("account in the other tenant");
    let foreign_membership = auth
        .create_membership(other, foreign.id, MembershipStatus::Active, now)
        .await
        .expect("membership in the other tenant");
    assert_eq!(
        auth.add_group_member(tenant, group, foreign_membership.id)
            .await,
        Err(AuthError::Conflict),
        "a membership from another tenant is not added"
    );
    assert_eq!(
        auth.add_group_member(tenant, Id::now_v7(), membership.id)
            .await,
        Err(AuthError::NotFound),
        "an unknown group"
    );
    assert_eq!(
        auth.add_group_member(tenant, group, Id::now_v7()).await,
        Err(AuthError::NotFound),
        "an unknown membership"
    );
    auth.add_group_member(other, other_group, foreign_membership.id)
        .await
        .expect("link the other tenant's own group");
    assert_eq!(
        auth.remove_group_member(tenant, other_group, foreign_membership.id)
            .await,
        Err(AuthError::NotFound),
        "the router tenant cannot remove another tenant's link"
    );
    auth.remove_group_member(other, other_group, foreign_membership.id)
        .await
        .expect("the other tenant's link is still there");

    auth.remove_group_member(tenant, group, membership.id)
        .await
        .expect("remove the membership");
    assert_eq!(
        auth.remove_group_member(tenant, group, membership.id).await,
        Err(AuthError::NotFound),
        "the pair is gone"
    );
}

/// An invitation is issued once, spent once, and leaves an active membership for the
/// account that holds its email.
async fn invitations<S: AuthStore>(
    auth: &Auth<'_, S>,
    user: &User,
    role: Id,
    other_role: Id,
    now: Timestamp,
) -> Membership {
    let tenant = user.tenant_id;
    let token = auth
        .issue_invitation(
            tenant,
            "  Invitee@Example.Test  ",
            now + Duration::hours(1),
            vec![role],
            now,
        )
        .await
        .expect("invitation");
    assert!(
        matches!(
            auth.issue_invitation(tenant, "invitee@example.test", now, vec![], now)
                .await,
            Err(AuthError::Invalid)
        ),
        "expiry must be in the future"
    );
    assert!(
        matches!(
            auth.issue_invitation(
                tenant,
                "invitee@example.test",
                now + Duration::hours(1),
                vec![other_role],
                now
            )
            .await,
            Err(AuthError::Conflict)
        ),
        "a role from another tenant"
    );
    assert_eq!(
        auth.accept_invitation("not-an-invitation-token", now).await,
        Err(AuthError::Unauthorized)
    );
    assert_eq!(
        auth.accept_invitation(token.expose(), now).await,
        Err(AuthError::NotFound),
        "no account holds the invited email yet"
    );

    let invitee = auth
        .sign_up(tenant, "invitee@example.test", &hashed(PASSWORD), now)
        .await
        .expect("invitee");
    let accepted = auth
        .accept_invitation(token.expose(), now)
        .await
        .expect("acceptance after registration");
    assert_eq!(accepted.user_id, invitee.id);
    assert_eq!(accepted.tenant_id, tenant);
    assert_eq!(accepted.status, MembershipStatus::Active);
    assert_eq!(
        auth.membership(tenant, invitee.id)
            .await
            .expect("membership created by acceptance"),
        accepted
    );
    assert_eq!(
        auth.accept_invitation(token.expose(), now).await,
        Err(AuthError::Unauthorized),
        "an invitation is spent once"
    );
    assert!(!format!("{token:?}").contains(token.expose()));
    accepted
}

/// A second invitation activates a suspended membership instead of adding a row, and
/// an expired one is refused.
async fn reinvitation<S: AuthStore>(
    auth: &Auth<'_, S>,
    user: &User,
    accepted: Membership,
    now: Timestamp,
) {
    let tenant = user.tenant_id;
    let second = auth
        .issue_invitation(
            tenant,
            "invitee@example.test",
            now + Duration::hours(1),
            vec![],
            now,
        )
        .await
        .expect("second invitation");
    auth.set_membership_status(accepted.id, MembershipStatus::Suspended, now)
        .await
        .expect("suspend the invitee");
    let reactivated = auth
        .accept_invitation(second.expose(), now)
        .await
        .expect("acceptance activates an existing membership");
    assert_eq!(reactivated.id, accepted.id, "no second membership");
    assert_eq!(reactivated.status, MembershipStatus::Active);

    let expired = auth
        .issue_invitation(
            tenant,
            "invitee@example.test",
            now + Duration::minutes(5),
            vec![],
            now,
        )
        .await
        .expect("expiring invitation");
    assert_eq!(
        auth.accept_invitation(expired.expose(), now + Duration::minutes(5))
            .await,
        Err(AuthError::Unauthorized)
    );
}

/// A suspended tenant is not active: no sign-in, no new membership, no invitation.
async fn suspended_tenant<S: AuthStore>(store: &S, auth: &Auth<'_, S>, now: Timestamp) {
    let dormant = Id::now_v7();
    store
        .create_tenant(dormant, "membership-dormant", now)
        .await
        .expect("dormant tenant");
    let member = auth
        .sign_up(dormant, "dormant@example.test", &hashed(PASSWORD), now)
        .await
        .expect("dormant user");
    auth.suspend_tenant(dormant, now)
        .await
        .expect("suspend tenant");
    assert!(matches!(
        sign_in(auth, dormant, "dormant@example.test", PASSWORD, now).await,
        Err(AuthError::Unauthorized)
    ));
    assert_eq!(
        auth.create_membership(dormant, member.id, MembershipStatus::Active, now)
            .await,
        Err(AuthError::Conflict)
    );
    assert!(matches!(
        auth.issue_invitation(
            dormant,
            "dormant@example.test",
            now + Duration::hours(1),
            vec![],
            now
        )
        .await,
        Err(AuthError::Conflict)
    ));
    assert_eq!(
        auth.suspend_tenant(Id::now_v7(), now).await,
        Err(AuthError::NotFound)
    );
}

/// A replaced [`Policy`] must reach sessions, lockout, and proofs, and issuance must
/// expose the raw token plus the 64-character version 1 hex digest.
#[allow(clippy::too_many_lines)]
async fn policy<S: AuthStore>(store: &S, now: Timestamp) {
    let auth = Auth::new(
        store,
        [9; 32],
        Policy {
            session_ttl: Duration::hours(2),
            session_sliding: true,
            session_max_lifetime: None,
            failure_limit: 3,
            lockout: Duration::minutes(7),
            proof_ttl: Duration::minutes(5),
        },
    );
    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "policy", now)
        .await
        .expect("tenant");
    let user = auth
        .sign_up(tenant, "policy@example.test", &hashed(PASSWORD), now)
        .await
        .expect("policy user");
    for _ in 0..3 {
        assert!(matches!(
            sign_in(&auth, tenant, &user.email, b"wrong", now).await,
            Err(AuthError::Unauthorized)
        ));
    }
    assert_eq!(
        store
            .password(user.id)
            .await
            .expect("three failures")
            .failed_attempts,
        3
    );
    assert!(matches!(
        sign_in(&auth, tenant, &user.email, PASSWORD, now).await,
        Err(AuthError::Unauthorized)
    ));

    let unlocked = now + Duration::minutes(7);
    let session = sign_in(&auth, tenant, &user.email, PASSWORD, unlocked)
        .await
        .expect("configured lockout expires");
    let extended = auth
        .resolve_session(
            session.token().expose(),
            unlocked + Duration::hours(2) - Duration::seconds(1),
        )
        .await
        .expect("inside the configured session ttl");
    assert_eq!(
        auth.resolve_session(session.token().expose(), extended.expires_at)
            .await,
        Err(AuthError::Unauthorized)
    );

    let (keyed, digest_hex) = auth.session_digest(session.token().expose());
    assert_eq!(digest_hex, session.digest_hex());
    assert_eq!(digest_hex.len(), 64);
    assert!(
        digest_hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );
    assert_ne!(
        session.digest_hex(),
        session.token().expose(),
        "the digest is not the bearer value"
    );
    let resolved = auth
        .resolve_session(session.token().expose(), unlocked)
        .await
        .expect("resolve issued session");
    assert_eq!(
        resolved.token_digest.len(),
        33,
        "version byte plus 32 bytes"
    );
    assert_eq!(&resolved.token_digest[1..], keyed.as_slice());

    let proof = auth
        .issue_proof(tenant, &user.email, Purpose::VerifyEmail, unlocked)
        .await
        .expect("configured proof");
    assert_eq!(
        auth.verify_email(
            proof.expose(),
            unlocked + Duration::minutes(5) - Duration::seconds(1)
        )
        .await,
        Ok(user.id)
    );
    let expired = auth
        .issue_proof(tenant, &user.email, Purpose::VerifyEmail, unlocked)
        .await
        .expect("configured proof");
    assert_eq!(
        auth.verify_email(expired.expose(), unlocked + Duration::minutes(5))
            .await,
        Err(AuthError::Unauthorized)
    );
}

/// Social sign-in through the non-HTTP workflows.
///
/// Returns the raw state value the first start minted so a database-specific test can
/// assert that the stored row holds the digest and not this value.
#[cfg(feature = "social")]
#[allow(clippy::too_many_lines)]
pub(crate) async fn social<S: AuthStore>(store: &S, now: Timestamp) -> Vec<u8> {
    use vaelspire_core::SocialProvider;

    let tenant = Id::now_v7();
    store
        .create_tenant(tenant, "social-conformance", now)
        .await
        .expect("social tenant");
    let auth = Auth::new(store, [51; 32], Policy::default()).auditing(true);

    // A start stores state, and the callback spends it into a session.
    let state = auth
        .start_social_state(
            tenant,
            SocialProvider::GitHub.as_str(),
            Duration::minutes(10),
            now,
        )
        .await
        .expect("state");
    let raw_state = state.expose().as_bytes().to_vec();
    let first = auth
        .complete_social_sign_in(
            tenant,
            SocialProvider::GitHub.as_str(),
            "subject-1",
            "social-created@example.test",
            true,
            state.expose(),
            now,
        )
        .await
        .expect("first social session");
    let first_session = auth
        .resolve_session(first.token().expose(), now)
        .await
        .expect("the session resolves");
    assert_eq!(first_session.tenant_id, tenant);

    // The same subject signs in to the account it already owns.
    let again = auth
        .start_social_state(
            tenant,
            SocialProvider::GitHub.as_str(),
            Duration::minutes(10),
            now,
        )
        .await
        .expect("second state");
    let second = auth
        .complete_social_sign_in(
            tenant,
            SocialProvider::GitHub.as_str(),
            "subject-1",
            "social-created@example.test",
            true,
            again.expose(),
            now,
        )
        .await
        .expect("second social session");
    let second_session = auth
        .resolve_session(second.token().expose(), now)
        .await
        .expect("the second session resolves");
    assert_eq!(
        second_session.user_id, first_session.user_id,
        "one subject is one account"
    );

    // A reused state is refused and issues no session.
    assert!(
        matches!(
            auth.complete_social_sign_in(
                tenant,
                SocialProvider::GitHub.as_str(),
                "subject-1",
                "social-created@example.test",
                true,
                state.expose(),
                now,
            )
            .await,
            Err(AuthError::Unauthorized)
        ),
        "a state is spent once"
    );

    // A provider email that belongs to another live account does not take it over.
    let victim = auth
        .sign_up(tenant, "social-taken@example.test", &hashed(PASSWORD), now)
        .await
        .expect("existing account");
    for (subject, verified) in [("subject-2", true), ("subject-3", false)] {
        let conflict_state = auth
            .start_social_state(
                tenant,
                SocialProvider::Google.as_str(),
                Duration::minutes(10),
                now,
            )
            .await
            .expect("conflict state");
        assert!(
            matches!(
                auth.complete_social_sign_in(
                    tenant,
                    SocialProvider::Google.as_str(),
                    subject,
                    "social-taken@example.test",
                    verified,
                    conflict_state.expose(),
                    now,
                )
                .await,
                Err(AuthError::Conflict)
            ),
            "a live email is never taken over, verified or not"
        );
    }
    assert_eq!(
        store
            .find_user(tenant, "social-taken@example.test")
            .await
            .expect("the original account")
            .id,
        victim.id,
        "the existing account keeps its identifier"
    );

    // A failed audit insert leaves no account, identity, or session.
    let blocked = reserve_audit(store, tenant, now).await;
    let mut rollback_digest = vec![7_u8; 33];
    rollback_digest[0] = 1;
    store
        .create_social_state(
            &rollback_digest,
            tenant,
            SocialProvider::Microsoft.as_str(),
            now + Duration::minutes(10),
            now,
        )
        .await
        .expect("rollback state");
    let session_id = Id::now_v7();
    let session_digest = vec![7_u8; 33];
    let event = collision(blocked, tenant, session_id, "auth.session.issued");
    assert_eq!(
        store
            .complete_social_sign_in(
                &rollback_digest,
                tenant,
                SocialProvider::Microsoft.as_str(),
                "subject-4",
                "social-rollback@example.test",
                true,
                session_id,
                &session_digest,
                now + Duration::hours(1),
                Some(event),
                now,
            )
            .await,
        Err(AuthError::Conflict),
        "the audit row cannot be written"
    );
    assert_eq!(
        store.find_session(&session_digest, now).await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no session"
    );
    assert_eq!(
        store
            .find_user(tenant, "social-rollback@example.test")
            .await,
        Err(AuthError::NotFound),
        "a failed audit insert leaves no account"
    );

    // Audit off writes no row and still issues the session.
    let quiet_tenant = Id::now_v7();
    store
        .create_tenant(quiet_tenant, "social-quiet", now)
        .await
        .expect("quiet tenant");
    let quiet = Auth::new(store, [52; 32], Policy::default());
    let quiet_state = quiet
        .start_social_state(
            quiet_tenant,
            SocialProvider::Google.as_str(),
            Duration::minutes(10),
            now,
        )
        .await
        .expect("quiet state");
    let quiet_issued = quiet
        .complete_social_sign_in(
            quiet_tenant,
            SocialProvider::Google.as_str(),
            "quiet-subject",
            "social-quiet@example.test",
            true,
            quiet_state.expose(),
            now,
        )
        .await
        .expect("quiet session");
    quiet
        .resolve_session(quiet_issued.token().expose(), now)
        .await
        .expect("the quiet session resolves");

    raw_state
}
