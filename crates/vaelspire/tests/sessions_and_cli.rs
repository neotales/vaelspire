//! Integration tests verifying sliding vs. fixed session expirations, hard absolute
//! session ceilings (`session_max_lifetime`), and GDPR privacy redaction guarantees.

use std::sync::Arc;

use time::Duration;
use vaelspire::bootstrap::ensure_tenant;
use vaelspire_auth::{Auth, Policy, SignInOutcome, hash_password};
use vaelspire_core::privacy::{AuditIpMode, PiiLogMode, format_email_for_log, format_ip_for_audit};
use vaelspire_core::{AuthError, Timestamp};
use vaelspire_store_sqlite::open;

#[tokio::test]
async fn fixed_sessions_do_not_slide_and_hard_max_lifetime_enforces_ceiling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(open(&dir.path().join("sess.sqlite")).await.expect("sqlite"));
    let tenant = ensure_tenant(&store, "sess-test").await.expect("tenant");
    let key = [0x33; 32];
    let now = Timestamp::now_utc();
    let hash = hash_password(b"correct-horse-battery-staple").expect("hash");

    // 1. Fixed session policy: does NOT slide even past half-TTL.
    let fixed_policy = Policy {
        session_ttl: Duration::hours(2),
        session_sliding: false,
        session_max_lifetime: None,
        ..Policy::default()
    };
    let fixed_auth = Auth::new(store.as_ref(), key, fixed_policy);
    fixed_auth
        .sign_up(tenant, "fixed@example.test", &hash, now)
        .await
        .expect("signup fixed");
    let attempt = fixed_auth
        .begin_sign_in(tenant, "fixed@example.test", now)
        .await
        .expect("begin");
    let issued = fixed_auth
        .finish_sign_in(
            attempt,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .expect("finish");
    let s1 = fixed_auth
        .resolve_session(issued.token().expose(), now + Duration::minutes(90))
        .await
        .expect("resolve at +90m");
    assert_eq!(
        s1.expires_at,
        now + Duration::hours(2),
        "fixed session must NOT slide past initial expiry"
    );

    // 2. Sliding session with hard absolute ceiling (idle 2h, max 3h).
    let sliding_hard_policy = Policy {
        session_ttl: Duration::hours(2),
        session_sliding: true,
        session_max_lifetime: Some(Duration::hours(3)),
        ..Policy::default()
    };
    let sliding_auth = Auth::new(store.as_ref(), key, sliding_hard_policy);
    sliding_auth
        .sign_up(tenant, "sliding@example.test", &hash, now)
        .await
        .expect("signup sliding");
    let attempt2 = sliding_auth
        .begin_sign_in(tenant, "sliding@example.test", now)
        .await
        .expect("begin2");
    let issued2 = sliding_auth
        .finish_sign_in(
            attempt2,
            SignInOutcome::Verified {
                replacement_hash: None,
            },
            now,
        )
        .await
        .expect("finish2");

    // At +90m (past half of 2h), sliding extends expiry, but CLAMPS at ~+3h hard ceiling!
    let s2 = sliding_auth
        .resolve_session(issued2.token().expose(), now + Duration::minutes(90))
        .await
        .expect("resolve sliding at +90m");
    assert!(
        s2.expires_at > now + Duration::hours(2),
        "sliding session should extend past initial 2h"
    );
    assert!(
        s2.expires_at <= now + Duration::hours(3) + Duration::seconds(2),
        "sliding extension must be clamped by 3h hard max_lifetime"
    );

    // Past the 3h hard ceiling (+3h 1m), session MUST be rejected as Unauthorized.
    let err = sliding_auth
        .resolve_session(issued2.token().expose(), now + Duration::minutes(181))
        .await
        .expect_err("must reject past hard max lifetime");
    assert_eq!(err, AuthError::Unauthorized);

    // Verify GDPR redaction & IP truncation helpers directly.
    assert_eq!(
        format_email_for_log("wfischer@domain.com", PiiLogMode::Masked),
        "wf******@domain.com"
    );
    assert_eq!(
        format_ip_for_audit(Some("198.51.100.77"), AuditIpMode::Truncated).as_deref(),
        Some("198.51.100.0/24")
    );
}
