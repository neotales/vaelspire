//! Authentication workflows over an application-selected store.
//! Password/session are defaults; API keys are explicitly enabled with `apikeys`,
//! signing in with an email proof is explicitly enabled with `email-signin`, and
//! signing in with a GitHub, Google, or Microsoft identity is explicitly enabled with
//! `social`, which does not need `password`. Signing in with a passkey is explicitly
//! enabled with `passkey`. The caller of those methods passes the relying party id and
//! origin; the store never contains them.
//!
//! No async workflow here runs Argon2 or bcrypt. A caller hashes with
//! [`hash_password`] before [`Auth::sign_up`] and [`Auth::reset_password`], and
//! verifies with [`verify_password`] between [`Auth::begin_sign_in`] and
//! [`Auth::finish_sign_in`], so that work belongs on its blocking executor.
//!
//! Membership, role, group, and invitation workflows store only names the application
//! supplied; a tenant is created with `owner`, `admin`, and `member`, and the crate
//! seeds no permission. Audit is off by default and
//! enabled per [`Auth`] with [`Auth::auditing`]. An enabled audit writes one
//! `auth_audit` row per successful or denied identity mutation. A mutation hands its
//! row to the store call that writes it, so the two commit in one transaction and a
//! failed insert leaves neither. A refusal that writes no mutation writes the row on
//! its own.
//!
//! A row carries the tenant and the actor the workflow knows: a user acting on their
//! own account is the actor, and a refusal after the store was consulted has an
//! outcome of `denied`. Administrative mutations (a membership, an invitation) have
//! no actor the library can verify, so `actor_id` is null. Client IP and user agent
//! arrive only from a [`Call`]; a workflow run on the shared [`Auth`] writes them
//! null. No password, token, OTP, digest, or key value is ever in a row.

#[cfg(feature = "mfa")]
pub mod mfa;
#[cfg(feature = "passkey")]
mod passkey;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use time::Duration;
#[cfg(feature = "password")]
use vaelspire_core::PasswordCredential;
#[cfg(feature = "session")]
use vaelspire_core::Session;
#[cfg(any(feature = "password", feature = "apikeys"))]
use vaelspire_core::User;
use vaelspire_core::{
    AuditEvent, AuthError, AuthStore, Id, Invitation, Membership, MembershipStatus, OneTime,
    Purpose, Timestamp,
};
use zeroize::Zeroizing;

#[cfg(feature = "session")]
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

#[cfg(feature = "session")]
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(0);

// Invalidating both on entry and drop also covers cancellation of an in-flight
// mutation. A concurrent old read can only populate an already-stale generation.
#[cfg(feature = "session")]
struct InvalidateSessions;
#[cfg(feature = "session")]
impl InvalidateSessions {
    fn new() -> Self {
        SESSION_GENERATION.fetch_add(1, Ordering::SeqCst);
        Self
    }
}
#[cfg(feature = "session")]
impl Drop for InvalidateSessions {
    fn drop(&mut self) {
        SESSION_GENERATION.fetch_add(1, Ordering::SeqCst);
    }
}

/// Per-router session cache. Another process may serve a revoked session for up to
/// its cache duration. Share this value among every local workflow that revokes a
/// session. It stores keyed digests and session snapshots, never bearer values.
#[cfg(feature = "session")]
#[derive(Debug)]
pub struct SessionCache {
    duration: std::time::Duration,
    entries: tokio::sync::Mutex<HashMap<Vec<u8>, (Session, Instant, u64)>>,
}

#[cfg(feature = "session")]
impl SessionCache {
    /// Create a cache with the supplied lifetime. Zero disables caching.
    #[must_use]
    pub fn new(duration: std::time::Duration) -> Self {
        Self {
            duration,
            entries: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[cfg(feature = "session")]
impl Default for SessionCache {
    fn default() -> Self {
        Self::new(std::time::Duration::from_secs(5))
    }
}

// Stable action names. An application filters audit rows on these strings, so they
// do not change when a workflow is refactored. Catalogue writes (permission and role)
// and tenant status have no action in this set and write no event.
#[cfg(feature = "password")]
const ACTION_USER_CREATED: &str = "auth.user.created";
#[cfg(any(
    all(feature = "password", feature = "session"),
    feature = "email-signin",
    feature = "social",
    feature = "passkey"
))]
const ACTION_SESSION_ISSUED: &str = "auth.session.issued";
#[cfg(any(
    all(feature = "password", feature = "session"),
    feature = "email-signin",
    feature = "social",
    feature = "passkey"
))]
const ACTION_SESSION_DENIED: &str = "auth.session.denied";
#[cfg(feature = "passkey")]
const ACTION_PASSKEY_REGISTERED: &str = "auth.passkey.registered";
#[cfg(feature = "session")]
const ACTION_SESSION_REVOKED: &str = "auth.session.revoked";
#[cfg(feature = "session")]
const ACTION_SESSION_EXTENDED: &str = "auth.session.extended";
const ACTION_PROOF_ISSUED: &str = "auth.proof.issued";
const ACTION_EMAIL_VERIFIED: &str = "auth.email.verified";
#[cfg(feature = "password")]
const ACTION_PASSWORD_RESET: &str = "auth.password.reset";
#[cfg(all(feature = "password", feature = "session"))]
const ACTION_PASSWORD_CHANGED: &str = "auth.password.changed";
#[cfg(feature = "session")]
const ACTION_EMAIL_CHANGED: &str = "auth.email.changed";
#[cfg(feature = "session")]
const ACTION_USER_DELETED: &str = "auth.user.deleted";
const ACTION_MEMBERSHIP_CREATED: &str = "auth.membership.created";
const ACTION_MEMBERSHIP_UPDATED: &str = "auth.membership.updated";
const ACTION_INVITATION_ISSUED: &str = "auth.invitation.issued";
const ACTION_INVITATION_ACCEPTED: &str = "auth.invitation.accepted";
#[cfg(all(feature = "apikeys", feature = "session"))]
const ACTION_API_KEY_REVOKED: &str = "auth.api_key.revoked";

#[cfg(feature = "password")]
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// A one-time returned bearer value. Debug is redacted and drop clears its buffer.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Explicitly expose the value for delivery to its intended recipient. Never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

/// A newly issued session: the bearer token, returned once, and the digest to store.
///
/// This is not a row shape. An application may add its own columns to a session
/// table (a membership identifier, a CSRF secret digest, an authentication factor);
/// the library does not model them.
#[derive(Debug)]
pub struct IssuedSession {
    token: Secret,
    digest_hex: String,
}

/// Password-verified login awaiting a second factor. Its bearer is returned once;
/// only its keyed digest is stored.
#[cfg(feature = "mfa")]
pub struct PendingSignIn(Secret);

#[cfg(feature = "mfa")]
impl PendingSignIn {
    /// Expose the one-time challenge token for delivery to the client.
    #[must_use]
    pub fn token(&self) -> &Secret {
        &self.0
    }
}

/// Password sign-in either issued a session or is awaiting MFA.
#[cfg(feature = "mfa")]
#[derive(Debug)]
pub enum SignInResult {
    /// Fully authenticated session.
    Session(IssuedSession),
    /// Second-factor challenge required.
    Pending(PendingSignIn),
}
#[cfg(feature = "mfa")]
type SignInCompletion = SignInResult;
#[cfg(not(feature = "mfa"))]
type SignInCompletion = IssuedSession;

#[cfg(feature = "mfa")]
impl std::fmt::Debug for PendingSignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingSignIn([REDACTED])")
    }
}

impl IssuedSession {
    /// Bearer value to hand to the client, exactly once. Never log it.
    #[must_use]
    pub fn token(&self) -> &Secret {
        &self.token
    }

    /// 64-character lowercase hex form of the session token's keyed digest.
    ///
    /// This is version 1 of the digest and is what a `^[0-9a-f]{64}$` column stores;
    /// the version byte is not part of it. See [`Auth::session_digest`].
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        &self.digest_hex
    }
}

/// What one of the caller's sessions looks like when the caller lists them.
///
/// This is a read model, not a row: it carries the identifier used to revoke that
/// session and its exclusive expiry, and the flag that marks the session that made the
/// request. It never carries the bearer token or the stored digest.
#[cfg(feature = "session")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    /// `UUIDv7` identifier to hand to [`Auth::revoke_session`].
    pub id: Id,
    /// Exclusive expiry instant.
    pub expires_at: Timestamp,
    /// Whether this is the session the listing was made for.
    pub current: bool,
}

/// A sign-in's loaded account and credential, waiting for the caller's password check.
///
/// [`Auth::begin_sign_in`] returns this instead of verifying, so the Argon2 work can
/// happen off the async worker. The caller reads [`Self::password_hash`], verifies
/// with [`verify_password`], rehashes with [`hash_password`] when
/// [`Self::needs_rehash`] says the stored hash is legacy bcrypt, and hands the result
/// to [`Auth::finish_sign_in`]. The value holds no token and no store handle.
#[cfg(all(feature = "password", feature = "session"))]
#[derive(Debug)]
pub struct SignInAttempt {
    tenant: Id,
    user: User,
    credential: PasswordCredential,
}

#[cfg(all(feature = "password", feature = "session"))]
impl SignInAttempt {
    /// The account the lookup found.
    #[must_use]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// The stored hash to verify: an Argon2id PHC string, or a legacy bcrypt hash.
    #[must_use]
    pub fn password_hash(&self) -> &str {
        &self.credential.password_hash
    }

    /// Whether the stored hash is legacy bcrypt and should be replaced after a
    /// successful verification. The library never writes bcrypt.
    #[must_use]
    pub fn needs_rehash(&self) -> bool {
        self.credential.password_hash.starts_with("$2")
    }
}

/// What the caller's password check found, handed to [`Auth::finish_sign_in`].
///
/// One value carries one outcome, so a failed check cannot arrive with a replacement
/// hash and a verified one cannot leave the failure path open.
#[cfg(all(feature = "password", feature = "session"))]
#[derive(Debug)]
pub enum SignInOutcome<'h> {
    /// The password did not verify. The failure count and the denial audit are recorded.
    Failed,
    /// The password verified. `replacement_hash` is the fresh Argon2id hash
    /// [`hash_password`] produced for a legacy bcrypt credential, or `None` when the
    /// stored hash already is Argon2id.
    Verified {
        /// Argon2id replacement for a legacy bcrypt hash, or `None`.
        replacement_hash: Option<&'h str>,
    },
}

/// Keyed digest of a bearer token under a domain label, in both forms a caller stores.
///
/// This is the encoding [`Auth::session_digest`] and [`Auth::proof_digest`] apply,
/// without a store, a [`Policy`], or an [`Auth`]: BLAKE3 keyed with `key`, over the
/// `domain` bytes, one `0` byte, and the token bytes. Two tokens of the same value
/// hash differently under different labels, so a session token is not a proof token
/// and a verification token is not a reset token. The library's own labels are
/// `"session"` and [`Purpose::as_str`] (`verify_email`, `reset_password`,
/// `email_otp`). `"invitation"` and `"api_key"` use the same keyed encoding and are
/// stored only as version byte `1` plus the 32 bytes, not as hex.
///
/// Returns the 32 keyed bytes and their 64-character lowercase hex form. The hex
/// form is version 1 of that digest and carries no version byte: it is what belongs
/// in a column checked against `^[0-9a-f]{64}$`. The library's own rows keep the
/// version byte `1` followed by the same 32 bytes, through the private `versioned`
/// helper.
///
/// A caller that keeps its own token table calls this directly and never needs to
/// construct an [`Auth`] to get a digest.
#[must_use]
pub fn token_digest(key: &[u8; 32], domain: &str, token: &str) -> ([u8; 32], String) {
    let keyed = keyed(key, domain, token);
    (keyed, hex(&keyed))
}

/// Hash a new password using Argon2id, the library's default cost, and a random salt.
///
/// This is [`hash_password_with`] at [`argon2::Params::default`], so an application that
/// configures a cost elsewhere gets the same result from either function once it passes
/// its own cost in.
///
/// # Errors
/// Returns `Invalid` for an empty/oversized password, `Store` if hashing fails.
#[cfg(feature = "password")]
pub fn hash_password(password: &[u8]) -> Result<String, AuthError> {
    let default = argon2::Params::default();
    hash_password_with(
        password,
        default.m_cost(),
        default.t_cost(),
        default.p_cost(),
    )
}

/// Hash a new password using Argon2id at a caller-selected cost.
///
/// `memory_kib` is the Argon2 memory size in kibibytes, `iterations` the time cost, and
/// `parallelism` the number of lanes. Pass the values the application validated at boot
/// rather than re-deriving them here; the library validates them again through
/// [`argon2::Params::new`] but has no opinion about the right cost for a deployment.
///
/// # Errors
/// Returns `Invalid` for an empty/oversized password or a cost Argon2 rejects
/// (`parallelism` of zero, `memory_kib` below `8 * parallelism`, and similar),
/// or `Store` if hashing fails.
#[cfg(feature = "password")]
pub fn hash_password_with(
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, AuthError> {
    if password.is_empty() || password.len() > 1024 {
        return Err(AuthError::Invalid);
    }
    let params = argon2::Params::new(memory_kib, iterations, parallelism, None)
        .map_err(|_| AuthError::Invalid)?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password(password)
        .map(|h| h.to_string())
        .map_err(|_| AuthError::Store)
}

/// Verify Argon2id or legacy bcrypt. This function never writes bcrypt.
/// Bcrypt inputs over 72 bytes are refused rather than silently truncated.
///
/// # Errors
/// Returns `Unauthorized` for malformed hashes.
#[cfg(feature = "password")]
pub fn verify_password(password: &[u8], encoded_hash: &str) -> Result<bool, AuthError> {
    if password.is_empty() || password.len() > 1024 {
        return Ok(false);
    }
    if encoded_hash.starts_with("$2") {
        if password.len() > 72 {
            return Ok(false);
        }
        return bcrypt::verify(password, encoded_hash).map_err(|_| AuthError::Unauthorized);
    }
    let hash = PasswordHash::new(encoded_hash).map_err(|_| AuthError::Unauthorized)?;
    if hash.algorithm.as_str() != "argon2id" {
        return Err(AuthError::Unauthorized);
    }
    Ok(Argon2::default().verify_password(password, &hash).is_ok())
}

/// Session, lockout, and proof policy.
///
/// Every value has a default, and every value is a public field, so an application
/// replaces exactly the ones it exposes as configuration instead of inheriting a
/// value the library happened to choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Lifetime (and sliding idle window when [`Self::session_sliding`] is `true`)
    /// of a session issued by [`Auth::finish_sign_in`], starting at the supplied instant.
    pub session_ttl: Duration,
    /// When `true` (default), active sessions extend automatically once half of
    /// [`Self::session_ttl`] has elapsed. When `false`, sessions use a fixed timeout.
    pub session_sliding: bool,
    /// Optional hard absolute maximum lifetime measured from the session's creation
    /// timestamp (`UUIDv7`). Sliding extensions never cross this ceiling, and once
    /// `now >= created_at + max_lifetime` the session is rejected as `Unauthorized`.
    pub session_max_lifetime: Option<Duration>,
    /// Consecutive failed passwords that lock the account.
    pub failure_limit: i32,
    /// How long the account stays locked once [`Self::failure_limit`] is reached.
    pub lockout: Duration,
    /// Lifetime of a one-time proof issued by [`Auth::issue_proof`].
    pub proof_ttl: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            session_ttl: Duration::hours(24),
            session_sliding: true,
            session_max_lifetime: None,
            failure_limit: 5,
            lockout: Duration::minutes(15),
            proof_ttl: Duration::minutes(30),
        }
    }
}

#[cfg(feature = "session")]
fn session_hard_deadline(session_id: Id, max_lifetime: Option<Duration>) -> Option<Timestamp> {
    let max_lifetime = max_lifetime?;
    let ts = session_id.get_timestamp()?;
    let (secs, nanos) = ts.to_unix();
    let total_nanos = i128::from(secs)
        .checked_mul(1_000_000_000)?
        .checked_add(i128::from(nanos))?;
    let created_at = Timestamp::from_unix_timestamp_nanos(total_nanos).ok()?;
    Some(created_at + max_lifetime)
}

/// Workflows with a caller-owned store, a 256-bit digest key, and a [`Policy`].
/// The key must be stable across restarts and supplied by the application's secret provider.
/// Operations take UTC time explicitly; expiry is exclusive. No delivery or logging occurs.
///
/// The value is shared and holds no request state: audit metadata arrives through a
/// per-call [`Call`], and audit itself is a per-instance switch, off unless
/// [`Auth::auditing`] turned it on.
///
/// A mutation returning [`AuthError::Store`] may have committed despite the
/// error. Reconcile persisted state before retrying, especially for one-time
/// proofs, invitations, sign-ins, and token issuance.
pub struct Auth<'a, S> {
    store: &'a S,
    key: Zeroizing<[u8; 32]>,
    policy: Policy,
    audit: bool,
    #[cfg(feature = "session")]
    cache: Option<Arc<SessionCache>>,
}

impl<S> std::fmt::Debug for Auth<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

// `S` is only borrowed, so a clone copies the reference, the key, and the policy
// without requiring the store to be `Clone`.
impl<S> Clone for Auth<'_, S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store,
            key: self.key.clone(),
            policy: self.policy,
            audit: self.audit,
            #[cfg(feature = "session")]
            cache: self.cache.clone(),
        }
    }
}

/// Request metadata for one call's audit row.
#[derive(Clone, Copy, Default)]
struct Meta<'m> {
    ip: Option<&'m str>,
    user_agent: Option<&'m str>,
}

impl<'a, S: AuthStore> Auth<'a, S> {
    /// Begin TOTP enrollment for an authenticated account. The returned secret is
    /// returned only once; the caller must not log it. The caller supplies the key
    /// identified by `key_id` from its secret provider. An existing factor is never
    /// replaced.
    ///
    /// The returned value is the 160-bit key encoded as **unpadded URL-safe base64**
    /// (base64url, no `=`). It is the caller-visible form for delivery or provisioning.
    /// Decode it before calling [`mfa::totp_code`], which takes the raw key bytes; the
    /// stored factor holds only the AES-GCM ciphertext.
    ///
    /// # Errors
    /// Returns a store, conflict, invalid input, or cryptographic error.
    #[cfg(feature = "mfa")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn enroll_totp(
        &self,
        user: Id,
        key_id: &str,
        key: &[u8; 32],
    ) -> Result<Secret, AuthError> {
        if key_id.is_empty() || key_id.len() > 64 {
            return Err(AuthError::Invalid);
        }
        let mut raw = Zeroizing::new([0u8; 20]);
        getrandom::fill(raw.as_mut()).map_err(|_| AuthError::Store)?;
        let ciphertext = mfa::encrypt_secret(key, raw.as_ref(), user.as_bytes())?;
        self.store.save_mfa(user, &ciphertext, key_id).await?;
        Ok(Secret(Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_ref()))))
    }

    /// Confirm an enrollment with a TOTP at the supplied instant. The key identifier
    /// must match the stored factor. Caller authorizes access to `user`.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an incorrect code or key identifier, or a store error.
    #[cfg(feature = "mfa")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn confirm_totp(
        &self,
        user: Id,
        key_id: &str,
        key: &[u8; 32],
        code: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let factor = self.store.load_mfa(user).await?;
        if factor.key_id != key_id || factor.enabled_at.is_some() || now.unix_timestamp() < 0 {
            return Err(AuthError::Unauthorized);
        }
        let secret = mfa::decrypt_secret(key, &factor.secret_crypt, user.as_bytes())?;
        if !mfa::verify_totp(&secret, code, now.unix_timestamp().cast_unsigned()) {
            return Err(AuthError::Unauthorized);
        }
        self.store.enable_mfa(user, &factor.secret_crypt, now).await
    }

    /// Issue a one-use recovery code for an enabled factor. Caller authorizes access
    /// to `user`. Only a keyed digest is stored; the returned code is shown once.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an unconfirmed factor, or a store or random error.
    #[cfg(feature = "mfa")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn issue_recovery_code(&self, user: Id) -> Result<Secret, AuthError> {
        if self.store.load_mfa(user).await?.enabled_at.is_none() {
            return Err(AuthError::Unauthorized);
        }
        let code = random_secret()?;
        let digest = versioned(keyed(&self.key, "mfa-recovery", code.expose()));
        self.store
            .insert_recovery_code(Id::now_v7(), user, &digest)
            .await?;
        Ok(code)
    }
    /// Construct with the selected store, an application-managed digest key, and the
    /// session policy. Use [`Policy::default`] to accept the library's defaults.
    #[must_use]
    pub fn new(store: &'a S, digest_key: [u8; 32], policy: Policy) -> Self {
        Self {
            store,
            key: Zeroizing::new(digest_key),
            policy,
            audit: false,
            #[cfg(feature = "session")]
            cache: None,
        }
    }

    /// Share a session cache with other local workflows using the same store and key.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn session_cache(mut self, cache: Arc<SessionCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Turn audit on or off for this value. Off is the default.
    ///
    /// When on, a successful or denied identity mutation writes one append-only
    /// `auth_audit` row. A mutation hands that row to the store call that writes the
    /// mutation, so the mutation and the row commit in one transaction; a failed insert
    /// returns its error and leaves neither. Only a denial that writes no mutation
    /// writes the row in its own call. Turning audit off writes nothing and preserves
    /// the previous behaviour exactly.
    #[must_use]
    pub fn auditing(mut self, enabled: bool) -> Self {
        self.audit = enabled;
        self
    }

    /// Start a per-call carrier for request metadata.
    ///
    /// [`Auth`] stays shared and free of request state, so this returns a clone that
    /// adds an optional client IP and user agent to the audit row of the workflows it
    /// runs. A call made on `Auth` directly writes those columns null.
    #[must_use]
    pub fn call(&self) -> Call<'a, S> {
        Call {
            auth: self.clone(),
            ip: None,
            user_agent: None,
        }
    }

    fn keyed(&self, domain: &str, value: &str) -> [u8; 32] {
        keyed(&self.key, domain, value)
    }

    fn digest(&self, domain: &str, value: &str) -> Vec<u8> {
        versioned(self.keyed(domain, value))
    }

    /// Build the audit row for a mutation, or `None` when audit is off.
    ///
    /// The returned event is handed to the store method that writes the mutation, so
    /// the row and the mutation commit in one transaction. A workflow that only
    /// refuses a request writes no mutation and uses [`Self::record`] instead.
    fn audit_event(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Option<Id>,
        actor: Option<Id>,
        action: &str,
        outcome: &str,
    ) -> Option<AuditEvent> {
        if !self.audit {
            return None;
        }
        let mut fields = Vec::new();
        if let Some(meta) = meta {
            if let Some(ip) = meta.ip {
                fields.push(("ip".to_owned(), clip(ip, 64)));
            }
            if let Some(user_agent) = meta.user_agent {
                fields.push(("user_agent".to_owned(), clip(user_agent, 512)));
            }
        }
        Some(AuditEvent {
            id: Id::now_v7(),
            tenant_id: tenant,
            actor_id: actor,
            action: action.to_owned(),
            outcome: outcome.to_owned(),
            fields,
        })
    }

    /// Append one audit row for a denial that writes no mutation, unless audit is off.
    /// A failed insert is the call's error.
    async fn record(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Option<Id>,
        actor: Option<Id>,
        action: &str,
        outcome: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let Some(event) = self.audit_event(meta, tenant, actor, action, outcome) else {
            return Ok(());
        };
        self.store.insert_audit(&event, now).await
    }

    /// Keyed digest of a session token, in the two forms a caller stores.
    ///
    /// Returns the 32-byte keyed digest and its 64-character lowercase hex form.
    /// The hex form is version 1 of that digest: it is what belongs in a column
    /// checked against `^[0-9a-f]{64}$`. The library's own `auth_session` row keeps
    /// the version byte `1` followed by the same 32 bytes, so the version byte is
    /// not part of the hex form.
    #[must_use]
    pub fn session_digest(&self, token: &str) -> ([u8; 32], String) {
        token_digest(&self.key, "session", token)
    }

    /// Keyed digest of a one-time proof token, in the two forms a caller stores.
    ///
    /// Returns the 32-byte keyed digest and its 64-character lowercase hex form, the
    /// same pair [`Auth::session_digest`] returns for a session token, domain-separated
    /// by `purpose`: a token hashes differently for [`Purpose::VerifyEmail`],
    /// [`Purpose::ResetPassword`], and [`Purpose::EmailOtp`]. This lets a caller that
    /// cannot spend the proof — sign-up holding an open transaction, for example — hash
    /// a verification or reset token and write its own row without calling
    /// [`Auth::issue_proof`].
    ///
    /// The hex form is version 1 of that digest: it is what belongs in a column checked
    /// against `^[0-9a-f]{64}$`, and the version byte is not part of it. The library's own
    /// `auth_one_time` row keeps the version byte `1` followed by the same 32 bytes.
    #[must_use]
    pub fn proof_digest(&self, purpose: Purpose, token: &str) -> ([u8; 32], String) {
        token_digest(&self.key, purpose.as_str(), token)
    }

    /// Register a normalized account with a password hash the caller already computed.
    ///
    /// Hash the password with [`hash_password`] or [`hash_password_with`] on a
    /// blocking executor, and pass the encoded hash here: this workflow stores the
    /// account and that hash, with the audit row, in one store call, and never runs
    /// Argon2 itself. An unusable password is refused by the hashing function,
    /// before this call. Tenant must already exist. Duplicate live email fails
    /// without a partial account.
    ///
    /// # Errors
    /// Returns `Invalid` for an invalid email, `Conflict` for a duplicate email or a
    /// hash the store will not accept — anything that is not an Argon2id PHC string —
    /// or `Store` on storage failure.
    #[cfg(feature = "password")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn sign_up(
        &self,
        tenant: Id,
        email: &str,
        password_hash: &str,
        now: Timestamp,
    ) -> Result<User, AuthError> {
        self.sign_up_with(None, tenant, email, password_hash, now)
            .await
    }

    #[cfg(feature = "password")]
    async fn sign_up_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        email: &str,
        password_hash: &str,
        now: Timestamp,
    ) -> Result<User, AuthError> {
        let email = normalized_email(email)?;
        let user = User {
            id: Id::now_v7(),
            tenant_id: tenant,
            email,
        };
        let audit = self.audit_event(meta, Some(tenant), Some(user.id), ACTION_USER_CREATED, "ok");
        self.store
            .create_user(&user, password_hash, audit, now)
            .await?;
        Ok(user)
    }

    /// Load the account and credential for a password check: the first half of sign-in.
    ///
    /// This resolves the account, reads the credential, and refuses an unknown or
    /// locked account, auditing that refusal exactly as a rejected password is
    /// audited. It returns the stored hash so the caller can run [`verify_password`]
    /// — and [`hash_password`] for a legacy bcrypt hash — on a blocking executor,
    /// outside the async workflow, and then call [`Auth::finish_sign_in`].
    ///
    /// # Errors
    /// Returns `Unauthorized` for unknown, inactive, or locked accounts, or `Store`
    /// on I/O failure.
    #[cfg(all(feature = "password", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn begin_sign_in(
        &self,
        tenant: Id,
        email: &str,
        now: Timestamp,
    ) -> Result<SignInAttempt, AuthError> {
        self.begin_sign_in_with(None, tenant, email, now).await
    }

    #[cfg(all(feature = "password", feature = "session"))]
    async fn begin_sign_in_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        email: &str,
        now: Timestamp,
    ) -> Result<SignInAttempt, AuthError> {
        let user = match self
            .store
            .find_user(tenant, &email.trim().to_lowercase())
            .await
            .map_err(hide_missing)
        {
            Ok(user) => user,
            Err(AuthError::Unauthorized) => {
                self.record(
                    meta,
                    Some(tenant),
                    None,
                    ACTION_SESSION_DENIED,
                    "denied",
                    now,
                )
                .await?;
                return Err(AuthError::Unauthorized);
            }
            Err(error) => return Err(error),
        };
        let credential = self.store.password(user.id).await?;
        if credential.locked_until.is_some_and(|until| until > now) {
            self.record(
                meta,
                Some(tenant),
                Some(user.id),
                ACTION_SESSION_DENIED,
                "denied",
                now,
            )
            .await?;
            return Err(AuthError::Unauthorized);
        }
        Ok(SignInAttempt {
            tenant,
            user,
            credential,
        })
    }

    /// Record the password check and issue the session when it passed: the second half
    /// of sign-in.
    ///
    /// [`SignInOutcome::Failed`] records the failure and audits the denial as
    /// `auth.session.denied`. Without an enabled MFA factor, [`SignInOutcome::Verified`]
    /// clears failures and stores a session, returning its token and hex digest. Its
    /// `replacement_hash` rewrites a legacy bcrypt credential as Argon2id in that store
    /// call. With MFA enabled it returns a pending challenge instead of a session.
    ///
    /// # Errors
    /// Returns `Unauthorized` for a failed password or a credential that changed since
    /// [`Auth::begin_sign_in`] read it, `Conflict` for a verified legacy bcrypt login
    /// with no `replacement_hash` (the store will not keep bcrypt), or `Store` on I/O
    /// failure.
    ///
    /// An application's handler hashes and verifies on its own blocking executor and
    /// calls this once per outcome:
    ///
    /// ```no_run
    /// use vaelspire_auth::{Auth, SignInOutcome, hash_password, verify_password};
    /// use vaelspire_core::{AuthError, AuthStore, Id, Timestamp};
    ///
    /// async fn application_sign_in<S: AuthStore>(
    ///     auth: &Auth<'_, S>,
    ///     tenant: Id,
    ///     email: &str,
    ///     password: &[u8],
    ///     now: Timestamp,
    /// ) -> Result<(), AuthError> {
    ///     let attempt = auth.begin_sign_in(tenant, email, now).await?;
    ///     let verified = verify_password(password, attempt.password_hash())?;
    ///     let replacement = if verified && attempt.needs_rehash() {
    ///         Some(hash_password(password)?)
    ///     } else {
    ///         None
    ///     };
    ///     let outcome = if verified {
    ///         SignInOutcome::Verified {
    ///             replacement_hash: replacement.as_deref(),
    ///         }
    ///     } else {
    ///         SignInOutcome::Failed
    ///     };
    ///     auth.finish_sign_in(attempt, outcome, now).await?;
    ///     Ok(())
    /// }
    /// ```
    #[cfg(all(feature = "password", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_sign_in(
        &self,
        attempt: SignInAttempt,
        outcome: SignInOutcome<'_>,
        now: Timestamp,
    ) -> Result<SignInCompletion, AuthError> {
        self.finish_sign_in_with(None, attempt, outcome, now).await
    }

    #[cfg(all(feature = "password", feature = "session"))]
    async fn finish_sign_in_with(
        &self,
        meta: Option<Meta<'_>>,
        attempt: SignInAttempt,
        outcome: SignInOutcome<'_>,
        now: Timestamp,
    ) -> Result<SignInCompletion, AuthError> {
        let SignInAttempt {
            tenant,
            user,
            credential,
        } = attempt;
        let replacement_hash = match outcome {
            SignInOutcome::Verified { replacement_hash } => replacement_hash,
            SignInOutcome::Failed => {
                let audit = self.audit_event(
                    meta,
                    Some(tenant),
                    Some(user.id),
                    ACTION_SESSION_DENIED,
                    "denied",
                );
                self.store
                    .record_failure(
                        user.id,
                        audit,
                        now,
                        now + self.policy.lockout,
                        self.policy.failure_limit,
                    )
                    .await?;
                return Err(AuthError::Unauthorized);
            }
        };
        #[cfg(feature = "mfa")]
        match self.store.load_mfa(user.id).await {
            Ok(factor) if factor.enabled_at.is_some() => {
                let token = random_secret()?;
                let digest = versioned(keyed(&self.key, "mfa-pending", token.expose()));
                self.store
                    .create_mfa_pending(
                        &digest,
                        user.id,
                        tenant,
                        &credential.password_hash,
                        now + Duration::minutes(5),
                    )
                    .await?;
                return Ok(SignInResult::Pending(PendingSignIn(token)));
            }
            Ok(_) | Err(AuthError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let token = random_secret()?;
        let (keyed, digest_hex) = self.session_digest(token.expose());
        let session = Session {
            id: Id::now_v7(),
            user_id: user.id,
            tenant_id: tenant,
            token_digest: versioned(keyed),
            expires_at: now + self.policy.session_ttl,
        };
        self.store
            .complete_login(
                &session,
                &credential.password_hash,
                replacement_hash,
                self.audit_event(
                    meta,
                    Some(tenant),
                    Some(user.id),
                    ACTION_SESSION_ISSUED,
                    "ok",
                ),
                now,
            )
            .await?;
        let issued = IssuedSession { token, digest_hex };
        #[cfg(feature = "mfa")]
        {
            Ok(SignInResult::Session(issued))
        }
        #[cfg(not(feature = "mfa"))]
        {
            Ok(issued)
        }
    }

    /// Complete a pending login using a TOTP or one-use recovery code.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an invalid, expired, or already-consumed pending token
    /// or code; `Store` on an I/O or cryptographic failure.
    #[cfg(all(feature = "mfa", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_mfa(
        &self,
        pending_token: &str,
        code: &str,
        key_id: &str,
        key: &[u8; 32],
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        let digest = versioned(keyed(&self.key, "mfa-pending", pending_token));
        // The challenge identifies user; consume path is bound to the factor's owner by
        // looking up candidates through the challenge store in complete_mfa_login.
        let session_token = random_secret()?;
        let (keyed_session, digest_hex) = self.session_digest(session_token.expose());
        // Use recovery digest namespace as a second credential option. TOTP auth uses
        // the caller's key identifier and a user id carried by challenge completion.
        let user = self.store.mfa_pending_user(&digest, now).await?;
        let factor = self.store.load_mfa(user).await?;
        if factor.enabled_at.is_none() || factor.key_id != key_id {
            return Err(AuthError::Unauthorized);
        }
        let secret = mfa::decrypt_secret(key, &factor.secret_crypt, user.as_bytes())?;
        let recovery = if code.len() == 6 {
            if now.unix_timestamp() < 0
                || !mfa::verify_totp(&secret, code, now.unix_timestamp().cast_unsigned())
            {
                return Err(AuthError::Unauthorized);
            }
            None
        } else {
            Some(versioned(keyed(&self.key, "mfa-recovery", code)))
        };
        let tenant = self.store.user_tenant(user).await?;
        let session = Session {
            id: Id::now_v7(),
            user_id: user,
            tenant_id: tenant,
            token_digest: versioned(keyed_session),
            expires_at: now + self.policy.session_ttl,
        };
        self.store
            .complete_mfa_login(&digest, &session, recovery.as_deref(), now)
            .await?;
        Ok(IssuedSession {
            token: session_token,
            digest_hex,
        })
    }

    /// Resolve an active, unexpired session. The bearer value is never sent to storage.
    ///
    /// This delegates to [`Auth::resolve_session_sliding`]: when less than half the
    /// configured session lifetime remains, it may extend the expiry and, if auditing
    /// is enabled, write an audit row in the same transaction. This wrapper discards
    /// the extension flag; callers refreshing a cookie can use the sliding method.
    ///
    /// # Errors
    /// Returns `Unauthorized` for invalid/revoked/expired sessions or `Store` on I/O failure.
    /// An extension may have committed despite [`AuthError::Store`]; reconcile the
    /// persisted session before retrying.
    #[cfg(feature = "session")]
    pub async fn resolve_session(&self, token: &str, now: Timestamp) -> Result<Session, AuthError> {
        self.resolve_session_sliding(token, now)
            .await
            .map(|(session, _)| session)
    }

    /// Resolve a session and report whether its expiry was extended. A caller serving
    /// a cookie must refresh its Max-Age when the second return value is true.
    /// When auditing is enabled, an extension also writes an audit row in the same transaction.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an invalid session or a store error on failure.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn resolve_session_sliding(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<(Session, bool), AuthError> {
        let digest = self.digest("session", token);
        let mut entries = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        let generation = SESSION_GENERATION.load(Ordering::SeqCst);
        if let Some(entries) = entries.as_mut() {
            if let Some((session, until, cached_generation)) = entries.get(&digest)
                && *cached_generation == generation
                && *until > Instant::now()
                && session.expires_at > now
                && session_hard_deadline(session.id, self.policy.session_max_lifetime)
                    .is_none_or(|deadline| now < deadline)
                && (!self.policy.session_sliding
                    || session.expires_at - now >= self.policy.session_ttl / 2)
            {
                return Ok((session.clone(), false));
            }
            entries.remove(&digest);
        }
        let mut session = self
            .store
            .find_session(&digest, now)
            .await
            .map_err(hide_missing)?;
        let hard_deadline = session_hard_deadline(session.id, self.policy.session_max_lifetime);
        if hard_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(AuthError::Unauthorized);
        }
        let mut extended = false;
        if self.policy.session_sliding
            && self.policy.session_ttl.is_positive()
            && session.expires_at - now < self.policy.session_ttl / 2
        {
            let proposed = now + self.policy.session_ttl;
            let expires_at = hard_deadline.map_or(proposed, |deadline| proposed.min(deadline));
            if expires_at > session.expires_at {
                self.store
                    .extend_session(
                        &digest,
                        expires_at,
                        self.audit_event(
                            None,
                            Some(session.tenant_id),
                            Some(session.user_id),
                            ACTION_SESSION_EXTENDED,
                            "ok",
                        ),
                        now,
                    )
                    .await
                    .map_err(hide_missing)?;
                session.expires_at = expires_at;
                extended = true;
            }
        }
        if let (Some(cache), Some(entries)) = (&self.cache, entries.as_mut())
            && !cache.duration.is_zero()
        {
            let instant = Instant::now();
            entries.retain(|_, (_, until, cached_generation)| {
                *until > instant && *cached_generation == generation
            });
            if let Some(until) = instant.checked_add(cache.duration) {
                entries.insert(digest, (session.clone(), until, generation));
            }
        }
        Ok((session, extended))
    }

    /// Revoke the presented session. Safe to repeat, including for unknown tokens.
    ///
    /// When audit is on, the row carries the session's tenant and account when the
    /// token still resolves, and nulls when it does not.
    ///
    /// # Errors
    /// Returns `Store` on I/O failure.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn sign_out(&self, token: &str, now: Timestamp) -> Result<(), AuthError> {
        self.sign_out_with(None, token, now).await
    }

    #[cfg(feature = "session")]
    async fn sign_out_with(
        &self,
        meta: Option<Meta<'_>>,
        token: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _invalidate = InvalidateSessions::new();
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        let digest = self.digest("session", token);
        let session = if self.audit {
            self.store.find_session(&digest, now).await.ok()
        } else {
            None
        };
        let audit = self.audit_event(
            meta,
            session.as_ref().map(|session| session.tenant_id),
            session.as_ref().map(|session| session.user_id),
            ACTION_SESSION_REVOKED,
            "ok",
        );
        self.store.revoke_session(&digest, audit, now).await
    }

    /// List the caller's live sessions, marking the one that presented the request.
    ///
    /// `current` is the session the application resolved from the request. The list is
    /// that account's unrevoked, unexpired sessions at `now`, newest first, each with
    /// its identifier and its expiry. Neither the bearer token nor the stored digest is
    /// in the result. The list is a store read: no cache answers it, and reading it does
    /// not extend any session's expiry.
    ///
    /// # Errors
    /// Returns `Unsupported` for a store that does not implement listing, or `Store` on
    /// I/O failure.
    #[cfg(feature = "session")]
    pub async fn list_sessions(
        &self,
        current: &Session,
        now: Timestamp,
    ) -> Result<Vec<SessionInfo>, AuthError> {
        let sessions = self.store.list_sessions(current.user_id, now).await?;
        Ok(sessions
            .into_iter()
            .map(|session| SessionInfo {
                id: session.id,
                expires_at: session.expires_at,
                current: session.id == current.id,
            })
            .collect())
    }

    /// Revoke one of the caller's sessions by its [`SessionInfo::id`].
    ///
    /// The identifier is scoped to the account that presented `current`: an identifier
    /// belonging to another account is [`AuthError::NotFound`] and its session stays
    /// live. Revoking `current` itself succeeds; the route that calls this clears the
    /// cookie when the revoked identifier is the presented one.
    ///
    /// A session that is already revoked or expired is `NotFound` too, so a repeated
    /// revoke is never reported as a second success, and a refusal writes no audit row.
    /// When audit is on, a successful revoke writes one `auth.session.revoked` row in
    /// the same store call as the revoke, carrying the calling session's tenant and
    /// account, and no token. A failed insert is the call's error and leaves the session
    /// live.
    ///
    /// # Errors
    /// Returns `NotFound` for a session the caller does not own or one that is no longer
    /// live, `Unsupported` for a store that does not implement it, or `Store` on I/O
    /// failure.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke_session(
        &self,
        current: &Session,
        id: Id,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.revoke_session_with(None, current, id, now).await
    }

    #[cfg(feature = "session")]
    async fn revoke_session_with(
        &self,
        meta: Option<Meta<'_>>,
        current: &Session,
        id: Id,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _invalidate = InvalidateSessions::new();
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        self.store
            .revoke_session_by_id(current.user_id, id, self.revoke_audit(meta, current), now)
            .await
    }

    /// Revoke every other live session of the caller, keeping `current`.
    ///
    /// The presented session and its cookie stay as they are, and another account's
    /// sessions are untouched. When audit is on, the revoke writes one
    /// `auth.session.revoked` row in the same store call, even when the caller had no
    /// other live session to revoke.
    ///
    /// # Errors
    /// Returns `Unsupported` for a store that does not implement it, or `Store` on I/O
    /// failure. A failed audit insert is the call's error and leaves every session live.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke_other_sessions(
        &self,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.revoke_other_sessions_with(None, current, now).await
    }

    #[cfg(feature = "session")]
    async fn revoke_other_sessions_with(
        &self,
        meta: Option<Meta<'_>>,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _invalidate = InvalidateSessions::new();
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        self.store
            .revoke_sessions(
                current.user_id,
                Some(current.id),
                self.revoke_audit(meta, current),
                now,
            )
            .await
    }

    /// Revoke every live session of the caller, including `current`.
    ///
    /// The route that calls this clears the cookie afterwards, because the presented
    /// session is gone. Another account's sessions are untouched. When audit is on, the
    /// revoke writes one `auth.session.revoked` row in the same store call.
    ///
    /// # Errors
    /// Returns `Unsupported` for a store that does not implement it, or `Store` on I/O
    /// failure. A failed audit insert is the call's error and leaves every session live.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke_all_sessions(
        &self,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.revoke_all_sessions_with(None, current, now).await
    }

    #[cfg(feature = "session")]
    async fn revoke_all_sessions_with(
        &self,
        meta: Option<Meta<'_>>,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _invalidate = InvalidateSessions::new();
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        self.store
            .revoke_sessions(current.user_id, None, self.revoke_audit(meta, current), now)
            .await
    }

    /// The audit row a revoke writes, in the revoking session's tenant and account.
    #[cfg(feature = "session")]
    fn revoke_audit(&self, meta: Option<Meta<'_>>, current: &Session) -> Option<AuditEvent> {
        self.audit_event(
            meta,
            Some(current.tenant_id),
            Some(current.user_id),
            ACTION_SESSION_REVOKED,
            "ok",
        )
    }

    /// Load the stored password credential of an account.
    ///
    /// An application reads the hash here, verifies the password the caller typed with
    /// [`verify_password`] on its blocking executor, and hands the observed hash to
    /// [`Auth::change_password`] together with the new Argon2id hash. This workflow never
    /// runs Argon2 and never returns the hash to a client.
    ///
    /// # Errors
    /// Returns `NotFound` for an unknown account and `Store` on I/O failure.
    #[cfg(feature = "password")]
    pub async fn credential(&self, user: Id) -> Result<PasswordCredential, AuthError> {
        self.store.password(user).await
    }

    /// Replace the signed-in caller's password, keeping its current session.
    ///
    /// `expected_hash` is the stored hash the caller observed and verified with
    /// [`verify_password`]; `new_hash` is the Argon2id hash [`hash_password`] produced.
    /// Verification and hashing happen on the caller's blocking executor: this workflow
    /// never runs Argon2.
    ///
    /// In one store transaction it writes `new_hash`, clears the failure count and
    /// lockout, consumes the account's outstanding email sign-in proofs, revokes every
    /// live session except `current`, and writes the audit row. A failed audit insert
    /// leaves the old hash and the other sessions. The presented session and its cookie
    /// stay.
    ///
    /// # Errors
    /// Returns `Unauthorized` when the stored hash changed since it was read, `Conflict`
    /// for a new hash the store will not accept, `Unsupported` for a store that does not
    /// implement the operation, or `Store` on I/O failure.
    #[cfg(all(feature = "password", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn change_password(
        &self,
        current: &Session,
        expected_hash: &str,
        new_hash: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.change_password_with(None, current, expected_hash, new_hash, now)
            .await
    }

    #[cfg(all(feature = "password", feature = "session"))]
    async fn change_password_with(
        &self,
        meta: Option<Meta<'_>>,
        current: &Session,
        expected_hash: &str,
        new_hash: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _invalidate = InvalidateSessions::new();
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        self.store
            .change_password(
                current.user_id,
                current.id,
                expected_hash,
                new_hash,
                self.audit_event(
                    meta,
                    Some(current.tenant_id),
                    Some(current.user_id),
                    ACTION_PASSWORD_CHANGED,
                    "ok",
                ),
                now,
            )
            .await
    }

    /// Replace the signed-in caller's email address and clear its verification.
    ///
    /// The address is trimmed and lowercased; a malformed one is `Invalid`. A live
    /// duplicate in the caller's tenant is `Conflict`. The account keeps its identifier,
    /// its password, and every live session, including the presented one. When audit is
    /// on, the row commits with the update and carries no token.
    ///
    /// # Errors
    /// Returns `Invalid` for a malformed address, `Conflict` for a duplicate, `NotFound`
    /// for an account that is no longer live, `Unsupported` for a store that does not
    /// implement the operation, or `Store` on I/O failure.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn change_email(
        &self,
        current: &Session,
        email: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.change_email_with(None, current, email, now).await
    }

    #[cfg(feature = "session")]
    async fn change_email_with(
        &self,
        meta: Option<Meta<'_>>,
        current: &Session,
        email: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let email = normalized_email(email)?;
        self.store
            .change_email(
                current.user_id,
                current.tenant_id,
                &email,
                self.audit_event(
                    meta,
                    Some(current.tenant_id),
                    Some(current.user_id),
                    ACTION_EMAIL_CHANGED,
                    "ok",
                ),
                now,
            )
            .await
    }

    /// Delete the signed-in caller's account.
    ///
    /// The account row is kept and marked with `deleted_at`, so a later lookup or sign-in
    /// for the address fails. Every live session of the account, including `current`, is
    /// revoked in the same store transaction as the audit row. The route that calls this
    /// clears the cookie afterwards, because the presented session is gone.
    ///
    /// # Errors
    /// Returns `NotFound` for an account that is already deleted, `Unsupported` for a
    /// store that does not implement the operation, or `Store` on I/O failure. A failed
    /// audit insert is the call's error and leaves the account and its sessions.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn delete_user(&self, current: &Session, now: Timestamp) -> Result<(), AuthError> {
        self.delete_user_with(None, current, now).await
    }

    #[cfg(feature = "session")]
    async fn delete_user_with(
        &self,
        meta: Option<Meta<'_>>,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _invalidate = InvalidateSessions::new();
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        self.store
            .delete_user(
                current.user_id,
                self.audit_event(
                    meta,
                    Some(current.tenant_id),
                    Some(current.user_id),
                    ACTION_USER_DELETED,
                    "ok",
                ),
                now,
            )
            .await
    }

    /// Issue a purpose-bound proof for a known account, for [`Policy::proof_ttl`].
    /// Deliver through `vaelspire-email`; public reset endpoints should conceal
    /// account existence. Delivery failure leaves a valid proof that may be retried.
    ///
    /// # Errors
    /// Returns `Invalid` for a malformed email, `NotFound` for an unknown account, or
    /// storage/crypto failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn issue_proof(
        &self,
        tenant: Id,
        email: &str,
        purpose: Purpose,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        self.issue_proof_with(None, tenant, email, purpose, now)
            .await
    }

    async fn issue_proof_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        email: &str,
        purpose: Purpose,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        let email = normalized_email(email)?;
        let user = self.store.find_user(tenant, &email).await?;
        let token = random_secret()?;
        let token_digest = versioned(self.proof_digest(purpose, token.expose()).0);
        self.store
            .create_one_time(
                &OneTime {
                    id: Id::now_v7(),
                    user_id: user.id,
                    purpose,
                    token_digest,
                    expires_at: now + self.policy.proof_ttl,
                },
                self.audit_event(meta, Some(tenant), Some(user.id), ACTION_PROOF_ISSUED, "ok"),
                now,
            )
            .await?;
        Ok(token)
    }

    /// Spend a reset proof once with a password hash the caller already computed.
    ///
    /// Hash the new password with [`hash_password`] on a blocking executor and pass
    /// the encoded hash here: this workflow consumes the proof, replaces the password
    /// with that hash, clears lockout, and revokes sessions in one store call, and
    /// never runs Argon2 itself.
    ///
    /// A refused token is audited as `auth.password.reset` with outcome `denied` when
    /// audit is on; the account is unknown until the store accepts the token.
    ///
    /// # Errors
    /// Returns `Unauthorized` for expired/consumed/wrong-purpose proofs; validation or store failure otherwise.
    #[cfg(feature = "password")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn reset_password(
        &self,
        token: &str,
        password_hash: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.reset_password_with(None, token, password_hash, now)
            .await
    }

    #[cfg(feature = "password")]
    async fn reset_password_with(
        &self,
        meta: Option<Meta<'_>>,
        token: &str,
        password_hash: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        #[cfg(feature = "session")]
        let _invalidate = InvalidateSessions::new();
        #[cfg(feature = "session")]
        let mut cache = match &self.cache {
            Some(cache) => Some(cache.entries.lock().await),
            None => None,
        };
        #[cfg(feature = "session")]
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
        let token_digest = versioned(self.proof_digest(Purpose::ResetPassword, token).0);
        let audit = self.audit_event(meta, None, None, ACTION_PASSWORD_RESET, "ok");
        match self
            .store
            .consume_one_time(
                Purpose::ResetPassword,
                &token_digest,
                Some(password_hash),
                audit,
                now,
            )
            .await
        {
            Ok(_user) => Ok(()),
            Err(AuthError::Unauthorized) => {
                self.record(meta, None, None, ACTION_PASSWORD_RESET, "denied", now)
                    .await?;
                Err(AuthError::Unauthorized)
            }
            Err(error) => Err(error),
        }
    }

    /// Spend a verification proof once and mark its account email verified.
    ///
    /// A refused token is audited as `auth.email.verified` with outcome `denied` when
    /// audit is on.
    ///
    /// # Errors
    /// Returns `Unauthorized` for invalid/expired/consumed proofs, or `Store`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn verify_email(&self, token: &str, now: Timestamp) -> Result<Id, AuthError> {
        self.verify_email_with(None, token, now).await
    }

    async fn verify_email_with(
        &self,
        meta: Option<Meta<'_>>,
        token: &str,
        now: Timestamp,
    ) -> Result<Id, AuthError> {
        let token_digest = versioned(self.proof_digest(Purpose::VerifyEmail, token).0);
        let audit = self.audit_event(meta, None, None, ACTION_EMAIL_VERIFIED, "ok");
        match self
            .store
            .consume_one_time(Purpose::VerifyEmail, &token_digest, None, audit, now)
            .await
        {
            Ok(user) => Ok(user),
            Err(AuthError::Unauthorized) => {
                self.record(meta, None, None, ACTION_EMAIL_VERIFIED, "denied", now)
                    .await?;
                Err(AuthError::Unauthorized)
            }
            Err(error) => Err(error),
        }
    }

    /// Spend an email OTP once, returning its authenticated user identifier.
    /// Does not issue a browser session. No audit action is defined for this
    /// workflow in this version, so it writes no event. To spend the same proof and
    /// issue a session, enable `email-signin` and call
    /// `Auth::sign_in_with_email_proof`; this method never does.
    ///
    /// # Errors
    /// Returns `Unauthorized` for invalid/expired/consumed proofs, or `Store`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn verify_otp(&self, token: &str, now: Timestamp) -> Result<Id, AuthError> {
        let token_digest = versioned(self.proof_digest(Purpose::EmailOtp, token).0);
        self.store
            .consume_one_time(Purpose::EmailOtp, &token_digest, None, None, now)
            .await
    }

    /// Spend an email sign-in proof once and issue its session.
    ///
    /// The proof is the `EmailOtp` one-time token [`Auth::issue_proof`] mints; this
    /// workflow does not introduce a second proof. Consumption and the session insert
    /// happen in one store call, so a second spend is `Unauthorized` and a failed
    /// audit insert leaves neither the consumed proof nor the session behind.
    ///
    /// When audit is on, a successful spend writes `auth.session.issued` in that same
    /// transaction, and a refused token writes `auth.session.denied` on its own. A
    /// refusal names no account: the store learns it only by accepting the proof.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an invalid, expired, or already-consumed proof;
    /// `Unsupported` for a store that does not implement session issuance; `Store` on
    /// I/O failure.
    #[cfg(feature = "email-signin")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn sign_in_with_email_proof(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        self.sign_in_with_email_proof_with(None, token, now).await
    }

    #[cfg(feature = "email-signin")]
    async fn sign_in_with_email_proof_with(
        &self,
        meta: Option<Meta<'_>>,
        token: &str,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        let proof_digest = versioned(self.proof_digest(Purpose::EmailOtp, token).0);
        let token = random_secret()?;
        let (keyed, digest_hex) = self.session_digest(token.expose());
        match self
            .store
            .complete_email_sign_in(
                &proof_digest,
                Id::now_v7(),
                &versioned(keyed),
                now + self.policy.session_ttl,
                self.audit_event(meta, None, None, ACTION_SESSION_ISSUED, "ok"),
                now,
            )
            .await
        {
            Ok(_session) => Ok(IssuedSession { token, digest_hex }),
            Err(AuthError::Unauthorized) => {
                self.record(meta, None, None, ACTION_SESSION_DENIED, "denied", now)
                    .await?;
                Err(AuthError::Unauthorized)
            }
            Err(error) => Err(error),
        }
    }

    /// Mint a single-use state for a social sign-in and store only its digest.
    ///
    /// The returned [`Secret`] is the raw value that belongs in the provider's
    /// `state` query parameter and nowhere else. The store receives the versioned
    /// keyed digest, bound to `tenant` and `provider`, for `ttl`. The callback spends
    /// it through [`Auth::complete_social_sign_in`], so a second use fails.
    ///
    /// This workflow does not write an audit row: it issues no identity and no session.
    ///
    /// # Errors
    /// Returns `Invalid` for an empty or non-positive lifetime, `Store` for a store
    /// that cannot record the state, or `NotFound` for a tenant that is not active.
    #[cfg(feature = "social")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn start_social_state(
        &self,
        tenant: Id,
        provider: &str,
        ttl: Duration,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        if ttl <= Duration::seconds(0) {
            return Err(AuthError::Invalid);
        }
        let token = random_secret()?;
        self.store
            .create_social_state(
                &self.digest("social_state", token.expose()),
                tenant,
                provider,
                now + ttl,
                now,
            )
            .await?;
        Ok(token)
    }

    /// Check that a social state may still be spent, without spending it.
    ///
    /// The callback route calls this before it makes a network request, so an unknown,
    /// expired, already-spent, or provider-mismatched state is `Unauthorized` before
    /// the code exchange. [`Auth::complete_social_sign_in`] still spends the state
    /// atomically, so this read is an early refusal, not the replay guarantee.
    ///
    /// # Errors
    /// Returns `Unauthorized` when the state cannot be spent, or `Unsupported` for a
    /// store without social support, or `Store` on I/O failure.
    #[cfg(feature = "social")]
    pub async fn check_social_state(
        &self,
        tenant: Id,
        provider: &str,
        state: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.store
            .check_social_state(&self.digest("social_state", state), tenant, provider, now)
            .await
    }

    /// Spend a social sign-in state and issue the cookie's session.
    ///
    /// The provider exchanged the authorization code out of band; this workflow takes
    /// the provider's stable subject and email. With `password` compiled out it still
    /// issues the same session [`Auth::finish_sign_in`] does, because it borrows the
    /// same [`Policy::session_ttl`] and the same digest key.
    ///
    /// A state that is unknown, expired, already spent, bound to another tenant, or
    /// bound to another provider is `Unauthorized`. A subject the store has seen signs
    /// in to the account it already owns. A new subject creates an account with
    /// `email`, unless a live account in the tenant already holds that address, in
    /// which case this is `Conflict` and no session is issued. The library never links
    /// an existing account to a social identity, and `email_verified` only marks the
    /// newly created account's address.
    ///
    /// When audit is on, the success row commits with the state spend and the session
    /// insert; a denial writes `auth.session.denied` on its own. Neither the response
    /// nor the audit row carries an access token, a refresh token, or a client secret.
    ///
    /// # Errors
    /// Returns `Unauthorized` for a refused or reused state, `Conflict` when the
    /// provider email belongs to a live account this subject did not create, `Invalid`
    /// for a malformed email or subject, `Unsupported` for a store without social
    /// support, or `Store` on I/O failure.
    #[cfg(feature = "social")]
    #[allow(clippy::too_many_arguments)]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn complete_social_sign_in(
        &self,
        tenant: Id,
        provider: &str,
        subject: &str,
        email: &str,
        email_verified: bool,
        state: &str,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        self.complete_social_sign_in_with(
            None,
            tenant,
            provider,
            subject,
            email,
            email_verified,
            state,
            now,
        )
        .await
    }

    #[cfg(feature = "social")]
    #[allow(clippy::too_many_arguments)]
    async fn complete_social_sign_in_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        provider: &str,
        subject: &str,
        email: &str,
        email_verified: bool,
        state: &str,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        let subject = subject.trim();
        if subject.is_empty() || subject.len() > 255 {
            return Err(AuthError::Invalid);
        }
        let email = normalized_email(email)?;
        let state_digest = self.digest("social_state", state);
        let token = random_secret()?;
        let (keyed, digest_hex) = self.session_digest(token.expose());
        match self
            .store
            .complete_social_sign_in(
                &state_digest,
                tenant,
                provider,
                subject,
                &email,
                email_verified,
                Id::now_v7(),
                &versioned(keyed),
                now + self.policy.session_ttl,
                self.audit_event(meta, Some(tenant), None, ACTION_SESSION_ISSUED, "ok"),
                now,
            )
            .await
        {
            Ok(_session) => Ok(IssuedSession { token, digest_hex }),
            Err(AuthError::Unauthorized) => {
                self.record(
                    meta,
                    Some(tenant),
                    None,
                    ACTION_SESSION_DENIED,
                    "denied",
                    now,
                )
                .await?;
                Err(AuthError::Unauthorized)
            }
            Err(AuthError::Conflict) => {
                self.record(
                    meta,
                    Some(tenant),
                    None,
                    ACTION_SESSION_DENIED,
                    "denied",
                    now,
                )
                .await?;
                Err(AuthError::Conflict)
            }
            Err(error) => Err(error),
        }
    }

    /// Suspend a tenant, which makes it not active: its accounts cannot sign in, and
    /// no membership is created and no invitation is accepted in it.
    ///
    /// There is no reactivation workflow; a store that supports one can be used
    /// directly. Tenant status has no action in this version's audit set, so this
    /// call writes no event.
    ///
    /// # Errors
    /// Returns `NotFound` for an unknown tenant, or `Unsupported` for a store that does
    /// not implement the operation, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn suspend_tenant(&self, tenant: Id, now: Timestamp) -> Result<(), AuthError> {
        self.store.suspend_tenant(tenant, now).await
    }

    /// Create a membership for a user who is already in the tenant.
    ///
    /// `status` is stored as given. [`MembershipStatus::Invited`] and
    /// [`MembershipStatus::Suspended`] are readable but carry no authority.
    ///
    /// # Errors
    /// Returns `Conflict` for a duplicate membership, a user outside the tenant, or an
    /// inactive tenant; `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn create_membership(
        &self,
        tenant: Id,
        user: Id,
        status: MembershipStatus,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.create_membership_with(None, tenant, user, status, now)
            .await
    }

    async fn create_membership_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        user: Id,
        status: MembershipStatus,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let membership = Membership {
            id: Id::now_v7(),
            tenant_id: tenant,
            user_id: user,
            status,
        };
        self.store
            .create_membership(
                &membership,
                self.audit_event(meta, Some(tenant), None, ACTION_MEMBERSHIP_CREATED, "ok"),
                now,
            )
            .await?;
        Ok(membership)
    }

    /// Read a membership by tenant and user, whatever its status. Not authority —
    /// the caller decides, with [`MembershipStatus::is_authority`] if it wants the
    /// library's rule that only `active` counts.
    ///
    /// # Errors
    /// Returns `NotFound` when there is no membership, or `Store` on I/O failure.
    pub async fn membership(&self, tenant: Id, user: Id) -> Result<Membership, AuthError> {
        self.store.find_membership(tenant, user).await
    }

    /// Replace a membership status and return the stored membership.
    ///
    /// # Errors
    /// Returns `NotFound` for an unknown membership, `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn set_membership_status(
        &self,
        membership: Id,
        status: MembershipStatus,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.set_membership_status_with(None, membership, status, now)
            .await
    }

    async fn set_membership_status_with(
        &self,
        meta: Option<Meta<'_>>,
        membership: Id,
        status: MembershipStatus,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.store
            .set_membership_status(
                membership,
                status,
                self.audit_event(meta, None, None, ACTION_MEMBERSHIP_UPDATED, "ok"),
                now,
            )
            .await
    }

    /// Store a permission under a name the caller supplies.
    ///
    /// The library has no permission catalogue: an empty or whitespace-only name is
    /// refused, and every other name is stored as given. Nothing is inserted unless
    /// the caller asks for it. Catalogue writes have no action in this version's
    /// audit set, so this call writes no event.
    ///
    /// # Errors
    /// Returns `Invalid` for an empty name, `Conflict` for one already used in the
    /// tenant, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn create_permission(&self, tenant: Id, name: &str) -> Result<Id, AuthError> {
        let name = catalogue_name(name)?;
        let id = Id::now_v7();
        self.store.create_permission(id, tenant, name).await?;
        Ok(id)
    }

    /// Store a role under a name the caller supplies.
    ///
    /// `owner`, `admin`, and `member` are inserted with the tenant by
    /// [`AuthStore::create_tenant`], so creating one of those names in that tenant is
    /// `Conflict` like any duplicate. They are not otherwise reserved, and any other
    /// name is still caller-supplied. Catalogue writes have no action in this version's
    /// audit set, so this call writes no event.
    ///
    /// # Errors
    /// Returns `Invalid` for an empty name, `Conflict` for one already used in the
    /// tenant, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn create_role(&self, tenant: Id, name: &str) -> Result<Id, AuthError> {
        let name = catalogue_name(name)?;
        let id = Id::now_v7();
        self.store.create_role(id, tenant, name).await?;
        Ok(id)
    }

    /// Create a group in `tenant` under a name the caller supplies.
    ///
    /// A group belongs to one tenant, and its members are memberships of that same
    /// tenant; see [`Self::add_group_member`]. An empty or whitespace-only name is
    /// `Invalid`, and a duplicate name in the tenant is `Conflict`. Group writes have
    /// no action in this version's audit set, so this call writes no event.
    ///
    /// # Errors
    /// Returns `Invalid` for an empty or over-long name, `Conflict` for one already
    /// used in the tenant, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn create_group(
        &self,
        tenant: Id,
        name: &str,
        now: Timestamp,
    ) -> Result<Id, AuthError> {
        let name = catalogue_name(name)?;
        let id = Id::now_v7();
        self.store.create_group(id, tenant, name, now).await?;
        Ok(id)
    }

    /// Add a membership to a group in `tenant`.
    ///
    /// There is no group read, so `tenant` is how the caller names its tenant. A group
    /// that is not in it is `NotFound`, including one that exists elsewhere. The
    /// membership must be in that same tenant. Adding the same membership again
    /// succeeds, as [`Self::assign_role`] does. Group writes have no action in this
    /// version's audit set, so this call writes no event.
    ///
    /// # Errors
    /// Returns `NotFound` for a group outside `tenant` or a missing membership,
    /// `Conflict` for a membership of another tenant — which is not added — or `Store`
    /// on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn add_group_member(
        &self,
        tenant: Id,
        group: Id,
        membership: Id,
    ) -> Result<(), AuthError> {
        self.store.add_group_member(tenant, group, membership).await
    }

    /// Remove a membership from a group in `tenant`.
    ///
    /// A group outside `tenant` looks missing, so the call does not remove a link that
    /// belongs to another tenant.
    ///
    /// # Errors
    /// Returns `NotFound` when the group is outside `tenant`, or when the membership or
    /// their link is absent, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn remove_group_member(
        &self,
        tenant: Id,
        group: Id,
        membership: Id,
    ) -> Result<(), AuthError> {
        self.store
            .remove_group_member(tenant, group, membership)
            .await
    }

    /// Attach a role to a membership and return the membership.
    ///
    /// Repeating the same assignment succeeds. A role from another tenant is refused.
    ///
    /// # Errors
    /// Returns `Conflict` for a role outside the membership's tenant or an unknown
    /// membership or role, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn assign_role(
        &self,
        membership: Id,
        role: Id,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.assign_role_with(None, membership, role, now).await
    }

    async fn assign_role_with(
        &self,
        meta: Option<Meta<'_>>,
        membership: Id,
        role: Id,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.store
            .assign_role(
                membership,
                role,
                self.audit_event(meta, None, None, ACTION_MEMBERSHIP_UPDATED, "ok"),
                now,
            )
            .await
    }

    /// Issue an invitation for an email in a tenant, with an exclusive expiry.
    ///
    /// The email is stored trimmed and lowercase. The raw token is returned once and
    /// never stored or logged; the store keeps only its versioned keyed digest. Put
    /// the token in the message your sender builds for `vaelspire-email`.
    /// `role_ids` are roles the caller already created in that tenant; they are
    /// attached to the invitation and granted when it is accepted. An unused role id
    /// is fine, and a role from another tenant fails the whole write.
    ///
    /// # Errors
    /// Returns `Invalid` for an invalid email or a past expiry, `Conflict` for a role
    /// outside the tenant, or `Store` on I/O failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn issue_invitation(
        &self,
        tenant: Id,
        email: &str,
        expires_at: Timestamp,
        role_ids: Vec<Id>,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        self.issue_invitation_with(None, tenant, email, expires_at, role_ids, now)
            .await
    }

    async fn issue_invitation_with(
        &self,
        meta: Option<Meta<'_>>,
        tenant: Id,
        email: &str,
        expires_at: Timestamp,
        role_ids: Vec<Id>,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        let email = normalized_email(email)?;
        if expires_at <= now {
            return Err(AuthError::Invalid);
        }
        let token = random_secret()?;
        self.store
            .create_invitation(
                &Invitation {
                    id: Id::now_v7(),
                    tenant_id: tenant,
                    email,
                    token_digest: self.digest("invitation", token.expose()),
                    expires_at,
                    role_ids,
                },
                self.audit_event(meta, Some(tenant), None, ACTION_INVITATION_ISSUED, "ok"),
                now,
            )
            .await?;
        Ok(token)
    }

    /// Spend an invitation once and return the membership it produced.
    ///
    /// The membership is created when the user has none in that tenant and set to
    /// [`MembershipStatus::Active`] when one exists, so an invitation activates a
    /// suspended or previously invited membership. The user is the live account with
    /// the invited email in that tenant; this workflow does not create accounts, so
    /// the account must be registered first. The invitation's roles are attached to
    /// the membership.
    ///
    /// # Errors
    /// Returns `Unauthorized` for an unknown, spent, or expired token, `NotFound` when
    /// no user holds the invited email in that tenant, `Store` on I/O failure. A
    /// second acceptance with the same token is `Unauthorized`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn accept_invitation(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.accept_invitation_with(None, token, now).await
    }

    async fn accept_invitation_with(
        &self,
        meta: Option<Meta<'_>>,
        token: &str,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let audit = self.audit_event(meta, None, None, ACTION_INVITATION_ACCEPTED, "ok");
        match self
            .store
            .accept_invitation(Id::now_v7(), &self.digest("invitation", token), audit, now)
            .await
        {
            Ok(membership) => Ok(membership),
            Err(AuthError::Unauthorized) => {
                self.record(meta, None, None, ACTION_INVITATION_ACCEPTED, "denied", now)
                    .await?;
                Err(AuthError::Unauthorized)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(any(feature = "session", feature = "apikeys"))]
fn hide_missing(error: AuthError) -> AuthError {
    if error == AuthError::NotFound {
        AuthError::Unauthorized
    } else {
        error
    }
}

/// Trimmed lowercase account email, or `Invalid` when it cannot be one.
fn normalized_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_lowercase();
    if email.len() > 254 || !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(AuthError::Invalid);
    }
    Ok(email)
}

/// A catalogue name as the caller wrote it, with surrounding blanks removed.
/// Interior characters, case, and dots are the application's choice, not ours.
fn catalogue_name(name: &str) -> Result<&str, AuthError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(AuthError::Invalid);
    }
    Ok(name)
}

/// Cut a request-metadata value to the width of its column on a character boundary.
///
/// Audit metadata is decoration, not identity: a long header must not turn a login
/// into a failure, so it is clipped rather than rejected.
fn clip(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn random_secret() -> Result<Secret, AuthError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| AuthError::Store)?;
    Ok(Secret(Zeroizing::new(
        URL_SAFE_NO_PAD.encode(bytes.as_ref()),
    )))
}

/// BLAKE3 keyed with the 32-byte key, over the domain label, a `0` byte, and the token.
///
/// This is the one place the encoding lives: every digest the crate produces goes
/// through it, so the version-1 hex form and the versioned row form cannot drift apart.
fn keyed(key: &[u8; 32], domain: &str, value: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(value.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Digest format version 1: the version byte the library's own rows keep, followed by
/// the keyed bytes. Stored outside the hex form, which stays 64 characters.
fn versioned(keyed: [u8; 32]) -> Vec<u8> {
    let mut digest = Vec::with_capacity(33);
    digest.push(1);
    digest.extend_from_slice(&keyed);
    digest
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Per-call request metadata, cloned from [`Auth`] with [`Auth::call`].
///
/// [`Auth`] is shared between requests and holds no request state, so it writes
/// audit rows with `ip` and `user_agent` null. A `Call` adds those two values to the
/// audit row of every workflow it runs, through the same private workflow an `Auth`
/// call uses. Nothing is written back to [`Auth`], so two concurrent calls cannot
/// observe each other's metadata. The crate never reads a header: the values are
/// what the application already extracted from its own request.
pub struct Call<'a, S> {
    auth: Auth<'a, S>,
    ip: Option<String>,
    user_agent: Option<String>,
}

impl<S> std::fmt::Debug for Call<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Call")
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

impl<S> Call<'_, S> {
    /// Add the client address the application observed. Clipped to the audit column
    /// width on a character boundary when the row is written.
    #[must_use]
    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = Some(ip.to_owned());
        self
    }

    /// Add the user agent the application observed. Clipped to the audit column
    /// width on a character boundary when the row is written.
    #[must_use]
    pub fn user_agent(mut self, user_agent: &str) -> Self {
        self.user_agent = Some(user_agent.to_owned());
        self
    }
}

impl<S> Call<'_, S> {
    fn meta(&self) -> Meta<'_> {
        Meta {
            ip: self.ip.as_deref(),
            user_agent: self.user_agent.as_deref(),
        }
    }
}

impl<S: AuthStore> Call<'_, S> {
    /// [`Auth::sign_up`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::sign_up`].
    #[cfg(feature = "password")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn sign_up(
        &self,
        tenant: Id,
        email: &str,
        password_hash: &str,
        now: Timestamp,
    ) -> Result<User, AuthError> {
        self.auth
            .sign_up_with(Some(self.meta()), tenant, email, password_hash, now)
            .await
    }

    /// [`Auth::begin_sign_in`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::begin_sign_in`].
    #[cfg(all(feature = "password", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn begin_sign_in(
        &self,
        tenant: Id,
        email: &str,
        now: Timestamp,
    ) -> Result<SignInAttempt, AuthError> {
        self.auth
            .begin_sign_in_with(Some(self.meta()), tenant, email, now)
            .await
    }

    /// [`Auth::finish_sign_in`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::finish_sign_in`].
    #[cfg(all(feature = "password", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn finish_sign_in(
        &self,
        attempt: SignInAttempt,
        outcome: SignInOutcome<'_>,
        now: Timestamp,
    ) -> Result<SignInCompletion, AuthError> {
        self.auth
            .finish_sign_in_with(Some(self.meta()), attempt, outcome, now)
            .await
    }

    /// [`Auth::sign_out`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::sign_out`].
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn sign_out(&self, token: &str, now: Timestamp) -> Result<(), AuthError> {
        self.auth.sign_out_with(Some(self.meta()), token, now).await
    }

    /// [`Auth::revoke_session`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::revoke_session`].
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke_session(
        &self,
        current: &Session,
        id: Id,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .revoke_session_with(Some(self.meta()), current, id, now)
            .await
    }

    /// [`Auth::revoke_other_sessions`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::revoke_other_sessions`].
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke_other_sessions(
        &self,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .revoke_other_sessions_with(Some(self.meta()), current, now)
            .await
    }

    /// [`Auth::revoke_all_sessions`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::revoke_all_sessions`].
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke_all_sessions(
        &self,
        current: &Session,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .revoke_all_sessions_with(Some(self.meta()), current, now)
            .await
    }

    /// [`Auth::change_password`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::change_password`].
    #[cfg(all(feature = "password", feature = "session"))]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn change_password(
        &self,
        current: &Session,
        expected_hash: &str,
        new_hash: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .change_password_with(Some(self.meta()), current, expected_hash, new_hash, now)
            .await
    }

    /// [`Auth::change_email`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::change_email`].
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn change_email(
        &self,
        current: &Session,
        email: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .change_email_with(Some(self.meta()), current, email, now)
            .await
    }

    /// [`Auth::delete_user`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::delete_user`].
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn delete_user(&self, current: &Session, now: Timestamp) -> Result<(), AuthError> {
        self.auth
            .delete_user_with(Some(self.meta()), current, now)
            .await
    }

    /// [`Auth::issue_proof`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::issue_proof`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn issue_proof(
        &self,
        tenant: Id,
        email: &str,
        purpose: Purpose,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        self.auth
            .issue_proof_with(Some(self.meta()), tenant, email, purpose, now)
            .await
    }

    /// [`Auth::reset_password`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::reset_password`].
    #[cfg(feature = "password")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn reset_password(
        &self,
        token: &str,
        password_hash: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        self.auth
            .reset_password_with(Some(self.meta()), token, password_hash, now)
            .await
    }

    /// [`Auth::verify_email`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::verify_email`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn verify_email(&self, token: &str, now: Timestamp) -> Result<Id, AuthError> {
        self.auth
            .verify_email_with(Some(self.meta()), token, now)
            .await
    }

    /// [`Auth::sign_in_with_email_proof`] with this call's request metadata in the
    /// audit row.
    ///
    /// # Errors
    /// As [`Auth::sign_in_with_email_proof`].
    #[cfg(feature = "email-signin")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn sign_in_with_email_proof(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        self.auth
            .sign_in_with_email_proof_with(Some(self.meta()), token, now)
            .await
    }

    /// [`Auth::complete_social_sign_in`] with this call's request metadata in the
    /// audit row.
    ///
    /// # Errors
    /// As [`Auth::complete_social_sign_in`].
    #[cfg(feature = "social")]
    #[allow(clippy::too_many_arguments)]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn complete_social_sign_in(
        &self,
        tenant: Id,
        provider: &str,
        subject: &str,
        email: &str,
        email_verified: bool,
        state: &str,
        now: Timestamp,
    ) -> Result<IssuedSession, AuthError> {
        self.auth
            .complete_social_sign_in_with(
                Some(self.meta()),
                tenant,
                provider,
                subject,
                email,
                email_verified,
                state,
                now,
            )
            .await
    }

    /// [`Auth::create_membership`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::create_membership`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn create_membership(
        &self,
        tenant: Id,
        user: Id,
        status: MembershipStatus,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.auth
            .create_membership_with(Some(self.meta()), tenant, user, status, now)
            .await
    }

    /// [`Auth::set_membership_status`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::set_membership_status`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn set_membership_status(
        &self,
        membership: Id,
        status: MembershipStatus,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.auth
            .set_membership_status_with(Some(self.meta()), membership, status, now)
            .await
    }

    /// [`Auth::assign_role`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::assign_role`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn assign_role(
        &self,
        membership: Id,
        role: Id,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.auth
            .assign_role_with(Some(self.meta()), membership, role, now)
            .await
    }

    /// [`Auth::issue_invitation`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::issue_invitation`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn issue_invitation(
        &self,
        tenant: Id,
        email: &str,
        expires_at: Timestamp,
        role_ids: Vec<Id>,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        self.auth
            .issue_invitation_with(Some(self.meta()), tenant, email, expires_at, role_ids, now)
            .await
    }

    /// [`Auth::accept_invitation`] with this call's request metadata in the audit row.
    ///
    /// # Errors
    /// As [`Auth::accept_invitation`].
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn accept_invitation(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        self.auth
            .accept_invitation_with(Some(self.meta()), token, now)
            .await
    }
}

/// API-key issuer, authenticator, and revoker.
///
/// Issuing and lookup need neither `password` nor `session`. Revoking identifies its
/// caller by the live session it is given, so the revoke method needs `session`.
#[cfg(feature = "apikeys")]
pub struct ApiKeys<'a, S> {
    auth: Auth<'a, S>,
    prefix: vaelspire_core::ApiKeyPrefix,
}

#[cfg(feature = "apikeys")]
impl<S> std::fmt::Debug for ApiKeys<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeys")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "apikeys")]
impl<'a, S: AuthStore> ApiKeys<'a, S> {
    /// Construct with an optional application prefix (default `nak`).
    ///
    /// API keys issue no sessions and no proofs, so the default [`Policy`] applies
    /// and is never consulted.
    ///
    /// # Errors
    /// Returns `Invalid` for an invalid prefix.
    pub fn new(
        store: &'a S,
        digest_key: [u8; 32],
        prefix: Option<&str>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            auth: Auth::new(store, digest_key, Policy::default()),
            prefix: vaelspire_core::ApiKeyPrefix::new(prefix)?,
        })
    }

    /// Turn audit on or off for this issuer. Off is the default, including for a value
    /// the router builds.
    ///
    /// When on, a successful revoke writes one `auth.api_key.revoked` row in the same
    /// store call as the revocation. Issuing and looking up a key write no row.
    #[must_use]
    pub fn auditing(mut self, enabled: bool) -> Self {
        self.auth = self.auth.auditing(enabled);
        self
    }

    /// Issue a user-owned key with caller-selected scopes and exclusive expiry.
    /// The raw key is returned once; no session is required or copied.
    ///
    /// # Errors
    /// Returns `Invalid` for a past expiry, or `Store` on storage/crypto failure.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn issue(
        &self,
        user: &User,
        scopes: Vec<String>,
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<Secret, AuthError> {
        if expires_at <= now {
            return Err(AuthError::Invalid);
        }
        let id = Id::now_v7();
        let secret = random_secret()?;
        let token = Secret(Zeroizing::new(format!(
            "{}_{}_{}",
            self.prefix.as_str(),
            &id.simple().to_string()[..12],
            secret.expose()
        )));
        self.auth
            .store
            .create_api_key(
                &vaelspire_core::ApiKey {
                    id,
                    tenant_id: user.tenant_id,
                    user_id: user.id,
                    prefix: self.prefix.as_str().to_owned(),
                    secret_digest: self.auth.digest("api_key", token.expose()),
                    scopes,
                    expires_at,
                    last_used_at: None,
                },
                now,
            )
            .await?;
        Ok(token)
    }

    /// Authenticate against the prefix persisted at issuance, not the current setting.
    ///
    /// A successful lookup records `last_used_at` at `now` and returns the key with that
    /// instant already in it. A wrong prefix, an unknown key, a revoked key, an expired
    /// key, and a disabled owner or tenant are `Unauthorized` and do not move the column.
    ///
    /// # Errors
    /// Returns `Unauthorized` for invalid/expired/revoked keys, `Unsupported` for a store
    /// that does not record use, or `Store`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn lookup(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<vaelspire_core::ApiKey, AuthError> {
        let (prefix, _) = token.split_once('_').ok_or(AuthError::Unauthorized)?;
        let mut key = self
            .auth
            .store
            .find_api_key(&self.auth.digest("api_key", token), prefix, now)
            .await
            .map_err(hide_missing)?;
        self.auth
            .store
            .record_api_key_use(key.id, now)
            .await
            .map_err(hide_missing)?;
        key.last_used_at = Some(now);
        Ok(key)
    }

    /// Revoke one of the caller's keys by its identifier.
    ///
    /// The identifier is scoped to the account that presented `session`: an identifier
    /// belonging to another account is [`AuthError::NotFound`] and its key stays
    /// usable. A key that is already revoked or expired is `NotFound` too, so a repeated
    /// revoke is never reported as a second success, and a refusal writes no audit row.
    ///
    /// When audit is on, a successful revoke writes one `auth.api_key.revoked` row in
    /// the same store call as the revoke, carrying the calling session's tenant and
    /// account. The row never carries the key's secret or any presented value. A failed
    /// insert is the call's error and leaves the key usable. The issuer holds no request
    /// state, so that row's IP and user agent columns are null; a workflow run on the
    /// shared [`Auth`] writes them null for the same reason.
    ///
    /// # Errors
    /// Returns `NotFound` for a key the caller does not own or one that is no longer
    /// usable, `Unsupported` for a store that does not implement revoking, or `Store` on
    /// I/O failure.
    #[cfg(feature = "session")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    pub async fn revoke(&self, session: &Session, id: Id, now: Timestamp) -> Result<(), AuthError> {
        self.auth
            .store
            .revoke_api_key(
                session.user_id,
                id,
                self.auth.audit_event(
                    None,
                    Some(session.tenant_id),
                    Some(session.user_id),
                    ACTION_API_KEY_REVOKED,
                    "ok",
                ),
                now,
            )
            .await
    }
}

#[cfg(all(test, feature = "password"))]
mod tests {
    use super::{hash_password, hash_password_with, verify_password};
    use vaelspire_core::AuthError;

    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[test]
    fn hash_password_uses_the_default_cost() {
        let default = argon2::Params::default();
        let encoded = hash_password(PASSWORD).expect("default hash");
        assert!(encoded.starts_with(&format!(
            "$argon2id$v=19$m={},t={},p={}$",
            default.m_cost(),
            default.t_cost(),
            default.p_cost()
        )));
        assert_eq!(verify_password(PASSWORD, &encoded), Ok(true));
    }

    #[test]
    fn hash_password_with_records_the_supplied_cost() {
        let encoded = hash_password_with(PASSWORD, 64, 1, 4).expect("explicit cost");
        assert!(
            encoded.starts_with("$argon2id$v=19$m=64,t=1,p=4$"),
            "{encoded}"
        );
        assert_eq!(verify_password(PASSWORD, &encoded), Ok(true));
        assert_eq!(verify_password(b"wrong password", &encoded), Ok(false));
    }

    #[test]
    fn hash_password_with_rejects_unusable_input() {
        assert_eq!(
            hash_password_with(b"", 64, 1, 1),
            Err(AuthError::Invalid),
            "empty password"
        );
        assert_eq!(
            hash_password_with(PASSWORD, 64, 1, 0),
            Err(AuthError::Invalid),
            "zero parallels"
        );
        assert_eq!(
            hash_password_with(PASSWORD, 8, 1, 2),
            Err(AuthError::Invalid),
            "memory below eight blocks per lane"
        );
    }
}

#[cfg(test)]
mod digest_tests {
    use super::{Auth, Policy, token_digest};
    use vaelspire_core::{
        ApiKey, AuditEvent, AuthError, AuthStore, Id, OneTime, PasswordCredential, Purpose,
        Session, Timestamp, User,
    };

    /// Constructed only so the wrappers have an [`Auth`] to be called on; no method
    /// is reached, because both wrappers are pure over the key.
    struct UnusedStore;

    static STORE: UnusedStore = UnusedStore;

    #[async_trait::async_trait]
    impl AuthStore for UnusedStore {
        async fn create_tenant(
            &self,
            _id: Id,
            _name: &str,
            _now: Timestamp,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn create_user(
            &self,
            _user: &User,
            _hash: &str,
            _audit: Option<AuditEvent>,
            _now: Timestamp,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn find_user(&self, _tenant: Id, _email: &str) -> Result<User, AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn password(&self, _user: Id) -> Result<PasswordCredential, AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn record_failure(
            &self,
            _user: Id,
            _audit: Option<AuditEvent>,
            _now: Timestamp,
            _until: Timestamp,
            _limit: i32,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn complete_login(
            &self,
            _session: &Session,
            _expected_hash: &str,
            _replacement: Option<&str>,
            _audit: Option<AuditEvent>,
            _now: Timestamp,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn find_session(
            &self,
            _digest: &[u8],
            _now: Timestamp,
        ) -> Result<Session, AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn revoke_session(
            &self,
            _digest: &[u8],
            _audit: Option<AuditEvent>,
            _now: Timestamp,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn create_one_time(
            &self,
            _proof: &OneTime,
            _audit: Option<AuditEvent>,
            _now: Timestamp,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn consume_one_time(
            &self,
            _purpose: Purpose,
            _digest: &[u8],
            _hash: Option<&str>,
            _audit: Option<AuditEvent>,
            _now: Timestamp,
        ) -> Result<Id, AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn create_api_key(&self, _key: &ApiKey, _now: Timestamp) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn find_api_key(
            &self,
            _digest: &[u8],
            _prefix: &str,
            _now: Timestamp,
        ) -> Result<ApiKey, AuthError> {
            unimplemented!("a digest never reaches the store")
        }

        async fn insert_audit(
            &self,
            _event: &AuditEvent,
            _now: Timestamp,
        ) -> Result<(), AuthError> {
            unimplemented!("a digest never reaches the store")
        }
    }

    fn auth(key: [u8; 32]) -> Auth<'static, UnusedStore> {
        Auth::new(&STORE, key, Policy::default())
    }

    #[test]
    fn both_wrappers_return_what_the_pure_function_returns() {
        let key = [7_u8; 32];
        let auth = auth(key);
        assert_eq!(
            auth.session_digest("a-session-token"),
            token_digest(&key, "session", "a-session-token"),
            "the session wrapper adds no encoding of its own"
        );
        for purpose in [
            Purpose::VerifyEmail,
            Purpose::ResetPassword,
            Purpose::EmailOtp,
        ] {
            assert_eq!(
                auth.proof_digest(purpose, "a-one-time-token"),
                token_digest(&key, purpose.as_str(), "a-one-time-token"),
                "the proof wrapper adds no encoding of its own"
            );
        }
        assert_ne!(
            auth.proof_digest(Purpose::VerifyEmail, "a-one-time-token"),
            auth.session_digest("a-one-time-token"),
            "the domain label separates a proof from a session"
        );
    }

    #[test]
    fn the_version_1_encoding_is_pinned() {
        // Generated by the version-1 function these wrappers delegate to, not
        // written by hand. A change to the key, the label framing, or the token
        // bytes moves this value.
        let key = [7_u8; 32];
        let (session_bytes, session_hex) = token_digest(&key, "session", "a-session-token");
        assert_eq!(
            &session_bytes,
            &[
                0x58, 0xc9, 0xbc, 0xa7, 0x1f, 0xd7, 0x95, 0x51, 0x55, 0x4c, 0xd2, 0x07, 0x37, 0x82,
                0xb1, 0x7b, 0xe2, 0x0e, 0x73, 0x40, 0x11, 0xc0, 0xd7, 0xe6, 0xf7, 0xf9, 0xaa, 0x44,
                0x9a, 0xb8, 0xbf, 0xa3,
            ]
        );
        assert_eq!(
            session_hex,
            "58c9bca71fd79551554cd2073782b17be20e734011c0d7e6f7f9aa449ab8bfa3"
        );
        assert_eq!(
            token_digest(&key, "verify_email", "a-one-time-token").1,
            "7663697a422a54cc9a2edf49cb68176f6c8833be2214ba6050c7c7144af931f4"
        );
        assert_eq!(
            token_digest(&key, "reset_password", "a-one-time-token").1,
            "d5210ef8cd9b9d4d7ad4d9caaee66ef36861fb4c5c321f737a5b88b3a6e3abec"
        );
    }
}
