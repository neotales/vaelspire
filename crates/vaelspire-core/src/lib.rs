//! I/O-independent authentication contracts. A tenant is created with `owner`, `admin`,
//! and `member`; no permission is seeded.

pub use time::OffsetDateTime as Timestamp;
pub use uuid::Uuid as Id;

/// The role names [`AuthStore::create_tenant`] inserts with a new tenant, in order.
///
/// No permission is seeded, and these names are not reserved: creating one of them
/// again in the same tenant is `Conflict` like any other duplicate.
pub const SEEDED_ROLES: [&str; 3] = ["owner", "admin", "member"];

/// Opaque operation failure; never carries submitted credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Invalid credentials, expired/revoked token, or locked account.
    Unauthorized,
    /// No matching record.
    NotFound,
    /// Input the caller got wrong: an unusable password, an Argon2 cost the
    /// parameters reject, a malformed email, or an expiry that is not in the future.
    Invalid,
    /// Duplicate record or a concurrent credential replacement.
    Conflict,
    /// Storage or cryptographic operation failed.
    ///
    /// For a mutation this does not establish that the write was rolled back:
    /// the operation may have committed without its acknowledgement reaching
    /// the caller. Reconcile persisted state before retrying; some one-time
    /// operations cannot be safely repeated.
    Store,
    /// The store adapter does not implement the operation.
    Unsupported,
}

/// Persisted password state. Debug deliberately omits the hash.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordCredential {
    /// Argon2id PHC string, or a legacy bcrypt hash for verification only.
    pub password_hash: String,
    /// Consecutive failed attempts.
    pub failed_attempts: i32,
    /// Login is denied before this UTC instant.
    pub locked_until: Option<Timestamp>,
}

/// Stored TOTP factor. `enabled_at` is absent until the enrollment is confirmed.
#[derive(Clone, PartialEq, Eq)]
pub struct MfaFactor {
    /// AES-GCM ciphertext, including nonce and authentication tag.
    pub secret_crypt: Vec<u8>,
    /// Application-managed encryption key identifier.
    pub key_id: String,
    /// Confirmation time, or `None` for an unconfirmed enrollment.
    pub enabled_at: Option<Timestamp>,
}

impl std::fmt::Debug for MfaFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaFactor")
            .field("key_id", &self.key_id)
            .field("enabled_at", &self.enabled_at)
            .finish_non_exhaustive()
    }
}

/// A stored passkey. `public_key` is the JSON encoding of the credential, not a raw COSE key.
///
/// The authenticator identifier is stored beside that JSON so a later ceremony can exclude or
/// select it without parsing the credential. The sign counter is the value last accepted; the
/// JSON is what a ceremony deserializes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRecord {
    /// Authenticator credential identifier.
    pub credential_id: Vec<u8>,
    /// Serialized credential. The `auth_passkey.public_key` column stores these bytes.
    pub public_key: Vec<u8>,
    /// Signature counter last accepted for this credential.
    pub sign_count: i64,
}

impl std::fmt::Debug for PasswordCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCredential").finish_non_exhaustive()
    }
}

/// Account snapshot; email is trimmed and lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// `UUIDv7` account identifier.
    pub id: Id,
    /// Owning tenant.
    pub tenant_id: Id,
    /// Normalized email.
    pub email: String,
}

/// Session snapshot. Stores must exclude revoked and expired sessions on lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// `UUIDv7` identifier.
    pub id: Id,
    /// Owning account.
    pub user_id: Id,
    /// Owning tenant.
    pub tenant_id: Id,
    /// Versioned keyed digest, never the bearer value.
    pub token_digest: Vec<u8>,
    /// Exclusive expiry instant.
    pub expires_at: Timestamp,
}

/// One-time purpose; digests are domain-separated by purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Confirm ownership of an email address.
    VerifyEmail,
    /// Replace the account password.
    ResetPassword,
    /// Authenticate using an email-delivered code.
    EmailOtp,
}

impl Purpose {
    /// Stable database and digest domain label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::ResetPassword => "reset_password",
            Self::EmailOtp => "email_otp",
        }
    }
}

/// The closed set of social identity providers the library speaks.
///
/// The set is deliberately small. A provider is a variant, not a string loaded from
/// configuration, so a name outside this set cannot be turned into a start route.
#[cfg(feature = "social")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocialProvider {
    /// GitHub OAuth.
    GitHub,
    /// Google OAuth 2.0 and `OpenID` Connect.
    Google,
    /// Microsoft identity platform OAuth 2.0 and `OpenID` Connect.
    Microsoft,
}

#[cfg(feature = "social")]
impl SocialProvider {
    /// Stable path and database label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
            Self::Microsoft => "microsoft",
        }
    }

    /// Parse the closed provider label.
    ///
    /// # Errors
    /// Returns `Invalid` for any label outside the closed set.
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        match value {
            "github" => Ok(Self::GitHub),
            "google" => Ok(Self::Google),
            "microsoft" => Ok(Self::Microsoft),
            _ => Err(AuthError::Invalid),
        }
    }
}

/// Supported self-hosted `OpenID` Connect providers.
#[cfg(feature = "oidc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcProvider {
    /// Authentik.
    Authentik,
    /// Zitadel.
    Zitadel,
    /// Keycloak.
    Keycloak,
}

#[cfg(feature = "oidc")]
impl OidcProvider {
    /// Stable path and database label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentik => "authentik",
            Self::Zitadel => "zitadel",
            Self::Keycloak => "keycloak",
        }
    }

    /// Parse a supported provider label.
    ///
    /// # Errors
    /// Returns `Invalid` for an unsupported label.
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        match value {
            "authentik" => Ok(Self::Authentik),
            "zitadel" => Ok(Self::Zitadel),
            "keycloak" => Ok(Self::Keycloak),
            _ => Err(AuthError::Invalid),
        }
    }
}

/// Single-use proof stored only as a digest.
#[derive(Debug, Clone)]
pub struct OneTime {
    /// `UUIDv7` identifier.
    pub id: Id,
    /// Owning user.
    pub user_id: Id,
    /// Intended operation.
    pub purpose: Purpose,
    /// Versioned keyed digest.
    pub token_digest: Vec<u8>,
    /// Exclusive expiry.
    pub expires_at: Timestamp,
}

/// User-owned API key, independent of browser sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    /// `UUIDv7` identifier.
    pub id: Id,
    /// Owning tenant.
    pub tenant_id: Id,
    /// Owning user.
    pub user_id: Id,
    /// Non-secret label selected at issuance, retained across configuration changes.
    pub prefix: String,
    /// Versioned keyed digest of the complete presented key.
    pub secret_digest: Vec<u8>,
    /// Application-supplied scopes; no library-defined names.
    pub scopes: Vec<String>,
    /// Exclusive expiry.
    pub expires_at: Timestamp,
    /// When a successful lookup last presented this key, or `None` when it never has.
    /// A refused lookup does not move it.
    pub last_used_at: Option<Timestamp>,
}

/// Membership state. Only [`MembershipStatus::Active`] is authority.
///
/// The set is closed: a store rejects anything else in the column. Owner is not a
/// status and not a column. It is a role name the application inserts if it wants one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStatus {
    /// Invited, not yet accepted. Readable, but not authority.
    Invited,
    /// Active membership. The only status that is authority.
    Active,
    /// Suspended membership. Readable, but not authority.
    Suspended,
}

impl MembershipStatus {
    /// Stable database label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }

    /// Parse a stored label.
    ///
    /// # Errors
    /// Returns `Store` for a label outside the closed set.
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        match value {
            "invited" => Ok(Self::Invited),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            _ => Err(AuthError::Store),
        }
    }

    /// Whether this status carries authority. Invited and suspended do not.
    #[must_use]
    pub const fn is_authority(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Membership snapshot: a user's place in one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// `UUIDv7` identifier.
    pub id: Id,
    /// Owning tenant.
    pub tenant_id: Id,
    /// Member.
    pub user_id: Id,
    /// Current state; invited and suspended are readable but not authority.
    pub status: MembershipStatus,
}

/// Invitation to join a tenant, stored only as a keyed digest.
#[derive(Clone)]
pub struct Invitation {
    /// `UUIDv7` identifier.
    pub id: Id,
    /// Tenant the invitation is for.
    pub tenant_id: Id,
    /// Normalized email the invitation was addressed to.
    pub email: String,
    /// Versioned keyed digest. The raw token never reaches the port.
    pub token_digest: Vec<u8>,
    /// Exclusive expiry.
    pub expires_at: Timestamp,
    /// Roles the caller chose to grant on acceptance. Any of these from another
    /// tenant makes the whole write fail; no role name is decided here.
    pub role_ids: Vec<Id>,
}

impl std::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invitation")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("email", &self.email)
            .field("expires_at", &self.expires_at)
            .field("role_ids", &self.role_ids)
            .finish_non_exhaustive()
    }
}

/// Append-only audit event. Only the explicitly allowed metadata fields are accepted.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// `UUIDv7` event identifier.
    pub id: Id,
    /// Tenant, absent for unknown actors.
    pub tenant_id: Option<Id>,
    /// Actor, absent for unknown actors.
    pub actor_id: Option<Id>,
    /// Stable application action name.
    pub action: String,
    /// `ok`, `denied`, or `error`.
    pub outcome: String,
    /// Optional `ip` (64 bytes) and `user_agent` (512 bytes), each at most once.
    /// Any other field is refused, including credential field names.
    pub fields: Vec<(String, String)>,
}

impl AuditEvent {
    /// Validate before executing an insert; rejects unknown/duplicate metadata.
    ///
    /// # Errors
    /// Returns `Conflict` for invalid metadata, action, or outcome.
    pub fn validate(&self) -> Result<(), AuthError> {
        if self.action.is_empty()
            || self.action.len() > 128
            || !matches!(self.outcome.as_str(), "ok" | "denied" | "error")
        {
            return Err(AuthError::Conflict);
        }
        let mut seen = std::collections::HashSet::new();
        for (name, value) in &self.fields {
            let limit = match name.as_str() {
                "ip" => 64,
                "user_agent" => 512,
                _ => return Err(AuthError::Conflict),
            };
            if value.len() > limit || !seen.insert(name) {
                return Err(AuthError::Conflict);
            }
        }
        Ok(())
    }
}

/// Async persistence port. Implementations must make each mutation atomic.
/// Every mutation that carries an audit event commits it in the same transaction, so a
/// failed audit insert leaves no mutation behind. Failed-attempt increments must not
/// lose concurrent failures; successful login compares the hash observed by the
/// verifier and rechecks lockout before issuing. Methods return `Store` on I/O failure,
/// `NotFound` for missing reads, `Conflict` for uniqueness violations or a hash the
/// store will not accept, and `Invalid` for input the caller got wrong. Cancellation
/// or a `Store` error may leave a committed write. Before retrying any mutation,
/// reconcile persisted state; do not repeat one-time operations blindly.
/// Membership, role, group, and invitation operations are
/// optional: their default bodies report `Unsupported`, so an adapter written before
/// them keeps compiling and an adapter that supports them overrides the defaults.
#[async_trait::async_trait]
pub trait AuthStore: Send + Sync {
    /// Insert an unconfirmed factor; never replace an existing factor.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn save_mfa(&self, user: Id, secret_crypt: &[u8], key_id: &str) -> Result<(), AuthError> {
        let _ = (user, secret_crypt, key_id);
        Err(AuthError::Unsupported)
    }
    /// Load the factor, including an unconfirmed enrollment.
    async fn load_mfa(&self, user: Id) -> Result<MfaFactor, AuthError> {
        let _ = user;
        Err(AuthError::Unsupported)
    }
    /// Enable the exact factor that was verified, refusing concurrent replacement.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn enable_mfa(
        &self,
        user: Id,
        secret_crypt: &[u8],
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, secret_crypt, now);
        Err(AuthError::Unsupported)
    }
    /// Insert a keyed digest of a recovery code.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn insert_recovery_code(&self, id: Id, user: Id, digest: &[u8]) -> Result<(), AuthError> {
        let _ = (id, user, digest);
        Err(AuthError::Unsupported)
    }
    /// Atomically consume one unspent recovery code belonging to the user.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn consume_recovery_code(
        &self,
        user: Id,
        digest: &[u8],
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, digest, now);
        Err(AuthError::Unsupported)
    }
    /// Store a short-lived pending-login digest mapped to its session identity.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_mfa_pending(
        &self,
        digest: &[u8],
        user: Id,
        tenant: Id,
        expected_hash: &str,
        expires: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (digest, user, tenant, expected_hash, expires);
        Err(AuthError::Unsupported)
    }
    /// Consume a pending digest and atomically insert its session. Invalid/expired tokens are unauthorized.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn complete_mfa_login(
        &self,
        digest: &[u8],
        session: &Session,
        recovery_digest: Option<&[u8]>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (digest, session, recovery_digest, now);
        Err(AuthError::Unsupported)
    }
    /// Resolve the user associated with an unexpired MFA challenge without consuming it.
    async fn mfa_pending_user(&self, digest: &[u8], now: Timestamp) -> Result<Id, AuthError> {
        let _ = (digest, now);
        Err(AuthError::Unsupported)
    }
    /// Store a passkey ceremony. `challenge` is the raw challenge bytes. `ceremony` is the
    /// serialized registration or authentication state. The relying party id and origin are not
    /// stored here; the caller keeps them and passes them again when the ceremony finishes.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn save_passkey_ceremony(
        &self,
        user: Id,
        kind: &str,
        challenge: &[u8],
        ceremony: &str,
        expires: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, kind, challenge, ceremony, expires);
        Err(AuthError::Unsupported)
    }
    /// Read an unexpired passkey ceremony without deleting it.
    ///
    /// A missing or expired row is `Unauthorized`. The returned text is the serialized state.
    async fn load_passkey_ceremony(
        &self,
        kind: &str,
        challenge: &[u8],
        now: Timestamp,
    ) -> Result<(Id, String), AuthError> {
        let _ = (kind, challenge, now);
        Err(AuthError::Unsupported)
    }
    /// Delete the ceremony row and insert the passkey, in one transaction.
    ///
    /// A missing, expired, or already-finished ceremony is `Unauthorized`, and then neither the
    /// passkey nor the audit row is written.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn complete_passkey_registration(
        &self,
        user: Id,
        kind: &str,
        challenge: &[u8],
        passkey: &PasskeyRecord,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, kind, challenge, passkey, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Passkeys registered to `user`, oldest first.
    async fn list_passkeys(&self, user: Id) -> Result<Vec<PasskeyRecord>, AuthError> {
        let _ = user;
        Err(AuthError::Unsupported)
    }
    /// Delete the ceremony row, update the credential, and insert the session, in one transaction.
    ///
    /// The ceremony's user must be `session.user_id`. A missing or expired ceremony, or a
    /// credential that is not that user's, is `Unauthorized` and leaves the session unwritten.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn complete_passkey_login(
        &self,
        kind: &str,
        challenge: &[u8],
        session: &Session,
        passkey: &PasskeyRecord,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (kind, challenge, session, passkey, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Resolve an account's tenant for session issuance.
    async fn user_tenant(&self, user: Id) -> Result<Id, AuthError> {
        let _ = user;
        Err(AuthError::Unsupported)
    }
    /// Create a tenant and the [`SEEDED_ROLES`] in one transaction, or neither.
    /// Duplicate identifiers/names fail.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_tenant(&self, id: Id, name: &str, now: Timestamp) -> Result<(), AuthError>;
    /// Create account and Argon2id password together, or neither. When `audit` is
    /// `Some`, its row commits in the same transaction.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_user(
        &self,
        user: &User,
        hash: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError>;
    /// Find a non-deleted account in an active tenant; inactive accounts are denied.
    async fn find_user(&self, tenant: Id, email: &str) -> Result<User, AuthError>;
    /// Load credential state.
    async fn password(&self, user: Id) -> Result<PasswordCredential, AuthError>;
    /// Atomically increment failures and set a timed lock after the threshold. When
    /// `audit` is `Some`, its row commits in the same transaction as the increment.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn record_failure(
        &self,
        user: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
        until: Timestamp,
        limit: i32,
    ) -> Result<(), AuthError>;
    /// Compare current hash and lock state, reset failures, optionally rehash, and insert session atomically.
    /// When `audit` is `Some`, its row commits in the same transaction.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn complete_login(
        &self,
        session: &Session,
        expected_hash: &str,
        replacement: Option<&str>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError>;
    /// Resolve an unexpired, unrevoked session for an active account and tenant.
    async fn find_session(&self, digest: &[u8], now: Timestamp) -> Result<Session, AuthError>;
    /// Extend a live session and update its last-seen time in the same transaction as
    /// `audit`. Refuse an expired, revoked, or otherwise inactive session.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn extend_session(
        &self,
        digest: &[u8],
        expires_at: Timestamp,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (digest, expires_at, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Revoke a session by digest. Repeated revocation succeeds. When `audit` is
    /// `Some`, its row commits in the same transaction as the revocation.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn revoke_session(
        &self,
        digest: &[u8],
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError>;
    /// List the live sessions of one account: unrevoked and unexpired at `now`, newest
    /// first. The rows carry the stored digest, so a caller that displays them must not
    /// forward it.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    async fn list_sessions(&self, user: Id, now: Timestamp) -> Result<Vec<Session>, AuthError> {
        let _ = (user, now);
        Err(AuthError::Unsupported)
    }
    /// Revoke one live session by identifier, only when it belongs to `user`.
    ///
    /// A session of another account, one already revoked, and one already expired are
    /// all `NotFound`, so the port never says whether an identifier the caller does not
    /// own exists. When `audit` is `Some`, its row commits in the same transaction as
    /// the revocation, so a failed insert leaves the session live.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn revoke_session_by_id(
        &self,
        user: Id,
        session: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, session, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Revoke every live session of `user`, except `keep` when it is `Some`. `None`
    /// revokes all of them, including the presented one; a `keep` that is not live does
    /// not stop the others from being revoked.
    ///
    /// When `audit` is `Some`, its row commits in the same transaction as the
    /// revocations, so a failed insert leaves every session live.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn revoke_sessions(
        &self,
        user: Id,
        keep: Option<Id>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, keep, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Replace the password of `user`, but only while the stored hash still is
    /// `expected_hash`.
    ///
    /// In one transaction the store writes `hash`, clears the lockout state, consumes the
    /// account's outstanding `EmailOtp` proofs, revokes every live session except `keep`,
    /// and commits `audit`. The presented session and its cookie stay. A hash that is not
    /// an Argon2id PHC string is `Conflict`; a stored hash that no longer is
    /// `expected_hash`, an unknown account, or a deleted one is `Unauthorized`.
    ///
    /// A failed audit insert is the call's error and leaves the old hash and every other
    /// session as they were.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn change_password(
        &self,
        user: Id,
        keep: Id,
        expected_hash: &str,
        hash: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, keep, expected_hash, hash, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Replace an account's email with `email` and clear its verification instant.
    ///
    /// `user` must be a live account of `tenant`. A normalized address already held by
    /// another live account in that tenant is `Conflict`; an unknown or deleted account
    /// is `NotFound`. When `audit` is `Some`, its row commits in the same transaction and
    /// carries no token.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn change_email(
        &self,
        user: Id,
        tenant: Id,
        email: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, tenant, email, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Mark an account deleted and revoke every live session it owns, including the
    /// presented one, in one transaction.
    ///
    /// The account row is kept: `deleted_at` is the delete, and a later lookup or sign-in
    /// does not find it. An account that is already deleted is `NotFound`. When `audit`
    /// is `Some`, its row commits in the same transaction, so a failed insert leaves the
    /// account and its sessions as they were.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn delete_user(
        &self,
        user: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Save a proof. Raw token must never reach this port. When `audit` is `Some`, its
    /// row commits in the same transaction.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_one_time(
        &self,
        proof: &OneTime,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError>;
    /// Consume an unexpired proof exactly once, together with its effect.
    /// Reset requires an Argon2id hash and revokes all sessions. Verification and OTP require no hash.
    ///
    /// When `audit` is `Some`, its row commits in the same transaction. The workflow
    /// learns the account from the returned identifier, not before, so the store sets
    /// `actor_id` from the account it resolved when the event leaves it `None`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn consume_one_time(
        &self,
        purpose: Purpose,
        digest: &[u8],
        hash: Option<&str>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Id, AuthError>;

    /// Consume an [`Purpose::EmailOtp`] proof and insert the session it signs in, in
    /// one transaction.
    ///
    /// The store resolves the account from the proof, so neither its identifier nor
    /// its tenant is known to the caller before the spend. `session_id`,
    /// `session_digest`, and `expires_at` describe the session to insert; the
    /// returned [`Session`] carries the resolved account and tenant. A second spend of
    /// the same proof is `Unauthorized`.
    ///
    /// When `audit` is `Some`, its row commits with the consumption and the session
    /// insert. The store fills `tenant_id` and `actor_id` from the resolved account
    /// when the event leaves them `None`, and a failed insert leaves neither the
    /// consumed proof nor the session behind.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn complete_email_sign_in(
        &self,
        digest: &[u8],
        session_id: Id,
        session_digest: &[u8],
        expires_at: Timestamp,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Session, AuthError> {
        let _ = (digest, session_id, session_digest, expires_at, audit, now);
        Err(AuthError::Unsupported)
    }

    /// Store a single-use social sign-in state. The raw state value must never reach
    /// this port; `digest` is its versioned keyed digest.
    ///
    /// The row is bound to `tenant` and `provider`, expires at `expires_at`, and is
    /// spent by [`Self::complete_social_sign_in`]. A tenant that is not active is
    /// `NotFound`.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    #[cfg(feature = "social")]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_social_state(
        &self,
        digest: &[u8],
        tenant: Id,
        provider: &str,
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (digest, tenant, provider, expires_at, now);
        Err(AuthError::Unsupported)
    }

    /// Read whether a social sign-in state may still be spent.
    ///
    /// Returns `Ok(())` only for an unexpired, unconsumed row matching `digest`,
    /// `tenant`, and `provider`; every other state is `Unauthorized`. This is a read:
    /// [`Self::complete_social_sign_in`] spends the state atomically and remains the
    /// operation that guarantees a second use fails.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    #[cfg(feature = "social")]
    async fn check_social_state(
        &self,
        digest: &[u8],
        tenant: Id,
        provider: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (digest, tenant, provider, now);
        Err(AuthError::Unsupported)
    }

    /// Spend a social sign-in state and issue the session it signs in, in one
    /// transaction.
    ///
    /// The state is spent only when `state_digest`, `tenant`, and `provider` all match
    /// an unexpired, unconsumed row, so a mismatch, a replay, or a state minted for
    /// another provider is `Unauthorized`. A second spend of the same state is
    /// `Unauthorized` too.
    ///
    /// The store resolves the account from `(provider, subject)`. When that pair is
    /// already known, the session belongs to that account. When it is new, the account
    /// is created with `email` in the state's tenant, but only if no live account in
    /// that tenant already holds that address; otherwise this call is `Conflict` and
    /// neither an account, an identity, nor a session is written. Existing accounts are
    /// never linked to a social identity by this operation, and `email_verified` only
    /// decides whether the new account's address is marked verified.
    ///
    /// When `audit` is `Some`, its row commits with the state spend and the session
    /// insert. The store fills `tenant_id` and `actor_id` from the account it resolved
    /// when the event leaves them `None`, and a failed insert leaves the state, the
    /// account, the identity, and the session as they were.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    #[cfg(feature = "social")]
    #[allow(clippy::too_many_arguments)]
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn complete_social_sign_in(
        &self,
        state_digest: &[u8],
        tenant: Id,
        provider: &str,
        subject: &str,
        email: &str,
        email_verified: bool,
        session_id: Id,
        session_digest: &[u8],
        expires_at: Timestamp,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Session, AuthError> {
        let _ = (
            state_digest,
            tenant,
            provider,
            subject,
            email,
            email_verified,
            session_id,
            session_digest,
            expires_at,
            audit,
            now,
        );
        Err(AuthError::Unsupported)
    }

    /// Insert a user-owned key; prefix is persisted, not inferred from configuration.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_api_key(&self, key: &ApiKey, now: Timestamp) -> Result<(), AuthError>;
    /// Lookup active key by digest and its stored prefix, independent of sessions.
    ///
    /// The returned value carries the stored `last_used_at`; this read does not move it.
    /// [`Self::record_api_key_use`] is what a successful verification calls afterwards.
    async fn find_api_key(
        &self,
        digest: &[u8],
        prefix: &str,
        now: Timestamp,
    ) -> Result<ApiKey, AuthError>;
    /// Revoke one live key by identifier, only when it belongs to `user`.
    ///
    /// Another account's identifier, one already revoked, and one already expired are
    /// all `NotFound`, so the port never says whether an identifier the caller does not
    /// own exists. When `audit` is `Some`, its row commits in the same transaction as
    /// the revocation, so a failed insert leaves the key usable.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn revoke_api_key(
        &self,
        user: Id,
        key: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (user, key, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Record that `key` authenticated a request at `now`, writing `last_used_at`.
    ///
    /// Only a successful lookup reaches this call, so a refused, revoked, or expired
    /// key does not move the column. An identifier that no longer exists is `NotFound`.
    ///
    /// The default body reports `Unsupported`, so an adapter written before this
    /// operation keeps compiling; a caller that looks a key up on such an adapter gets
    /// `Unsupported` rather than a verification that silently records nothing.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn record_api_key_use(&self, key: Id, now: Timestamp) -> Result<(), AuthError> {
        let _ = (key, now);
        Err(AuthError::Unsupported)
    }
    /// Validate and append an event; no update/delete API exists. A mutation that
    /// writes an audit row passes the event to its own method instead, so the row and
    /// the mutation commit together. This method is for a denial that writes no
    /// mutation.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn insert_audit(&self, event: &AuditEvent, now: Timestamp) -> Result<(), AuthError>;

    /// Mark a tenant suspended. A suspended tenant is not active: its users cannot
    /// authenticate, and no membership or invitation is created in it.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn suspend_tenant(&self, tenant: Id, now: Timestamp) -> Result<(), AuthError> {
        let _ = (tenant, now);
        Err(AuthError::Unsupported)
    }
    /// Create a membership for a user who is already in that tenant. A duplicate
    /// membership, a user in another tenant, or an inactive tenant is refused. When
    /// `audit` is `Some`, its row commits in the same transaction.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_membership(
        &self,
        membership: &Membership,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (membership, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Read a membership by tenant and user regardless of status. Invited and
    /// suspended memberships are readable; authority is the caller's decision.
    async fn find_membership(&self, tenant: Id, user: Id) -> Result<Membership, AuthError> {
        let _ = (tenant, user);
        Err(AuthError::Unsupported)
    }
    /// Replace a membership status and return the updated membership. Any status in
    /// the closed set is accepted. When `audit` is `Some`, its row commits in the same
    /// transaction and the store fills `tenant_id` from the updated membership when the
    /// event leaves it `None`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn set_membership_status(
        &self,
        membership: Id,
        status: MembershipStatus,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let _ = (membership, status, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Store a permission under a caller-supplied name. No name is decided here.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_permission(&self, id: Id, tenant: Id, name: &str) -> Result<(), AuthError> {
        let _ = (id, tenant, name);
        Err(AuthError::Unsupported)
    }
    /// Store a role under a caller-supplied name. [`SEEDED_ROLES`] arrived with the
    /// tenant, so one of those names is already taken in it; every other name is the
    /// caller's.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_role(&self, id: Id, tenant: Id, name: &str) -> Result<(), AuthError> {
        let _ = (id, tenant, name);
        Err(AuthError::Unsupported)
    }
    /// Store a group under a caller-supplied name in one tenant.
    ///
    /// A group belongs to one tenant and holds memberships of that same tenant. No
    /// name is decided here, and this call writes no audit event. The default body
    /// reports `Unsupported`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_group(
        &self,
        id: Id,
        tenant: Id,
        name: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (id, tenant, name, now);
        Err(AuthError::Unsupported)
    }
    /// Add a membership to a group in `tenant`.
    ///
    /// There is no group read, so `tenant` is the caller's tenant. A group that is not
    /// in it is `NotFound`, including one that exists in another tenant. A missing
    /// membership is `NotFound`. A membership of another tenant is `Conflict` and is
    /// not added. Repeating the same add succeeds, as [`Self::assign_role`] does. The
    /// default body reports `Unsupported`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn add_group_member(
        &self,
        tenant: Id,
        group: Id,
        membership: Id,
    ) -> Result<(), AuthError> {
        let _ = (tenant, group, membership);
        Err(AuthError::Unsupported)
    }
    /// Remove a membership from a group in `tenant`.
    ///
    /// A group that is not in `tenant` is `NotFound`, so a link in another tenant is
    /// left in place. A membership, or a pair that is not linked, is `NotFound` too, so
    /// a repeated removal is. The default body reports `Unsupported`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn remove_group_member(
        &self,
        tenant: Id,
        group: Id,
        membership: Id,
    ) -> Result<(), AuthError> {
        let _ = (tenant, group, membership);
        Err(AuthError::Unsupported)
    }
    /// Attach a role to a membership and return the membership. A role from another
    /// tenant is refused; repeating the same assignment succeeds. When `audit` is
    /// `Some`, its row commits in the same transaction and the store fills `tenant_id`
    /// from the membership when the event leaves it `None`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn assign_role(
        &self,
        membership: Id,
        role: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let _ = (membership, role, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Store an invitation and its roles atomically. A role from another tenant
    /// makes the whole write fail. When `audit` is `Some`, its row commits in the same
    /// transaction.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn create_invitation(
        &self,
        invitation: &Invitation,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let _ = (invitation, audit, now);
        Err(AuthError::Unsupported)
    }
    /// Spend an invitation exactly once and leave an active membership for the
    /// user with that email in that tenant, carrying the invitation's roles.
    ///
    /// `id` names the membership when one has to be created; it is ignored when the
    /// user already has a membership in that tenant, which is activated instead. When
    /// `audit` is `Some`, its row commits in the same transaction and the store fills
    /// `tenant_id` and `actor_id` from the membership it resolved when the event leaves
    /// them `None`.
    ///
    /// See [`AuthError::Store`] for uncertain mutation outcomes; reconcile before retrying.
    async fn accept_invitation(
        &self,
        id: Id,
        digest: &[u8],
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let _ = (id, digest, audit, now);
        Err(AuthError::Unsupported)
    }
}

/// API-key prefix configuration; the parser uses the prefix stored on each row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyPrefix(String);

impl ApiKeyPrefix {
    /// Choose a 1–16 byte ASCII label, defaulting to `nak` when omitted.
    ///
    /// # Errors
    /// Returns `Invalid` for an empty, oversized, or non-ASCII prefix.
    pub fn new(prefix: Option<&str>) -> Result<Self, AuthError> {
        let value = prefix.unwrap_or("nak");
        if value.is_empty()
            || value.len() > 16
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(AuthError::Invalid);
        }
        Ok(Self(value.to_owned()))
    }
    /// Printable non-secret label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
