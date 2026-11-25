//! SQLite adapter over `neotales-dbapi`. Each multi-row security transition is a database
//! transaction.
//!
//! The schema is net-new: `open` (with default `sqlx-compat`) connects and applies the migration through
//! `neotales-migration-sqlite`, and returns a store. An existing database that predates the
//! migration ledger is refused rather than adopted. Disable default features and use
//! [`migrate_with_pool`] and [`SqliteStore::new`] with a `neotales-dbapi::SqlitePool`
//! implementation to avoid the `SQLx` provider.

use neotales_dbapi::{
    DbError, DbType, ErrorKind, Parameter, QueryOptions, Row, SqlitePool, Transaction, TxOptions,
    Value,
};
#[cfg(feature = "sqlx-compat")]
use neotales_dbapi_sqlite::{SqliteConfig, SqlitePoolProvider};
use neotales_migration::{Migration, Migrations};
use neotales_migration_sqlite::SqliteBackend;
use vaelspire_core::{
    ApiKey, AuditEvent, AuthError, AuthStore, Id, Invitation, Membership, MembershipStatus,
    OneTime, PasskeyRecord, PasswordCredential, Purpose, SEEDED_ROLES, Session, Timestamp, User,
};

/// The schema, applied as one net-new definition. There is no legacy adoption path.
pub const SCHEMA: &str = include_str!("../migrations/0001_auth.sql");

/// Migration module name in the shared ledger.
const MIGRATION_MODULE: &str = "auth";
/// Binding fingerprint recorded with the applied migration.
const MIGRATION_FINGERPRINT: &str = "neotales-auth/sqlite/v1";
/// Main-database ledger table owned by this module.
const MIGRATION_LEDGER: &str = "auth_schema_history";
/// Busy-handler wait bound used by the migration backend for its exclusive transaction.
const MIGRATION_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Every application object the migration owns, so a pre-existing schema cannot be
/// mistaken for a fresh one. The ledger tables are deliberately absent: the backend
/// creates them before this list is checked.
const MANAGED_OBJECTS: [&str; 28] = [
    "auth_tenant",
    "auth_user",
    "auth_user_email_live",
    "auth_user_username_live",
    "auth_password",
    "auth_session",
    "auth_one_time",
    "auth_api_key",
    "auth_service_account",
    "auth_passkey",
    "auth_webauthn_challenge",
    "auth_mfa",
    "auth_recovery_code",
    "auth_permission",
    "auth_role",
    "auth_role_permission",
    "auth_membership",
    "auth_membership_role",
    "auth_invitation",
    "auth_invitation_role",
    "auth_audit",
    "auth_audit_no_update",
    "auth_audit_no_delete",
    "auth_group",
    "auth_group_member",
    "auth_social_state",
    "auth_social_identity",
    "auth_social_identity_user",
];

/// Opening or migrating the database failed. No driver text or submitted value is retained.
#[derive(Debug)]
pub enum OpenError {
    /// The provider could not be opened or queried.
    Database(DbError),
    /// The migration ledger or schema definition was rejected.
    Migration(neotales_migration_sqlite::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Migration(error) => write!(formatter, "migration error: {error}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// The complete net-new schema as migration definitions.
fn migrations() -> Result<Migrations, neotales_migration_sqlite::Error> {
    let migration = Migration::new(1, "auth_schema", SCHEMA, None)
        .map_err(|_| neotales_migration_sqlite::Error::Configuration)?;
    Migrations::new(vec![migration]).map_err(|_| neotales_migration_sqlite::Error::Configuration)
}

/// Apply the schema to an already-connected provider.
///
/// A fresh database receives the single definition. A database whose ledger already records
/// it is left untouched. A database that has the tables but no matching ledger is refused,
/// because those objects are unowned.
///
/// # Errors
/// Returns [`OpenError::Migration`] for an unowned or corrupt history, or
/// [`OpenError::Database`] when the provider cannot be opened or queried.
#[cfg(feature = "sqlx-compat")]
pub async fn migrate(provider: &SqlitePoolProvider) -> Result<(), OpenError> {
    migrate_with_pool(provider).await
}

/// Apply or verify the schema through a SQLite pool.
///
/// The pool must enable foreign keys on every acquired connection and keep them
/// enabled. All connections must address the same database.
///
/// # Errors
/// Returns a sanitized migration error if the schema cannot be applied or verified.
pub async fn migrate_with_pool(provider: &dyn SqlitePool) -> Result<(), OpenError> {
    let backend = SqliteBackend::new(MIGRATION_LEDGER, MIGRATION_BUSY_TIMEOUT_MS)
        .map_err(OpenError::Migration)?;
    let migrations = migrations().map_err(OpenError::Migration)?;
    backend
        .up_with_pool(
            provider,
            MIGRATION_MODULE,
            &migrations,
            MIGRATION_FINGERPRINT,
            &MANAGED_OBJECTS,
        )
        .await
        .map_err(OpenError::Migration)
}

/// Open or create the database at `path` and apply the schema.
///
/// Uses the provider defaults: a five-second busy timeout and five pooled connections.
/// Overlapping calls are supported, but competing writers can exhaust that finite SQLite
/// lock wait and return [`AuthError::Store`]; the timeout is not FIFO writer admission.
/// Call [`migrate`] with a custom [`SqliteConfig`] provider first when a
/// different policy is needed, then pass the provider to [`SqliteStore::new`].
///
/// # Errors
/// Returns [`OpenError::Database`] when the file cannot be opened and
/// [`OpenError::Migration`] when the schema cannot be applied or is unowned.
#[cfg(feature = "sqlx-compat")]
pub async fn open(path: impl Into<std::path::PathBuf>) -> Result<SqliteStore, OpenError> {
    let provider = SqlitePoolProvider::connect(SqliteConfig::new(path))
        .await
        .map_err(OpenError::Database)?;
    migrate(&provider).await?;
    Ok(SqliteStore { provider })
}

#[cfg(feature = "sqlx-compat")]
type DefaultProvider = SqlitePoolProvider;
#[cfg(not(feature = "sqlx-compat"))]
type DefaultProvider = ();

/// Cloneable store handle. Clones share the pool; dropping the final handle releases it.
/// For mutations, [`AuthError::Store`] can mean the write committed without
/// acknowledgement. Reconcile persisted state before retrying.
#[derive(Debug, Clone)]
pub struct SqliteStore<P = DefaultProvider> {
    provider: P,
}

impl<P: SqlitePool> SqliteStore<P> {
    /// Wrap an already-migrated provider satisfying [`migrate_with_pool`]'s connection requirements.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// The provider this store queries through.
    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

fn error(error: DbError) -> AuthError {
    match error.kind() {
        ErrorKind::Constraint => AuthError::Conflict,
        ErrorKind::NoRows => AuthError::NotFound,
        _ => AuthError::Store,
    }
}

fn text(value: &str) -> Parameter {
    Parameter::new(DbType::Text, Value::Text(value.to_owned())).expect("matching text parameter")
}

fn optional_text(value: Option<&str>) -> Parameter {
    value.map_or_else(
        || Parameter::new(DbType::Text, Value::Null(DbType::Text)).expect("typed null"),
        text,
    )
}

fn bytes(value: &[u8]) -> Parameter {
    Parameter::new(DbType::Bytes, Value::Bytes(value.to_vec())).expect("matching bytes parameter")
}

fn id(value: Id) -> Parameter {
    bytes(value.as_bytes())
}

fn optional_id(value: Option<Id>) -> Parameter {
    value.map_or_else(
        || Parameter::new(DbType::Bytes, Value::Null(DbType::Bytes)).expect("typed null"),
        id,
    )
}

fn integer(value: i64) -> Parameter {
    Parameter::new(DbType::I64, Value::I64(value)).expect("matching integer parameter")
}

// SQLite compares TEXT timestamps lexically. Always write nine fraction digits at UTC so
// `.5Z` does not sort before `Z`.
fn time(value: Timestamp) -> Result<Parameter, AuthError> {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]Z"
    );
    let formatted = value
        .to_offset(time::UtcOffset::UTC)
        .format(&format)
        .map_err(|_| AuthError::Store)?;
    Ok(text(&formatted))
}

fn read_id(row: &Row, column: &str) -> Result<Id, AuthError> {
    let raw: Vec<u8> = row.read(column).map_err(error)?;
    Id::from_slice(&raw).map_err(|_| AuthError::Store)
}

fn read_time(row: &Row, column: &str) -> Result<Timestamp, AuthError> {
    let stored: String = row.read(column).map_err(error)?;
    Timestamp::parse(&stored, &time::format_description::well_known::Rfc3339)
        .map_err(|_| AuthError::Store)
}

fn read_optional_time(row: &Row, column: &str) -> Result<Option<Timestamp>, AuthError> {
    let stored: Option<String> = row.read(column).map_err(error)?;
    stored.map_or(Ok(None), |value| {
        Timestamp::parse(&value, &time::format_description::well_known::Rfc3339)
            .map(Some)
            .map_err(|_| AuthError::Store)
    })
}

fn session(row: &Row) -> Result<Session, AuthError> {
    Ok(Session {
        id: read_id(row, "id")?,
        user_id: read_id(row, "user_id")?,
        tenant_id: read_id(row, "tenant_id")?,
        token_digest: row.read("token_digest").map_err(error)?,
        expires_at: read_time(row, "expires_at")?,
    })
}

fn read_membership(row: &Row) -> Result<Membership, AuthError> {
    let status: String = row.read("status").map_err(error)?;
    Ok(Membership {
        id: read_id(row, "id")?,
        tenant_id: read_id(row, "tenant_id")?,
        user_id: read_id(row, "user_id")?,
        status: MembershipStatus::parse(&status)?,
    })
}

/// Hash parameter profile, stored as JSON text.
fn profile(hash: &str) -> String {
    let phc_parameters = hash.split('$').nth(3).unwrap_or("");
    serde_json::json!({ "phc_parameters": phc_parameters }).to_string()
}

/// Append a mutation's audit row inside the transaction that writes the mutation, so
/// a failed insert rolls the mutation back instead of leaving it committed.
async fn audit_row(
    tx: &mut (dyn Transaction<'_> + '_),
    audit: Option<&AuditEvent>,
    now: Timestamp,
) -> Result<(), AuthError> {
    let Some(event) = audit else {
        return Ok(());
    };
    event.validate()?;
    let field = |name: &str| {
        event
            .fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let parameters = [
        id(event.id),
        optional_id(event.tenant_id),
        optional_id(event.actor_id),
        text(&event.action),
        text(&event.outcome),
        optional_text(field("ip")),
        optional_text(field("user_agent")),
        time(now)?,
    ];
    let affected = tx
        .execute_async(
            "INSERT INTO auth_audit(id,tenant_id,actor_id,action,outcome,ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        // A duplicate audit id is a caller conflict, while any other write failure is a
        // storage failure. The row count tells them apart without relying on a
        // sanitized error category that also covers trigger aborts.
        .map_err(|_| AuthError::Store)?;
    if affected != 1 {
        return Err(AuthError::Conflict);
    }
    Ok(())
}

#[async_trait::async_trait]
impl<P: SqlitePool> AuthStore for SqliteStore<P> {
    async fn mfa_pending_user(&self, digest: &[u8], now: Timestamp) -> Result<Id, AuthError> {
        let parameters = [bytes(digest), time(now)?];
        let row = self
            .provider
            .fetch_first_async(
                "SELECT user_id FROM auth_webauthn_challenge WHERE kind='mfa_login' AND challenge=? AND consumed_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        read_id(&row, "user_id")
    }

    async fn save_passkey_ceremony(
        &self,
        user: Id,
        kind: &str,
        challenge: &[u8],
        ceremony: &str,
        expires: Timestamp,
    ) -> Result<(), AuthError> {
        let parameters = [
            id(Id::now_v7()),
            id(user),
            text(kind),
            bytes(challenge),
            time(expires)?,
            text(ceremony),
        ];
        self.provider
            .execute_async(
                "INSERT INTO auth_webauthn_challenge(id,user_id,kind,challenge,expires_at,ceremony) VALUES(?,?,?,?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn load_passkey_ceremony(
        &self,
        kind: &str,
        challenge: &[u8],
        now: Timestamp,
    ) -> Result<(Id, String), AuthError> {
        let parameters = [text(kind), bytes(challenge), time(now)?];
        let row = self
            .provider
            .fetch_first_async(
                "SELECT user_id, ceremony FROM auth_webauthn_challenge WHERE kind=? AND challenge=? AND ceremony IS NOT NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(|failure| match failure.kind() {
                ErrorKind::NoRows => AuthError::Unauthorized,
                _ => error(failure),
            })?
            .ok_or(AuthError::Unauthorized)?;
        let user = read_id(&row, "user_id")?;
        let ceremony: String = row.read("ceremony").map_err(error)?;
        Ok((user, ceremony))
    }

    async fn complete_passkey_registration(
        &self,
        user: Id,
        kind: &str,
        challenge: &[u8],
        passkey: &PasskeyRecord,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [text(kind), bytes(challenge), id(user), now_time.clone()];
        let n = tx
            .execute_async(
                "DELETE FROM auth_webauthn_challenge WHERE kind=? AND challenge=? AND user_id=? AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if n != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [
            id(Id::now_v7()),
            id(user),
            bytes(&passkey.credential_id),
            bytes(&passkey.public_key),
            integer(passkey.sign_count),
            now_time,
        ];
        tx.execute_async(
            "INSERT INTO auth_passkey(id,user_id,credential_id,public_key,sign_count,transports,backed_up,created_at) VALUES(?,?,?,?,?,'[]',0,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn list_passkeys(&self, user: Id) -> Result<Vec<PasskeyRecord>, AuthError> {
        let rows = self
            .provider
            .fetch_all_async(
                "SELECT credential_id, public_key, sign_count FROM auth_passkey WHERE user_id=? ORDER BY created_at",
                QueryOptions::new().bind(id(user)),
            )
            .await
            .map_err(error)?;
        rows.iter()
            .map(|row| {
                Ok(PasskeyRecord {
                    credential_id: row.read("credential_id").map_err(error)?,
                    public_key: row.read("public_key").map_err(error)?,
                    sign_count: row.read("sign_count").map_err(error)?,
                })
            })
            .collect()
    }

    async fn complete_passkey_login(
        &self,
        kind: &str,
        challenge: &[u8],
        session: &Session,
        passkey: &PasskeyRecord,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            text(kind),
            bytes(challenge),
            id(session.user_id),
            now_time.clone(),
        ];
        let n = tx
            .execute_async(
                "DELETE FROM auth_webauthn_challenge WHERE kind=? AND challenge=? AND user_id=? AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if n != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [
            bytes(&passkey.public_key),
            integer(passkey.sign_count),
            bytes(&passkey.credential_id),
            id(session.user_id),
        ];
        let updated = tx
            .execute_async(
                "UPDATE auth_passkey SET public_key=?, sign_count=? WHERE credential_id=? AND user_id=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if updated != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [id(session.user_id), id(session.tenant_id)];
        let live = tx
            .fetch_one_async(
                "SELECT count(*) AS live FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=? AND u.tenant_id=? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .read::<i64>("live")
            .map_err(error)?;
        if live != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [
            id(session.id),
            id(session.user_id),
            id(session.tenant_id),
            bytes(&session.token_digest),
            time(session.expires_at)?,
            now_time.clone(),
            now_time,
        ];
        tx.execute_async(
            "INSERT INTO auth_session(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn user_tenant(&self, user: Id) -> Result<Id, AuthError> {
        let row = self
            .provider
            .fetch_one_async(
                "SELECT tenant_id FROM auth_user WHERE id=? AND deleted_at IS NULL",
                QueryOptions::new().bind(id(user)),
            )
            .await
            .map_err(error)?;
        read_id(&row, "tenant_id")
    }

    async fn create_mfa_pending(
        &self,
        digest: &[u8],
        user: Id,
        _tenant: Id,
        expected_hash: &str,
        expires: Timestamp,
    ) -> Result<(), AuthError> {
        let parameters = [
            id(Id::now_v7()),
            id(user),
            bytes(digest),
            time(expires)?,
            text(expected_hash),
        ];
        self.provider
            .execute_async(
                "INSERT INTO auth_webauthn_challenge(id,user_id,kind,challenge,expires_at,expected_password_hash) VALUES(?,?,'mfa_login',?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn complete_mfa_login(
        &self,
        digest: &[u8],
        value: &Session,
        recovery_digest: Option<&[u8]>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        // Lock and recheck the credential observed before password verification.
        let parameters = [
            id(value.user_id),
            bytes(digest),
            id(value.user_id),
            now_time.clone(),
            now_time.clone(),
            id(value.user_id),
            id(value.tenant_id),
        ];
        let count = tx
            .execute_async(
                "UPDATE auth_password SET row_version=row_version+1 WHERE user_id=? AND password_hash=(SELECT expected_password_hash FROM auth_webauthn_challenge WHERE kind='mfa_login' AND challenge=? AND user_id=? AND consumed_at IS NULL AND expires_at>?) AND (locked_until IS NULL OR locked_until<=?) AND EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=? AND u.tenant_id=? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Unauthorized);
        }
        if let Some(code) = recovery_digest {
            let parameters = [now_time.clone(), id(value.user_id), bytes(code)];
            let n = tx
                .execute_async(
                    "UPDATE auth_recovery_code SET consumed_at=? WHERE user_id=? AND code_digest=? AND consumed_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
            if n != 1 {
                return Err(AuthError::Unauthorized);
            }
        }
        let parameters = [
            now_time.clone(),
            bytes(digest),
            id(value.user_id),
            now_time.clone(),
        ];
        let n = tx
            .execute_async(
                "UPDATE auth_webauthn_challenge SET consumed_at=? WHERE kind='mfa_login' AND challenge=? AND user_id=? AND consumed_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if n != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [
            id(value.id),
            id(value.user_id),
            id(value.tenant_id),
            bytes(&value.token_digest),
            time(value.expires_at)?,
            now_time.clone(),
            now_time,
        ];
        tx.execute_async(
            "INSERT INTO auth_session(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        tx.commit_async().await.map_err(error)
    }

    async fn save_mfa(&self, user: Id, secret_crypt: &[u8], key_id: &str) -> Result<(), AuthError> {
        let parameters = [
            id(user),
            bytes(secret_crypt),
            text(key_id),
            time(Timestamp::UNIX_EPOCH)?,
        ];
        self.provider
            .execute_async(
                "INSERT INTO auth_mfa(user_id,totp_secret_crypt,key_id,enabled_at) VALUES(?,?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn load_mfa(&self, user: Id) -> Result<vaelspire_core::MfaFactor, AuthError> {
        let row = self
            .provider
            .fetch_one_async(
                "SELECT totp_secret_crypt,key_id,enabled_at FROM auth_mfa WHERE user_id=?",
                QueryOptions::new().bind(id(user)),
            )
            .await
            .map_err(error)?;
        let enabled = read_time(&row, "enabled_at")?;
        Ok(vaelspire_core::MfaFactor {
            secret_crypt: row.read("totp_secret_crypt").map_err(error)?,
            key_id: row.read("key_id").map_err(error)?,
            enabled_at: (enabled != Timestamp::UNIX_EPOCH).then_some(enabled),
        })
    }

    async fn enable_mfa(
        &self,
        user: Id,
        secret_crypt: &[u8],
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if now <= Timestamp::UNIX_EPOCH {
            return Err(AuthError::Invalid);
        }
        let parameters = [
            time(now)?,
            id(user),
            bytes(secret_crypt),
            time(Timestamp::UNIX_EPOCH)?,
        ];
        let n = self
            .provider
            .execute_async(
                "UPDATE auth_mfa SET enabled_at=? WHERE user_id=? AND totp_secret_crypt=? AND enabled_at=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if n != 1 {
            return Err(AuthError::Conflict);
        }
        Ok(())
    }

    async fn insert_recovery_code(
        &self,
        id_value: Id,
        user: Id,
        digest: &[u8],
    ) -> Result<(), AuthError> {
        let parameters = [id(id_value), id(user), bytes(digest)];
        self.provider
            .execute_async(
                "INSERT INTO auth_recovery_code(id,user_id,code_digest) VALUES(?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn consume_recovery_code(
        &self,
        user: Id,
        digest: &[u8],
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let parameters = [time(now)?, id(user), bytes(digest)];
        let n = self
            .provider
            .execute_async(
                "UPDATE auth_recovery_code SET consumed_at=? WHERE user_id=? AND code_digest=? AND consumed_at IS NULL",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if n != 1 {
            return Err(AuthError::Unauthorized);
        }
        Ok(())
    }

    async fn create_tenant(&self, tenant: Id, name: &str, now: Timestamp) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [id(tenant), text(name), now_time.clone(), now_time];
        tx.execute_async(
            "INSERT INTO auth_tenant(id,name,status,created_at,updated_at) VALUES(?,?,'active',?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        for role in SEEDED_ROLES {
            let parameters = [id(Id::now_v7()), id(tenant), text(role)];
            tx.execute_async(
                "INSERT INTO auth_role(id,tenant_id,name) VALUES(?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        }
        tx.commit_async().await.map_err(error)
    }

    async fn create_user(
        &self,
        user: &User,
        hash: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        if !hash.starts_with("$argon2id$") {
            return Err(AuthError::Conflict);
        }
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(user.id),
            id(user.tenant_id),
            text(&user.email),
            now_time.clone(),
            now_time.clone(),
        ];
        tx.execute_async(
            "INSERT INTO auth_user(id,tenant_id,email,status,created_at,updated_at) VALUES(?,?,?,'active',?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [id(user.id), text(hash), text(&profile(hash)), now_time];
        tx.execute_async(
            "INSERT INTO auth_password(user_id,password_hash,algorithm,parameters,password_changed_at) VALUES(?,?,'argon2id',?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn find_user(&self, tenant: Id, email: &str) -> Result<User, AuthError> {
        let parameters = [id(tenant), text(email)];
        let row = self
            .provider
            .fetch_one_async(
                "SELECT u.id,u.tenant_id,u.email FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.tenant_id=? AND u.email=? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(User {
            id: read_id(&row, "id")?,
            tenant_id: read_id(&row, "tenant_id")?,
            email: row.read("email").map_err(error)?,
        })
    }

    async fn password(&self, user: Id) -> Result<PasswordCredential, AuthError> {
        let row = self
            .provider
            .fetch_one_async(
                "SELECT password_hash,failed_attempts,locked_until FROM auth_password WHERE user_id=?",
                QueryOptions::new().bind(id(user)),
            )
            .await
            .map_err(error)?;
        Ok(PasswordCredential {
            password_hash: row.read("password_hash").map_err(error)?,
            failed_attempts: row.read("failed_attempts").map_err(error)?,
            locked_until: read_optional_time(&row, "locked_until")?,
        })
    }

    async fn record_failure(
        &self,
        user: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
        until: Timestamp,
        limit: i32,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            now_time.clone(),
            now_time.clone(),
            integer(i64::from(limit)),
            time(until)?,
            id(user),
            now_time,
        ];
        tx.execute_async(
            "UPDATE auth_password SET failed_attempts=CASE WHEN locked_until IS NOT NULL AND locked_until<=? THEN 1 ELSE failed_attempts+1 END, locked_until=CASE WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until<=? THEN 1 ELSE failed_attempts+1 END)>=? THEN ? ELSE NULL END, row_version=row_version+1 WHERE user_id=? AND (locked_until IS NULL OR locked_until<=?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn complete_login(
        &self,
        value: &Session,
        expected_hash: &str,
        replacement: Option<&str>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        if !replacement
            .unwrap_or(expected_hash)
            .starts_with("$argon2id$")
        {
            return Err(AuthError::Conflict);
        }
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            optional_text(replacement),
            optional_text(replacement.map(profile).as_deref()),
            id(value.user_id),
            text(expected_hash),
            now_time.clone(),
            id(value.user_id),
            id(value.tenant_id),
        ];
        let count = tx
            .execute_async(
                "UPDATE auth_password SET password_hash=COALESCE(?,password_hash),parameters=COALESCE(?,parameters),algorithm='argon2id',failed_attempts=0,locked_until=NULL,row_version=row_version+1 WHERE user_id=? AND password_hash=? AND (locked_until IS NULL OR locked_until<=?) AND EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=? AND u.tenant_id=? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [
            id(value.id),
            id(value.user_id),
            id(value.tenant_id),
            bytes(&value.token_digest),
            time(value.expires_at)?,
            now_time.clone(),
            now_time.clone(),
        ];
        tx.execute_async(
            "INSERT INTO auth_session(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), now_time, id(value.user_id)];
        tx.execute_async(
            "UPDATE auth_user SET last_login_at=?,updated_at=?,row_version=row_version+1 WHERE id=?",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn find_session(&self, digest: &[u8], now: Timestamp) -> Result<Session, AuthError> {
        let parameters = [bytes(digest), time(now)?];
        let row = self
            .provider
            .fetch_one_async(
                "SELECT s.* FROM auth_session s JOIN auth_user u ON u.id=s.user_id JOIN auth_tenant t ON t.id=s.tenant_id WHERE s.token_digest=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        session(&row)
    }

    async fn extend_session(
        &self,
        digest: &[u8],
        expires_at: Timestamp,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            time(expires_at)?,
            now_time.clone(),
            bytes(digest),
            now_time.clone(),
        ];
        let count = tx
            .execute_async(
                "UPDATE auth_session SET expires_at=?,last_seen_at=? WHERE token_digest=? AND revoked_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=auth_session.user_id AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn revoke_session(
        &self,
        digest: &[u8],
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time, bytes(digest)];
        tx.execute_async(
            "UPDATE auth_session SET revoked_at=? WHERE token_digest=? AND revoked_at IS NULL",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn list_sessions(&self, user: Id, now: Timestamp) -> Result<Vec<Session>, AuthError> {
        let parameters = [id(user), time(now)?];
        let rows = self
            .provider
            .fetch_all_async(
                "SELECT id,user_id,tenant_id,token_digest,expires_at FROM auth_session WHERE user_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC,id DESC",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        rows.iter().map(session).collect()
    }

    async fn revoke_session_by_id(
        &self,
        user: Id,
        session_id: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), id(session_id), id(user), now_time];
        let count = tx
            .execute_async(
                "UPDATE auth_session SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn revoke_sessions(
        &self,
        user: Id,
        keep: Option<Id>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        if let Some(keep) = keep {
            let parameters = [now_time.clone(), id(user), now_time.clone(), id(keep)];
            tx.execute_async(
                "UPDATE auth_session SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND expires_at>? AND id<>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        } else {
            let parameters = [now_time.clone(), id(user), now_time];
            tx.execute_async(
                "UPDATE auth_session SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn change_password(
        &self,
        user: Id,
        keep: Id,
        expected_hash: &str,
        hash: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if !hash.starts_with("$argon2id$") {
            return Err(AuthError::Conflict);
        }
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            text(hash),
            text(&profile(hash)),
            now_time.clone(),
            id(user),
            text(expected_hash),
            id(user),
        ];
        let count = tx
            .execute_async(
                "UPDATE auth_password SET password_hash=?,algorithm='argon2id',parameters=?,failed_attempts=0,locked_until=NULL,password_changed_at=?,row_version=row_version+1 WHERE user_id=? AND password_hash=? AND EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [now_time.clone(), id(user), now_time.clone(), id(keep)];
        tx.execute_async(
            "UPDATE auth_session SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND expires_at>? AND id<>?",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), id(user)];
        tx.execute_async(
            "UPDATE auth_one_time SET consumed_at=? WHERE user_id=? AND purpose='email_otp' AND consumed_at IS NULL",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn change_email(
        &self,
        user: Id,
        tenant: Id,
        email: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [text(email), now_time, id(user), id(tenant)];
        let count = tx
            .execute_async(
                "UPDATE auth_user SET email=?,email_verified_at=NULL,updated_at=?,row_version=row_version+1 WHERE id=? AND tenant_id=? AND deleted_at IS NULL",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn delete_user(
        &self,
        user: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), now_time.clone(), id(user)];
        let count = tx
            .execute_async(
                "UPDATE auth_user SET deleted_at=?,updated_at=?,row_version=row_version+1 WHERE id=? AND deleted_at IS NULL",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        let parameters = [now_time.clone(), id(user)];
        tx.execute_async(
            "UPDATE auth_session SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn create_one_time(
        &self,
        proof: &OneTime,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(proof.id),
            id(proof.user_id),
            text(proof.purpose.as_str()),
            bytes(&proof.token_digest),
            time(proof.expires_at)?,
            now_time,
        ];
        tx.execute_async(
            "INSERT INTO auth_one_time(id,user_id,purpose,token_digest,expires_at,created_at) VALUES(?,?,?,?,?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn consume_one_time(
        &self,
        purpose: Purpose,
        digest: &[u8],
        hash: Option<&str>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Id, AuthError> {
        let now_time = time(now)?;
        if (purpose == Purpose::ResetPassword) != hash.is_some()
            || hash.is_some_and(|value| !value.starts_with("$argon2id$"))
        {
            return Err(AuthError::Conflict);
        }
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            now_time.clone(),
            text(purpose.as_str()),
            bytes(digest),
            now_time.clone(),
        ];
        let row = tx
            .fetch_first_async(
                "UPDATE auth_one_time SET consumed_at=?,attempt_count=attempt_count+1 WHERE purpose=? AND token_digest=? AND consumed_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=auth_one_time.user_id AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active') RETURNING user_id",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        let user = read_id(&row, "user_id")?;
        match purpose {
            Purpose::ResetPassword => {
                let Some(hash) = hash else {
                    return Err(AuthError::Conflict);
                };
                let parameters = [text(hash), text(&profile(hash)), now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE auth_password SET password_hash=?,algorithm='argon2id',parameters=?,failed_attempts=0,locked_until=NULL,password_changed_at=?,row_version=row_version+1 WHERE user_id=?",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE auth_session SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE auth_one_time SET consumed_at=? WHERE user_id=? AND purpose='reset_password' AND consumed_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE auth_one_time SET consumed_at=? WHERE user_id=? AND purpose='email_otp' AND consumed_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
            }
            Purpose::VerifyEmail => {
                let parameters = [now_time.clone(), now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE auth_user SET email_verified_at=?,status='active',updated_at=?,row_version=row_version+1 WHERE id=?",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
            }
            Purpose::EmailOtp => {}
        }
        if let Some(mut event) = audit {
            event.actor_id = Some(event.actor_id.unwrap_or(user));
            audit_row(&mut *tx, Some(&event), now).await?;
        }
        tx.commit_async().await.map_err(error)?;
        Ok(user)
    }

    async fn complete_email_sign_in(
        &self,
        digest: &[u8],
        session_id: Id,
        session_digest: &[u8],
        expires_at: Timestamp,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Session, AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), bytes(digest), now_time.clone()];
        let row = tx
            .fetch_first_async(
                "UPDATE auth_one_time SET consumed_at=?,attempt_count=attempt_count+1 WHERE purpose='email_otp' AND token_digest=? AND consumed_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=auth_one_time.user_id AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active') RETURNING user_id",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        let user = read_id(&row, "user_id")?;
        let tenant_row = tx
            .fetch_one_async(
                "SELECT tenant_id FROM auth_user WHERE id=?",
                QueryOptions::new().bind(id(user)),
            )
            .await
            .map_err(error)?;
        let tenant = read_id(&tenant_row, "tenant_id")?;
        let parameters = [
            id(session_id),
            id(user),
            id(tenant),
            bytes(session_digest),
            time(expires_at)?,
            now_time.clone(),
            now_time.clone(),
        ];
        tx.execute_async(
            "INSERT INTO auth_session(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), now_time, id(user)];
        tx.execute_async(
            "UPDATE auth_user SET last_login_at=?,updated_at=?,row_version=row_version+1 WHERE id=?",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        if let Some(mut event) = audit {
            event.tenant_id = Some(event.tenant_id.unwrap_or(tenant));
            event.actor_id = Some(event.actor_id.unwrap_or(user));
            audit_row(&mut *tx, Some(&event), now).await?;
        }
        tx.commit_async().await.map_err(error)?;
        Ok(Session {
            id: session_id,
            user_id: user,
            tenant_id: tenant,
            token_digest: session_digest.to_vec(),
            expires_at,
        })
    }

    #[cfg(feature = "social")]
    async fn create_social_state(
        &self,
        digest: &[u8],
        tenant: Id,
        provider: &str,
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let parameters = [
            id(Id::now_v7()),
            id(tenant),
            text(provider),
            bytes(digest),
            time(expires_at)?,
            time(now)?,
            id(tenant),
        ];
        let count = self
            .provider
            .execute_async(
                "INSERT INTO auth_social_state(id,tenant_id,provider,token_digest,expires_at,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_tenant WHERE id=? AND status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    #[cfg(feature = "social")]
    async fn check_social_state(
        &self,
        digest: &[u8],
        tenant: Id,
        provider: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let parameters = [bytes(digest), id(tenant), text(provider), time(now)?];
        let found = self
            .provider
            .fetch_first_async(
                "SELECT 1 AS found FROM auth_social_state WHERE token_digest=? AND tenant_id=? AND provider=? AND consumed_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        found.map(|_| ()).ok_or(AuthError::Unauthorized)
    }

    #[cfg(feature = "social")]
    // One transaction owns the state spend, the account/identity creation, and the
    // session insert; they cannot be split without breaking that atomicity.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            now_time.clone(),
            bytes(state_digest),
            id(tenant),
            text(provider),
            now_time.clone(),
        ];
        let spent = tx
            .execute_async(
                "UPDATE auth_social_state SET consumed_at=? WHERE token_digest=? AND tenant_id=? AND provider=? AND consumed_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if spent != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [text(provider), text(subject), id(tenant)];
        let existing = tx
            .fetch_first_async(
                "SELECT i.user_id FROM auth_social_identity i JOIN auth_user u ON u.id=i.user_id JOIN auth_tenant t ON t.id=u.tenant_id WHERE i.provider=? AND i.subject=? AND u.tenant_id=? AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        let user = if let Some(row) = existing {
            read_id(&row, "user_id")?
        } else {
            let parameters = [id(tenant), text(email)];
            let taken = tx
                .fetch_first_async(
                    "SELECT id FROM auth_user WHERE tenant_id=? AND email=? AND deleted_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
            if taken.is_some() {
                return Err(AuthError::Conflict);
            }
            let user = Id::now_v7();
            let verified_at = if email_verified {
                now_time.clone()
            } else {
                Parameter::new(DbType::Text, Value::Null(DbType::Text)).expect("typed null")
            };
            let parameters = [
                id(user),
                id(tenant),
                text(email),
                verified_at,
                now_time.clone(),
                now_time.clone(),
            ];
            tx.execute_async(
                "INSERT INTO auth_user(id,tenant_id,email,status,email_verified_at,created_at,updated_at) VALUES(?,?,?,'active',?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
            let parameters = [text(provider), text(subject), id(user), now_time.clone()];
            tx.execute_async(
                "INSERT INTO auth_social_identity(provider,subject,user_id,created_at) VALUES(?,?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
            user
        };
        let parameters = [
            id(session_id),
            id(user),
            id(tenant),
            bytes(session_digest),
            time(expires_at)?,
            now_time.clone(),
            now_time.clone(),
        ];
        tx.execute_async(
            "INSERT INTO auth_session(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), now_time, id(user)];
        tx.execute_async(
            "UPDATE auth_user SET last_login_at=?,updated_at=?,row_version=row_version+1 WHERE id=?",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        if let Some(mut event) = audit {
            event.tenant_id = Some(event.tenant_id.unwrap_or(tenant));
            event.actor_id = Some(event.actor_id.unwrap_or(user));
            audit_row(&mut *tx, Some(&event), now).await?;
        }
        tx.commit_async().await.map_err(error)?;
        Ok(Session {
            id: session_id,
            user_id: user,
            tenant_id: tenant,
            token_digest: session_digest.to_vec(),
            expires_at,
        })
    }

    async fn create_api_key(&self, key: &ApiKey, now: Timestamp) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let scopes = serde_json::to_string(&key.scopes).map_err(|_| AuthError::Store)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(key.id),
            id(key.tenant_id),
            id(key.user_id),
            text(&key.prefix),
            bytes(&key.secret_digest),
            text(&scopes),
            time(key.expires_at)?,
            now_time,
            id(key.user_id),
            id(key.tenant_id),
        ];
        let count = tx
            .execute_async(
                "INSERT INTO auth_api_key(id,tenant_id,user_id,name,prefix,secret_digest,scopes,expires_at,created_at) SELECT ?,?,?, '',?,?,?, ?,? WHERE EXISTS(SELECT 1 FROM auth_user WHERE id=? AND tenant_id=?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Conflict);
        }
        tx.commit_async().await.map_err(error)
    }

    async fn find_api_key(
        &self,
        digest: &[u8],
        prefix: &str,
        now: Timestamp,
    ) -> Result<ApiKey, AuthError> {
        let parameters = [bytes(digest), text(prefix), time(now)?];
        let row = self
            .provider
            .fetch_one_async(
                "SELECT k.id,k.tenant_id,k.user_id,k.prefix,k.secret_digest,k.scopes,k.expires_at,k.last_used_at FROM auth_api_key k JOIN auth_user u ON u.id=k.user_id JOIN auth_tenant t ON t.id=k.tenant_id WHERE k.secret_digest=? AND k.prefix=? AND k.revoked_at IS NULL AND k.expires_at>? AND u.deleted_at IS NULL AND u.status='active' AND t.status='active'",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        let scopes: String = row.read("scopes").map_err(error)?;
        let scopes = serde_json::from_str(&scopes).map_err(|_| AuthError::Store)?;
        Ok(ApiKey {
            id: read_id(&row, "id")?,
            tenant_id: read_id(&row, "tenant_id")?,
            user_id: read_id(&row, "user_id")?,
            prefix: row.read("prefix").map_err(error)?,
            secret_digest: row.read("secret_digest").map_err(error)?,
            scopes,
            expires_at: read_time(&row, "expires_at")?,
            last_used_at: read_optional_time(&row, "last_used_at")?,
        })
    }

    async fn revoke_api_key(
        &self,
        user: Id,
        key: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), id(key), id(user), now_time];
        let count = tx
            .execute_async(
                "UPDATE auth_api_key SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL AND expires_at>?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn record_api_key_use(&self, key: Id, now: Timestamp) -> Result<(), AuthError> {
        let parameters = [time(now)?, id(key)];
        let count = self
            .provider
            .execute_async(
                "UPDATE auth_api_key SET last_used_at=? WHERE id=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn insert_audit(&self, event: &AuditEvent, now: Timestamp) -> Result<(), AuthError> {
        event.validate()?;
        let field = |name: &str| {
            event
                .fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        let parameters = [
            id(event.id),
            optional_id(event.tenant_id),
            optional_id(event.actor_id),
            text(&event.action),
            text(&event.outcome),
            optional_text(field("ip")),
            optional_text(field("user_agent")),
            time(now)?,
        ];
        let affected = self
            .provider
            .execute_async(
                "INSERT INTO auth_audit(id,tenant_id,actor_id,action,outcome,ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(|_| AuthError::Store)?;
        if affected != 1 {
            return Err(AuthError::Conflict);
        }
        Ok(())
    }

    async fn suspend_tenant(&self, tenant: Id, now: Timestamp) -> Result<(), AuthError> {
        let parameters = [time(now)?, id(tenant)];
        let count = self
            .provider
            .execute_async(
                "UPDATE auth_tenant SET status='suspended',updated_at=?,row_version=row_version+1 WHERE id=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn create_membership(
        &self,
        membership: &Membership,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(membership.id),
            id(membership.tenant_id),
            id(membership.user_id),
            text(membership.status.as_str()),
            id(membership.user_id),
            id(membership.tenant_id),
            id(membership.tenant_id),
            id(membership.user_id),
        ];
        let count = tx
            .execute_async(
                "INSERT INTO auth_membership(id,tenant_id,user_id,status) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_user u JOIN auth_tenant t ON t.id=u.tenant_id WHERE u.id=? AND u.tenant_id=? AND u.deleted_at IS NULL AND t.status='active') AND NOT EXISTS(SELECT 1 FROM auth_membership m WHERE m.tenant_id=? AND m.user_id=?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Conflict);
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn find_membership(&self, tenant: Id, user: Id) -> Result<Membership, AuthError> {
        let parameters = [id(tenant), id(user)];
        let row = self
            .provider
            .fetch_one_async(
                "SELECT id,tenant_id,user_id,status FROM auth_membership WHERE tenant_id=? AND user_id=? LIMIT 1",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        read_membership(&row)
    }

    async fn set_membership_status(
        &self,
        membership: Id,
        status: MembershipStatus,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [text(status.as_str()), id(membership)];
        let row = tx
            .fetch_first_async(
                "UPDATE auth_membership SET status=? WHERE id=? RETURNING id,tenant_id,user_id,status",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::NotFound)?;
        let updated = read_membership(&row)?;
        if let Some(mut event) = audit {
            event.tenant_id = Some(event.tenant_id.unwrap_or(updated.tenant_id));
            audit_row(&mut *tx, Some(&event), now).await?;
        }
        tx.commit_async().await.map_err(error)?;
        Ok(updated)
    }

    async fn create_permission(
        &self,
        id_value: Id,
        tenant: Id,
        name: &str,
    ) -> Result<(), AuthError> {
        let parameters = [id(id_value), id(tenant), text(name)];
        self.provider
            .execute_async(
                "INSERT INTO auth_permission(id,tenant_id,name) VALUES(?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn create_role(&self, id_value: Id, tenant: Id, name: &str) -> Result<(), AuthError> {
        let parameters = [id(id_value), id(tenant), text(name)];
        self.provider
            .execute_async(
                "INSERT INTO auth_role(id,tenant_id,name) VALUES(?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn create_group(
        &self,
        group: Id,
        tenant: Id,
        name: &str,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        let parameters = [id(group), id(tenant), text(name), time(now)?];
        self.provider
            .execute_async(
                "INSERT INTO auth_group(id,tenant_id,name,created_at) VALUES(?,?,?,?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn add_group_member(
        &self,
        tenant: Id,
        group: Id,
        membership: Id,
    ) -> Result<(), AuthError> {
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [id(group), id(tenant)];
        let group_tenant = tx
            .fetch_first_async(
                "SELECT tenant_id FROM auth_group WHERE id=? AND tenant_id=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::NotFound)?;
        let group_tenant = read_id(&group_tenant, "tenant_id")?;
        let member_tenant = tx
            .fetch_first_async(
                "SELECT tenant_id FROM auth_membership WHERE id=?",
                QueryOptions::new().bind(id(membership)),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::NotFound)?;
        let member_tenant = read_id(&member_tenant, "tenant_id")?;
        if group_tenant != member_tenant {
            return Err(AuthError::Conflict);
        }
        let parameters = [id(group), id(membership)];
        tx.execute_async(
            "INSERT OR IGNORE INTO auth_group_member(group_id,membership_id) VALUES(?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        tx.commit_async().await.map_err(error)
    }

    async fn remove_group_member(
        &self,
        tenant: Id,
        group: Id,
        membership: Id,
    ) -> Result<(), AuthError> {
        let parameters = [id(group), id(membership), id(group), id(tenant)];
        let count = self
            .provider
            .execute_async(
                "DELETE FROM auth_group_member WHERE group_id=? AND membership_id=? AND EXISTS(SELECT 1 FROM auth_group WHERE id=? AND tenant_id=?)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn assign_role(
        &self,
        membership: Id,
        role: Id,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [id(membership), id(role)];
        let same_tenant = tx
            .fetch_first_async(
                "SELECT 1 AS found FROM auth_membership m JOIN auth_role r ON r.tenant_id=m.tenant_id WHERE m.id=? AND r.id=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if same_tenant.is_none() {
            return Err(AuthError::Conflict);
        }
        let parameters = [id(membership), id(role)];
        tx.execute_async(
            "INSERT OR IGNORE INTO auth_membership_role(membership_id,role_id) VALUES(?,?)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let row = tx
            .fetch_one_async(
                "SELECT id,tenant_id,user_id,status FROM auth_membership WHERE id=?",
                QueryOptions::new().bind(id(membership)),
            )
            .await
            .map_err(error)?;
        let updated = read_membership(&row)?;
        if let Some(mut event) = audit {
            event.tenant_id = Some(event.tenant_id.unwrap_or(updated.tenant_id));
            audit_row(&mut *tx, Some(&event), now).await?;
        }
        tx.commit_async().await.map_err(error)?;
        Ok(updated)
    }

    async fn create_invitation(
        &self,
        invitation: &Invitation,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if invitation.expires_at <= now {
            return Err(AuthError::Invalid);
        }
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(invitation.id),
            id(invitation.tenant_id),
            text(&invitation.email),
            bytes(&invitation.token_digest),
            time(invitation.expires_at)?,
            id(invitation.tenant_id),
        ];
        let count = tx
            .execute_async(
                "INSERT INTO auth_invitation(id,tenant_id,email,token_digest,expires_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_tenant WHERE id=? AND status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Conflict);
        }
        for role in &invitation.role_ids {
            let parameters = [
                id(invitation.id),
                id(*role),
                id(*role),
                id(invitation.tenant_id),
            ];
            let count = tx
                .execute_async(
                    "INSERT INTO auth_invitation_role(invitation_id,role_id) SELECT ?,? WHERE EXISTS(SELECT 1 FROM auth_role WHERE id=? AND tenant_id=?)",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
            if count != 1 {
                return Err(AuthError::Conflict);
            }
        }
        audit_row(&mut *tx, audit.as_ref(), now).await?;
        tx.commit_async().await.map_err(error)
    }

    async fn accept_invitation(
        &self,
        membership_id: Id,
        digest: &[u8],
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Membership, AuthError> {
        let now_time = time(now)?;
        let mut connection = self.provider.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), bytes(digest), now_time.clone()];
        let row = tx
            .fetch_first_async(
                "UPDATE auth_invitation SET accepted_at=? WHERE token_digest=? AND accepted_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_tenant t WHERE t.id=auth_invitation.tenant_id AND t.status='active') RETURNING id,tenant_id,email",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        let invitation = read_id(&row, "id")?;
        let tenant = read_id(&row, "tenant_id")?;
        let email: String = row.read("email").map_err(error)?;
        let parameters = [id(tenant), text(&email)];
        let user = tx
            .fetch_first_async(
                "SELECT id FROM auth_user WHERE tenant_id=? AND email=? AND deleted_at IS NULL",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::NotFound)?;
        let user = read_id(&user, "id")?;
        let parameters = [id(tenant), id(user)];
        let existing = tx
            .fetch_first_async(
                "SELECT id FROM auth_membership WHERE tenant_id=? AND user_id=?",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        let membership = if let Some(row) = existing {
            let existing_id = read_id(&row, "id")?;
            tx.execute_async(
                "UPDATE auth_membership SET status='active' WHERE id=?",
                QueryOptions::new().bind(id(existing_id)),
            )
            .await
            .map_err(error)?;
            existing_id
        } else {
            let parameters = [id(membership_id), id(tenant), id(user)];
            tx.execute_async(
                "INSERT INTO auth_membership(id,tenant_id,user_id,status) VALUES(?,?,?,'active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
            membership_id
        };
        let parameters = [id(membership), id(invitation)];
        tx.execute_async(
            "INSERT OR IGNORE INTO auth_membership_role(membership_id,role_id) SELECT ?,role_id FROM auth_invitation_role WHERE invitation_id=?",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        if let Some(mut event) = audit {
            event.tenant_id = Some(event.tenant_id.unwrap_or(tenant));
            event.actor_id = Some(event.actor_id.unwrap_or(user));
            audit_row(&mut *tx, Some(&event), now).await?;
        }
        tx.commit_async().await.map_err(error)?;
        Ok(Membership {
            id: membership,
            tenant_id: tenant,
            user_id: user,
            status: MembershipStatus::Active,
        })
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::{AuthError, DbError, ErrorKind, error};

    #[test]
    fn unknown_write_and_commit_are_store_not_proof_of_rollback() {
        for kind in [
            ErrorKind::WriteOutcomeUnknown,
            ErrorKind::CommitOutcomeUnknown,
        ] {
            assert_eq!(error(DbError::new(kind)), AuthError::Store);
        }
    }
}

// These identifiers predate the package rename and are stored or authenticated.
#[cfg(test)]
mod persisted_identity_tests {
    #[test]
    fn identifiers_remain_compatible() {
        assert_eq!(super::MIGRATION_MODULE, "auth");
        assert_eq!(super::MIGRATION_FINGERPRINT, "neotales-auth/sqlite/v1");
    }
}
