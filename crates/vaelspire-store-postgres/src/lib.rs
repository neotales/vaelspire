//! PostgreSQL adapter over `neotales-dbapi`. Each multi-row security transition is a database
//! transaction.
//!
//! The schema is net-new: [`open`] applies the single versioned migration through
//! `neotales-migration-postgres` and returns a store. An existing database that predates the
//! migration ledger is refused rather than adopted. Identifiers are `bytea`, timestamps are
//! microseconds since the Unix epoch, and arrays are stored as JSON text, because the dbapi
//! contract transports only bool, integer, float, text, and bytes.

use neotales_dbapi::{
    DbError, DbType, ErrorKind, Parameter, Pool, QueryOptions, Row, Transaction, TxOptions, Value,
};
use neotales_dbapi_postgres::PostgresPool;
use neotales_migration::{Migration, Migrations};
use neotales_migration_postgres::PostgresBackend;
use vaelspire_core::{
    ApiKey, AuditEvent, AuthError, AuthStore, Id, Invitation, Membership, MembershipStatus,
    OneTime, PasswordCredential, Purpose, SEEDED_ROLES, Session, Timestamp, User,
};

/// The schema, applied as one net-new definition. There is no legacy adoption path.
pub const SCHEMA: &str = include_str!("../migrations/0001_auth.sql");

/// Schema that owns every application relation.
const SCHEMA_NAME: &str = "public";
/// Migration module name in the shared ledger.
const MIGRATION_MODULE: &str = "auth";
/// Binding fingerprint recorded with the applied migration.
const MIGRATION_FINGERPRINT: &str = "neotales-auth/postgres/v1";
/// Ledger table owned by this module, in [`SCHEMA_NAME`].
const MIGRATION_LEDGER: &str = "auth_schema_history";
/// Advisory-lock acquisition bound for the migration backend.
const MIGRATION_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Every application relation the migration owns, so a pre-existing schema cannot be
/// mistaken for a fresh one.
const MANAGED_OBJECTS: [(&str, &str); 20] = [
    (SCHEMA_NAME, "auth_tenant"),
    (SCHEMA_NAME, "auth_user"),
    (SCHEMA_NAME, "auth_password"),
    (SCHEMA_NAME, "auth_session"),
    (SCHEMA_NAME, "auth_one_time"),
    (SCHEMA_NAME, "auth_api_key"),
    (SCHEMA_NAME, "auth_service_account"),
    (SCHEMA_NAME, "auth_passkey"),
    (SCHEMA_NAME, "auth_webauthn_challenge"),
    (SCHEMA_NAME, "auth_mfa"),
    (SCHEMA_NAME, "auth_recovery_code"),
    (SCHEMA_NAME, "auth_permission"),
    (SCHEMA_NAME, "auth_role"),
    (SCHEMA_NAME, "auth_role_permission"),
    (SCHEMA_NAME, "auth_membership"),
    (SCHEMA_NAME, "auth_membership_role"),
    (SCHEMA_NAME, "auth_invitation"),
    (SCHEMA_NAME, "auth_invitation_role"),
    (SCHEMA_NAME, "auth_audit"),
    (SCHEMA_NAME, "auth_group"),
];

/// Opening or migrating the database failed. No driver text or submitted value is retained.
#[derive(Debug)]
pub enum OpenError {
    /// The migration ledger or schema definition was rejected.
    Migration(neotales_migration_postgres::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Migration(error) => write!(formatter, "migration error: {error}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// The complete net-new schema as migration definitions.
fn migrations() -> Result<Migrations, OpenError> {
    let migration = Migration::new(1, "auth_schema", SCHEMA, None).map_err(|_| {
        OpenError::Migration(neotales_migration_postgres::Error::InvalidDefinitions)
    })?;
    Migrations::new(vec![migration])
        .map_err(|_| OpenError::Migration(neotales_migration_postgres::Error::InvalidDefinitions))
}

/// Apply the schema to an already-connected pool.
///
/// A fresh database receives the single definition. A database whose ledger already records
/// it is left untouched. A database that has the tables but no matching ledger is refused,
/// because those objects are unowned. The backend requires PostgreSQL 17.
///
/// # Errors
/// Returns [`OpenError::Migration`] for an unowned or corrupt history, an unsupported server
/// version, or a failed script.
pub async fn migrate(pool: &dyn Pool) -> Result<(), OpenError> {
    let backend = PostgresBackend::new(SCHEMA_NAME, MIGRATION_LEDGER, MIGRATION_LOCK_TIMEOUT)
        .map_err(OpenError::Migration)?;
    let migrations = migrations()?;
    backend
        .up(
            pool,
            MIGRATION_MODULE,
            &migrations,
            MIGRATION_FINGERPRINT,
            &MANAGED_OBJECTS,
        )
        .await
        .map_err(OpenError::Migration)?;
    Ok(())
}

/// Apply the schema, then wrap `pool` in a store.
///
/// # Errors
/// Returns [`OpenError::Migration`] when the schema cannot be applied or is unowned.
pub async fn open(pool: PostgresPool) -> Result<PostgresStore, OpenError> {
    migrate(&pool).await?;
    Ok(PostgresStore { pool })
}

/// Cloneable store handle; clones share the initialized pool.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PostgresPool,
}

impl PostgresStore {
    /// Wrap a pool whose schema has already been applied by [`migrate`].
    #[must_use]
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// The pool this store queries through.
    #[must_use]
    pub fn pool(&self) -> &PostgresPool {
        &self.pool
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

// Timestamps are microseconds since the Unix epoch, which keeps ordering and range checks
// in a single portable integer column.
fn time(value: Timestamp) -> Result<Parameter, AuthError> {
    let micros = (value - Timestamp::UNIX_EPOCH).whole_microseconds();
    i64::try_from(micros)
        .map(integer)
        .map_err(|_| AuthError::Store)
}

fn read_id(row: &Row, column: &str) -> Result<Id, AuthError> {
    let raw: Vec<u8> = row.read(column).map_err(error)?;
    Id::from_slice(&raw).map_err(|_| AuthError::Store)
}

fn read_time(row: &Row, column: &str) -> Result<Timestamp, AuthError> {
    let micros: i64 = row.read(column).map_err(error)?;
    Timestamp::UNIX_EPOCH
        .checked_add(time::Duration::microseconds(micros))
        .ok_or(AuthError::Store)
}

fn read_optional_time(row: &Row, column: &str) -> Result<Option<Timestamp>, AuthError> {
    let micros: Option<i64> = row.read(column).map_err(error)?;
    micros.map_or(Ok(None), |value| {
        Timestamp::UNIX_EPOCH
            .checked_add(time::Duration::microseconds(value))
            .map(Some)
            .ok_or(AuthError::Store)
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
            "INSERT INTO \"public\".\"auth_audit\"(id,tenant_id,actor_id,action,outcome,ip,user_agent,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING",
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
impl AuthStore for PostgresStore {
    async fn mfa_pending_user(&self, digest: &[u8], now: Timestamp) -> Result<Id, AuthError> {
        let parameters = [bytes(digest), time(now)?];
        let row = self
            .pool
            .fetch_first_async(
                "SELECT user_id FROM \"public\".\"auth_webauthn_challenge\" WHERE kind='mfa_login' AND challenge=$1 AND consumed_at IS NULL AND expires_at>$2",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        read_id(&row, "user_id")
    }

    async fn user_tenant(&self, user: Id) -> Result<Id, AuthError> {
        let row = self
            .pool
            .fetch_one_async(
                "SELECT tenant_id FROM \"public\".\"auth_user\" WHERE id=$1 AND deleted_at IS NULL",
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
        self.pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_webauthn_challenge\"(id,user_id,kind,challenge,expires_at,expected_password_hash) VALUES($1,$2,'mfa_login',$3,$4,$5)",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        // Lock and recheck the credential observed before password verification.
        let parameters = [
            id(value.user_id),
            bytes(digest),
            now_time.clone(),
            id(value.tenant_id),
        ];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_password\" SET row_version=row_version+1 WHERE user_id=$1 AND password_hash=(SELECT expected_password_hash FROM \"public\".\"auth_webauthn_challenge\" WHERE kind='mfa_login' AND challenge=$2 AND user_id=$1 AND consumed_at IS NULL AND expires_at>$3) AND (locked_until IS NULL OR locked_until<=$3) AND EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=$1 AND u.tenant_id=$4 AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
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
                    "UPDATE \"public\".\"auth_recovery_code\" SET consumed_at=$1 WHERE user_id=$2 AND code_digest=$3 AND consumed_at IS NULL",
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
                "UPDATE \"public\".\"auth_webauthn_challenge\" SET consumed_at=$1 WHERE kind='mfa_login' AND challenge=$2 AND user_id=$3 AND consumed_at IS NULL AND expires_at>$4",
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
            "INSERT INTO \"public\".\"auth_session\"(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
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
        self.pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_mfa\"(user_id,totp_secret_crypt,key_id,enabled_at) VALUES($1,$2,$3,$4)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn load_mfa(&self, user: Id) -> Result<vaelspire_core::MfaFactor, AuthError> {
        let row = self
            .pool
            .fetch_one_async(
                "SELECT totp_secret_crypt,key_id,enabled_at FROM \"public\".\"auth_mfa\" WHERE user_id=$1",
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
            .pool
            .execute_async(
                "UPDATE \"public\".\"auth_mfa\" SET enabled_at=$1 WHERE user_id=$2 AND totp_secret_crypt=$3 AND enabled_at=$4",
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
        self.pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_recovery_code\"(id,user_id,code_digest) VALUES($1,$2,$3)",
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
            .pool
            .execute_async(
                "UPDATE \"public\".\"auth_recovery_code\" SET consumed_at=$1 WHERE user_id=$2 AND code_digest=$3 AND consumed_at IS NULL",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [id(tenant), text(name), now_time.clone(), now_time];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_tenant\"(id,name,status,created_at,updated_at) VALUES($1,$2,'active',$3,$4)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        for role in SEEDED_ROLES {
            let parameters = [id(Id::now_v7()), id(tenant), text(role)];
            tx.execute_async(
                "INSERT INTO \"public\".\"auth_role\"(id,tenant_id,name) VALUES($1,$2,$3)",
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
        if !hash.starts_with("$argon2id$") {
            return Err(AuthError::Conflict);
        }
        let now_time = time(now)?;
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
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
            "INSERT INTO \"public\".\"auth_user\"(id,tenant_id,email,status,created_at,updated_at) VALUES($1,$2,$3,'active',$4,$5)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [id(user.id), text(hash), text(&profile(hash)), now_time];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_password\"(user_id,password_hash,algorithm,parameters,password_changed_at) VALUES($1,$2,'argon2id',$3,$4)",
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
            .pool
            .fetch_one_async(
                "SELECT u.id,u.tenant_id,u.email FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.email=$2 AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
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
            .pool
            .fetch_one_async(
                "SELECT password_hash,failed_attempts,locked_until FROM \"public\".\"auth_password\" WHERE user_id=$1",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(user),
            now_time.clone(),
            time(until)?,
            integer(i64::from(limit)),
        ];
        tx.execute_async(
            "UPDATE \"public\".\"auth_password\" SET failed_attempts=CASE WHEN locked_until IS NOT NULL AND locked_until<=$2 THEN 1 ELSE failed_attempts+1 END, locked_until=CASE WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until<=$2 THEN 1 ELSE failed_attempts+1 END)>=$4 THEN $3 ELSE NULL END, row_version=row_version+1 WHERE user_id=$1 AND (locked_until IS NULL OR locked_until<=$2)",
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
        if !replacement
            .unwrap_or(expected_hash)
            .starts_with("$argon2id$")
        {
            return Err(AuthError::Conflict);
        }
        let now_time = time(now)?;
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            optional_text(replacement),
            id(value.user_id),
            text(expected_hash),
            now_time.clone(),
            id(value.tenant_id),
            optional_text(replacement.map(profile).as_deref()),
        ];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_password\" SET password_hash=COALESCE($1,password_hash),parameters=COALESCE($6,parameters),algorithm='argon2id',failed_attempts=0,locked_until=NULL,row_version=row_version+1 WHERE user_id=$2 AND password_hash=$3 AND (locked_until IS NULL OR locked_until<=$4) AND EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=$2 AND u.tenant_id=$5 AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
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
        ];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_session\"(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$6)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), id(value.user_id)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_user\" SET last_login_at=$1,updated_at=$1,row_version=row_version+1 WHERE id=$2",
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
            .pool
            .fetch_one_async(
                "SELECT s.* FROM \"public\".\"auth_session\" s JOIN \"public\".\"auth_user\" u ON u.id=s.user_id JOIN \"public\".\"auth_tenant\" t ON t.id=s.tenant_id WHERE s.token_digest=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [time(expires_at)?, now_time.clone(), bytes(digest)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_session\" SET expires_at=$1,last_seen_at=$2 WHERE token_digest=$3 AND revoked_at IS NULL AND expires_at>$2 AND EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=\"public\".\"auth_session\".user_id AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time, bytes(digest)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE token_digest=$2 AND revoked_at IS NULL",
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
            .pool
            .fetch_all_async(
                "SELECT s.id,s.user_id,s.tenant_id,s.token_digest,s.expires_at FROM \"public\".\"auth_session\" s WHERE s.user_id=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 ORDER BY s.created_at DESC,s.id DESC",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), id(session_id), id(user)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>$1",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        if let Some(keep) = keep {
            let parameters = [now_time.clone(), id(user), id(keep)];
            tx.execute_async(
                "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL AND expires_at>$1 AND id<>$3",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        } else {
            let parameters = [now_time.clone(), id(user)];
            tx.execute_async(
                "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL AND expires_at>$1",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
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
        ];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_password\" SET password_hash=$1,algorithm='argon2id',parameters=$2,failed_attempts=0,locked_until=NULL,password_changed_at=$3,row_version=row_version+1 WHERE user_id=$4 AND password_hash=$5 AND EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=$4 AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [now_time.clone(), id(user), id(keep)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL AND expires_at>$1 AND id<>$3",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), id(user)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_one_time\" SET consumed_at=$1 WHERE user_id=$2 AND purpose='email_otp' AND consumed_at IS NULL",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [text(email), now_time, id(user), id(tenant)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_user\" SET email=$1,email_verified_at=NULL,updated_at=$2,row_version=row_version+1 WHERE id=$3 AND tenant_id=$4 AND deleted_at IS NULL",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), id(user)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_user\" SET deleted_at=$1,updated_at=$1,row_version=row_version+1 WHERE id=$2 AND deleted_at IS NULL",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::NotFound);
        }
        let parameters = [now_time.clone(), id(user)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
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
            "INSERT INTO \"public\".\"auth_one_time\"(id,user_id,purpose,token_digest,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)",
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
        if (purpose == Purpose::ResetPassword) != hash.is_some()
            || hash.is_some_and(|value| !value.starts_with("$argon2id$"))
        {
            return Err(AuthError::Conflict);
        }
        let now_time = time(now)?;
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        // Lock the account credential first: serializes reset/login and avoids a
        // proof/session lock inversion when different reset tokens race.
        let parameters = [text(purpose.as_str()), bytes(digest)];
        let user = tx
            .fetch_first_async(
                "SELECT p.user_id FROM \"public\".\"auth_password\" p JOIN \"public\".\"auth_one_time\" o ON o.user_id=p.user_id WHERE o.purpose=$1 AND o.token_digest=$2 FOR UPDATE OF p",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        let user = read_id(&user, "user_id")?;
        let parameters = [now_time.clone(), text(purpose.as_str()), bytes(digest)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_one_time\" SET consumed_at=$1,attempt_count=attempt_count+1 WHERE purpose=$2 AND token_digest=$3 AND consumed_at IS NULL AND expires_at>$1 AND EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=\"public\".\"auth_one_time\".user_id AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Unauthorized);
        }
        match purpose {
            Purpose::ResetPassword => {
                let Some(hash) = hash else {
                    return Err(AuthError::Conflict);
                };
                let parameters = [text(hash), now_time.clone(), id(user), text(&profile(hash))];
                tx.execute_async(
                    "UPDATE \"public\".\"auth_password\" SET password_hash=$1,algorithm='argon2id',parameters=$4,failed_attempts=0,locked_until=NULL,password_changed_at=$2,row_version=row_version+1 WHERE user_id=$3",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE \"public\".\"auth_session\" SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE \"public\".\"auth_one_time\" SET consumed_at=$1 WHERE user_id=$2 AND purpose='reset_password' AND consumed_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE \"public\".\"auth_one_time\" SET consumed_at=$1 WHERE user_id=$2 AND purpose='email_otp' AND consumed_at IS NULL",
                    QueryOptions::new().bind_all(&parameters),
                )
                .await
                .map_err(error)?;
            }
            Purpose::VerifyEmail => {
                let parameters = [now_time.clone(), id(user)];
                tx.execute_async(
                    "UPDATE \"public\".\"auth_user\" SET email_verified_at=$1,status='active',updated_at=$1,row_version=row_version+1 WHERE id=$2",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        // Lock the credential first, exactly as `complete_login` does. A concurrent
        // password reset then waits, and its revocation of outstanding email proofs is
        // ordered against this spend rather than racing the session insert.
        let parameters = [bytes(digest)];
        let user = tx
            .fetch_first_async(
                "SELECT p.user_id FROM \"public\".\"auth_password\" p JOIN \"public\".\"auth_one_time\" o ON o.user_id=p.user_id WHERE o.purpose='email_otp' AND o.token_digest=$1 FOR UPDATE OF p",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::Unauthorized)?;
        let user = read_id(&user, "user_id")?;
        let parameters = [now_time.clone(), bytes(digest)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_one_time\" SET consumed_at=$1,attempt_count=attempt_count+1 WHERE purpose='email_otp' AND token_digest=$2 AND consumed_at IS NULL AND expires_at>$1 AND EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=\"public\".\"auth_one_time\".user_id AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Unauthorized);
        }
        let parameters = [id(user)];
        let tenant = tx
            .fetch_one_async(
                "SELECT tenant_id FROM \"public\".\"auth_user\" WHERE id=$1",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        let tenant = read_id(&tenant, "tenant_id")?;
        let parameters = [
            id(session_id),
            id(user),
            id(tenant),
            bytes(session_digest),
            time(expires_at)?,
            now_time.clone(),
        ];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_session\"(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$6)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), id(user)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_user\" SET last_login_at=$1,updated_at=$1,row_version=row_version+1 WHERE id=$2",
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
        ];
        let count = self
            .pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_social_state\"(id,tenant_id,provider,token_digest,expires_at,created_at) SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS(SELECT 1 FROM \"public\".\"auth_tenant\" WHERE id=$2 AND status='active')",
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
            .pool
            .fetch_first_async(
                "SELECT 1::bigint AS found FROM \"public\".\"auth_social_state\" WHERE token_digest=$1 AND tenant_id=$2 AND provider=$3 AND consumed_at IS NULL AND expires_at>$4",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            now_time.clone(),
            bytes(state_digest),
            id(tenant),
            text(provider),
        ];
        let spent = tx
            .execute_async(
                "UPDATE \"public\".\"auth_social_state\" SET consumed_at=$1 WHERE token_digest=$2 AND tenant_id=$3 AND provider=$4 AND consumed_at IS NULL AND expires_at>$1",
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
                "SELECT i.user_id FROM \"public\".\"auth_social_identity\" i JOIN \"public\".\"auth_user\" u ON u.id=i.user_id JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE i.provider=$1 AND i.subject=$2 AND u.tenant_id=$3 AND u.deleted_at IS NULL AND u.status IN ('active','pending') AND t.status='active'",
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
                    "SELECT id FROM \"public\".\"auth_user\" WHERE tenant_id=$1 AND email=$2 AND deleted_at IS NULL",
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
                Parameter::new(DbType::I64, Value::Null(DbType::I64)).expect("typed null")
            };
            let parameters = [
                id(user),
                id(tenant),
                text(email),
                verified_at,
                now_time.clone(),
            ];
            tx.execute_async(
                "INSERT INTO \"public\".\"auth_user\"(id,tenant_id,email,status,email_verified_at,created_at,updated_at) VALUES($1,$2,$3,'active',$4,$5,$5)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
            let parameters = [text(provider), text(subject), id(user), now_time.clone()];
            tx.execute_async(
                "INSERT INTO \"public\".\"auth_social_identity\"(provider,subject,user_id,created_at) VALUES($1,$2,$3,$4)",
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
        ];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_session\"(id,user_id,tenant_id,token_digest,expires_at,created_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$6)",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let parameters = [now_time.clone(), id(user)];
        tx.execute_async(
            "UPDATE \"public\".\"auth_user\" SET last_login_at=$1,updated_at=$1,row_version=row_version+1 WHERE id=$2",
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
        let scopes = serde_json::to_string(&key.scopes).map_err(|_| AuthError::Store)?;
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
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
            time(now)?,
        ];
        let count = tx
            .execute_async(
                "INSERT INTO \"public\".\"auth_api_key\"(id,tenant_id,user_id,name,prefix,secret_digest,scopes,expires_at,created_at) SELECT $1,$2,$3,'',$4,$5,$6,$7,$8 WHERE EXISTS(SELECT 1 FROM \"public\".\"auth_user\" WHERE id=$3 AND tenant_id=$2)",
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
            .pool
            .fetch_one_async(
                "SELECT k.id,k.tenant_id,k.user_id,k.prefix,k.secret_digest,k.scopes,k.expires_at,k.last_used_at FROM \"public\".\"auth_api_key\" k JOIN \"public\".\"auth_user\" u ON u.id=k.user_id JOIN \"public\".\"auth_tenant\" t ON t.id=k.tenant_id WHERE k.secret_digest=$1 AND k.prefix=$2 AND k.revoked_at IS NULL AND k.expires_at>$3 AND u.deleted_at IS NULL AND u.status='active' AND t.status='active'",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), id(key), id(user)];
        let count = tx
            .execute_async(
                "UPDATE \"public\".\"auth_api_key\" SET revoked_at=$1 WHERE id=$2 AND user_id=$3 AND revoked_at IS NULL AND expires_at>$1",
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
            .pool
            .execute_async(
                "UPDATE \"public\".\"auth_api_key\" SET last_used_at=$1 WHERE id=$2",
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
            .pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_audit\"(id,tenant_id,actor_id,action,outcome,ip,user_agent,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING",
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
            .pool
            .execute_async(
                "UPDATE \"public\".\"auth_tenant\" SET status='suspended',updated_at=$1,row_version=row_version+1 WHERE id=$2",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [
            id(membership.id),
            id(membership.tenant_id),
            id(membership.user_id),
            text(membership.status.as_str()),
        ];
        let count = tx
            .execute_async(
                "INSERT INTO \"public\".\"auth_membership\"(id,tenant_id,user_id,status) SELECT $1,$2,$3,$4 WHERE EXISTS(SELECT 1 FROM \"public\".\"auth_user\" u JOIN \"public\".\"auth_tenant\" t ON t.id=u.tenant_id WHERE u.id=$3 AND u.tenant_id=$2 AND u.deleted_at IS NULL AND t.status='active') AND NOT EXISTS(SELECT 1 FROM \"public\".\"auth_membership\" m WHERE m.tenant_id=$2 AND m.user_id=$3)",
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
            .pool
            .fetch_one_async(
                "SELECT id,tenant_id,user_id,status FROM \"public\".\"auth_membership\" WHERE tenant_id=$1 AND user_id=$2 LIMIT 1",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [text(status.as_str()), id(membership)];
        let row = tx
            .fetch_first_async(
                "UPDATE \"public\".\"auth_membership\" SET status=$1 WHERE id=$2 RETURNING id,tenant_id,user_id,status",
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
        self.pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_permission\"(id,tenant_id,name) VALUES($1,$2,$3)",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        Ok(())
    }

    async fn create_role(&self, id_value: Id, tenant: Id, name: &str) -> Result<(), AuthError> {
        let parameters = [id(id_value), id(tenant), text(name)];
        self.pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_role\"(id,tenant_id,name) VALUES($1,$2,$3)",
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
        self.pool
            .execute_async(
                "INSERT INTO \"public\".\"auth_group\"(id,tenant_id,name,created_at) VALUES($1,$2,$3,$4)",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [id(group), id(tenant)];
        let group_tenant = tx
            .fetch_first_async(
                "SELECT tenant_id FROM \"public\".\"auth_group\" WHERE id=$1 AND tenant_id=$2",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::NotFound)?;
        let group_tenant = read_id(&group_tenant, "tenant_id")?;
        let member_tenant = tx
            .fetch_first_async(
                "SELECT tenant_id FROM \"public\".\"auth_membership\" WHERE id=$1",
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
            "INSERT INTO \"public\".\"auth_group_member\"(group_id,membership_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
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
        let parameters = [id(group), id(membership), id(tenant)];
        let count = self
            .pool
            .execute_async(
                "DELETE FROM \"public\".\"auth_group_member\" WHERE group_id=$1 AND membership_id=$2 AND EXISTS(SELECT 1 FROM \"public\".\"auth_group\" WHERE id=$1 AND tenant_id=$3)",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [id(membership), id(role)];
        let same_tenant = tx
            .fetch_first_async(
                "SELECT 1::bigint AS found FROM \"public\".\"auth_membership\" m JOIN \"public\".\"auth_role\" r ON r.tenant_id=m.tenant_id WHERE m.id=$1 AND r.id=$2",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if same_tenant.is_none() {
            return Err(AuthError::Conflict);
        }
        let parameters = [id(membership), id(role)];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_membership_role\"(membership_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
            QueryOptions::new().bind_all(&parameters),
        )
        .await
        .map_err(error)?;
        let row = tx
            .fetch_one_async(
                "SELECT id,tenant_id,user_id,status FROM \"public\".\"auth_membership\" WHERE id=$1",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
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
        ];
        let count = tx
            .execute_async(
                "INSERT INTO \"public\".\"auth_invitation\"(id,tenant_id,email,token_digest,expires_at) SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM \"public\".\"auth_tenant\" WHERE id=$2 AND status='active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        if count != 1 {
            return Err(AuthError::Conflict);
        }
        for role in &invitation.role_ids {
            let parameters = [id(invitation.id), id(*role), id(invitation.tenant_id)];
            let count = tx
                .execute_async(
                    "INSERT INTO \"public\".\"auth_invitation_role\"(invitation_id,role_id) SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM \"public\".\"auth_role\" WHERE id=$2 AND tenant_id=$3)",
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
        let mut connection = self.pool.acquire_async().await.map_err(error)?;
        let mut tx = connection
            .begin_async(TxOptions::default())
            .await
            .map_err(error)?;
        let parameters = [now_time.clone(), bytes(digest)];
        let row = tx
            .fetch_first_async(
                "UPDATE \"public\".\"auth_invitation\" SET accepted_at=$1 WHERE token_digest=$2 AND accepted_at IS NULL AND expires_at>$1 AND EXISTS(SELECT 1 FROM \"public\".\"auth_tenant\" t WHERE t.id=\"public\".\"auth_invitation\".tenant_id AND t.status='active') RETURNING id,tenant_id,email",
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
                "SELECT id FROM \"public\".\"auth_user\" WHERE tenant_id=$1 AND email=$2 AND deleted_at IS NULL",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?
            .ok_or(AuthError::NotFound)?;
        let user = read_id(&user, "id")?;
        let parameters = [id(tenant), id(user)];
        let existing = tx
            .fetch_first_async(
                "SELECT id FROM \"public\".\"auth_membership\" WHERE tenant_id=$1 AND user_id=$2",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
        let membership = if let Some(row) = existing {
            let existing_id = read_id(&row, "id")?;
            tx.execute_async(
                "UPDATE \"public\".\"auth_membership\" SET status='active' WHERE id=$1",
                QueryOptions::new().bind(id(existing_id)),
            )
            .await
            .map_err(error)?;
            existing_id
        } else {
            let parameters = [id(membership_id), id(tenant), id(user)];
            tx.execute_async(
                "INSERT INTO \"public\".\"auth_membership\"(id,tenant_id,user_id,status) VALUES($1,$2,$3,'active')",
                QueryOptions::new().bind_all(&parameters),
            )
            .await
            .map_err(error)?;
            membership_id
        };
        let parameters = [id(membership), id(invitation)];
        tx.execute_async(
            "INSERT INTO \"public\".\"auth_membership_role\"(membership_id,role_id) SELECT $1,role_id FROM \"public\".\"auth_invitation_role\" WHERE invitation_id=$2 ON CONFLICT DO NOTHING",
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

// These identifiers predate the package rename and are stored or authenticated.
#[cfg(test)]
mod persisted_identity_tests {
    #[test]
    fn identifiers_remain_compatible() {
        assert_eq!(super::MIGRATION_MODULE, "auth");
        assert_eq!(super::MIGRATION_FINGERPRINT, "neotales-auth/postgres/v1");
    }
}
