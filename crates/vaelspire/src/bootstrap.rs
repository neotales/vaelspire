//! Idempotent SQLite tenant bootstrap, admin provisioning, and readiness helpers.

use std::fmt;

use neotales_dbapi::{DbType, ErrorKind, Parameter, Pool, QueryOptions, Value};
use vaelspire_auth::{Auth, Policy, hash_password};
use vaelspire_core::{AuthError, AuthStore, Id, MembershipStatus, Timestamp};
use vaelspire_store_sqlite::SqliteStore;
use zeroize::Zeroizing;

/// Result of running [`bootstrap_admin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// A brand-new admin user (with active `owner` membership) was created.
    Created(Id),
    /// An account with that email already existed in the tenant.
    AlreadyExists(Id),
}

/// Failure during store bootstrap or lookup.
#[derive(Debug)]
pub enum BootstrapError {
    /// An authentication workflow or store constraint failed.
    Auth(AuthError),
    /// Underlying `neotales-dbapi` query error.
    Database(neotales_dbapi::DbError),
    /// Background Argon2 task panicked or was cancelled.
    TaskJoin,
    /// Persisted UUID bytes were malformed.
    CorruptId,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(err) => write!(f, "auth error: {err:?}"),
            Self::Database(err) => write!(f, "database error: {err}"),
            Self::TaskJoin => f.write_str("blocking password hash task failed"),
            Self::CorruptId => f.write_str("stored identifier bytes were invalid"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// Ensure the named tenant exists, returning its persistent [`Id`].
///
/// Reuses the existing tenant row across restarts; creates a fresh `UUIDv7` tenant
/// (with seeded `owner`, `admin`, and `member` roles) on first run.
///
/// # Errors
/// Returns [`BootstrapError`] if querying or creating the tenant fails.
pub async fn ensure_tenant(store: &SqliteStore, name: &str) -> Result<Id, BootstrapError> {
    let param = Parameter::new(DbType::Text, Value::Text(name.to_owned()))
        .map_err(BootstrapError::Database)?;
    match store
        .provider()
        .fetch_one_async(
            "SELECT id FROM auth_tenant WHERE name = ? LIMIT 1",
            QueryOptions::new().bind(param),
        )
        .await
    {
        Ok(row) => {
            let raw: Vec<u8> = row.read("id").map_err(BootstrapError::Database)?;
            Id::from_slice(&raw).map_err(|_| BootstrapError::CorruptId)
        }
        Err(err) if err.kind() == ErrorKind::NoRows => {
            let tenant_id = Id::now_v7();
            store
                .create_tenant(tenant_id, name, Timestamp::now_utc())
                .await
                .map_err(BootstrapError::Auth)?;
            Ok(tenant_id)
        }
        Err(err) => Err(BootstrapError::Database(err)),
    }
}

/// Idempotently provision an administrator account in `tenant_id` with the `owner` role.
///
/// # Errors
/// Returns [`BootstrapError`] if password hashing, user creation, or role assignment fails.
pub async fn bootstrap_admin(
    store: &SqliteStore,
    tenant_id: Id,
    email: &str,
    password: Zeroizing<String>,
    digest_key: [u8; 32],
) -> Result<BootstrapOutcome, BootstrapError> {
    let normalized = email.trim().to_ascii_lowercase();
    match store.find_user(tenant_id, &normalized).await {
        Ok(existing) => return Ok(BootstrapOutcome::AlreadyExists(existing.id)),
        Err(AuthError::NotFound) => {}
        Err(err) => return Err(BootstrapError::Auth(err)),
    }

    let hash = tokio::task::spawn_blocking(move || hash_password(password.as_bytes()))
        .await
        .map_err(|_| BootstrapError::TaskJoin)?
        .map_err(BootstrapError::Auth)?;

    let now = Timestamp::now_utc();
    let auth = Auth::new(store, digest_key, Policy::default()).auditing(true);
    let user = auth
        .sign_up(tenant_id, &normalized, &hash, now)
        .await
        .map_err(BootstrapError::Auth)?;

    let membership = auth
        .create_membership(tenant_id, user.id, MembershipStatus::Active, now)
        .await
        .map_err(BootstrapError::Auth)?;

    if let Some(owner_role_id) = find_role_id(store, tenant_id, "owner").await? {
        auth.assign_role(membership.id, owner_role_id, now)
            .await
            .map_err(BootstrapError::Auth)?;
    }

    Ok(BootstrapOutcome::Created(user.id))
}

/// Look up an active user's normalized email by `user_id` (used for `/forward-auth` headers).
///
/// # Errors
/// Returns [`BootstrapError::Database`] if the database query fails.
pub async fn lookup_user_email(
    store: &SqliteStore,
    user_id: Id,
) -> Result<Option<String>, BootstrapError> {
    let param = Parameter::new(DbType::Bytes, Value::Bytes(user_id.as_bytes().to_vec()))
        .map_err(BootstrapError::Database)?;
    match store
        .provider()
        .fetch_one_async(
            "SELECT email FROM auth_user WHERE id = ? AND deleted_at IS NULL LIMIT 1",
            QueryOptions::new().bind(param),
        )
        .await
    {
        Ok(row) => {
            let email: String = row.read("email").map_err(BootstrapError::Database)?;
            Ok(Some(email))
        }
        Err(err) if err.kind() == ErrorKind::NoRows => Ok(None),
        Err(err) => Err(BootstrapError::Database(err)),
    }
}

/// Execute a lightweight `SELECT 1` probe against SQLite for `/ready`.
///
/// # Errors
/// Returns [`BootstrapError::Database`] if the database cannot answer.
pub async fn check_store_ready(store: &SqliteStore) -> Result<(), BootstrapError> {
    let _row = store
        .provider()
        .fetch_one_async("SELECT 1 AS ok", QueryOptions::new())
        .await
        .map_err(BootstrapError::Database)?;
    Ok(())
}

/// Summary user row for SCIM 2.0 and Admin directory views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryUser {
    /// `UUIDv7` account identifier.
    pub id: Id,
    /// Owning tenant identifier.
    pub tenant_id: Id,
    /// Normalized lowercase email.
    pub email: String,
    /// Account status (`active`, `pending`, etc.).
    pub status: String,
}

/// List non-deleted users in `tenant_id` (newest first, capped at `limit`).
///
/// # Errors
/// Returns [`BootstrapError::Database`] or [`BootstrapError::CorruptId`] on failure.
pub async fn list_tenant_users(
    store: &SqliteStore,
    tenant_id: Id,
    limit: i64,
) -> Result<Vec<DirectoryUser>, BootstrapError> {
    let params = [
        Parameter::new(DbType::Bytes, Value::Bytes(tenant_id.as_bytes().to_vec()))
            .map_err(BootstrapError::Database)?,
        Parameter::new(DbType::I64, Value::I64(limit.clamp(1, 500)))
            .map_err(BootstrapError::Database)?,
    ];
    let rows = store
        .provider()
        .fetch_all_async(
            "SELECT id, tenant_id, email, status FROM auth_user WHERE tenant_id = ? AND deleted_at IS NULL ORDER BY id DESC LIMIT ?",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .map_err(BootstrapError::Database)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let user_id_bytes: Vec<u8> = row.read("id").map_err(BootstrapError::Database)?;
        let tenant_id_bytes: Vec<u8> = row.read("tenant_id").map_err(BootstrapError::Database)?;
        out.push(DirectoryUser {
            id: Id::from_slice(&user_id_bytes).map_err(|_| BootstrapError::CorruptId)?,
            tenant_id: Id::from_slice(&tenant_id_bytes).map_err(|_| BootstrapError::CorruptId)?,
            email: row.read("email").map_err(BootstrapError::Database)?,
            status: row.read("status").map_err(BootstrapError::Database)?,
        });
    }
    Ok(out)
}

/// Fetch one non-deleted user in `tenant_id` by `user_id`.
///
/// # Errors
/// Returns [`BootstrapError::Database`] or [`BootstrapError::CorruptId`] on failure.
pub async fn find_directory_user(
    store: &SqliteStore,
    tenant_id: Id,
    user_id: Id,
) -> Result<Option<DirectoryUser>, BootstrapError> {
    let params = [
        Parameter::new(DbType::Bytes, Value::Bytes(tenant_id.as_bytes().to_vec()))
            .map_err(BootstrapError::Database)?,
        Parameter::new(DbType::Bytes, Value::Bytes(user_id.as_bytes().to_vec()))
            .map_err(BootstrapError::Database)?,
    ];
    match store
        .provider()
        .fetch_one_async(
            "SELECT id, tenant_id, email, status FROM auth_user WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL LIMIT 1",
            QueryOptions::new().bind_all(&params),
        )
        .await
    {
        Ok(row) => {
            let user_id_bytes: Vec<u8> = row.read("id").map_err(BootstrapError::Database)?;
            let tenant_id_bytes: Vec<u8> =
                row.read("tenant_id").map_err(BootstrapError::Database)?;
            Ok(Some(DirectoryUser {
                id: Id::from_slice(&user_id_bytes).map_err(|_| BootstrapError::CorruptId)?,
                tenant_id: Id::from_slice(&tenant_id_bytes)
                    .map_err(|_| BootstrapError::CorruptId)?,
                email: row.read("email").map_err(BootstrapError::Database)?,
                status: row.read("status").map_err(BootstrapError::Database)?,
            }))
        }
        Err(err) if err.kind() == ErrorKind::NoRows => Ok(None),
        Err(err) => Err(BootstrapError::Database(err)),
    }
}

/// Soft-delete a user by `user_id` within `tenant_id` (used by SCIM 2.0 `DELETE /scim/v2/Users/{id}`).
///
/// # Errors
/// Returns [`BootstrapError::Database`] on failure.
pub async fn soft_delete_directory_user(
    store: &SqliteStore,
    tenant_id: Id,
    user_id: Id,
) -> Result<bool, BootstrapError> {
    let now_str = Timestamp::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let params = [
        Parameter::new(DbType::Text, Value::Text(now_str)).map_err(BootstrapError::Database)?,
        Parameter::new(DbType::Bytes, Value::Bytes(tenant_id.as_bytes().to_vec()))
            .map_err(BootstrapError::Database)?,
        Parameter::new(DbType::Bytes, Value::Bytes(user_id.as_bytes().to_vec()))
            .map_err(BootstrapError::Database)?,
    ];
    let affected = store
        .provider()
        .execute_async(
            "UPDATE auth_user SET deleted_at = ?, status = 'deleted' WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .map_err(BootstrapError::Database)?;
    Ok(affected > 0)
}

async fn find_role_id(
    store: &SqliteStore,
    tenant_id: Id,
    role_name: &str,
) -> Result<Option<Id>, BootstrapError> {
    let params = [
        Parameter::new(DbType::Bytes, Value::Bytes(tenant_id.as_bytes().to_vec()))
            .expect("matching bytes parameter"),
        Parameter::new(DbType::Text, Value::Text(role_name.to_owned()))
            .expect("matching text parameter"),
    ];
    match store
        .provider()
        .fetch_one_async(
            "SELECT id FROM auth_role WHERE tenant_id = ? AND name = ? LIMIT 1",
            QueryOptions::new().bind_all(&params),
        )
        .await
    {
        Ok(row) => {
            let raw: Vec<u8> = row.read("id").map_err(BootstrapError::Database)?;
            let id = Id::from_slice(&raw).map_err(|_| BootstrapError::CorruptId)?;
            Ok(Some(id))
        }
        Err(err) if err.kind() == ErrorKind::NoRows => Ok(None),
        Err(err) => Err(BootstrapError::Database(err)),
    }
}
