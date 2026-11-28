//! Additive `SQLite` schema tables for persistent OIDC clients, org-wide & per-app RBAC,
//! self-service organization `IdP` / domain policies, and per-org SCIM tokens.
//!
//! All tables are created idempotently with `CREATE TABLE IF NOT EXISTS` alongside the
//! core `0001_auth.sql` schema so existing `conformance.rs` invariants stay untouched.

use neotales_dbapi::{DbType, Parameter, Pool, QueryOptions, Value};
use vaelspire_core::Id;
use vaelspire_store_sqlite::SqliteStore;

/// SQL statements for Vaelspire's extended server tables.
const EXTENDED_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS vs_oidc_client (
        client_id TEXT PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        name TEXT NOT NULL,
        confidential INTEGER NOT NULL DEFAULT 1,
        secret_digest BLOB,
        redirect_uris_json TEXT NOT NULL,
        allowed_scopes_json TEXT NOT NULL,
        grant_types_json TEXT NOT NULL,
        require_pkce INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS vs_app_role (
        id BLOB PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        app_id TEXT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE(tenant_id, app_id, name)
    )",
    "CREATE TABLE IF NOT EXISTS vs_app_permission (
        id BLOB PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        app_id TEXT,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE(tenant_id, app_id, name)
    )",
    "CREATE TABLE IF NOT EXISTS vs_app_role_permission (
        role_id BLOB NOT NULL REFERENCES vs_app_role(id) ON DELETE CASCADE,
        permission_id BLOB NOT NULL REFERENCES vs_app_permission(id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, permission_id)
    )",
    "CREATE TABLE IF NOT EXISTS vs_user_role (
        tenant_id BLOB NOT NULL,
        user_id BLOB NOT NULL,
        role_id BLOB NOT NULL REFERENCES vs_app_role(id) ON DELETE CASCADE,
        PRIMARY KEY (tenant_id, user_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS vs_group (
        id BLOB PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        name TEXT NOT NULL,
        external_id TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(tenant_id, name)
    )",
    "CREATE TABLE IF NOT EXISTS vs_group_member (
        group_id BLOB NOT NULL REFERENCES vs_group(id) ON DELETE CASCADE,
        user_id BLOB NOT NULL,
        PRIMARY KEY (group_id, user_id)
    )",
    "CREATE TABLE IF NOT EXISTS vs_group_role (
        group_id BLOB NOT NULL REFERENCES vs_group(id) ON DELETE CASCADE,
        role_id BLOB NOT NULL REFERENCES vs_app_role(id) ON DELETE CASCADE,
        PRIMARY KEY (group_id, role_id)
    )",
    "CREATE TABLE IF NOT EXISTS vs_org_policy (
        tenant_id BLOB PRIMARY KEY,
        email_policy TEXT NOT NULL DEFAULT 'allow_public',
        session_sliding INTEGER NOT NULL DEFAULT 1,
        session_idle_secs INTEGER NOT NULL DEFAULT 86400,
        session_absolute_secs INTEGER NOT NULL DEFAULT 604800,
        break_glass_enabled INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS vs_org_domain (
        id BLOB PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        domain TEXT NOT NULL UNIQUE,
        verification_token TEXT NOT NULL,
        verified_at TEXT,
        created_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS vs_org_idp (
        id BLOB PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        name TEXT NOT NULL,
        protocol TEXT NOT NULL,
        issuer_url TEXT NOT NULL DEFAULT '',
        client_id TEXT NOT NULL DEFAULT '',
        client_secret TEXT NOT NULL DEFAULT '',
        metadata_xml TEXT NOT NULL DEFAULT '',
        jit_provisioning INTEGER NOT NULL DEFAULT 1,
        default_role TEXT NOT NULL DEFAULT 'member',
        group_claim TEXT NOT NULL DEFAULT 'groups',
        enabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS vs_scim_token (
        id BLOB PRIMARY KEY,
        tenant_id BLOB NOT NULL,
        name TEXT NOT NULL,
        token_digest BLOB NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        revoked_at TEXT
    )",
];

/// Ensure all extended Vaelspire tables exist in `store`.
///
/// # Errors
/// Returns a [`neotales_dbapi::DbError`] if any DDL statement fails.
pub async fn ensure_extended_schema(store: &SqliteStore) -> Result<(), neotales_dbapi::DbError> {
    for sql in EXTENDED_SCHEMA {
        store
            .provider()
            .execute_async(sql, QueryOptions::new())
            .await?;
    }
    Ok(())
}

/// Helper to build a bytes parameter for a `UUIDv7` [`Id`].
///
/// # Errors
/// Returns a [`neotales_dbapi::DbError`] if parameter construction fails.
pub fn id_param(id: Id) -> Result<Parameter, neotales_dbapi::DbError> {
    Parameter::new(DbType::Bytes, Value::Bytes(id.as_bytes().to_vec()))
}

/// Helper to build a string parameter.
///
/// # Errors
/// Returns a [`neotales_dbapi::DbError`] if parameter construction fails.
pub fn text_param(s: &str) -> Result<Parameter, neotales_dbapi::DbError> {
    Parameter::new(DbType::Text, Value::Text(s.to_owned()))
}

/// Helper to build an optional string parameter.
///
/// # Errors
/// Returns a [`neotales_dbapi::DbError`] if parameter construction fails.
pub fn opt_text_param(s: Option<&str>) -> Result<Parameter, neotales_dbapi::DbError> {
    match s {
        Some(v) => Parameter::new(DbType::Text, Value::Text(v.to_owned())),
        None => Parameter::new(DbType::Text, Value::Null(DbType::Text)),
    }
}

/// Helper to build an integer parameter.
///
/// # Errors
/// Returns a [`neotales_dbapi::DbError`] if parameter construction fails.
pub fn i64_param(v: i64) -> Result<Parameter, neotales_dbapi::DbError> {
    Parameter::new(DbType::I64, Value::I64(v))
}

/// Helper to build an optional bytes parameter.
///
/// # Errors
/// Returns a [`neotales_dbapi::DbError`] if parameter construction fails.
pub fn opt_bytes_param(b: Option<&[u8]>) -> Result<Parameter, neotales_dbapi::DbError> {
    match b {
        Some(v) => Parameter::new(DbType::Bytes, Value::Bytes(v.to_vec())),
        None => Parameter::new(DbType::Bytes, Value::Null(DbType::Bytes)),
    }
}
