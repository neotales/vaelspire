//! Pure-Rust, zero-native-C, `wasm32`-compatible **Cloudflare D1** [`AuthStore`] adapter.
//!
//! Implement [`D1Client`] over Cloudflare Workers' `D1Database` binding (in `wasm32`) or
//! over the Cloudflare D1 HTTPS REST API, then wrap it in [`D1Store`] to run Vaelspire's
//! authentication workflows on ultra-low-cost edge infrastructure.

use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use vaelspire_core::{
    ApiKey, AuditEvent, AuthError, AuthStore, Id, OneTime, PasswordCredential, Purpose,
    SEEDED_ROLES, Session, Timestamp, User,
};

/// D1-compatible `SQLite` DDL schema matching Vaelspire's core tables and append-only audit triggers.
pub const D1_SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS auth_tenant (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_user (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES auth_tenant(id),
    email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE(tenant_id, email)
);
CREATE TABLE IF NOT EXISTS auth_password (
    user_id TEXT PRIMARY KEY REFERENCES auth_user(id),
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);
CREATE TABLE IF NOT EXISTS auth_session (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_user(id),
    tenant_id TEXT NOT NULL REFERENCES auth_tenant(id),
    token_digest TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS auth_one_time (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_user(id),
    purpose TEXT NOT NULL,
    token_digest TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    UNIQUE(purpose, token_digest)
);
CREATE TABLE IF NOT EXISTS auth_api_key (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES auth_tenant(id),
    user_id TEXT NOT NULL REFERENCES auth_user(id),
    prefix TEXT NOT NULL,
    secret_digest TEXT NOT NULL UNIQUE,
    scopes_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_audit (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    actor_id TEXT,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS auth_audit_no_update BEFORE UPDATE ON auth_audit BEGIN
    SELECT RAISE(ABORT, 'append-only');
END;
CREATE TRIGGER IF NOT EXISTS auth_audit_no_delete BEFORE DELETE ON auth_audit BEGIN
    SELECT RAISE(ABORT, 'append-only');
END;
CREATE TABLE IF NOT EXISTS auth_role (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES auth_tenant(id),
    name TEXT NOT NULL,
    UNIQUE(tenant_id, name)
);
CREATE TABLE IF NOT EXISTS auth_permission (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES auth_tenant(id),
    name TEXT NOT NULL,
    UNIQUE(tenant_id, name)
);
CREATE TABLE IF NOT EXISTS auth_group (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES auth_tenant(id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, name)
);
";

/// Bound SQL parameter value compatible with Cloudflare D1 JSON & Worker bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum D1Value {
    /// SQL `NULL`.
    Null,
    /// SQL `TEXT`.
    Text(String),
    /// SQL `INTEGER`.
    Int(i64),
}

/// One returned D1 row keyed by column name.
pub type D1Row = BTreeMap<String, Value>;

/// Minimal error kind returned by a [`D1Client`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D1Error {
    /// Unique or foreign-key constraint violation.
    Constraint,
    /// Network, binding, or SQL execution failure.
    Backend,
}

/// Transport-agnostic Cloudflare D1 client seam (Workers JS binding or D1 HTTPS REST API).
#[async_trait]
pub trait D1Client: Send + Sync {
    /// Execute a read query and return matching rows.
    ///
    /// # Errors
    /// Returns [`D1Error`] on execution failure.
    async fn query(&self, sql: &str, params: &[D1Value]) -> Result<Vec<D1Row>, D1Error>;

    /// Execute a mutating statement and return the number of rows changed.
    ///
    /// # Errors
    /// Returns [`D1Error::Constraint`] on uniqueness violations or [`D1Error::Backend`] on I/O errors.
    async fn execute(&self, sql: &str, params: &[D1Value]) -> Result<u64, D1Error>;
}

/// Cloudflare D1-backed implementation of [`AuthStore`].
#[derive(Debug, Clone)]
pub struct D1Store<C> {
    client: C,
}

impl<C: D1Client> D1Store<C> {
    /// Wrap any [`D1Client`] in a Vaelspire [`AuthStore`].
    #[must_use]
    pub const fn new(client: C) -> Self {
        Self { client }
    }

    /// Borrow the underlying [`D1Client`].
    #[must_use]
    pub const fn client(&self) -> &C {
        &self.client
    }
}

fn fmt_ts(ts: Timestamp) -> Result<String, AuthError> {
    ts.format(&Rfc3339).map_err(|_| AuthError::Store)
}

fn parse_ts(raw: &str) -> Result<Timestamp, AuthError> {
    Timestamp::parse(raw, &Rfc3339).map_err(|_| AuthError::Store)
}

fn encode_digest(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_digest(s: &str) -> Result<Vec<u8>, AuthError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| AuthError::Store)
}

fn map_d1_err(err: D1Error) -> AuthError {
    match err {
        D1Error::Constraint => AuthError::Conflict,
        D1Error::Backend => AuthError::Store,
    }
}

fn row_str<'a>(row: &'a D1Row, key: &str) -> Result<&'a str, AuthError> {
    row.get(key).and_then(Value::as_str).ok_or(AuthError::Store)
}

fn row_opt_str<'a>(row: &'a D1Row, key: &str) -> Option<&'a str> {
    row.get(key).and_then(Value::as_str)
}

fn row_i64(row: &D1Row, key: &str) -> Result<i64, AuthError> {
    row.get(key).and_then(Value::as_i64).ok_or(AuthError::Store)
}

#[async_trait]
impl<C: D1Client> AuthStore for D1Store<C> {
    async fn create_tenant(&self, id: Id, name: &str, now: Timestamp) -> Result<(), AuthError> {
        let now_s = fmt_ts(now)?;
        self.client
            .execute(
                "INSERT INTO auth_tenant (id, name, status, created_at) VALUES (?, ?, 'active', ?)",
                &[
                    D1Value::Text(id.to_string()),
                    D1Value::Text(name.to_owned()),
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        for role in SEEDED_ROLES {
            self.client
                .execute(
                    "INSERT INTO auth_role (id, tenant_id, name) VALUES (?, ?, ?)",
                    &[
                        D1Value::Text(Id::now_v7().to_string()),
                        D1Value::Text(id.to_string()),
                        D1Value::Text(role.to_owned()),
                    ],
                )
                .await
                .map_err(map_d1_err)?;
        }
        Ok(())
    }

    async fn create_user(
        &self,
        user: &User,
        hash: &str,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let now_s = fmt_ts(now)?;
        self.client
            .execute(
                "INSERT INTO auth_user (id, tenant_id, email, status, created_at) VALUES (?, ?, ?, 'active', ?)",
                &[
                    D1Value::Text(user.id.to_string()),
                    D1Value::Text(user.tenant_id.to_string()),
                    D1Value::Text(user.email.clone()),
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        self.client
            .execute(
                "INSERT INTO auth_password (user_id, password_hash, failed_attempts) VALUES (?, ?, 0)",
                &[
                    D1Value::Text(user.id.to_string()),
                    D1Value::Text(hash.to_owned()),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(())
    }

    async fn find_user(&self, tenant: Id, email: &str) -> Result<User, AuthError> {
        let rows = self
            .client
            .query(
                "SELECT id, tenant_id, email FROM auth_user WHERE tenant_id = ? AND email = ? AND status = 'active' AND deleted_at IS NULL LIMIT 1",
                &[
                    D1Value::Text(tenant.to_string()),
                    D1Value::Text(email.to_owned()),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        let row = rows.first().ok_or(AuthError::NotFound)?;
        Ok(User {
            id: Id::parse_str(row_str(row, "id")?).map_err(|_| AuthError::Store)?,
            tenant_id: Id::parse_str(row_str(row, "tenant_id")?).map_err(|_| AuthError::Store)?,
            email: row_str(row, "email")?.to_owned(),
        })
    }

    async fn password(&self, user: Id) -> Result<PasswordCredential, AuthError> {
        let rows = self
            .client
            .query(
                "SELECT password_hash, failed_attempts, locked_until FROM auth_password WHERE user_id = ? LIMIT 1",
                &[D1Value::Text(user.to_string())],
            )
            .await
            .map_err(map_d1_err)?;
        let row = rows.first().ok_or(AuthError::NotFound)?;
        let locked_until = row_opt_str(row, "locked_until").map(parse_ts).transpose()?;
        let attempts = i32::try_from(row_i64(row, "failed_attempts")?).unwrap_or(i32::MAX);
        Ok(PasswordCredential {
            password_hash: row_str(row, "password_hash")?.to_owned(),
            failed_attempts: attempts,
            locked_until,
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
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let until_s = fmt_ts(until)?;
        self.client
            .execute(
                "UPDATE auth_password \
                 SET failed_attempts = failed_attempts + 1, \
                     locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END \
                 WHERE user_id = ?",
                &[
                    D1Value::Int(i64::from(limit)),
                    D1Value::Text(until_s),
                    D1Value::Text(user.to_string()),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(())
    }

    async fn complete_login(
        &self,
        session: &Session,
        expected_hash: &str,
        replacement: Option<&str>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let cred = self.password(session.user_id).await?;
        if cred.password_hash != expected_hash {
            return Err(AuthError::Unauthorized);
        }
        if cred.locked_until.is_some_and(|lock| lock > now) {
            return Err(AuthError::Unauthorized);
        }
        let new_hash = replacement.unwrap_or(expected_hash);
        self.client
            .execute(
                "UPDATE auth_password SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
                &[
                    D1Value::Text(new_hash.to_owned()),
                    D1Value::Text(session.user_id.to_string()),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        let now_s = fmt_ts(now)?;
        let exp_s = fmt_ts(session.expires_at)?;
        self.client
            .execute(
                "INSERT INTO auth_session (id, user_id, tenant_id, token_digest, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                &[
                    D1Value::Text(session.id.to_string()),
                    D1Value::Text(session.user_id.to_string()),
                    D1Value::Text(session.tenant_id.to_string()),
                    D1Value::Text(encode_digest(&session.token_digest)),
                    D1Value::Text(exp_s),
                    D1Value::Text(now_s.clone()),
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(())
    }

    async fn find_session(&self, digest: &[u8], now: Timestamp) -> Result<Session, AuthError> {
        let now_s = fmt_ts(now)?;
        let rows = self
            .client
            .query(
                "SELECT id, user_id, tenant_id, token_digest, expires_at FROM auth_session \
                 WHERE token_digest = ? AND revoked_at IS NULL AND expires_at > ? LIMIT 1",
                &[D1Value::Text(encode_digest(digest)), D1Value::Text(now_s)],
            )
            .await
            .map_err(map_d1_err)?;
        let row = rows.first().ok_or(AuthError::NotFound)?;
        Ok(Session {
            id: Id::parse_str(row_str(row, "id")?).map_err(|_| AuthError::Store)?,
            user_id: Id::parse_str(row_str(row, "user_id")?).map_err(|_| AuthError::Store)?,
            tenant_id: Id::parse_str(row_str(row, "tenant_id")?).map_err(|_| AuthError::Store)?,
            token_digest: decode_digest(row_str(row, "token_digest")?)?,
            expires_at: parse_ts(row_str(row, "expires_at")?)?,
        })
    }

    async fn extend_session(
        &self,
        digest: &[u8],
        expires_at: Timestamp,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let exp_s = fmt_ts(expires_at)?;
        let now_s = fmt_ts(now)?;
        let changed = self
            .client
            .execute(
                "UPDATE auth_session SET expires_at = ?, last_seen_at = ? \
                 WHERE token_digest = ? AND revoked_at IS NULL AND expires_at > ?",
                &[
                    D1Value::Text(exp_s),
                    D1Value::Text(now_s.clone()),
                    D1Value::Text(encode_digest(digest)),
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        if changed == 0 {
            return Err(AuthError::NotFound);
        }
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(())
    }

    async fn revoke_session(
        &self,
        digest: &[u8],
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let now_s = fmt_ts(now)?;
        self.client
            .execute(
                "UPDATE auth_session SET revoked_at = ? WHERE token_digest = ? AND revoked_at IS NULL",
                &[
                    D1Value::Text(now_s),
                    D1Value::Text(encode_digest(digest)),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(())
    }

    async fn create_one_time(
        &self,
        proof: &OneTime,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<(), AuthError> {
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let exp_s = fmt_ts(proof.expires_at)?;
        self.client
            .execute(
                "INSERT INTO auth_one_time (id, user_id, purpose, token_digest, expires_at) VALUES (?, ?, ?, ?, ?)",
                &[
                    D1Value::Text(proof.id.to_string()),
                    D1Value::Text(proof.user_id.to_string()),
                    D1Value::Text(proof.purpose.as_str().to_owned()),
                    D1Value::Text(encode_digest(&proof.token_digest)),
                    D1Value::Text(exp_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(())
    }

    async fn consume_one_time(
        &self,
        purpose: Purpose,
        digest: &[u8],
        hash: Option<&str>,
        audit: Option<AuditEvent>,
        now: Timestamp,
    ) -> Result<Id, AuthError> {
        if let Some(ref ev) = audit {
            ev.validate()?;
        }
        let now_s = fmt_ts(now)?;
        let rows = self
            .client
            .query(
                "SELECT id, user_id FROM auth_one_time \
                 WHERE purpose = ? AND token_digest = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1",
                &[
                    D1Value::Text(purpose.as_str().to_owned()),
                    D1Value::Text(encode_digest(digest)),
                    D1Value::Text(now_s.clone()),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        let row = rows.first().ok_or(AuthError::Unauthorized)?;
        let proof_id = row_str(row, "id")?.to_owned();
        let user_id = Id::parse_str(row_str(row, "user_id")?).map_err(|_| AuthError::Store)?;
        self.client
            .execute(
                "UPDATE auth_one_time SET consumed_at = ? WHERE id = ?",
                &[D1Value::Text(now_s), D1Value::Text(proof_id)],
            )
            .await
            .map_err(map_d1_err)?;
        if let Some(new_hash) = hash {
            self.client
                .execute(
                    "UPDATE auth_password SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
                    &[
                        D1Value::Text(new_hash.to_owned()),
                        D1Value::Text(user_id.to_string()),
                    ],
                )
                .await
                .map_err(map_d1_err)?;
        }
        if let Some(ref ev) = audit {
            self.insert_audit(ev, now).await?;
        }
        Ok(user_id)
    }

    async fn create_api_key(&self, key: &ApiKey, now: Timestamp) -> Result<(), AuthError> {
        let scopes_json = serde_json::to_string(&key.scopes).map_err(|_| AuthError::Store)?;
        let exp_s = fmt_ts(key.expires_at)?;
        let now_s = fmt_ts(now)?;
        self.client
            .execute(
                "INSERT INTO auth_api_key (id, tenant_id, user_id, prefix, secret_digest, scopes_json, expires_at, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                &[
                    D1Value::Text(key.id.to_string()),
                    D1Value::Text(key.tenant_id.to_string()),
                    D1Value::Text(key.user_id.to_string()),
                    D1Value::Text(key.prefix.clone()),
                    D1Value::Text(encode_digest(&key.secret_digest)),
                    D1Value::Text(scopes_json),
                    D1Value::Text(exp_s),
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        Ok(())
    }

    async fn find_api_key(
        &self,
        digest: &[u8],
        prefix: &str,
        now: Timestamp,
    ) -> Result<ApiKey, AuthError> {
        let now_s = fmt_ts(now)?;
        let rows = self
            .client
            .query(
                "SELECT id, tenant_id, user_id, prefix, secret_digest, scopes_json, expires_at, last_used_at \
                 FROM auth_api_key WHERE secret_digest = ? AND prefix = ? AND revoked_at IS NULL AND expires_at > ? LIMIT 1",
                &[
                    D1Value::Text(encode_digest(digest)),
                    D1Value::Text(prefix.to_owned()),
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        let row = rows.first().ok_or(AuthError::NotFound)?;
        let scopes: Vec<String> =
            serde_json::from_str(row_str(row, "scopes_json")?).map_err(|_| AuthError::Store)?;
        let last_used_at = row_opt_str(row, "last_used_at").map(parse_ts).transpose()?;
        Ok(ApiKey {
            id: Id::parse_str(row_str(row, "id")?).map_err(|_| AuthError::Store)?,
            tenant_id: Id::parse_str(row_str(row, "tenant_id")?).map_err(|_| AuthError::Store)?,
            user_id: Id::parse_str(row_str(row, "user_id")?).map_err(|_| AuthError::Store)?,
            prefix: row_str(row, "prefix")?.to_owned(),
            secret_digest: decode_digest(row_str(row, "secret_digest")?)?,
            scopes,
            expires_at: parse_ts(row_str(row, "expires_at")?)?,
            last_used_at,
        })
    }

    async fn insert_audit(&self, event: &AuditEvent, now: Timestamp) -> Result<(), AuthError> {
        event.validate()?;
        let now_s = fmt_ts(now)?;
        let ip = event
            .fields
            .iter()
            .find(|(k, _)| k == "ip")
            .map_or(D1Value::Null, |(_, v)| D1Value::Text(v.clone()));
        let ua = event
            .fields
            .iter()
            .find(|(k, _)| k == "user_agent")
            .map_or(D1Value::Null, |(_, v)| D1Value::Text(v.clone()));
        self.client
            .execute(
                "INSERT INTO auth_audit (id, tenant_id, actor_id, action, outcome, ip, user_agent, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                &[
                    D1Value::Text(event.id.to_string()),
                    event
                        .tenant_id
                        .map_or(D1Value::Null, |id| D1Value::Text(id.to_string())),
                    event
                        .actor_id
                        .map_or(D1Value::Null, |id| D1Value::Text(id.to_string())),
                    D1Value::Text(event.action.clone()),
                    D1Value::Text(event.outcome.clone()),
                    ip,
                    ua,
                    D1Value::Text(now_s),
                ],
            )
            .await
            .map_err(map_d1_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Lightweight mock [`D1Client`] verifying exact SQL & parameter wiring without Cloudflare network access.
    #[derive(Default)]
    struct MockD1Client {
        queries: Mutex<Vec<(String, Vec<D1Value>)>>,
        session_row: Mutex<Option<D1Row>>,
    }

    #[async_trait]
    impl D1Client for MockD1Client {
        async fn query(&self, sql: &str, params: &[D1Value]) -> Result<Vec<D1Row>, D1Error> {
            self.queries
                .lock()
                .expect("lock")
                .push((sql.to_owned(), params.to_vec()));
            if sql.contains("FROM auth_session") {
                return Ok(self
                    .session_row
                    .lock()
                    .expect("lock")
                    .clone()
                    .into_iter()
                    .collect());
            }
            Ok(Vec::new())
        }

        async fn execute(&self, sql: &str, params: &[D1Value]) -> Result<u64, D1Error> {
            self.queries
                .lock()
                .expect("lock")
                .push((sql.to_owned(), params.to_vec()));
            Ok(1)
        }
    }

    #[tokio::test]
    async fn d1_store_creates_tenant_session_and_audit_cleanly() {
        let mock = MockD1Client::default();
        let store = D1Store::new(mock);
        let now = Timestamp::now_utc();
        let tid = Id::now_v7();
        let uid = Id::now_v7();
        let sid = Id::now_v7();

        store
            .create_tenant(tid, "edge-org", now)
            .await
            .expect("tenant");
        let audit = AuditEvent {
            id: Id::now_v7(),
            tenant_id: Some(tid),
            actor_id: Some(uid),
            action: "auth.session.issued".into(),
            outcome: "ok".into(),
            fields: vec![("ip".into(), "198.51.100.0/24".into())],
        };
        store.insert_audit(&audit, now).await.expect("audit");

        // Seed a session row and confirm find_session + extend_session decode RFC3339 & base64url digest.
        let mut row = D1Row::new();
        row.insert("id".into(), Value::String(sid.to_string()));
        row.insert("user_id".into(), Value::String(uid.to_string()));
        row.insert("tenant_id".into(), Value::String(tid.to_string()));
        row.insert(
            "token_digest".into(),
            Value::String(encode_digest(&[7u8; 32])),
        );
        row.insert(
            "expires_at".into(),
            Value::String(fmt_ts(now + time::Duration::hours(2)).unwrap()),
        );
        *store.client().session_row.lock().expect("lock") = Some(row);

        let found = store.find_session(&[7u8; 32], now).await.expect("session");
        assert_eq!(found.id, sid);
        assert_eq!(found.user_id, uid);

        store
            .extend_session(&[7u8; 32], now + time::Duration::hours(4), None, now)
            .await
            .expect("extend");
        assert!(D1_SCHEMA_SQL.contains("auth_audit_no_delete"));
    }
}
