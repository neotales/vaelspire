-- Vaelspire Core Cloudflare D1 Schema (matches crates/vaelspire-store-d1::D1_SCHEMA_SQL)
-- Apply with: wrangler d1 execute vaelspire-db --file=schema.sql

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
