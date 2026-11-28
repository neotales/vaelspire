//! Operator management CLI commands (`user`, `org`, `client`, `role`, `perm`, `group`, `audit`).
//!
//! Operates directly on the configured `SQLite` database (air-gapped / local-first) with
//! GDPR-safe redacted logging (`user_id` + `wf******@domain.com`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use neotales_dbapi::{Pool, QueryOptions};
use serde_json::json;
use vaelspire_auth::{Auth, Policy, hash_password};
use vaelspire_core::privacy::{PiiLogMode, format_email_for_log};
use vaelspire_core::{Id, Timestamp};
use vaelspire_store_sqlite::open;

use crate::bootstrap::{ensure_tenant, list_tenant_users, soft_delete_directory_user};
use crate::config::load_or_create_key;
use crate::ext_store::{ensure_extended_schema, i64_param, id_param, opt_text_param, text_param};
use crate::gdpr::{build_user_export, erase_user_gdpr};
use crate::org::EmailPolicy;
use crate::rbac::resolve_effective_access;

/// User lifecycle management subcommands (`vaelspire user ...`).
#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// List active users in the tenant.
    List {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
    },
    /// Create a new user account with Argon2id password hashing.
    Create {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// User email address.
        #[arg(long)]
        email: String,
        /// Initial password.
        #[arg(long)]
        password: String,
    },
    /// Disable (soft-delete) a user and revoke active sessions.
    Disable {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// User `UUIDv7`.
        #[arg(long)]
        id: String,
    },
    /// Export a GDPR Right of Access JSON bundle for a user.
    Export {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// User `UUIDv7`.
        #[arg(long)]
        id: String,
    },
    /// Execute GDPR Right to Erasure (anonymizes PII while preserving append-only audit integrity).
    GdprErase {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// User `UUIDv7`.
        #[arg(long)]
        id: String,
    },
}

/// Organization policy & domain subcommands (`vaelspire org ...`).
#[derive(Debug, Subcommand)]
pub enum OrgCommand {
    /// Configure the organization's email domain policy and session timeouts.
    PolicySet {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// Email policy (`allow_public`, `business_domains_only`, or `verified_domains_only`).
        #[arg(long, default_value = "allow_public")]
        email_policy: String,
        /// Enable sliding session expirations.
        #[arg(long, default_value_t = true)]
        sliding: bool,
        /// Idle session timeout in seconds.
        #[arg(long, default_value_t = 86_400)]
        idle_secs: i64,
        /// Hard absolute session lifetime in seconds.
        #[arg(long, default_value_t = 604_800)]
        absolute_secs: i64,
    },
    /// Register a domain for DNS TXT ownership verification.
    DomainAdd {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// Company domain (e.g. `acme.com`).
        #[arg(long)]
        domain: String,
    },
}

/// RBAC management subcommands (`vaelspire rbac ...`).
#[derive(Debug, Subcommand)]
pub enum RbacCommand {
    /// Create an org-wide or per-application role.
    RoleCreate {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// Role name.
        #[arg(long)]
        name: String,
        /// Optional OIDC `client_id` scoping this role to one app (omit for org-wide).
        #[arg(long)]
        app_id: Option<String>,
    },
    /// Create an org-wide or per-application permission.
    PermCreate {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// Permission name (e.g. `secrets:read`).
        #[arg(long)]
        name: String,
        /// Optional OIDC `client_id` scoping this permission to one app.
        #[arg(long)]
        app_id: Option<String>,
    },
    /// Grant a permission to a role.
    GrantPerm {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Role `UUIDv7`.
        #[arg(long)]
        role_id: String,
        /// Permission `UUIDv7`.
        #[arg(long)]
        perm_id: String,
    },
    /// Assign a role directly to a user.
    AssignUser {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// User `UUIDv7`.
        #[arg(long)]
        user_id: String,
        /// Role `UUIDv7`.
        #[arg(long)]
        role_id: String,
    },
    /// Inspect effective resolved roles, groups, and permissions for a user.
    Effective {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Tenant name.
        #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
        tenant_name: String,
        /// User `UUIDv7`.
        #[arg(long)]
        user_id: String,
        /// Optional OIDC `client_id` filter.
        #[arg(long)]
        app_id: Option<String>,
    },
}

/// Audit log inspection subcommands (`vaelspire audit ...`).
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Print recent append-only audit rows as JSON lines.
    Tail {
        /// Path to the `SQLite` database.
        #[arg(
            long,
            env = "VAELSPIRE_SQLITE_PATH",
            default_value = "./vaelspire.sqlite"
        )]
        sqlite: PathBuf,
        /// Maximum number of recent rows to display.
        #[arg(long, default_value_t = 25)]
        limit: i64,
    },
}

/// Execute `vaelspire user ...`.
#[allow(clippy::too_many_lines)]
pub async fn run_user_command(cmd: UserCommand) -> ExitCode {
    match cmd {
        UserCommand::List {
            sqlite,
            tenant_name,
        } => {
            let Ok(store) = open(&sqlite).await else {
                tracing::error!(sqlite = %sqlite.display(), "failed to open sqlite database");
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            match list_tenant_users(&store, tenant_id, 200).await {
                Ok(users) => {
                    for u in users {
                        println!(
                            "{}",
                            json!({
                                "id": u.id.to_string(),
                                "email_masked": format_email_for_log(&u.email, PiiLogMode::Masked),
                                "status": u.status,
                            })
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(_) => ExitCode::FAILURE,
            }
        }
        UserCommand::Create {
            sqlite,
            tenant_name,
            email,
            password,
        } => {
            let Ok(store) = open(&sqlite).await else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok((digest_key, _)) = load_or_create_key(None, &sqlite) else {
                return ExitCode::FAILURE;
            };
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            let Ok(hash) = hash_password(password.as_bytes()) else {
                tracing::error!("invalid password");
                return ExitCode::FAILURE;
            };
            let auth = Auth::new(&store, *digest_key, Policy::default()).auditing(true);
            match auth
                .sign_up(tenant_id, &email, &hash, Timestamp::now_utc())
                .await
            {
                Ok(u) => {
                    println!(
                        "{}",
                        json!({
                            "id": u.id.to_string(),
                            "email_masked": format_email_for_log(&u.email, PiiLogMode::Masked),
                            "status": "active",
                        })
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    tracing::error!(error = ?err, "failed to create user");
                    ExitCode::FAILURE
                }
            }
        }
        UserCommand::Disable {
            sqlite,
            tenant_name,
            id,
        } => {
            let (Ok(store), Ok(uid)) = (open(&sqlite).await, Id::parse_str(&id)) else {
                return ExitCode::FAILURE;
            };
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            match soft_delete_directory_user(&store, tenant_id, uid).await {
                Ok(true) => {
                    println!("{}", json!({ "id": uid.to_string(), "status": "disabled" }));
                    ExitCode::SUCCESS
                }
                _ => ExitCode::FAILURE,
            }
        }
        UserCommand::Export {
            sqlite,
            tenant_name,
            id,
        } => {
            let (Ok(store), Ok(uid)) = (open(&sqlite).await, Id::parse_str(&id)) else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            match build_user_export(&store, tenant_id, uid).await {
                Ok(Some(bundle)) => {
                    println!("{bundle}");
                    ExitCode::SUCCESS
                }
                _ => ExitCode::FAILURE,
            }
        }
        UserCommand::GdprErase {
            sqlite,
            tenant_name,
            id,
        } => {
            let (Ok(store), Ok(uid)) = (open(&sqlite).await, Id::parse_str(&id)) else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            match erase_user_gdpr(&store, tenant_id, uid).await {
                Ok(true) => {
                    println!("{}", json!({ "id": uid.to_string(), "status": "erased" }));
                    ExitCode::SUCCESS
                }
                _ => ExitCode::FAILURE,
            }
        }
    }
}

/// Execute `vaelspire org ...`.
#[allow(clippy::too_many_lines)]
pub async fn run_org_command(cmd: OrgCommand) -> ExitCode {
    match cmd {
        OrgCommand::PolicySet {
            sqlite,
            tenant_name,
            email_policy,
            sliding,
            idle_secs,
            absolute_secs,
        } => {
            let Some(policy) = EmailPolicy::parse(&email_policy) else {
                tracing::error!(
                    "email_policy must be allow_public, business_domains_only, or verified_domains_only"
                );
                return ExitCode::FAILURE;
            };
            let Ok(store) = open(&sqlite).await else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            let now = Timestamp::now_utc().to_string();
            let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
                Ok([
                    id_param(tenant_id)?,
                    text_param(policy.as_str())?,
                    i64_param(i64::from(sliding))?,
                    i64_param(idle_secs)?,
                    i64_param(absolute_secs)?,
                    i64_param(1)?,
                    text_param(&now)?,
                ])
            })() else {
                return ExitCode::FAILURE;
            };
            let sql = "INSERT INTO vs_org_policy \
                (tenant_id, email_policy, session_sliding, session_idle_secs, session_absolute_secs, break_glass_enabled, updated_at) \
                VALUES (?, ?, ?, ?, ?, ?, ?) \
                ON CONFLICT(tenant_id) DO UPDATE SET \
                email_policy = excluded.email_policy, session_sliding = excluded.session_sliding, \
                session_idle_secs = excluded.session_idle_secs, session_absolute_secs = excluded.session_absolute_secs, \
                updated_at = excluded.updated_at";
            if store
                .provider()
                .execute_async(sql, QueryOptions::new().bind_all(&params))
                .await
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            println!(
                "{}",
                json!({
                    "tenant": tenant_name,
                    "email_policy": policy.as_str(),
                    "session_sliding": sliding,
                    "session_idle_secs": idle_secs,
                    "session_absolute_secs": absolute_secs,
                })
            );
            ExitCode::SUCCESS
        }
        OrgCommand::DomainAdd {
            sqlite,
            tenant_name,
            domain,
        } => {
            let Ok(store) = open(&sqlite).await else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            let id = Id::now_v7();
            let clean = domain.trim().to_ascii_lowercase();
            let token = format!("vaelspire-site-verification={id}");
            let now = Timestamp::now_utc().to_string();
            let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
                Ok([
                    id_param(id)?,
                    id_param(tenant_id)?,
                    text_param(&clean)?,
                    text_param(&token)?,
                    text_param(&now)?,
                ])
            })() else {
                return ExitCode::FAILURE;
            };
            if store
                .provider()
                .execute_async(
                    "INSERT INTO vs_org_domain (id, tenant_id, domain, verification_token, created_at) VALUES (?, ?, ?, ?, ?)",
                    QueryOptions::new().bind_all(&params),
                )
                .await
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            println!(
                "{}",
                json!({
                    "id": id.to_string(),
                    "domain": clean,
                    "txt_record": format!("_vaelspire-verify.{clean}"),
                    "value": token,
                })
            );
            ExitCode::SUCCESS
        }
    }
}

/// Execute `vaelspire rbac ...`.
#[allow(clippy::too_many_lines)]
pub async fn run_rbac_command(cmd: RbacCommand) -> ExitCode {
    match cmd {
        RbacCommand::RoleCreate {
            sqlite,
            tenant_name,
            name,
            app_id,
        } => {
            let Ok(store) = open(&sqlite).await else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            let id = Id::now_v7();
            let now = Timestamp::now_utc().to_string();
            let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
                Ok([
                    id_param(id)?,
                    id_param(tenant_id)?,
                    opt_text_param(app_id.as_deref())?,
                    text_param(name.trim())?,
                    text_param("")?,
                    text_param(&now)?,
                ])
            })() else {
                return ExitCode::FAILURE;
            };
            if store
                .provider()
                .execute_async(
                    "INSERT INTO vs_app_role (id, tenant_id, app_id, name, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    QueryOptions::new().bind_all(&params),
                )
                .await
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            println!(
                "{}",
                json!({ "id": id.to_string(), "app_id": app_id, "name": name.trim() })
            );
            ExitCode::SUCCESS
        }
        RbacCommand::PermCreate {
            sqlite,
            tenant_name,
            name,
            app_id,
        } => {
            let Ok(store) = open(&sqlite).await else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            let id = Id::now_v7();
            let now = Timestamp::now_utc().to_string();
            let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
                Ok([
                    id_param(id)?,
                    id_param(tenant_id)?,
                    opt_text_param(app_id.as_deref())?,
                    text_param(name.trim())?,
                    text_param("")?,
                    text_param(&now)?,
                ])
            })() else {
                return ExitCode::FAILURE;
            };
            if store
                .provider()
                .execute_async(
                    "INSERT INTO vs_app_permission (id, tenant_id, app_id, name, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    QueryOptions::new().bind_all(&params),
                )
                .await
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            println!(
                "{}",
                json!({ "id": id.to_string(), "app_id": app_id, "name": name.trim() })
            );
            ExitCode::SUCCESS
        }
        RbacCommand::GrantPerm {
            sqlite,
            role_id,
            perm_id,
        } => {
            let (Ok(store), Ok(rid), Ok(pid)) = (
                open(&sqlite).await,
                Id::parse_str(&role_id),
                Id::parse_str(&perm_id),
            ) else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let (Ok(rp), Ok(pp)) = (id_param(rid), id_param(pid)) else {
                return ExitCode::FAILURE;
            };
            if store
                .provider()
                .execute_async(
                    "INSERT OR IGNORE INTO vs_app_role_permission (role_id, permission_id) VALUES (?, ?)",
                    QueryOptions::new().bind_all(&[rp, pp]),
                )
                .await
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            println!(
                "{}",
                json!({ "role_id": rid.to_string(), "perm_id": pid.to_string(), "granted": true })
            );
            ExitCode::SUCCESS
        }
        RbacCommand::AssignUser {
            sqlite,
            tenant_name,
            user_id,
            role_id,
        } => {
            let (Ok(store), Ok(uid), Ok(rid)) = (
                open(&sqlite).await,
                Id::parse_str(&user_id),
                Id::parse_str(&role_id),
            ) else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            let (Ok(tp), Ok(up), Ok(rp)) = (id_param(tenant_id), id_param(uid), id_param(rid))
            else {
                return ExitCode::FAILURE;
            };
            if store
                .provider()
                .execute_async(
                    "INSERT OR IGNORE INTO vs_user_role (tenant_id, user_id, role_id) VALUES (?, ?, ?)",
                    QueryOptions::new().bind_all(&[tp, up, rp]),
                )
                .await
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            println!(
                "{}",
                json!({ "user_id": uid.to_string(), "role_id": rid.to_string(), "assigned": true })
            );
            ExitCode::SUCCESS
        }
        RbacCommand::Effective {
            sqlite,
            tenant_name,
            user_id,
            app_id,
        } => {
            let (Ok(store), Ok(uid)) = (open(&sqlite).await, Id::parse_str(&user_id)) else {
                return ExitCode::FAILURE;
            };
            let _ = ensure_extended_schema(&store).await;
            let Ok(tenant_id) = ensure_tenant(&store, &tenant_name).await else {
                return ExitCode::FAILURE;
            };
            match resolve_effective_access(&store, tenant_id, uid, app_id.as_deref()).await {
                Ok(access) => {
                    if let Ok(text) = serde_json::to_string_pretty(&access) {
                        println!("{text}");
                    }
                    ExitCode::SUCCESS
                }
                Err(_) => ExitCode::FAILURE,
            }
        }
    }
}

/// Execute `vaelspire audit ...`.
pub async fn run_audit_command(cmd: AuditCommand) -> ExitCode {
    match cmd {
        AuditCommand::Tail { sqlite, limit } => {
            let Ok(store) = open(&sqlite).await else {
                return ExitCode::FAILURE;
            };
            let Ok(lim) = i64_param(limit.clamp(1, 500)) else {
                return ExitCode::FAILURE;
            };
            let Ok(rows) = store
                .provider()
                .fetch_all_async(
                    "SELECT id, actor_id, action, outcome, ip, created_at FROM auth_audit ORDER BY created_at DESC LIMIT ?",
                    QueryOptions::new().bind_all(&[lim]),
                )
                .await
            else {
                return ExitCode::FAILURE;
            };
            for r in rows {
                let id = r
                    .read::<Vec<u8>>("id")
                    .ok()
                    .and_then(|b| Id::from_slice(&b).ok())
                    .map(|u| u.to_string());
                let actor = r
                    .read::<Vec<u8>>("actor_id")
                    .ok()
                    .and_then(|b| Id::from_slice(&b).ok())
                    .map(|u| u.to_string());
                println!(
                    "{}",
                    json!({
                        "id": id,
                        "actor_id": actor,
                        "action": r.read::<String>("action").ok(),
                        "outcome": r.read::<String>("outcome").ok(),
                        "ip": r.read::<String>("ip").ok(),
                        "created_at": r.read::<String>("created_at").ok(),
                    })
                );
            }
            ExitCode::SUCCESS
        }
    }
}
