//! `vaelspire` single-binary CLI and HTTP server entrypoint.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use vaelspire::alerts::{AlertCliArgs, AlertCommand, run_alert_command};
use vaelspire::bootstrap::{BootstrapOutcome, bootstrap_admin, ensure_tenant};
use vaelspire::cli_mgmt::{
    AuditCommand, OrgCommand, RbacCommand, UserCommand, run_audit_command, run_org_command,
    run_rbac_command, run_user_command,
};
use vaelspire::config::{LogFormat, ServerConfig, UiMode, generate_hex_key, load_or_create_key};
use vaelspire::ext_store::ensure_extended_schema;
use vaelspire::security::{IpCidr, IpSource};
use vaelspire::server::serve;
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
use vaelspire_core::privacy::{AuditIpMode, PiiLogMode, format_email_for_log};
use vaelspire_store_sqlite::open;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "vaelspire",
    version,
    about = "Ultra-lightweight Rust identity & authentication server + CLI by Neotales"
)]
struct Cli {
    /// Log output format (`pretty` or `json`).
    #[arg(
        long,
        env = "VAELSPIRE_LOG_FORMAT",
        default_value = "pretty",
        global = true
    )]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the Vaelspire Core HTTP server (Auth API + OIDC + SCIM + RBAC + /forward-auth + /metrics).
    Serve(Box<ServeArgs>),
    /// Open the database and apply pending Vaelspire schema migrations.
    Migrate(DbArgs),
    /// Generate a cryptographically random 256-bit hex key for `VAELSPIRE_AUTH_KEY`.
    Keygen,
    /// Administrative provisioning commands.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// User lifecycle & GDPR management commands.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Organization policy & domain verification commands.
    Org {
        #[command(subcommand)]
        command: OrgCommand,
    },
    /// Org-wide & per-application RBAC (roles, permissions, effective access) commands.
    Rbac {
        #[command(subcommand)]
        command: RbacCommand,
    },
    /// Append-only audit log inspection commands.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Multi-sink alert testing and diagnostics (`vaelspire-alerts`).
    Alert {
        #[command(subcommand)]
        command: AlertCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Idempotently create the default tenant and initial administrator account.
    Bootstrap(BootstrapArgs),
}

#[derive(Debug, Args)]
struct DbArgs {
    /// Path to the `SQLite` database file.
    #[arg(
        long,
        env = "VAELSPIRE_SQLITE_PATH",
        default_value = "./vaelspire.sqlite"
    )]
    sqlite: PathBuf,
}

#[derive(Debug, Args)]
struct BootstrapArgs {
    /// Path to the `SQLite` database file.
    #[arg(
        long,
        env = "VAELSPIRE_SQLITE_PATH",
        default_value = "./vaelspire.sqlite"
    )]
    sqlite: PathBuf,

    /// Default tenant name.
    #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
    tenant_name: String,

    /// 64-char hex digest key (auto-created at `<sqlite>.key` when omitted).
    #[arg(long, env = "VAELSPIRE_AUTH_KEY")]
    auth_key: Option<String>,

    /// Administrator email address.
    #[arg(long, env = "VAELSPIRE_ADMIN_EMAIL")]
    email: String,

    /// Administrator password (prefer passing via `VAELSPIRE_ADMIN_PASSWORD` env var).
    #[arg(long, env = "VAELSPIRE_ADMIN_PASSWORD")]
    password: String,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
struct ServeArgs {
    /// Address and port to listen on.
    #[arg(long, env = "VAELSPIRE_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// Path to the `SQLite` database file.
    #[arg(
        long,
        env = "VAELSPIRE_SQLITE_PATH",
        default_value = "./vaelspire.sqlite"
    )]
    sqlite: PathBuf,

    /// Default tenant name (reused across restarts or created on first run).
    #[arg(long, env = "VAELSPIRE_TENANT_NAME", default_value = "default")]
    tenant_name: String,

    /// 64-char hex digest key (auto-created at `<sqlite>.key` when omitted).
    #[arg(long, env = "VAELSPIRE_AUTH_KEY")]
    auth_key: Option<String>,

    /// Allow non-Secure cookies over plain HTTP (for local development only).
    #[arg(long, env = "VAELSPIRE_INSECURE_HTTP", default_value_t = false)]
    insecure_http: bool,

    /// Comma-separated list of allowed `Origin` headers for state-changing requests.
    #[arg(long, env = "VAELSPIRE_ALLOWED_ORIGINS", value_delimiter = ',')]
    allowed_origins: Option<Vec<String>>,

    /// Trust the first `X-Forwarded-For` header entry behind a reverse proxy.
    #[arg(long, env = "VAELSPIRE_TRUST_PROXY", default_value_t = false)]
    trust_proxy: bool,

    /// Header source for trusted client IP extraction (`direct`, `x-forwarded-for`, `cf-connecting-ip`, `forwarded`).
    #[arg(long, env = "VAELSPIRE_IP_SOURCE", default_value = "direct")]
    ip_source: IpSource,

    /// Comma-separated trusted proxy CIDR blocks (e.g. `10.0.0.0/8,127.0.0.1/32`).
    #[arg(long, env = "VAELSPIRE_TRUSTED_PROXIES", value_delimiter = ',')]
    trusted_proxies: Vec<String>,

    /// Session cookie name.
    #[arg(
        long,
        env = "VAELSPIRE_SESSION_COOKIE",
        default_value = DEFAULT_SESSION_COOKIE
    )]
    session_cookie: String,

    /// CSRF cookie name.
    #[arg(long, env = "VAELSPIRE_CSRF_COOKIE", default_value = DEFAULT_CSRF_COOKIE)]
    csrf_cookie: String,

    /// API-key prefix (1-16 ASCII alphanumeric or `-` chars).
    #[arg(long, env = "VAELSPIRE_API_KEY_PREFIX", default_value = "vsp")]
    api_key_prefix: String,

    /// Disable transactional append-only audit rows.
    #[arg(long, env = "VAELSPIRE_NO_AUDITING", default_value_t = false)]
    no_auditing: bool,

    /// Disable role, permission, and group write endpoints.
    #[arg(long, env = "VAELSPIRE_NO_ROLES", default_value_t = false)]
    no_roles: bool,

    /// Maximum state-changing requests per client IP per rate-limit window.
    #[arg(long, env = "VAELSPIRE_RATE_LIMIT_MAX", default_value_t = 30)]
    rate_limit_max: usize,

    /// Rate-limit window length in seconds.
    #[arg(long, env = "VAELSPIRE_RATE_LIMIT_WINDOW_SECS", default_value_t = 60)]
    rate_limit_window_secs: u64,

    /// Optional login URL to redirect unauthenticated `/forward-auth` callers to.
    #[arg(long, env = "VAELSPIRE_FORWARD_AUTH_LOGIN_URL")]
    forward_auth_login_url: Option<String>,

    /// Canonical public OIDC issuer URL (defaults to `http://<bind>` or `https://<bind>`).
    #[arg(long, env = "VAELSPIRE_ISSUER")]
    issuer: Option<String>,

    /// Web UI serving mode (`embedded`, `external`, or `api-only`).
    #[arg(long, env = "VAELSPIRE_UI_MODE", default_value = "embedded")]
    ui_mode: UiMode,

    /// Email PII redaction mode in logs (`masked`, `id-only`, or `full`).
    #[arg(long, env = "VAELSPIRE_PII_LOG_MODE", default_value = "masked")]
    pii_log_mode: String,

    /// IP address retention mode in append-only audit logs (`full`, `truncated`, or `none`).
    #[arg(long, env = "VAELSPIRE_AUDIT_IP_MODE", default_value = "full")]
    audit_ip_mode: String,

    /// Disable sliding session expirations (use fixed session timeout instead).
    #[arg(long, env = "VAELSPIRE_SESSION_FIXED", default_value_t = false)]
    session_fixed: bool,

    /// Idle (or fixed) session lifetime in seconds (default 24h).
    #[arg(long, env = "VAELSPIRE_SESSION_IDLE_SECS", default_value_t = 86_400)]
    session_idle_secs: u64,

    /// Optional hard absolute maximum session lifetime in seconds (0 = no hard cap; default 7 days).
    #[arg(long, env = "VAELSPIRE_SESSION_MAX_SECS", default_value_t = 604_800)]
    session_max_secs: u64,

    /// Optional WebAuthn Relying Party ID (defaults to host of `--issuer`).
    #[arg(long, env = "VAELSPIRE_RP_ID")]
    rp_id: Option<String>,

    /// Optional WebAuthn Relying Party origin (defaults to `--issuer`).
    #[arg(long, env = "VAELSPIRE_RP_ORIGIN")]
    rp_origin: Option<String>,

    /// Optional initial admin email to bootstrap idempotently on startup.
    #[arg(long, env = "VAELSPIRE_ADMIN_EMAIL")]
    admin_email: Option<String>,

    /// Optional initial admin password (used together with `--admin-email`).
    #[arg(long, env = "VAELSPIRE_ADMIN_PASSWORD")]
    admin_password: Option<String>,

    /// Optional multi-sink alerting configuration (`vaelspire-alerts`).
    #[command(flatten)]
    alerts: AlertCliArgs,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if matches!(cli.command, Command::Keygen) {
        return match generate_hex_key() {
            Ok(hex) => {
                println!("{}", hex.as_str());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        };
    }

    init_tracing(cli.log_format);

    match cli.command {
        Command::User { command } => run_user_command(command).await,
        Command::Org { command } => run_org_command(command).await,
        Command::Rbac { command } => run_rbac_command(command).await,
        Command::Audit { command } => run_audit_command(command).await,
        Command::Alert { command } => run_alert_command(command).await,
        other => match run(other).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                tracing::error!(error = %err, "vaelspire command failed");
                ExitCode::FAILURE
            }
        },
    }
}

#[allow(clippy::too_many_lines)]
async fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Keygen
        | Command::User { .. }
        | Command::Org { .. }
        | Command::Rbac { .. }
        | Command::Audit { .. }
        | Command::Alert { .. } => unreachable!("handled directly in main"),
        Command::Migrate(args) => {
            let store = open(&args.sqlite).await?;
            ensure_extended_schema(&store).await?;
            tracing::info!(sqlite = %args.sqlite.display(), "migrations verified (core + extended)");
            Ok(())
        }
        Command::Admin {
            command: AdminCommand::Bootstrap(args),
        } => {
            let (digest_key, key_file) =
                load_or_create_key(args.auth_key.as_deref(), &args.sqlite)?;
            if let Some(path) = key_file {
                tracing::info!(key_file = %path.display(), "loaded local digest key file");
            }
            let store = open(&args.sqlite).await?;
            ensure_extended_schema(&store).await?;
            let tenant_id = ensure_tenant(&store, &args.tenant_name).await?;
            let outcome = bootstrap_admin(
                &store,
                tenant_id,
                &args.email,
                Zeroizing::new(args.password),
                *digest_key,
            )
            .await?;
            let masked = format_email_for_log(&args.email, PiiLogMode::Masked);
            match outcome {
                BootstrapOutcome::Created(user_id) => {
                    tracing::info!(%tenant_id, %user_id, email = %masked, "admin created");
                }
                BootstrapOutcome::AlreadyExists(user_id) => {
                    tracing::info!(%tenant_id, %user_id, email = %masked, "admin already exists");
                }
            }
            Ok(())
        }
        Command::Serve(args) => {
            let pii_log_mode = PiiLogMode::parse(&args.pii_log_mode).unwrap_or_default();
            let audit_ip_mode = AuditIpMode::parse(&args.audit_ip_mode).unwrap_or_default();
            let trusted_proxies: Vec<IpCidr> = args
                .trusted_proxies
                .iter()
                .filter_map(|raw| IpCidr::parse(raw))
                .collect();

            let (digest_key, key_file) =
                load_or_create_key(args.auth_key.as_deref(), &args.sqlite)?;
            if let Some(path) = key_file {
                tracing::info!(key_file = %path.display(), "using local digest key file");
            }

            let store = Arc::new(open(&args.sqlite).await?);
            ensure_extended_schema(&store).await?;
            let tenant_id = ensure_tenant(&store, &args.tenant_name).await?;

            if let (Some(email), Some(password)) = (args.admin_email, args.admin_password) {
                let masked = format_email_for_log(&email, pii_log_mode);
                match bootstrap_admin(
                    &store,
                    tenant_id,
                    &email,
                    Zeroizing::new(password),
                    *digest_key,
                )
                .await?
                {
                    BootstrapOutcome::Created(user_id) => {
                        tracing::info!(%tenant_id, %user_id, email = %masked, "bootstrapped initial admin");
                    }
                    BootstrapOutcome::AlreadyExists(user_id) => {
                        tracing::info!(%tenant_id, %user_id, email = %masked, "initial admin already present");
                    }
                }
            }

            let cookie_secure = !args.insecure_http;
            if !cookie_secure && !args.bind.ip().is_loopback() {
                tracing::warn!(
                    bind = %args.bind,
                    "running with --insecure-http on a non-loopback address; enable TLS in production"
                );
            }

            let scheme = if cookie_secure { "https" } else { "http" };
            let issuer_url = args
                .issuer
                .unwrap_or_else(|| format!("{scheme}://{}", args.bind));

            let session_max_lifetime =
                (args.session_max_secs > 0).then(|| Duration::from_secs(args.session_max_secs));
            let alerts = args.alerts.to_alerts_config()?;

            let config = ServerConfig {
                bind: args.bind,
                sqlite_path: args.sqlite,
                tenant_name: args.tenant_name,
                digest_key,
                cookie_secure,
                allowed_origins: args.allowed_origins,
                trust_proxy: args.trust_proxy,
                session_cookie: args.session_cookie,
                csrf_cookie: args.csrf_cookie,
                api_key_prefix: args.api_key_prefix,
                auditing: !args.no_auditing,
                roles: !args.no_roles,
                rate_limit: (
                    args.rate_limit_max,
                    Duration::from_secs(args.rate_limit_window_secs),
                ),
                forward_auth_login_url: args.forward_auth_login_url,
                issuer_url,
                ui_mode: args.ui_mode,
                pii_log_mode,
                audit_ip_mode,
                ip_source: args.ip_source,
                trusted_proxies,
                session_sliding: !args.session_fixed,
                session_idle_ttl: Duration::from_secs(args.session_idle_secs),
                session_max_lifetime,
                rp_id: args.rp_id,
                rp_origin: args.rp_origin,
                alerts,
            };

            serve(store, tenant_id, config).await
        }
    }
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("vaelspire=info,tower_http=info"));
    match format {
        LogFormat::Pretty => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
    }
}
