//! `vaelspire` single-binary CLI and HTTP server entrypoint.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use vaelspire::bootstrap::{BootstrapOutcome, bootstrap_admin, ensure_tenant};
use vaelspire::config::{LogFormat, ServerConfig, UiMode, generate_hex_key, load_or_create_key};
use vaelspire::server::serve;
use vaelspire_axum::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE};
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
    /// Start the Vaelspire Core HTTP server (Auth API + /forward-auth + /metrics).
    Serve(ServeArgs),
    /// Open the database and apply pending Vaelspire schema migrations.
    Migrate(DbArgs),
    /// Generate a cryptographically random 256-bit hex key for `VAELSPIRE_AUTH_KEY`.
    Keygen,
    /// Administrative provisioning commands.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Idempotently create the default tenant and initial administrator account.
    Bootstrap(BootstrapArgs),
}

#[derive(Debug, Args)]
struct DbArgs {
    /// Path to the SQLite database file.
    #[arg(
        long,
        env = "VAELSPIRE_SQLITE_PATH",
        default_value = "./vaelspire.sqlite"
    )]
    sqlite: PathBuf,
}

#[derive(Debug, Args)]
struct BootstrapArgs {
    /// Path to the SQLite database file.
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

    /// Path to the SQLite database file.
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

    /// Optional initial admin email to bootstrap idempotently on startup.
    #[arg(long, env = "VAELSPIRE_ADMIN_EMAIL")]
    admin_email: Option<String>,

    /// Optional initial admin password (used together with `--admin-email`).
    #[arg(long, env = "VAELSPIRE_ADMIN_PASSWORD")]
    admin_password: Option<String>,
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

    match run(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "vaelspire command failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Keygen => unreachable!("handled before tracing init"),
        Command::Migrate(args) => {
            let _store = open(&args.sqlite).await?;
            tracing::info!(sqlite = %args.sqlite.display(), "migrations verified");
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
            let tenant_id = ensure_tenant(&store, &args.tenant_name).await?;
            let outcome = bootstrap_admin(
                &store,
                tenant_id,
                &args.email,
                Zeroizing::new(args.password),
                *digest_key,
            )
            .await?;
            match outcome {
                BootstrapOutcome::Created(user_id) => {
                    tracing::info!(%tenant_id, %user_id, email = %args.email, "admin created");
                }
                BootstrapOutcome::AlreadyExists(user_id) => {
                    tracing::info!(%tenant_id, %user_id, email = %args.email, "admin already exists");
                }
            }
            Ok(())
        }
        Command::Serve(args) => {
            let (digest_key, key_file) =
                load_or_create_key(args.auth_key.as_deref(), &args.sqlite)?;
            if let Some(path) = key_file {
                tracing::info!(key_file = %path.display(), "using local digest key file");
            }

            let store = Arc::new(open(&args.sqlite).await?);
            let tenant_id = ensure_tenant(&store, &args.tenant_name).await?;

            if let (Some(email), Some(password)) = (args.admin_email, args.admin_password) {
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
                        tracing::info!(%tenant_id, %user_id, %email, "bootstrapped initial admin");
                    }
                    BootstrapOutcome::AlreadyExists(user_id) => {
                        tracing::info!(%tenant_id, %user_id, %email, "initial admin already present");
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
