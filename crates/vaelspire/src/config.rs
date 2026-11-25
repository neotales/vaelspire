//! Configuration and key-handling helpers for the `vaelspire` CLI and server.

use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

/// Output format for server logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// Human-readable logs for local development.
    Pretty,
    /// Structured JSON logs for production log collectors.
    Json,
}

/// Errors encountered while loading or validating server configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// The supplied hex key was not 64 hexadecimal characters (32 bytes).
    InvalidAuthKey,
    /// Operating-system randomness failed.
    Randomness,
    /// Reading or persisting the local auth key file failed.
    KeyIo(std::io::Error),
    /// An invalid API key prefix was provided.
    InvalidApiKeyPrefix,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthKey => f.write_str(
                "VAELSPIRE_AUTH_KEY must be exactly 64 hexadecimal characters (32 bytes)",
            ),
            Self::Randomness => f.write_str("failed to generate cryptographic random bytes"),
            Self::KeyIo(err) => write!(f, "failed to read or write auth key file: {err}"),
            Self::InvalidApiKeyPrefix => {
                f.write_str("api key prefix must be 1-16 ASCII alphanumeric or '-' characters")
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyIo(err) => Some(err),
            _ => None,
        }
    }
}

/// Runtime configuration for [`crate::server::serve`].
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerConfig {
    /// Socket address the HTTP listener binds to.
    pub bind: SocketAddr,
    /// Path to the SQLite database file.
    pub sqlite_path: PathBuf,
    /// Default tenant name (reused across restarts or created on first boot).
    pub tenant_name: String,
    /// 256-bit key for keyed BLAKE3 session, proof, and API-key digests.
    pub digest_key: Zeroizing<[u8; 32]>,
    /// Marks session and CSRF cookies `Secure` (should be `true` behind TLS).
    pub cookie_secure: bool,
    /// Explicit allowed `Origin` headers for state-changing routes.
    /// `None` accepts localhost origins only.
    pub allowed_origins: Option<Vec<String>>,
    /// Trust the first `X-Forwarded-For` entry for client IP audit/rate-limit keys.
    pub trust_proxy: bool,
    /// Session cookie name (defaults to [`vaelspire_axum::DEFAULT_SESSION_COOKIE`]).
    pub session_cookie: String,
    /// CSRF cookie name (defaults to [`vaelspire_axum::DEFAULT_CSRF_COOKIE`]).
    pub csrf_cookie: String,
    /// Prefix for issued API keys (defaults to `vsp`).
    pub api_key_prefix: String,
    /// Enable transactional append-only audit rows.
    pub auditing: bool,
    /// Enable role, permission, and group write routes.
    pub roles: bool,
    /// Fixed-window state-changing rate limit (`max_requests`, `window`).
    pub rate_limit: (usize, Duration),
    /// Optional server-configured login URL for `/forward-auth` unauthenticated redirects.
    /// When `None`, `/forward-auth` returns `401 Unauthorized`.
    pub forward_auth_login_url: Option<String>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind", &self.bind)
            .field("sqlite_path", &self.sqlite_path)
            .field("tenant_name", &self.tenant_name)
            .field("cookie_secure", &self.cookie_secure)
            .field("allowed_origins", &self.allowed_origins)
            .field("trust_proxy", &self.trust_proxy)
            .field("session_cookie", &self.session_cookie)
            .field("csrf_cookie", &self.csrf_cookie)
            .field("api_key_prefix", &self.api_key_prefix)
            .field("auditing", &self.auditing)
            .field("roles", &self.roles)
            .field("rate_limit", &self.rate_limit)
            .field("forward_auth_login_url", &self.forward_auth_login_url)
            .finish_non_exhaustive()
    }
}

/// Generate a cryptographically random 32-byte key formatted as 64 lowercase hex chars.
///
/// # Errors
/// Returns [`ConfigError::Randomness`] if the OS CSPRNG fails.
pub fn generate_hex_key() -> Result<Zeroizing<String>, ConfigError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut()).map_err(|_| ConfigError::Randomness)?;
    Ok(Zeroizing::new(encode_hex(raw.as_ref())))
}

/// Decode a 64-character hex string into a 32-byte key.
///
/// # Errors
/// Returns [`ConfigError::InvalidAuthKey`] if the length is not 64 or any byte is non-hex.
pub fn parse_hex_key(hex_str: &str) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 {
        return Err(ConfigError::InvalidAuthKey);
    }
    let bytes = trimmed.as_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    for (idx, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or(ConfigError::InvalidAuthKey)?;
        let lo = hex_nibble(chunk[1]).ok_or(ConfigError::InvalidAuthKey)?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Load a 32-byte digest key from `explicit_hex`, or load/create `<db>.key` beside `sqlite_path`.
///
/// On Unix, newly created key files are written with mode `0600`.
///
/// # Errors
/// Returns [`ConfigError`] if parsing, random generation, or filesystem I/O fails.
pub fn load_or_create_key(
    explicit_hex: Option<&str>,
    sqlite_path: &Path,
) -> Result<(Zeroizing<[u8; 32]>, Option<PathBuf>), ConfigError> {
    if let Some(hex) = explicit_hex {
        return Ok((parse_hex_key(hex)?, None));
    }

    let key_path = key_file_beside(sqlite_path);
    if key_path.exists() {
        let content = Zeroizing::new(fs::read_to_string(&key_path).map_err(ConfigError::KeyIo)?);
        return Ok((parse_hex_key(&content)?, Some(key_path)));
    }

    if let Some(parent) = key_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(ConfigError::KeyIo)?;
    }

    let generated = generate_hex_key()?;
    write_secret_file(&key_path, generated.as_bytes())?;
    let parsed = parse_hex_key(&generated)?;
    Ok((parsed, Some(key_path)))
}

fn key_file_beside(sqlite_path: &Path) -> PathBuf {
    let mut path = sqlite_path.as_os_str().to_os_string();
    path.push(".key");
    PathBuf::from(path)
}

fn write_secret_file(path: &Path, content: &[u8]) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(ConfigError::KeyIo)?;
        file.write_all(content).map_err(ConfigError::KeyIo)?;
        file.write_all(b"\n").map_err(ConfigError::KeyIo)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut buf = content.to_vec();
        buf.push(b'\n');
        fs::write(path, buf).map_err(ConfigError::KeyIo)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
