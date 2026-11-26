//! `OpenID` Connect 1.0 & OAuth 2.0 Identity Provider (`IdP`) engine for **Vaelspire**.
//!
//! Provides:
//! - Rotating `EdDSA` (`Ed25519`) signing keys + RFC 7517 JWKS (`/.well-known/jwks.json`)
//! - OIDC Discovery metadata (`/.well-known/openid-configuration`)
//! - Exact-match OAuth client registry (confidential + public PKCE clients)
//! - Authorization Code + PKCE (`S256`) single-use grant flow
//! - Refresh Token Rotation with automatic family revocation on replay
//! - `client_credentials` with strict scope attenuation for Non-Human Identities (service accounts & AI agents)
//! - Token Introspection (RFC 7662), Token Revocation (RFC 7009), and `UserInfo` verification
//!
//! No logging occurs inside this crate; callers inspect typed [`OidcError`] values.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::RwLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::Duration;
use vaelspire_core::{Id, Timestamp};
use vaelspire_verify::{Audience, Jwk, Jwks, TokenVerifier, VerifiedClaims};
use zeroize::Zeroizing;

/// Stable OAuth 2.0 / OIDC error codes per RFC 6749 §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcError {
    /// Missing or malformed request parameter (`invalid_request`).
    InvalidRequest,
    /// Unknown client or invalid client secret (`invalid_client`).
    InvalidClient,
    /// Expired, unknown, replayed, or mismatched code / PKCE / refresh token (`invalid_grant`).
    InvalidGrant,
    /// Client is not permitted to use the requested grant type (`unauthorized_client`).
    UnauthorizedClient,
    /// Requested grant type is not supported (`unsupported_grant_type`).
    UnsupportedGrantType,
    /// Requested scope exceeds client's allowed scopes (`invalid_scope`).
    InvalidScope,
    /// Access token is missing, invalid, expired, or revoked (`invalid_token`).
    InvalidToken,
    /// Internal cryptographic randomness or state error (`server_error`).
    ServerError,
}

impl OidcError {
    /// RFC 6749 error code string.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidToken => "invalid_token",
            Self::ServerError => "server_error",
        }
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for OidcError {}

/// OAuth 2.0 grant types supported by Vaelspire's `IdP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Interactive browser/CLI Authorization Code + PKCE (`S256`).
    AuthorizationCode,
    /// Rotating offline/refresh token exchange.
    RefreshToken,
    /// Machine-to-machine / AI agent Non-Human Identity grant with scope attenuation.
    ClientCredentials,
}

/// Registered OAuth 2.0 / OIDC client metadata.
#[derive(Clone)]
pub struct OidcClient {
    /// Public client identifier (e.g., `"vaelsgard"`).
    pub client_id: String,
    /// Display name shown on the consent screen.
    pub name: String,
    /// Owning Vaelspire tenant.
    pub tenant_id: Id,
    /// Exact allowed redirect URIs (no wildcards — prevents open redirects).
    pub redirect_uris: Vec<String>,
    /// Allowed OAuth scopes for this client.
    pub allowed_scopes: Vec<String>,
    /// Permitted grant types.
    pub grant_types: Vec<GrantType>,
    /// Keyed BLAKE3 digest of the client secret for confidential clients (`None` = public PKCE client).
    secret_digest: Option<[u8; 32]>,
    /// Whether PKCE `S256` is required (always enforced for public clients).
    pub require_pkce: bool,
}

impl fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcClient")
            .field("client_id", &self.client_id)
            .field("name", &self.name)
            .field("tenant_id", &self.tenant_id)
            .field("redirect_uris", &self.redirect_uris)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("grant_types", &self.grant_types)
            .field("confidential", &self.secret_digest.is_some())
            .field("require_pkce", &self.require_pkce)
            .finish()
    }
}

impl OidcClient {
    /// Whether this client is confidential (holds a registered client secret).
    #[must_use]
    pub const fn is_confidential(&self) -> bool {
        self.secret_digest.is_some()
    }
}

/// Input parameters for registering a new OAuth/OIDC client.
#[derive(Debug, Clone)]
pub struct RegisterClientInput {
    /// Public client identifier.
    pub client_id: String,
    /// Human-readable application name.
    pub name: String,
    /// Owning tenant identifier.
    pub tenant_id: Id,
    /// Exact allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed scopes (e.g., `["openid", "email", "profile", "offline_access"]`).
    pub allowed_scopes: Vec<String>,
    /// Permitted grant types.
    pub grant_types: Vec<GrantType>,
    /// `true` generates a 256-bit client secret (returned once); `false` creates a public PKCE client.
    pub confidential: bool,
}

/// Result of registering a client. `client_secret` is returned once for confidential clients.
pub struct RegisteredClient {
    /// Stored public client descriptor.
    pub client: OidcClient,
    /// Plaintext client secret for confidential clients (never stored in plaintext, never logged).
    pub client_secret: Option<Zeroizing<String>>,
}

impl fmt::Debug for RegisteredClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredClient")
            .field("client", &self.client)
            .field("has_secret", &self.client_secret.is_some())
            .finish()
    }
}

/// `OpenID` Connect Discovery 1.0 metadata (`/.well-known/openid-configuration`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// Issuer URL.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// `UserInfo` endpoint URL.
    pub userinfo_endpoint: String,
    /// JWKS endpoint URL.
    pub jwks_uri: String,
    /// RFC 7662 introspection endpoint URL.
    pub introspection_endpoint: String,
    /// RFC 7009 revocation endpoint URL.
    pub revocation_endpoint: String,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Supported ID token JWS signing algorithms.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported OAuth grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported PKCE challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported token endpoint authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported claims.
    pub claims_supported: Vec<String>,
}

/// Authenticated user context handed to [`OidcProvider::create_authorization_code`].
#[derive(Debug, Clone)]
pub struct AuthorizeSubject {
    /// User `UUIDv7`.
    pub user_id: Id,
    /// Owning tenant `UUIDv7`.
    pub tenant_id: Id,
    /// Normalized user email.
    pub email: String,
}

/// Validated authorization request parameters.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    /// OAuth `client_id`.
    pub client_id: String,
    /// Exact registered `redirect_uri`.
    pub redirect_uri: String,
    /// Space-delimited scopes requested.
    pub scope: String,
    /// Optional OIDC nonce echoed into the ID token.
    pub nonce: Option<String>,
    /// Optional PKCE `S256` challenge (required for public clients and PKCE-enforced clients).
    pub code_challenge: Option<String>,
    /// Optional PKCE method (only `"S256"` is accepted when present).
    pub code_challenge_method: Option<String>,
}

/// Standard RFC 6749 / OIDC token response payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Signed `EdDSA` access token.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Access token lifetime in seconds.
    pub expires_in: i64,
    /// Granted space-delimited scopes.
    pub scope: String,
    /// Signed `EdDSA` ID token (when `openid` scope is granted on interactive flows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Opaque rotating refresh token (when `offline_access` scope + `RefreshToken` grant are active).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("has_id_token", &self.id_token.is_some())
            .field("has_refresh_token", &self.refresh_token.is_some())
            .finish_non_exhaustive()
    }
}

/// Standard OIDC `UserInfo` response (`GET /oauth2/userinfo`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInfoResponse {
    /// Subject (`user_id` or `client_id`).
    pub sub: String,
    /// Normalized user email (if present in token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Owning tenant identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Granted scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// RFC 7662 Token Introspection response (`POST /oauth2/introspect`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active and unrevoked.
    pub active: bool,
    /// Subject identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Client identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Space-delimited scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Issuer URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Expiration timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issued-at timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Owning tenant identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

struct SigningKeyEntry {
    kid: String,
    signing_key: SigningKey,
    jwk: Jwk,
}

struct AuthCodeRecord {
    client_id: String,
    redirect_uri: String,
    scope: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    subject: AuthorizeSubject,
    expires_at: Timestamp,
    consumed: bool,
}

struct RefreshTokenRecord {
    family_id: Id,
    client_id: String,
    scope: String,
    subject: AuthorizeSubject,
    expires_at: Timestamp,
    rotated: bool,
    revoked: bool,
}

struct ProviderState {
    keys: Vec<SigningKeyEntry>,
    clients: HashMap<String, OidcClient>,
    auth_codes: HashMap<[u8; 32], AuthCodeRecord>,
    refresh_tokens: HashMap<[u8; 32], RefreshTokenRecord>,
    revoked_jtis: HashMap<String, i64>,
}

/// Configuration for [`OidcProvider`].
#[derive(Clone)]
pub struct OidcProviderConfig {
    /// Canonical issuer URL (e.g., `"https://auth.example.com"`, no trailing slash).
    pub issuer: String,
    /// 256-bit key used for keyed BLAKE3 hashing of codes, refresh tokens, and client secrets.
    pub digest_key: Zeroizing<[u8; 32]>,
    /// Access token TTL (default: 15 minutes).
    pub access_token_ttl: Duration,
    /// ID token TTL (default: 15 minutes).
    pub id_token_ttl: Duration,
    /// Authorization code TTL (default: 2 minutes).
    pub auth_code_ttl: Duration,
    /// Refresh token TTL (default: 14 days).
    pub refresh_token_ttl: Duration,
}

impl fmt::Debug for OidcProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProviderConfig")
            .field("issuer", &self.issuer)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("id_token_ttl", &self.id_token_ttl)
            .field("auth_code_ttl", &self.auth_code_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .finish_non_exhaustive()
    }
}

impl OidcProviderConfig {
    /// Construct defaults for `issuer` and `digest_key`.
    #[must_use]
    pub fn new(issuer: impl Into<String>, digest_key: [u8; 32]) -> Self {
        let trimmed = issuer.into().trim_end_matches('/').to_owned();
        Self {
            issuer: trimmed,
            digest_key: Zeroizing::new(digest_key),
            access_token_ttl: Duration::minutes(15),
            id_token_ttl: Duration::minutes(15),
            auth_code_ttl: Duration::minutes(2),
            refresh_token_ttl: Duration::days(14),
        }
    }
}

/// Thread-safe `OpenID` Connect 1.0 & OAuth 2.0 Identity Provider engine.
pub struct OidcProvider {
    config: OidcProviderConfig,
    state: RwLock<ProviderState>,
}

impl fmt::Debug for OidcProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProvider")
            .field("issuer", &self.config.issuer)
            .finish_non_exhaustive()
    }
}

impl OidcProvider {
    /// Initialize a new `IdP` with a freshly generated `Ed25519` signing key.
    ///
    /// # Errors
    /// Returns [`OidcError::ServerError`] if OS randomness fails.
    pub fn new(config: OidcProviderConfig) -> Result<Self, OidcError> {
        let initial = generate_signing_key()?;
        Ok(Self {
            config,
            state: RwLock::new(ProviderState {
                keys: vec![initial],
                clients: HashMap::new(),
                auth_codes: HashMap::new(),
                refresh_tokens: HashMap::new(),
                revoked_jtis: HashMap::new(),
            }),
        })
    }

    /// Rotate the active `Ed25519` signing key while retaining previous public keys in JWKS
    /// so already-issued tokens remain verifiable until expiry.
    ///
    /// # Errors
    /// Returns [`OidcError::ServerError`] on RNG or lock failure.
    pub fn rotate_signing_key(&self) -> Result<String, OidcError> {
        let next = generate_signing_key()?;
        let kid = next.kid.clone();
        let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
        guard.keys.insert(0, next);
        // Keep up to 4 historical verification keys in JWKS.
        guard.keys.truncate(5);
        Ok(kid)
    }

    /// Return the `OpenID` Connect Discovery 1.0 document.
    #[must_use]
    pub fn discovery(&self) -> DiscoveryDocument {
        let base = &self.config.issuer;
        DiscoveryDocument {
            issuer: base.clone(),
            authorization_endpoint: format!("{base}/oauth2/authorize"),
            token_endpoint: format!("{base}/oauth2/token"),
            userinfo_endpoint: format!("{base}/oauth2/userinfo"),
            jwks_uri: format!("{base}/.well-known/jwks.json"),
            introspection_endpoint: format!("{base}/oauth2/introspect"),
            revocation_endpoint: format!("{base}/oauth2/revoke"),
            response_types_supported: vec!["code".to_owned()],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["EdDSA".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
                "client_credentials".to_owned(),
            ],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_owned(),
                "client_secret_basic".to_owned(),
                "none".to_owned(),
            ],
            scopes_supported: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
                "offline_access".to_owned(),
            ],
            claims_supported: vec![
                "iss".to_owned(),
                "sub".to_owned(),
                "aud".to_owned(),
                "exp".to_owned(),
                "iat".to_owned(),
                "nonce".to_owned(),
                "email".to_owned(),
                "tenant_id".to_owned(),
            ],
        }
    }

    /// Export all active and retained public verification keys as RFC 7517 [`Jwks`].
    ///
    /// # Errors
    /// Returns [`OidcError::ServerError`] if the internal state lock is poisoned.
    pub fn jwks(&self) -> Result<Jwks, OidcError> {
        let guard = self.state.read().map_err(|_| OidcError::ServerError)?;
        Ok(Jwks {
            keys: guard.keys.iter().map(|entry| entry.jwk.clone()).collect(),
        })
    }

    /// Register a new OAuth 2.0 / OIDC client.
    ///
    /// # Errors
    /// Returns [`OidcError::InvalidRequest`] if `client_id` is empty or duplicate.
    pub fn register_client(
        &self,
        input: RegisterClientInput,
    ) -> Result<RegisteredClient, OidcError> {
        if input.client_id.trim().is_empty() || input.name.trim().is_empty() {
            return Err(OidcError::InvalidRequest);
        }

        let (secret_plain, secret_digest) = if input.confidential {
            let raw = random_token("vsc")?;
            let digest = keyed_digest(&self.config.digest_key, "oidc_client_secret", &raw);
            (Some(raw), Some(digest))
        } else {
            (None, None)
        };

        let client = OidcClient {
            client_id: input.client_id,
            name: input.name,
            tenant_id: input.tenant_id,
            redirect_uris: input.redirect_uris,
            allowed_scopes: input.allowed_scopes,
            grant_types: input.grant_types,
            secret_digest,
            require_pkce: !input.confidential,
        };

        let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
        if guard.clients.contains_key(&client.client_id) {
            return Err(OidcError::InvalidRequest);
        }
        guard
            .clients
            .insert(client.client_id.clone(), client.clone());

        Ok(RegisteredClient {
            client,
            client_secret: secret_plain,
        })
    }

    /// Look up public metadata for a registered client.
    ///
    /// # Errors
    /// Returns [`OidcError::InvalidClient`] if unknown.
    pub fn get_client(&self, client_id: &str) -> Result<OidcClient, OidcError> {
        let guard = self.state.read().map_err(|_| OidcError::ServerError)?;
        guard
            .clients
            .get(client_id)
            .cloned()
            .ok_or(OidcError::InvalidClient)
    }

    /// List all registered OAuth/OIDC clients (public metadata only; secrets never leave).
    ///
    /// # Errors
    /// Returns [`OidcError::ServerError`] if the internal lock is poisoned.
    pub fn list_clients(&self) -> Result<Vec<OidcClient>, OidcError> {
        let guard = self.state.read().map_err(|_| OidcError::ServerError)?;
        let mut clients: Vec<OidcClient> = guard.clients.values().cloned().collect();
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(clients)
    }

    /// Validate an interactive authorization request and mint a short-lived single-use code.
    ///
    /// # Errors
    /// Returns typed [`OidcError`] for unknown client, unregistered `redirect_uri`,
    /// disallowed scopes, or missing PKCE `S256` challenge.
    pub fn create_authorization_code(
        &self,
        req: &AuthorizeRequest,
        subject: AuthorizeSubject,
        now: Timestamp,
    ) -> Result<Zeroizing<String>, OidcError> {
        let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
        let client = guard
            .clients
            .get(&req.client_id)
            .ok_or(OidcError::InvalidClient)?;

        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(OidcError::UnauthorizedClient);
        }
        if !client.redirect_uris.iter().any(|u| u == &req.redirect_uri) {
            return Err(OidcError::InvalidRequest);
        }

        let normalized_scope = validate_scopes(&req.scope, &client.allowed_scopes)?;

        if let Some(method) = req.code_challenge_method.as_deref()
            && method != "S256"
        {
            return Err(OidcError::InvalidRequest);
        }
        if client.require_pkce && req.code_challenge.as_deref().unwrap_or("").is_empty() {
            return Err(OidcError::InvalidRequest);
        }

        let code = random_token("vsa")?;
        let digest = keyed_digest(&self.config.digest_key, "oidc_auth_code", &code);
        guard.auth_codes.insert(
            digest,
            AuthCodeRecord {
                client_id: req.client_id.clone(),
                redirect_uri: req.redirect_uri.clone(),
                scope: normalized_scope,
                nonce: req.nonce.clone(),
                code_challenge: req.code_challenge.clone(),
                subject,
                expires_at: now + self.config.auth_code_ttl,
                consumed: false,
            },
        );
        Ok(code)
    }

    /// Exchange an authorization code (verifying PKCE `S256` and confidential client secret)
    /// for signed `EdDSA` access + ID tokens and an optional rotating refresh token.
    ///
    /// # Errors
    /// Returns [`OidcError::InvalidClient`] or [`OidcError::InvalidGrant`] on any validation failure.
    pub fn exchange_authorization_code(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
        now: Timestamp,
    ) -> Result<TokenResponse, OidcError> {
        let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
        let client = guard
            .clients
            .get(client_id)
            .ok_or(OidcError::InvalidClient)?
            .clone();

        verify_client_auth(&client, client_secret, &self.config.digest_key)?;

        let code_digest = keyed_digest(&self.config.digest_key, "oidc_auth_code", code);
        let record = guard
            .auth_codes
            .get_mut(&code_digest)
            .ok_or(OidcError::InvalidGrant)?;

        if record.consumed || record.expires_at <= now {
            return Err(OidcError::InvalidGrant);
        }
        if record.client_id != client_id || record.redirect_uri != redirect_uri {
            return Err(OidcError::InvalidGrant);
        }
        if let Some(expected_challenge) = &record.code_challenge {
            let verifier = code_verifier.ok_or(OidcError::InvalidGrant)?;
            if !verify_pkce_s256(verifier, expected_challenge) {
                return Err(OidcError::InvalidGrant);
            }
        }

        record.consumed = true;
        let scope = record.scope.clone();
        let nonce = record.nonce.clone();
        let subject = record.subject.clone();

        let signing = guard.keys.first().ok_or(OidcError::ServerError)?;
        let access_token = sign_jwt(
            signing,
            &VerifiedClaims {
                iss: self.config.issuer.clone(),
                sub: subject.user_id.to_string(),
                aud: Audience::Single(client.client_id.clone()),
                exp: (now + self.config.access_token_ttl).unix_timestamp(),
                iat: now.unix_timestamp(),
                jti: Some(Id::now_v7().to_string()),
                nonce: None,
                email: Some(subject.email.clone()),
                tenant_id: Some(subject.tenant_id.to_string()),
                scope: Some(scope.clone()),
                client_id: Some(client.client_id.clone()),
                token_use: Some("access".to_owned()),
            },
        )?;

        let scopes: HashSet<&str> = scope.split_whitespace().collect();
        let id_token = if scopes.contains("openid") {
            Some(sign_jwt(
                signing,
                &VerifiedClaims {
                    iss: self.config.issuer.clone(),
                    sub: subject.user_id.to_string(),
                    aud: Audience::Single(client.client_id.clone()),
                    exp: (now + self.config.id_token_ttl).unix_timestamp(),
                    iat: now.unix_timestamp(),
                    jti: Some(Id::now_v7().to_string()),
                    nonce,
                    email: scopes.contains("email").then(|| subject.email.clone()),
                    tenant_id: Some(subject.tenant_id.to_string()),
                    scope: None,
                    client_id: Some(client.client_id.clone()),
                    token_use: Some("id".to_owned()),
                },
            )?)
        } else {
            None
        };

        let refresh_token = if scopes.contains("offline_access")
            && client.grant_types.contains(&GrantType::RefreshToken)
        {
            let rt = random_token("vsr")?;
            let rt_digest = keyed_digest(&self.config.digest_key, "oidc_refresh_token", &rt);
            guard.refresh_tokens.insert(
                rt_digest,
                RefreshTokenRecord {
                    family_id: Id::now_v7(),
                    client_id: client.client_id,
                    scope: scope.clone(),
                    subject,
                    expires_at: now + self.config.refresh_token_ttl,
                    rotated: false,
                    revoked: false,
                },
            );
            Some(rt.to_string())
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.config.access_token_ttl.whole_seconds(),
            scope,
            id_token,
            refresh_token,
        })
    }

    /// Exchange a refresh token with **strict rotation and reuse detection**.
    ///
    /// Re-presenting an already-rotated refresh token immediately revokes the entire token
    /// family and returns [`OidcError::InvalidGrant`].
    ///
    /// # Errors
    /// Returns [`OidcError::InvalidClient`] or [`OidcError::InvalidGrant`].
    pub fn exchange_refresh_token(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        refresh_token: &str,
        requested_scope: Option<&str>,
        now: Timestamp,
    ) -> Result<TokenResponse, OidcError> {
        let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
        let client = guard
            .clients
            .get(client_id)
            .ok_or(OidcError::InvalidClient)?
            .clone();

        if !client.grant_types.contains(&GrantType::RefreshToken) {
            return Err(OidcError::UnauthorizedClient);
        }
        verify_client_auth(&client, client_secret, &self.config.digest_key)?;

        let rt_digest = keyed_digest(&self.config.digest_key, "oidc_refresh_token", refresh_token);
        let (family_id, reuse_detected, valid_scope, subject) = {
            let record = guard
                .refresh_tokens
                .get_mut(&rt_digest)
                .ok_or(OidcError::InvalidGrant)?;
            if record.client_id != client_id || record.revoked || record.expires_at <= now {
                return Err(OidcError::InvalidGrant);
            }
            if record.rotated {
                (
                    record.family_id,
                    true,
                    String::new(),
                    record.subject.clone(),
                )
            } else {
                let allowed: Vec<String> = record
                    .scope
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect();
                let next_scope = match requested_scope {
                    Some(req) if !req.trim().is_empty() => validate_scopes(req, &allowed)?,
                    _ => record.scope.clone(),
                };
                record.rotated = true;
                (record.family_id, false, next_scope, record.subject.clone())
            }
        };

        if reuse_detected {
            for entry in guard.refresh_tokens.values_mut() {
                if entry.family_id == family_id {
                    entry.revoked = true;
                }
            }
            return Err(OidcError::InvalidGrant);
        }

        let signing = guard.keys.first().ok_or(OidcError::ServerError)?;
        let access_token = sign_jwt(
            signing,
            &VerifiedClaims {
                iss: self.config.issuer.clone(),
                sub: subject.user_id.to_string(),
                aud: Audience::Single(client.client_id.clone()),
                exp: (now + self.config.access_token_ttl).unix_timestamp(),
                iat: now.unix_timestamp(),
                jti: Some(Id::now_v7().to_string()),
                nonce: None,
                email: Some(subject.email.clone()),
                tenant_id: Some(subject.tenant_id.to_string()),
                scope: Some(valid_scope.clone()),
                client_id: Some(client.client_id.clone()),
                token_use: Some("access".to_owned()),
            },
        )?;

        let next_rt = random_token("vsr")?;
        let next_digest = keyed_digest(&self.config.digest_key, "oidc_refresh_token", &next_rt);
        guard.refresh_tokens.insert(
            next_digest,
            RefreshTokenRecord {
                family_id,
                client_id: client.client_id,
                scope: valid_scope.clone(),
                subject,
                expires_at: now + self.config.refresh_token_ttl,
                rotated: false,
                revoked: false,
            },
        );

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.config.access_token_ttl.whole_seconds(),
            scope: valid_scope,
            id_token: None,
            refresh_token: Some(next_rt.to_string()),
        })
    }

    /// Issue a short-lived machine-to-machine / AI agent token via `client_credentials`
    /// with strict scope attenuation (requested scopes must be a subset of allowed scopes).
    ///
    /// # Errors
    /// Returns [`OidcError::InvalidClient`], [`OidcError::UnauthorizedClient`], or [`OidcError::InvalidScope`].
    pub fn exchange_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
        requested_scope: Option<&str>,
        now: Timestamp,
    ) -> Result<TokenResponse, OidcError> {
        let guard = self.state.read().map_err(|_| OidcError::ServerError)?;
        let client = guard
            .clients
            .get(client_id)
            .ok_or(OidcError::InvalidClient)?;

        if !client.is_confidential() || !client.grant_types.contains(&GrantType::ClientCredentials)
        {
            return Err(OidcError::UnauthorizedClient);
        }
        verify_client_auth(client, Some(client_secret), &self.config.digest_key)?;

        let granted_scope = match requested_scope {
            Some(req) if !req.trim().is_empty() => validate_scopes(req, &client.allowed_scopes)?,
            _ => client.allowed_scopes.join(" "),
        };

        let signing = guard.keys.first().ok_or(OidcError::ServerError)?;
        let access_token = sign_jwt(
            signing,
            &VerifiedClaims {
                iss: self.config.issuer.clone(),
                sub: format!("client:{}", client.client_id),
                aud: Audience::Single(client.client_id.clone()),
                exp: (now + self.config.access_token_ttl).unix_timestamp(),
                iat: now.unix_timestamp(),
                jti: Some(Id::now_v7().to_string()),
                nonce: None,
                email: None,
                tenant_id: Some(client.tenant_id.to_string()),
                scope: Some(granted_scope.clone()),
                client_id: Some(client.client_id.clone()),
                token_use: Some("access".to_owned()),
            },
        )?;

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.config.access_token_ttl.whole_seconds(),
            scope: granted_scope,
            id_token: None,
            refresh_token: None,
        })
    }

    /// Validate a Bearer access token against active JWKS and revocation denylist,
    /// returning OIDC [`UserInfoResponse`].
    ///
    /// # Errors
    /// Returns [`OidcError::InvalidToken`] if expired, invalid, or revoked.
    pub fn userinfo(
        &self,
        access_token: &str,
        now: Timestamp,
    ) -> Result<UserInfoResponse, OidcError> {
        let claims = self.verify_access_token(access_token, now)?;
        Ok(UserInfoResponse {
            sub: claims.sub,
            email: claims.email,
            tenant_id: claims.tenant_id,
            scope: claims.scope,
        })
    }

    /// RFC 7662 Token Introspection. Invalid, expired, or revoked tokens return `active: false`.
    ///
    /// # Errors
    /// Returns [`OidcError::ServerError`] on lock poison.
    pub fn introspect(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<IntrospectionResponse, OidcError> {
        if let Ok(claims) = self.verify_access_token(token, now) {
            return Ok(IntrospectionResponse {
                active: true,
                sub: Some(claims.sub),
                client_id: claims.client_id,
                scope: claims.scope,
                iss: Some(claims.iss),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                tenant_id: claims.tenant_id,
            });
        }

        // Also support introspecting live refresh tokens.
        let guard = self.state.read().map_err(|_| OidcError::ServerError)?;
        let rt_digest = keyed_digest(&self.config.digest_key, "oidc_refresh_token", token);
        if let Some(rec) = guard.refresh_tokens.get(&rt_digest)
            && !rec.revoked
            && !rec.rotated
            && rec.expires_at > now
        {
            return Ok(IntrospectionResponse {
                active: true,
                sub: Some(rec.subject.user_id.to_string()),
                client_id: Some(rec.client_id.clone()),
                scope: Some(rec.scope.clone()),
                iss: Some(self.config.issuer.clone()),
                exp: Some(rec.expires_at.unix_timestamp()),
                iat: None,
                tenant_id: Some(rec.subject.tenant_id.to_string()),
            });
        }

        Ok(IntrospectionResponse {
            active: false,
            sub: None,
            client_id: None,
            scope: None,
            iss: None,
            exp: None,
            iat: None,
            tenant_id: None,
        })
    }

    /// RFC 7009 Token Revocation. Always succeeds idempotently for unknown tokens.
    ///
    /// # Errors
    /// Returns [`OidcError::ServerError`] on lock poison.
    pub fn revoke(&self, token: &str, now: Timestamp) -> Result<(), OidcError> {
        // 1. Try revoking as a refresh token (revokes entire family).
        let rt_digest = keyed_digest(&self.config.digest_key, "oidc_refresh_token", token);
        {
            let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
            if let Some(family_id) = guard.refresh_tokens.get(&rt_digest).map(|r| r.family_id) {
                for entry in guard.refresh_tokens.values_mut() {
                    if entry.family_id == family_id {
                        entry.revoked = true;
                    }
                }
                return Ok(());
            }
        }

        // 2. Try revoking as a signed access token by recording its `jti` until expiry.
        if let Ok(claims) = self.verify_access_token(token, now)
            && let Some(jti) = claims.jti
        {
            let mut guard = self.state.write().map_err(|_| OidcError::ServerError)?;
            let now_ts = now.unix_timestamp();
            guard.revoked_jtis.retain(|_, exp| *exp > now_ts);
            guard.revoked_jtis.insert(jti, claims.exp);
        }

        Ok(())
    }

    fn verify_access_token(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Result<VerifiedClaims, OidcError> {
        let jwks = self.jwks()?;
        let verifier = TokenVerifier::from_jwks(&jwks)
            .map_err(|_| OidcError::ServerError)?
            .require_issuer(&self.config.issuer);
        let claims = verifier
            .verify(token, now)
            .map_err(|_| OidcError::InvalidToken)?;

        if claims.token_use.as_deref() != Some("access") {
            return Err(OidcError::InvalidToken);
        }
        if let Some(jti) = &claims.jti {
            let guard = self.state.read().map_err(|_| OidcError::ServerError)?;
            if guard.revoked_jtis.contains_key(jti) {
                return Err(OidcError::InvalidToken);
            }
        }
        Ok(claims)
    }
}

fn generate_signing_key() -> Result<SigningKeyEntry, OidcError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| OidcError::ServerError)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying = signing_key.verifying_key();
    let x = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
    // RFC 7638 canonical JWK thumbprint for OKP Ed25519
    let thumbprint_input = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let digest = Sha256::digest(thumbprint_input.as_bytes());
    let kid = URL_SAFE_NO_PAD.encode(&digest[..16]);

    let jwk = Jwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        alg: Some("EdDSA".to_owned()),
        key_use: Some("sig".to_owned()),
        kid: kid.clone(),
        x,
    };

    Ok(SigningKeyEntry {
        kid,
        signing_key,
        jwk,
    })
}

fn sign_jwt(entry: &SigningKeyEntry, claims: &VerifiedClaims) -> Result<String, OidcError> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": entry.kid,
    });
    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| OidcError::ServerError)?);
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|_| OidcError::ServerError)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = entry.signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn random_token(prefix: &str) -> Result<Zeroizing<String>, OidcError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut()).map_err(|_| OidcError::ServerError)?;
    Ok(Zeroizing::new(format!(
        "{prefix}_{}",
        URL_SAFE_NO_PAD.encode(raw.as_ref())
    )))
}

fn keyed_digest(key: &[u8; 32], domain: &str, value: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(value.as_bytes());
    *hasher.finalize().as_bytes()
}

fn verify_client_auth(
    client: &OidcClient,
    presented_secret: Option<&str>,
    digest_key: &[u8; 32],
) -> Result<(), OidcError> {
    if let Some(expected_digest) = &client.secret_digest {
        let presented = presented_secret.ok_or(OidcError::InvalidClient)?;
        let actual = keyed_digest(digest_key, "oidc_client_secret", presented);
        if !bool::from(actual.ct_eq(expected_digest)) {
            return Err(OidcError::InvalidClient);
        }
    }
    Ok(())
}

fn verify_pkce_s256(verifier: &str, expected_challenge: &str) -> bool {
    if verifier.len() < 43 || verifier.len() > 128 {
        return false;
    }
    let hash = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);
    bool::from(computed.as_bytes().ct_eq(expected_challenge.as_bytes()))
}

fn validate_scopes(requested: &str, allowed: &[String]) -> Result<String, OidcError> {
    let allowed_set: HashSet<&str> = allowed.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for scope in requested.split_whitespace() {
        if !allowed_set.contains(scope) {
            return Err(OidcError::InvalidScope);
        }
        if seen.insert(scope) {
            out.push(scope);
        }
    }
    if out.is_empty() {
        return Err(OidcError::InvalidScope);
    }
    Ok(out.join(" "))
}
