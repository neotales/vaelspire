//! Zero-database stateless `EdDSA` (`Ed25519`) JWT & JWKS verifier for **Vaelspire** tokens.
//!
//! Embed this crate in **Vaelsgard** or any Rust service to verify Vaelspire OIDC ID tokens
//! and access tokens locally with zero per-request network round-trips.

use std::collections::HashMap;
use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Verification failure — opaque to untrusted callers, typed for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Token did not have three base64url dot-separated JWT segments.
    MalformedToken,
    /// Base64url or JSON decoding of header or claims failed.
    InvalidEncoding,
    /// Algorithm was not `EdDSA` or `kid` was missing.
    UnsupportedHeader,
    /// No public key in the JWKS matched the token's `kid`.
    UnknownKey,
    /// `Ed25519` signature verification failed.
    InvalidSignature,
    /// Token `exp` is at or before `now` (minus configured clock skew).
    Expired,
    /// Token `nbf` or `iat` is in the future beyond configured clock skew.
    NotYetValid,
    /// Token `iss` did not match expected issuer.
    IssuerMismatch,
    /// Token `aud` did not contain the expected audience.
    AudienceMismatch,
    /// JWKS JSON contained an invalid `Ed25519` key.
    InvalidJwk,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedToken => f.write_str("malformed JWT structure"),
            Self::InvalidEncoding => f.write_str("invalid JWT base64url or JSON encoding"),
            Self::UnsupportedHeader => f.write_str("unsupported JWT header or algorithm"),
            Self::UnknownKey => f.write_str("signing key id not found in JWKS"),
            Self::InvalidSignature => f.write_str("JWT EdDSA signature verification failed"),
            Self::Expired => f.write_str("JWT has expired"),
            Self::NotYetValid => f.write_str("JWT is not yet valid"),
            Self::IssuerMismatch => f.write_str("JWT issuer does not match"),
            Self::AudienceMismatch => f.write_str("JWT audience does not match"),
            Self::InvalidJwk => f.write_str("invalid Ed25519 JWK entry"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Single RFC 7517 OKP (`Ed25519`) public JSON Web Key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (must be `"OKP"`).
    pub kty: String,
    /// Curve name (must be `"Ed25519"`).
    pub crv: String,
    /// Algorithm (`"EdDSA"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key use (`"sig"`).
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    /// Key identifier matched against JWT `kid` header.
    pub kid: String,
    /// Base64url-encoded 32-byte `Ed25519` public key.
    pub x: String,
}

/// RFC 7517 JSON Web Key Set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// Public verification keys.
    pub keys: Vec<Jwk>,
}

/// Audience claim supporting either a single string or a list of strings per RFC 7519.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience string.
    Single(String),
    /// Multiple audience strings.
    Multiple(Vec<String>),
}

impl Audience {
    /// Whether this audience claim contains `expected`.
    #[must_use]
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multiple(list) => list.iter().any(|s| s == expected),
        }
    }
}

/// Verified Vaelspire OIDC / OAuth 2.0 JWT claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedClaims {
    /// Issuer URL (`iss`).
    pub iss: String,
    /// Subject identifier (`sub`, user `UUIDv7` or client id for `client_credentials`).
    pub sub: String,
    /// Intended audience (`aud`).
    pub aud: Audience,
    /// Exclusive Unix-seconds expiration (`exp`).
    pub exp: i64,
    /// Issued-at Unix seconds (`iat`).
    pub iat: i64,
    /// Optional JWT identifier (`jti`) for revocation / replay checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Optional OIDC nonce echoed in ID tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional normalized email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional owning tenant identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Optional space-delimited OAuth scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional OAuth client identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Token kind (`"id"` or `"access"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_use: Option<String>,
}

impl VerifiedClaims {
    /// Split the `scope` claim into individual space-separated scope strings.
    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_deref()
            .map_or_default(|s| s.split_whitespace().collect())
    }

    /// Whether the token carries `required_scope`.
    #[must_use]
    pub fn has_scope(&self, required_scope: &str) -> bool {
        self.scopes().contains(&required_scope)
    }
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

/// Stateless `EdDSA` JWT verifier backed by an in-memory JWKS key map.
#[derive(Debug, Clone)]
pub struct TokenVerifier {
    keys: HashMap<String, VerifyingKey>,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    clock_skew_secs: i64,
}

impl TokenVerifier {
    /// Build a verifier from an RFC 7517 [`Jwks`].
    ///
    /// # Errors
    /// Returns [`VerifyError::InvalidJwk`] if any `Ed25519` JWK entry cannot be decoded.
    pub fn from_jwks(jwks: &Jwks) -> Result<Self, VerifyError> {
        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for jwk in &jwks.keys {
            if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
                continue;
            }
            let raw = URL_SAFE_NO_PAD
                .decode(jwk.x.as_bytes())
                .map_err(|_| VerifyError::InvalidJwk)?;
            let key_bytes: [u8; 32] = raw.try_into().map_err(|_| VerifyError::InvalidJwk)?;
            let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::InvalidJwk)?;
            keys.insert(jwk.kid.clone(), vk);
        }
        Ok(Self {
            keys,
            expected_issuer: None,
            expected_audience: None,
            clock_skew_secs: 30,
        })
    }

    /// Parse a JWKS JSON document directly into a [`TokenVerifier`].
    ///
    /// # Errors
    /// Returns [`VerifyError::InvalidEncoding`] or [`VerifyError::InvalidJwk`].
    pub fn from_jwks_json(json: &str) -> Result<Self, VerifyError> {
        let jwks: Jwks = serde_json::from_str(json).map_err(|_| VerifyError::InvalidEncoding)?;
        Self::from_jwks(&jwks)
    }

    /// Require tokens to match `issuer` exactly.
    #[must_use]
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Require tokens to include `audience` in `aud`.
    #[must_use]
    pub fn require_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = Some(audience.into());
        self
    }

    /// Configure allowed clock skew in seconds (default: 30).
    #[must_use]
    pub const fn clock_skew_secs(mut self, secs: i64) -> Self {
        self.clock_skew_secs = secs;
        self
    }

    /// Verify a compact JWS (`header.payload.signature`) at UTC instant `now`.
    ///
    /// # Errors
    /// Returns a typed [`VerifyError`] on any structural, cryptographic, or claim failure.
    pub fn verify(&self, token: &str, now: OffsetDateTime) -> Result<VerifiedClaims, VerifyError> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(VerifyError::MalformedToken)?;
        let payload_b64 = parts.next().ok_or(VerifyError::MalformedToken)?;
        let sig_b64 = parts.next().ok_or(VerifyError::MalformedToken)?;
        if parts.next().is_some()
            || header_b64.is_empty()
            || payload_b64.is_empty()
            || sig_b64.is_empty()
        {
            return Err(VerifyError::MalformedToken);
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64.as_bytes())
            .map_err(|_| VerifyError::InvalidEncoding)?;
        let header: JwtHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| VerifyError::InvalidEncoding)?;

        if header.alg != "EdDSA" {
            return Err(VerifyError::UnsupportedHeader);
        }
        let kid = header.kid.ok_or(VerifyError::UnsupportedHeader)?;
        let verifying_key = self.keys.get(&kid).ok_or(VerifyError::UnknownKey)?;

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .map_err(|_| VerifyError::InvalidEncoding)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| VerifyError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_arr);

        let signing_input = format!("{header_b64}.{payload_b64}");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| VerifyError::InvalidSignature)?;

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64.as_bytes())
            .map_err(|_| VerifyError::InvalidEncoding)?;
        let claims: VerifiedClaims =
            serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::InvalidEncoding)?;

        let now_ts = now.unix_timestamp();
        if claims.exp <= now_ts - self.clock_skew_secs {
            return Err(VerifyError::Expired);
        }
        if claims.iat > now_ts + self.clock_skew_secs {
            return Err(VerifyError::NotYetValid);
        }
        if let Some(expected_iss) = &self.expected_issuer
            && claims.iss != *expected_iss
        {
            return Err(VerifyError::IssuerMismatch);
        }
        if let Some(expected_aud) = &self.expected_audience
            && !claims.aud.contains(expected_aud)
        {
            return Err(VerifyError::AudienceMismatch);
        }

        Ok(claims)
    }
}
