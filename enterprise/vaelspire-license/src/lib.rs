//! Copyright (c) Neotales. Proprietary — governed by `LICENSE-ENTERPRISE`.
//!
//! Offline Ed25519 `.vlic` license signer, verifier, and [`LicenseGate`] implementation.
//!
//! # Non-Bricking Guarantee
//! Expired, missing, or invalid Enterprise licenses NEVER block user authentication,
//! OIDC token issuance, `/forward-auth`, or SCIM operations. Only Enterprise-only
//! features (WORM compliance storage, multi-region replication, SIEM telemetry) degrade
//! gracefully when outside an active license window.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vaelspire_core::Timestamp;
use vaelspire_core::extensions::{EnterpriseFeature, LicenseGate, LicenseLimits, LicenseStatus};

/// Wire prefix identifying Vaelspire offline signed license tokens (`.vlic`).
pub const VLIC_PREFIX: &str = "vlic1.";

/// Errors returned while signing, parsing, or verifying a `.vlic` license file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LicenseError {
    /// License string does not start with `vlic1.` or is missing its signature segment.
    #[error("malformed vlic envelope")]
    MalformedEnvelope,
    /// Base64url payload or signature could not be decoded.
    #[error("invalid base64url encoding")]
    InvalidEncoding,
    /// JSON payload could not be parsed.
    #[error("invalid license payload JSON")]
    InvalidPayload,
    /// Ed25519 signature bytes had an invalid length or failed cryptographic verification.
    #[error("invalid Ed25519 license signature")]
    InvalidSignature,
}

/// Serializable commercial capacity limits inside a `.vlic` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLimits {
    /// Maximum number of active deployment regions.
    pub max_regions: u32,
    /// Optional workforce seat limit (`None` = unlimited).
    pub max_workforce_seats: Option<u64>,
    /// Optional CIAM monthly active user limit (`None` = unlimited).
    pub max_ciam_maus: Option<u64>,
}

impl From<SignedLimits> for LicenseLimits {
    fn from(value: SignedLimits) -> Self {
        Self {
            max_regions: value.max_regions.max(1),
            max_workforce_seats: value.max_workforce_seats,
            max_ciam_maus: value.max_ciam_maus,
        }
    }
}

/// Signed Enterprise license claims embedded inside a `.vlic` token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Unique license identifier (for audit and support).
    pub license_id: String,
    /// Licensed organization name.
    pub subject: String,
    /// Entitlement tier (e.g. `"enterprise"`, `"sovereign"`).
    pub tier: String,
    /// Unix epoch seconds when the license was issued.
    pub issued_at: i64,
    /// Unix epoch seconds when active Enterprise entitlements expire.
    pub expires_at: i64,
    /// Stable feature identifiers matching [`EnterpriseFeature::as_str`].
    pub features: Vec<String>,
    /// Capacity limits.
    pub limits: SignedLimits,
}

/// Offline Ed25519 license issuer (used by Neotales billing/provisioning).
pub struct LicenseSigner {
    signing_key: SigningKey,
}

impl std::fmt::Debug for LicenseSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseSigner").finish_non_exhaustive()
    }
}

impl LicenseSigner {
    /// Construct a signer from an Ed25519 32-byte private key seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Return the corresponding Ed25519 public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign `payload` into a portable offline `vlic1.<payload>.<signature>` token.
    ///
    /// # Errors
    /// Returns [`LicenseError::InvalidPayload`] if serialization fails.
    pub fn sign(&self, payload: &LicensePayload) -> Result<String, LicenseError> {
        let json = serde_json::to_vec(payload).map_err(|_| LicenseError::InvalidPayload)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(json);
        let sig = self.signing_key.sign(payload_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{VLIC_PREFIX}{payload_b64}.{sig_b64}"))
    }
}

/// Verify an offline `.vlic` token against a trusted Ed25519 [`VerifyingKey`].
///
/// # Errors
/// Returns [`LicenseError`] if the envelope, encoding, signature, or JSON payload is invalid.
pub fn verify_vlic(
    token: &str,
    verifying_key: &VerifyingKey,
) -> Result<LicensePayload, LicenseError> {
    let trimmed = token.trim();
    let body = trimmed
        .strip_prefix(VLIC_PREFIX)
        .ok_or(LicenseError::MalformedEnvelope)?;
    let (payload_b64, sig_b64) = body
        .split_once('.')
        .ok_or(LicenseError::MalformedEnvelope)?;
    if payload_b64.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(LicenseError::MalformedEnvelope);
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| LicenseError::InvalidEncoding)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| LicenseError::InvalidSignature)?;
    verifying_key
        .verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| LicenseError::InvalidEncoding)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| LicenseError::InvalidPayload)
}

/// Offline Ed25519 [`LicenseGate`] implementation for Vaelspire Enterprise deployments.
#[derive(Debug, Clone)]
pub struct Ed25519LicenseGate {
    payload: Option<LicensePayload>,
    tampered_or_invalid: bool,
}

impl Ed25519LicenseGate {
    /// Construct a license gate from a `.vlic` token and pinned Neotales public key.
    ///
    /// Invalid or tampered tokens never panic and never lock out logins; they fall back to
    /// [`LicenseStatus::Community`] while recording [`Self::is_invalid`] for admin alerting.
    #[must_use]
    pub fn from_vlic(token: &str, verifying_key: &VerifyingKey) -> Self {
        match verify_vlic(token, verifying_key) {
            Ok(payload) => Self {
                payload: Some(payload),
                tampered_or_invalid: false,
            },
            Err(_) => Self {
                payload: None,
                tampered_or_invalid: true,
            },
        }
    }

    /// Construct an unlicensed gate (identical to Community behavior).
    #[must_use]
    pub const fn community() -> Self {
        Self {
            payload: None,
            tampered_or_invalid: false,
        }
    }

    /// Whether the supplied `.vlic` failed signature or format verification.
    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        self.tampered_or_invalid
    }

    /// Inspect the verified [`LicensePayload`], if valid.
    #[must_use]
    pub const fn payload(&self) -> Option<&LicensePayload> {
        self.payload.as_ref()
    }
}

impl LicenseGate for Ed25519LicenseGate {
    fn status(&self, now: Timestamp) -> LicenseStatus {
        let Some(payload) = &self.payload else {
            return LicenseStatus::Community;
        };
        let limits = LicenseLimits::from(payload.limits);
        let expires_at =
            Timestamp::from_unix_timestamp(payload.expires_at).unwrap_or(Timestamp::UNIX_EPOCH);
        if now.unix_timestamp() < payload.expires_at {
            LicenseStatus::Licensed {
                subject: payload.subject.clone(),
                limits,
                expires_at,
            }
        } else {
            LicenseStatus::GracePeriod {
                subject: payload.subject.clone(),
                limits,
                expired_at: expires_at,
            }
        }
    }

    fn allows_feature(&self, feature: EnterpriseFeature, now: Timestamp) -> bool {
        let Some(payload) = &self.payload else {
            return false;
        };
        if now.unix_timestamp() >= payload.expires_at {
            return false;
        }
        payload
            .features
            .iter()
            .filter_map(|name| EnterpriseFeature::parse(name))
            .any(|f| f == feature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(expires_at: i64) -> LicensePayload {
        LicensePayload {
            license_id: "lic_01JTEST".into(),
            subject: "Acme Dragonworks".into(),
            tier: "enterprise".into(),
            issued_at: 1_700_000_000,
            expires_at,
            features: vec![
                EnterpriseFeature::WormStorage.as_str().into(),
                EnterpriseFeature::SiemTelemetry.as_str().into(),
            ],
            limits: SignedLimits {
                max_regions: 3,
                max_workforce_seats: Some(500),
                max_ciam_maus: Some(250_000),
            },
        }
    }

    #[test]
    fn valid_offline_license_enables_entitled_features_and_respects_limits() {
        let signer = LicenseSigner::from_seed([0x11; 32]);
        let token = signer.sign(&sample_payload(1_800_000_000)).expect("sign");
        let gate = Ed25519LicenseGate::from_vlic(&token, &signer.verifying_key());

        let active_now = Timestamp::from_unix_timestamp(1_750_000_000).expect("ts");
        assert!(!gate.is_invalid());
        assert!(matches!(
            gate.status(active_now),
            LicenseStatus::Licensed { .. }
        ));
        assert!(gate.allows_login());
        assert!(gate.allows_feature(EnterpriseFeature::WormStorage, active_now));
        assert!(gate.allows_feature(EnterpriseFeature::SiemTelemetry, active_now));
        assert!(!gate.allows_feature(EnterpriseFeature::GeoReplication, active_now));
        assert_eq!(gate.max_regions(active_now), 3);
    }

    #[test]
    fn expired_or_tampered_license_never_bricks_logins() {
        let signer = LicenseSigner::from_seed([0x22; 32]);
        let token = signer.sign(&sample_payload(1_710_000_000)).expect("sign");
        let gate = Ed25519LicenseGate::from_vlic(&token, &signer.verifying_key());

        let expired_now = Timestamp::from_unix_timestamp(1_720_000_000).expect("ts");
        assert!(matches!(
            gate.status(expired_now),
            LicenseStatus::GracePeriod { .. }
        ));
        assert!(
            gate.allows_login(),
            "expired license MUST NEVER block login"
        );
        assert!(!gate.allows_feature(EnterpriseFeature::WormStorage, expired_now));

        let tampered = format!("{token}x");
        let bad_gate = Ed25519LicenseGate::from_vlic(&tampered, &signer.verifying_key());
        assert!(bad_gate.is_invalid());
        assert_eq!(bad_gate.status(expired_now), LicenseStatus::Community);
        assert!(
            bad_gate.allows_login(),
            "invalid license MUST NEVER block login"
        );
        assert!(!bad_gate.allows_feature(EnterpriseFeature::WormStorage, expired_now));
    }
}
