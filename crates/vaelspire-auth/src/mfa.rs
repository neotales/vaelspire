//! Cryptographic primitives for protecting and checking TOTP secrets.
//!
//! These primitives do not enroll a factor or enforce MFA during sign-in.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use vaelspire_core::AuthError;
use zeroize::Zeroizing;

/// Encrypt a TOTP secret using AES-256-GCM. The output is a 12-byte random
/// nonce followed by authenticated ciphertext. Bind it to its owning user by
/// supplying that user's stable identifier as `associated_data`.
///
/// # Errors
/// Returns `Store` if randomness or encryption fails.
pub fn encrypt_secret(
    key: &[u8; 32],
    secret: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| AuthError::Store)?;
    let cipher = Aes256Gcm::new(key.into());
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: secret,
                aad: associated_data,
            },
        )
        .map_err(|_| AuthError::Store)?;
    let mut result = nonce.to_vec();
    result.extend_from_slice(&encrypted);
    Ok(result)
}

/// Decrypt a secret produced by [`encrypt_secret`]. The returned plaintext is
/// cleared on drop. The same associated data must be supplied at both calls.
///
/// # Errors
/// Returns `Store` for malformed or unauthenticated ciphertext.
pub fn decrypt_secret(
    key: &[u8; 32],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    if ciphertext.len() < 12 + 16 {
        return Err(AuthError::Store);
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::try_from(&ciphertext[..12]).map_err(|_| AuthError::Store)?;
    let secret = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext[12..],
                aad: associated_data,
            },
        )
        .map_err(|_| AuthError::Store)?;
    Ok(Zeroizing::new(secret))
}

/// Compute the six-digit SHA-1 TOTP code for an explicitly supplied Unix time.
///
/// `secret` is the **decoded raw key**, not an enrollment string. [`crate::Auth::enroll_totp`]
/// returns the 160-bit key as unpadded URL-safe base64, so decode that value first. The code
/// covers exactly the current 30-second step. This is the value an authenticator app
/// produces for the same secret and instant; [`verify_totp`] checks it in constant time.
///
/// # Panics
/// Panics only if the HMAC implementation rejects the key length, which `Hmac<Sha1>`
/// does not.
///
/// # Examples
/// ```
/// use vaelspire_auth::mfa::totp_code;
///
/// // The RFC 6238 SHA-1 vector at T = 59, with the decoded 20-byte key.
/// assert_eq!(totp_code(b"12345678901234567890", 59), "287082");
/// ```
#[must_use]
pub fn totp_code(secret: &[u8], unix_seconds: u64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&(unix_seconds / 30).to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[19] & 15);
    let binary = u32::from_be_bytes([
        hash[offset],
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]) & 0x7fff_ffff;
    format!("{:06}", binary % 1_000_000)
}

/// Check a six-digit SHA-1 TOTP code at an explicitly supplied Unix time.
///
/// `secret` is the decoded raw key, as for [`totp_code`]. The accepted interval is exactly
/// the current 30-second step.
///
/// # Panics
/// Panics only if the HMAC implementation rejects the key length, which `Hmac<Sha1>`
/// does not.
#[must_use]
pub fn verify_totp(secret: &[u8], code: &str, unix_seconds: u64) -> bool {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    bool::from(
        totp_code(secret, unix_seconds)
            .as_bytes()
            .ct_eq(code.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_authenticates_owner_and_key() {
        let key = [7; 32];
        let secret = b"12345678901234567890";
        let ciphertext = encrypt_secret(&key, secret, b"user").unwrap();
        assert_ne!(ciphertext, encrypt_secret(&key, secret, b"user").unwrap());
        assert_eq!(
            decrypt_secret(&key, &ciphertext, b"user")
                .unwrap()
                .as_slice(),
            secret
        );
        assert!(decrypt_secret(&key, &ciphertext, b"other").is_err());
        assert!(decrypt_secret(&[8; 32], &ciphertext, b"user").is_err());
    }

    #[test]
    fn totp_uses_supplied_time() {
        let secret = b"12345678901234567890";
        // RFC 6238 SHA-1 test vectors, truncated to six digits.
        assert!(verify_totp(secret, "287082", 59));
        assert!(verify_totp(secret, "081804", 1_111_111_109));
        assert!(!verify_totp(secret, "287082", 60));
        assert!(!verify_totp(secret, "x87082", 59));
    }
}
