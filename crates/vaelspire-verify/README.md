# 🪪 `vaelspire-verify`

Zero-database, `#![forbid(unsafe_code)]` stateless **`EdDSA` (`Ed25519`) JWT & JWKS verifier** for **Vaelspire** OIDC tokens.

Embed `vaelspire-verify` in **Vaelsgard** or any Rust backend to validate Vaelspire access and ID tokens locally with zero per-request network hop.

## 🧪 Usage Example

```rust
use time::OffsetDateTime;
use vaelspire_verify::TokenVerifier;

fn verify_token(jwks_json: &str, bearer: &str) -> Result<(), vaelspire_verify::VerifyError> {
    let verifier = TokenVerifier::from_jwks_json(jwks_json)?
        .require_issuer("https://auth.example.com")
        .require_audience("vaelsgard");

    let claims = verifier.verify(bearer, OffsetDateTime::now_utc())?;
    assert!(claims.has_scope("openid"));
    Ok(())
}
```
