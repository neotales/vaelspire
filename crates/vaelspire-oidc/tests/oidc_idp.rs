//! End-to-end OIDC / OAuth 2.0 Identity Provider verification suite.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use vaelspire_core::{Id, Timestamp};
use vaelspire_oidc::{
    AuthorizeRequest, AuthorizeSubject, GrantType, OidcError, OidcProvider, OidcProviderConfig,
    RegisterClientInput,
};
use vaelspire_verify::TokenVerifier;

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[test]
#[allow(clippy::too_many_lines)]
fn full_oidc_pkce_refresh_rotation_revocation_and_stateless_verify() {
    let now = Timestamp::now_utc();
    let tenant_id = Id::now_v7();
    let user_id = Id::now_v7();

    let idp = OidcProvider::new(OidcProviderConfig::new(
        "https://auth.vaelspire.test",
        [7u8; 32],
    ))
    .expect("idp");

    // 1. Discovery & JWKS
    let disc = idp.discovery();
    assert_eq!(disc.issuer, "https://auth.vaelspire.test");
    assert_eq!(disc.id_token_signing_alg_values_supported, vec!["EdDSA"]);
    assert_eq!(disc.code_challenge_methods_supported, vec!["S256"]);

    let jwks = idp.jwks().expect("jwks");
    assert_eq!(jwks.keys.len(), 1);
    let verifier = TokenVerifier::from_jwks(&jwks)
        .expect("verifier")
        .require_issuer("https://auth.vaelspire.test")
        .require_audience("vaelsgard");

    // 2. Register Vaelsgard confidential client
    let registered = idp
        .register_client(RegisterClientInput {
            client_id: "vaelsgard".to_owned(),
            name: "Vaelsgard Secrets Vault".to_owned(),
            tenant_id,
            redirect_uris: vec!["https://vault.example.test/callback".to_owned()],
            allowed_scopes: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
                "offline_access".to_owned(),
                "vault:read".to_owned(),
            ],
            grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
            ],
            confidential: true,
        })
        .expect("register");
    let secret = registered.client_secret.expect("confidential secret");

    // 3. Reject unregistered redirect_uri (no open redirects)
    let bad_redirect = idp.create_authorization_code(
        &AuthorizeRequest {
            client_id: "vaelsgard".to_owned(),
            redirect_uri: "https://evil.example.test/steal".to_owned(),
            scope: "openid email".to_owned(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        },
        AuthorizeSubject {
            user_id,
            tenant_id,
            email: "ada@vaelspire.test".to_owned(),
        },
        now,
    );
    assert_eq!(bad_redirect.unwrap_err(), OidcError::InvalidRequest);

    // 4. Mint single-use Authorization Code with PKCE S256
    let code_verifier = "vaelspire-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz";
    let code = idp
        .create_authorization_code(
            &AuthorizeRequest {
                client_id: "vaelsgard".to_owned(),
                redirect_uri: "https://vault.example.test/callback".to_owned(),
                scope: "openid email offline_access".to_owned(),
                nonce: Some("nonce-123".to_owned()),
                code_challenge: Some(pkce_challenge(code_verifier)),
                code_challenge_method: Some("S256".to_owned()),
            },
            AuthorizeSubject {
                user_id,
                tenant_id,
                email: "ada@vaelspire.test".to_owned(),
            },
            now,
        )
        .expect("auth code");

    // 5. Wrong PKCE verifier rejected
    let wrong_pkce = idp.exchange_authorization_code(
        "vaelsgard",
        Some(secret.as_str()),
        &code,
        "https://vault.example.test/callback",
        Some("wrong-verifier-that-is-at-least-43-characters-long-xxxx"),
        now,
    );
    assert_eq!(wrong_pkce.unwrap_err(), OidcError::InvalidGrant);

    // 6. Correct PKCE exchange issues EdDSA access_token + id_token + refresh_token
    let tokens = idp
        .exchange_authorization_code(
            "vaelsgard",
            Some(secret.as_str()),
            &code,
            "https://vault.example.test/callback",
            Some(code_verifier),
            now,
        )
        .expect("token exchange");

    // Replay of single-use code is rejected
    let replay = idp.exchange_authorization_code(
        "vaelsgard",
        Some(secret.as_str()),
        &code,
        "https://vault.example.test/callback",
        Some(code_verifier),
        now,
    );
    assert_eq!(replay.unwrap_err(), OidcError::InvalidGrant);

    // Stateless verification via vaelspire-verify (zero DB/network hop!)
    let id_claims = verifier
        .verify(tokens.id_token.as_deref().expect("id token"), now)
        .expect("verify id token");
    assert_eq!(id_claims.sub, user_id.to_string());
    assert_eq!(id_claims.nonce.as_deref(), Some("nonce-123"));
    assert_eq!(id_claims.email.as_deref(), Some("ada@vaelspire.test"));

    let access_claims = verifier
        .verify(&tokens.access_token, now)
        .expect("verify access token");
    assert_eq!(access_claims.token_use.as_deref(), Some("access"));
    assert!(access_claims.has_scope("openid"));

    // UserInfo & Introspect succeed
    let ui = idp.userinfo(&tokens.access_token, now).expect("userinfo");
    assert_eq!(ui.email.as_deref(), Some("ada@vaelspire.test"));
    let intro = idp
        .introspect(&tokens.access_token, now)
        .expect("introspect");
    assert!(intro.active);

    // 7. Refresh token rotation + reuse detection revokes entire family
    let rt1 = tokens.refresh_token.expect("refresh token");
    let rotated = idp
        .exchange_refresh_token(
            "vaelsgard",
            Some(secret.as_str()),
            &rt1,
            Some("openid"),
            now,
        )
        .expect("rotate refresh token");
    assert_eq!(rotated.scope, "openid");
    let rt2 = rotated.refresh_token.expect("next refresh token");

    // Reusing rt1 triggers family revocation
    assert_eq!(
        idp.exchange_refresh_token("vaelsgard", Some(secret.as_str()), &rt1, None, now)
            .unwrap_err(),
        OidcError::InvalidGrant
    );
    // rt2 from the same compromised family is now revoked too
    assert_eq!(
        idp.exchange_refresh_token("vaelsgard", Some(secret.as_str()), &rt2, None, now)
            .unwrap_err(),
        OidcError::InvalidGrant
    );

    // 8. Access token revocation immediately invalidates UserInfo & Introspect
    idp.revoke(&tokens.access_token, now).expect("revoke");
    assert_eq!(
        idp.userinfo(&tokens.access_token, now).unwrap_err(),
        OidcError::InvalidToken
    );
    assert!(
        !idp.introspect(&tokens.access_token, now)
            .expect("intro")
            .active
    );

    // 9. Key rotation keeps old tokens verifiable while signing new tokens with new kid
    let new_kid = idp.rotate_signing_key().expect("rotate key");
    assert_eq!(idp.jwks().expect("jwks").keys.len(), 2);
    assert_eq!(idp.jwks().expect("jwks").keys[0].kid, new_kid);

    // 10. Non-Human Identity (NHI / AI Agent) client_credentials with scope attenuation
    let m2m = idp
        .exchange_client_credentials("vaelsgard", secret.as_str(), Some("vault:read"), now)
        .expect("m2m");
    assert_eq!(m2m.scope, "vault:read");
    assert!(m2m.id_token.is_none());
    // Escalating outside allowed scopes fails closed
    assert_eq!(
        idp.exchange_client_credentials("vaelsgard", secret.as_str(), Some("vault:admin"), now)
            .unwrap_err(),
        OidcError::InvalidScope
    );
}
