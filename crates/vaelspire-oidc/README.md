# 🔑 `vaelspire-oidc`

OpenID Connect 1.0 & OAuth 2.0 Identity Provider (IdP) engine for **Vaelspire** (MIT Open-Core, `#![forbid(unsafe_code)]`).

## ✨ Capabilities

- 🔏 **Rotating `EdDSA` (`Ed25519`) JWKS** (`/.well-known/jwks.json`, RFC 7638 key thumbprints)
- 🧭 **OIDC Discovery 1.0** (`/.well-known/openid-configuration`)
- 🔒 **Authorization Code + PKCE (`S256`)** with single-use code consumption and exact `redirect_uri` matching
- 🔄 **Refresh Token Rotation with Reuse Detection** (replaying a rotated token revokes the entire token family)
- 🤖 **Non-Human Identity (`client_credentials`)** with strict scope attenuation for service accounts and AI agents
- 🔍 **RFC 7662 Introspection**, **RFC 7009 Revocation**, and **UserInfo**
- 🪶 Pairs with [`vaelspire-verify`](../vaelspire-verify/README.md) for zero-hop local token verification in **Vaelsgard** and upstream services.
