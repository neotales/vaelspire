//! Sign-in through a caller-configured `OpenID` Connect issuer.

use crate::handlers::session_json;
use crate::social::{SocialConfig, query_param};
use crate::{AuthState, append_cookie, auth_error, call_for, fail, now, session_cookie};
use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use vaelspire_core::{AuthError, AuthStore, OidcProvider, SocialProvider};

/// Endpoints and credentials for a supported OIDC issuer.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    provider: OidcProvider,
    inner: SocialConfig,
}

impl OidcConfig {
    /// Configure an issuer and the callback mounted by the application.
    ///
    /// For Authentik and Zitadel, configure the issuer's token endpoint using
    /// [`Self::token_url`]. The authorization and user-info endpoints can also be
    /// overridden when the issuer uses different paths.
    #[must_use]
    pub fn new(
        provider: OidcProvider,
        issuer: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let issuer = issuer.as_ref().trim_end_matches('/');
        let (authorization, token, user_info) = if provider == OidcProvider::Keycloak {
            (
                format!("{issuer}/protocol/openid-connect/auth"),
                format!("{issuer}/protocol/openid-connect/token"),
                format!("{issuer}/protocol/openid-connect/userinfo"),
            )
        } else {
            (
                format!("{issuer}/authorize"),
                format!("{issuer}/token"),
                format!("{issuer}/userinfo"),
            )
        };
        let inner = SocialConfig::new(
            SocialProvider::Google,
            client_id,
            client_secret,
            redirect_uri,
        )
        .authorization_url(authorization)
        .token_url(token)
        .user_info_url(user_info);
        Self { provider, inner }
    }

    /// Override the issuer's authorization endpoint.
    #[must_use]
    pub fn authorization_url(mut self, url: impl Into<String>) -> Self {
        self.inner = self.inner.authorization_url(url);
        self
    }
    /// Set the issuer's token endpoint.
    #[must_use]
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.inner = self.inner.token_url(url);
        self
    }
    /// Override the issuer's user-info endpoint.
    #[must_use]
    pub fn user_info_url(mut self, url: impl Into<String>) -> Self {
        self.inner = self.inner.user_info_url(url);
        self
    }
    /// The configured provider.
    #[must_use]
    pub fn provider(&self) -> OidcProvider {
        self.provider
    }
}

/// Redirect to the provider's authorization endpoint.
///
/// The configured callback is the `redirect_uri`; a value in the query string is
/// ignored because this route takes no query parameters. An unknown provider is 404
/// and a feature-enabled router without that provider's configuration is 503.
pub(crate) async fn oidc_start<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(provider): Path<String>,
) -> Response {
    let Ok(provider) = OidcProvider::parse(&provider) else {
        return fail(StatusCode::NOT_FOUND, "not found");
    };
    let Some(config) = state.oidc_config(provider) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC sign-in is not configured",
        );
    };
    let state_secret = match state
        .auth()
        .start_social_state(
            state.tenant(),
            provider.as_str(),
            config.inner.state_ttl_value(),
            now(),
        )
        .await
    {
        Ok(secret) => secret,
        Err(error) => return auth_error(error),
    };
    let location = match config.inner.authorization_redirect(state_secret.expose()) {
        Ok(location) => location,
        Err(error) => return auth_error(error),
    };
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// Spend the state, exchange the code, and set the session cookie.
///
/// A missing, unknown, expired, or already-spent state is 401 and issues no session. A
/// provider email that belongs to another live account is 409 and also issues none.
/// The response body is the session shape; no access token, refresh token, or client
/// secret is placed in it.
pub(crate) async fn oidc_callback<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(provider): Path<String>,
    request: Request,
) -> Response {
    let Ok(provider) = OidcProvider::parse(&provider) else {
        return fail(StatusCode::NOT_FOUND, "not found");
    };
    let Some(config) = state.oidc_config(provider) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC sign-in is not configured",
        );
    };
    let Some(code) = query_param(&request, "code") else {
        return fail(StatusCode::BAD_REQUEST, "invalid request");
    };
    let Some(state_value) = query_param(&request, "state") else {
        return auth_error(AuthError::Unauthorized);
    };
    if let Err(error) = state
        .auth()
        .check_social_state(state.tenant(), provider.as_str(), &state_value, now())
        .await
    {
        return auth_error(error);
    }
    let call = call_for(&state, &request);
    let access_token = match config.inner.exchange_code(&code).await {
        Ok(token) => token,
        Err(AuthError::Unauthorized) => return auth_error(AuthError::Unauthorized),
        Err(_) => return auth_error(AuthError::Store),
    };
    let user = match config.inner.user_info(&access_token).await {
        Ok(user) => user,
        Err(AuthError::Unauthorized) => return auth_error(AuthError::Unauthorized),
        Err(AuthError::Invalid) => return auth_error(AuthError::Invalid),
        Err(_) => return auth_error(AuthError::Store),
    };
    let Some(email) = user.email else {
        return auth_error(AuthError::Invalid);
    };
    match call
        .complete_social_sign_in(
            state.tenant(),
            provider.as_str(),
            &user.subject,
            &email,
            user.email_verified,
            &state_value,
            now(),
        )
        .await
    {
        Ok(issued) => {
            let token = issued.token().expose().to_owned();
            let auth = state.auth();
            let mut response = match auth.resolve_session(&token, now()).await {
                Ok(session) => (StatusCode::OK, Json(session_json(&session))).into_response(),
                Err(_) => fail(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            };
            append_cookie(&mut response, &session_cookie(&state, &token));
            response
        }
        Err(error) => auth_error(error),
    }
}
