//! GitHub, Google, and Microsoft sign-in through the router's session cookie.
//!
//! The provider set is closed. Configuration chooses the endpoints and the client
//! credentials; it cannot add a provider. The raw state value lives only in the
//! redirect and the callback query string; the store receives its keyed digest.

use std::fmt;

use axum::Json;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use reqwest::Client;
use serde_json::Value;
use time::Duration;
use url::Url;
use vaelspire_core::{AuthError, AuthStore, SocialProvider};
use zeroize::Zeroizing;

use crate::handlers::session_json;
use crate::{AuthState, append_cookie, auth_error, call_for, fail, now, session_cookie};

/// A provider's endpoints and the application's client credentials.
///
/// `new` fills in that provider's public endpoints and a ten-minute state lifetime.
/// Replace any endpoint with the builder methods, which is how a test points the token
/// exchange and user-info request at a local fake. The client secret is held in
/// [`Zeroizing`] and omitted from [`Debug`]; it is never placed in a response body, a
/// log line, or an audit row.
pub struct SocialConfig {
    provider: SocialProvider,
    client_id: String,
    client_secret: Zeroizing<String>,
    redirect_uri: String,
    authorization_url: String,
    token_url: String,
    user_info_url: String,
    email_url: Option<String>,
    scopes: Vec<String>,
    state_ttl: Duration,
    client: Client,
}

impl fmt::Debug for SocialConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocialConfig")
            .field("provider", &self.provider)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("authorization_url", &self.authorization_url)
            .field("token_url", &self.token_url)
            .field("user_info_url", &self.user_info_url)
            .field("email_url", &self.email_url)
            .field("scopes", &self.scopes)
            .field("state_ttl", &self.state_ttl)
            .finish_non_exhaustive()
    }
}

impl Clone for SocialConfig {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider,
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.redirect_uri.clone(),
            authorization_url: self.authorization_url.clone(),
            token_url: self.token_url.clone(),
            user_info_url: self.user_info_url.clone(),
            email_url: self.email_url.clone(),
            scopes: self.scopes.clone(),
            state_ttl: self.state_ttl,
            client: self.client.clone(),
        }
    }
}

impl SocialConfig {
    /// Configure one provider.
    ///
    /// `redirect_uri` is the library callback the application mounted. It is sent to
    /// the provider at start and again at the token exchange; the callback never reads
    /// a `redirect_uri` from the query string.
    #[must_use]
    pub fn new(
        provider: SocialProvider,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let (authorization_url, token_url, user_info_url, scopes) = match provider {
            SocialProvider::GitHub => (
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                "https://api.github.com/user",
                vec!["read:user".to_owned(), "user:email".to_owned()],
            ),
            SocialProvider::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                "https://openidconnect.googleapis.com/v1/userinfo",
                vec![
                    "openid".to_owned(),
                    "email".to_owned(),
                    "profile".to_owned(),
                ],
            ),
            SocialProvider::Microsoft => (
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                "https://graph.microsoft.com/oidc/userinfo",
                vec![
                    "openid".to_owned(),
                    "email".to_owned(),
                    "profile".to_owned(),
                ],
            ),
        };
        Self {
            provider,
            client_id: client_id.into(),
            client_secret: Zeroizing::new(client_secret.into()),
            redirect_uri: redirect_uri.into(),
            authorization_url: authorization_url.to_owned(),
            token_url: token_url.to_owned(),
            user_info_url: user_info_url.to_owned(),
            email_url: None,
            scopes,
            state_ttl: Duration::minutes(10),
            client: Client::new(),
        }
    }

    /// Replace the browser-facing authorization endpoint.
    #[must_use]
    pub fn authorization_url(mut self, url: impl Into<String>) -> Self {
        self.authorization_url = url.into();
        self
    }

    /// Replace the endpoint the callback posts the authorization code to.
    #[must_use]
    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = url.into();
        self
    }

    /// Replace the endpoint that returns the provider's subject, email, and
    /// `email_verified` flag.
    #[must_use]
    pub fn user_info_url(mut self, url: impl Into<String>) -> Self {
        self.user_info_url = url.into();
        self
    }

    /// Point GitHub's verified-email list at a URL. Off by default, so a callback
    /// whose user-info response carries `email_verified` makes no second request.
    #[must_use]
    pub fn email_url(mut self, url: Option<impl Into<String>>) -> Self {
        self.email_url = url.map(Into::into);
        self
    }

    /// Replace the requested scopes.
    #[must_use]
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Replace the state lifetime. The default is ten minutes.
    #[must_use]
    pub fn state_ttl(mut self, ttl: Duration) -> Self {
        self.state_ttl = ttl;
        self
    }

    /// The provider this configuration signs in.
    #[must_use]
    pub fn provider(&self) -> SocialProvider {
        self.provider
    }

    /// The state lifetime supplied to [`vaelspire_auth::Auth::start_social_state`].
    #[must_use]
    pub fn state_ttl_value(&self) -> Duration {
        self.state_ttl
    }

    /// The authorization URL the start route redirects to, with the configured
    /// callback and the one-time state.
    pub(crate) fn authorization_redirect(&self, state: &str) -> Result<String, AuthError> {
        let mut url = Url::parse(&self.authorization_url).map_err(|_| AuthError::Store)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", state);
        Ok(url.into())
    }

    /// Exchange the code at the configured token endpoint. No other host is called.
    pub(crate) async fn exchange_code(&self, code: &str) -> Result<String, AuthError> {
        let response = self
            .client
            .post(&self.token_url)
            .header(header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Store)?;
        if !response.status().is_success() {
            return Err(AuthError::Unauthorized);
        }
        let body: Value = response.json().await.map_err(|_| AuthError::Unauthorized)?;
        body.get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
            .ok_or(AuthError::Unauthorized)
    }

    /// Read the provider's subject and email. GitHub's public user object can omit the
    /// address, so a configured `email_url` fills it in when the address is not already
    /// marked verified.
    pub(crate) async fn user_info(&self, access_token: &str) -> Result<SocialUser, AuthError> {
        let response = self
            .client
            .get(&self.user_info_url)
            .bearer_auth(access_token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| AuthError::Store)?;
        if !response.status().is_success() {
            return Err(AuthError::Unauthorized);
        }
        let body: Value = response.json().await.map_err(|_| AuthError::Unauthorized)?;
        let mut user = parse_user(&body)?;
        if self.provider == SocialProvider::GitHub
            && !user.email_verified
            && let Some(email_url) = &self.email_url
            && let Some((email, verified)) = self.github_email(access_token, email_url).await?
        {
            user.email = Some(email);
            user.email_verified = verified;
        }
        if user.email.is_none() {
            return Err(AuthError::Invalid);
        }
        Ok(user)
    }

    /// The verified address from GitHub's email list, preferring the primary one.
    async fn github_email(
        &self,
        access_token: &str,
        url: &str,
    ) -> Result<Option<(String, bool)>, AuthError> {
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| AuthError::Store)?;
        if !response.status().is_success() {
            return Err(AuthError::Store);
        }
        let list: Vec<Value> = response.json().await.map_err(|_| AuthError::Store)?;
        let mut fallback = None;
        for item in list {
            if item.get("verified").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let Some(email) = item.get("email").and_then(Value::as_str) else {
                continue;
            };
            if item.get("primary").and_then(Value::as_bool) == Some(true) {
                return Ok(Some((email.to_owned(), true)));
            }
            fallback.get_or_insert_with(|| (email.to_owned(), true));
        }
        Ok(fallback)
    }
}

/// The provider fields the library signs in with.
#[derive(Debug)]
pub(crate) struct SocialUser {
    pub(crate) subject: String,
    pub(crate) email: Option<String>,
    pub(crate) email_verified: bool,
}

fn parse_user(body: &Value) -> Result<SocialUser, AuthError> {
    let subject = body
        .get("sub")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            body.get("id").map(|id| match id {
                Value::String(value) => value.clone(),
                other => other.to_string(),
            })
        })
        .filter(|subject| !subject.is_empty())
        .ok_or(AuthError::Unauthorized)?;
    let email = body
        .get("email")
        .and_then(Value::as_str)
        .or_else(|| body.get("mail").and_then(Value::as_str))
        .or_else(|| body.get("userPrincipalName").and_then(Value::as_str))
        .filter(|email| !email.is_empty())
        .map(str::to_owned);
    let email_verified = body
        .get("email_verified")
        .and_then(Value::as_bool)
        .or_else(|| body.get("verified_email").and_then(Value::as_bool))
        .unwrap_or(false);
    Ok(SocialUser {
        subject,
        email,
        email_verified,
    })
}

pub(crate) fn query_param(request: &Request, name: &str) -> Option<String> {
    url::form_urlencoded::parse(request.uri().query()?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Redirect to the provider's authorization endpoint.
///
/// The configured callback is the `redirect_uri`; a value in the query string is
/// ignored because this route takes no query parameters. An unknown provider is 404
/// and a feature-enabled router without that provider's configuration is 503.
pub async fn social_start<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(provider): Path<String>,
) -> Response {
    let Ok(provider) = SocialProvider::parse(&provider) else {
        return fail(StatusCode::NOT_FOUND, "not found");
    };
    let Some(config) = state.social_config(provider) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "social sign-in is not configured",
        );
    };
    let state_secret = match state
        .auth()
        .start_social_state(
            state.tenant(),
            provider.as_str(),
            config.state_ttl_value(),
            now(),
        )
        .await
    {
        Ok(secret) => secret,
        Err(error) => return auth_error(error),
    };
    let location = match config.authorization_redirect(state_secret.expose()) {
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
pub async fn social_callback<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(provider): Path<String>,
    request: Request,
) -> Response {
    let Ok(provider) = SocialProvider::parse(&provider) else {
        return fail(StatusCode::NOT_FOUND, "not found");
    };
    let Some(config) = state.social_config(provider) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "social sign-in is not configured",
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
    let access_token = match config.exchange_code(&code).await {
        Ok(token) => token,
        Err(AuthError::Unauthorized) => return auth_error(AuthError::Unauthorized),
        Err(_) => return auth_error(AuthError::Store),
    };
    let user = match config.user_info(&access_token).await {
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
