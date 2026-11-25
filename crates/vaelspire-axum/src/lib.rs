//! Axum routes, cookies, and CSRF for [`vaelspire_auth`].
//!
//! One [`AuthRouter::new`] plus [`AuthRouter::into_router`] mounts a working set of
//! routes around a store the application shares through an [`Arc`]:
//!
//! - `POST /sign-up`, `POST /sign-in`, `POST /sign-out`, `GET /session`
//! - `POST /passkey/register/begin`, `POST /passkey/register/finish`,
//!   `POST /passkey/login/begin`, and `POST /passkey/login/finish` when `passkey` is on
//! - `GET /sessions`, `DELETE /sessions/{session_id}`, `DELETE /sessions`,
//!   `DELETE /sessions/all` when `session` is on
//! - `POST /password/change` when `password` and `session` are on
//! - `POST /email/change`, `DELETE /user` when `session` is on
//! - `POST /email/verify/request`, `POST /email/verify`
//! - `POST /email/sign-in/request`, `POST /email/sign-in` when `email-signin` is on
//! - `POST /password/reset/request`, `POST /password/reset`
//! - `POST /memberships`, `POST /invitations`, `POST /invitations/accept`
//! - `POST /api-keys` and `GET /api-keys/verify` when `apikeys` is enabled, and
//!   `DELETE /api-keys/{id}` when `apikeys` and `session` are both on
//! - `POST /roles`, `POST /permissions`, `POST /groups`,
//!   `POST /groups/{id}/members`, and `DELETE /groups/{id}/members/{membership_id}`
//!   when [`AuthRouter::roles`] is on
//!
//! The routes follow the crate features. A route whose workflow is not compiled in is
//! not registered at all, so with `--no-default-features --features apikeys` the
//! sign-in route does not exist while the API-key routes do. Role, permission, and
//! group writes are off by default and enabled with [`AuthRouter::roles`].
//!
//! The mount fails closed. [`AuthRouter::new`] takes `cookie_secure` as an argument, so
//! the application picks `true` or `false` and there is no silent default. The routes
//! that mint a token — email-verification request, email sign-in request,
//! password-reset request, and invitation issue — are registered only when
//! [`AuthRouter::on_proof`] supplied a hook. Without it they answer 404, exactly as if
//! the feature were compiled out. The consume routes (`/email/verify`,
//! `/email/sign-in`, `/password/reset`, `/invitations/accept`) stay.
//!
//! The session bearer is carried in an `HttpOnly` cookie; no session token is written
//! into a JSON body. Every state-changing default handler runs two checks before it
//! reads a body: the request's `Origin` must be one the application allowed, and then
//! the double-submit CSRF pair must match. [`AuthRouter::allowed_origins`] replaces the
//! origin set; absent, only `http://localhost`, `http://127.0.0.1`, and `http://[::1]`
//! on any port are accepted and a request without an `Origin` is refused. An empty list
//! refuses every state-changing request. The CSRF check can be replaced or disabled
//! without changing the origin rule. The session routes — `GET /sessions`,
//! `DELETE /sessions/{session_id}`, `DELETE /sessions`, and `DELETE /sessions/all` —
//! resolve that cookie before they act and answer 401 without a live session; so do the
//! three signed-in account changes, `POST /password/change`, `POST /email/change`, and
//! `DELETE /user`, and the API-key revoke, `DELETE /api-keys/{id}`. They are the
//! default handlers that require a signed-in caller. IP and user agent reach the audit
//! row of every workflow through [`Auth::call`]; the IP is the connection address unless
//! [`AuthRouter::trust_proxy`] is enabled.
//!
//! The crate never opens a database. The application supplies the store in an [`Arc`],
//! the digest key, the policy, and the secure-cookie choice.

// `Response` is axum's standard return type and is deliberately not boxed in each
// fallible helper; the value is moved straight back to the caller.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequest, Request};
use axum::handler::Handler;
#[cfg(feature = "session")]
use axum::http::HeaderValue;
use axum::http::{HeaderName, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde_json::json;
use vaelspire_auth::{Auth, Call, Policy, Secret};
#[cfg(feature = "social")]
use vaelspire_core::SocialProvider;
use vaelspire_core::{AuthError, AuthStore, Id, Timestamp};
use zeroize::Zeroizing;

mod handlers;
#[cfg(feature = "oidc")]
mod oidc;
#[cfg(feature = "social")]
mod social;
#[cfg(feature = "oidc")]
pub use oidc::OidcConfig;
#[cfg(feature = "oidc")]
use vaelspire_core::OidcProvider;

/// The default handlers.
///
/// The functions here take [`AuthState`] as the axum state, so an application can pass
/// one back to the matching [`AuthRouter`] override method instead of writing its own.
pub mod default {
    #[cfg(all(feature = "password", feature = "session"))]
    pub use crate::handlers::change_password;
    #[cfg(all(feature = "apikeys", feature = "session"))]
    pub use crate::handlers::revoke_api_key;
    #[cfg(all(feature = "password", feature = "session"))]
    pub use crate::handlers::sign_in;
    pub use crate::handlers::{
        accept_invitation, add_group_member, create_group, create_membership, create_permission,
        create_role, email_verify, email_verify_request, issue_invitation, remove_group_member,
    };
    #[cfg(feature = "session")]
    pub use crate::handlers::{
        change_email, delete_user, revoke_all, revoke_others, revoke_session, session, sessions,
        sign_out,
    };
    #[cfg(feature = "email-signin")]
    pub use crate::handlers::{email_signin, email_signin_request};
    #[cfg(feature = "apikeys")]
    pub use crate::handlers::{issue_api_key, verify_api_key};
    #[cfg(feature = "password")]
    pub use crate::handlers::{password_reset, password_reset_request, sign_up};
    #[cfg(feature = "social")]
    pub use crate::social::{social_callback, social_start};
}

/// The cookie used for the session bearer unless the application replaces it.
pub const DEFAULT_SESSION_COOKIE: &str = "neotales.session";
/// The cookie used for the double-submit token unless the application replaces it.
pub const DEFAULT_CSRF_COOKIE: &str = "neotales.csrf";

/// GitHub, Google, or Microsoft endpoints and the application's client credentials.
///
/// The provider is a closed enum; this value cannot register a new one. See the
/// `social` feature and [`AuthRouter::social`].
#[cfg(feature = "social")]
pub use social::SocialConfig;

/// What a token handed to [`AuthRouter::on_proof`] is for.
///
/// The first three are the one-time proofs the store keys by
/// [`Purpose`](vaelspire_core::Purpose). An invitation is not a proof: its token
/// has its own digest domain, so it gets its own variant rather than pretending to be a
/// verification or a reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Confirm ownership of an email address.
    EmailVerification,
    /// Replace the account password.
    PasswordReset,
    /// Sign in with an email-delivered one-time proof. The store's purpose is
    /// [`Purpose::EmailOtp`](vaelspire_core::Purpose::EmailOtp).
    EmailSignIn,
    /// Accept a membership invitation.
    Invitation,
}

type TokenSink = dyn Fn(&str, TokenKind, &Secret) + Send + Sync;

#[derive(Clone)]
enum CsrfMode {
    DoubleSubmit,
    Disabled,
    Custom(Arc<dyn Fn(&Request) -> bool + Send + Sync>),
}

#[derive(Clone)]
struct Settings {
    session_cookie: String,
    csrf_cookie: String,
    csrf_header: HeaderName,
    secure: bool,
    trust_proxy: bool,
    csrf: CsrfMode,
    /// `None` accepts the three local origins; `Some([])` refuses every origin.
    origins: Option<Vec<String>>,
    token_sink: Option<Arc<TokenSink>>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("session_cookie", &self.session_cookie)
            .field("csrf_cookie", &self.csrf_cookie)
            .field("csrf_header", &self.csrf_header)
            .field("secure", &self.secure)
            .field("trust_proxy", &self.trust_proxy)
            .field("origins", &self.origins)
            .field("token_sink", &self.token_sink.is_some())
            .finish_non_exhaustive()
    }
}

impl Settings {
    /// The documented cookie names, the local-only origin set, and the caller's secure
    /// choice.
    fn new(secure: bool) -> Self {
        Self {
            session_cookie: DEFAULT_SESSION_COOKIE.to_owned(),
            csrf_cookie: DEFAULT_CSRF_COOKIE.to_owned(),
            csrf_header: HeaderName::from_static("x-csrf-token"),
            secure,
            trust_proxy: false,
            csrf: CsrfMode::DoubleSubmit,
            origins: None,
            token_sink: None,
        }
    }
}

/// The route paths the router registers.
///
/// Start from [`Paths::default`] or [`Paths::new`] and replace only the paths the
/// application wants to move. A replaced path is the one actually registered; the
/// default one is not registered as well.
#[derive(Debug, Clone)]
pub struct Paths {
    sign_up: String,
    sign_in: String,
    sign_out: String,
    session: String,
    sessions: String,
    sessions_others: String,
    sessions_all: String,
    session_id: String,
    #[cfg(all(feature = "password", feature = "session"))]
    password_change: String,
    #[cfg(feature = "session")]
    email_change: String,
    #[cfg(feature = "session")]
    user: String,
    email_verify_request: String,
    email_verify: String,
    #[cfg(feature = "email-signin")]
    email_signin_request: String,
    #[cfg(feature = "email-signin")]
    email_signin: String,
    password_reset_request: String,
    password_reset: String,
    memberships: String,
    invitations: String,
    invitations_accept: String,
    api_keys: String,
    api_keys_verify: String,
    api_keys_revoke: String,
    roles: String,
    permissions: String,
    groups: String,
    group_members: String,
    group_member: String,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            sign_up: "/sign-up".to_owned(),
            sign_in: "/sign-in".to_owned(),
            sign_out: "/sign-out".to_owned(),
            session: "/session".to_owned(),
            sessions: "/sessions".to_owned(),
            sessions_others: "/sessions".to_owned(),
            sessions_all: "/sessions/all".to_owned(),
            session_id: "/sessions/{session_id}".to_owned(),
            #[cfg(all(feature = "password", feature = "session"))]
            password_change: "/password/change".to_owned(),
            #[cfg(feature = "session")]
            email_change: "/email/change".to_owned(),
            #[cfg(feature = "session")]
            user: "/user".to_owned(),
            email_verify_request: "/email/verify/request".to_owned(),
            email_verify: "/email/verify".to_owned(),
            #[cfg(feature = "email-signin")]
            email_signin_request: "/email/sign-in/request".to_owned(),
            #[cfg(feature = "email-signin")]
            email_signin: "/email/sign-in".to_owned(),
            password_reset_request: "/password/reset/request".to_owned(),
            password_reset: "/password/reset".to_owned(),
            memberships: "/memberships".to_owned(),
            invitations: "/invitations".to_owned(),
            invitations_accept: "/invitations/accept".to_owned(),
            api_keys: "/api-keys".to_owned(),
            api_keys_verify: "/api-keys/verify".to_owned(),
            api_keys_revoke: "/api-keys/{id}".to_owned(),
            roles: "/roles".to_owned(),
            permissions: "/permissions".to_owned(),
            groups: "/groups".to_owned(),
            group_members: "/groups/{id}/members".to_owned(),
            group_member: "/groups/{id}/members/{membership_id}".to_owned(),
        }
    }
}

impl Paths {
    /// The default paths.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the sign-up path.
    #[must_use]
    pub fn sign_up(mut self, path: impl Into<String>) -> Self {
        self.sign_up = path.into();
        self
    }

    /// Replace the sign-in path.
    #[must_use]
    pub fn sign_in(mut self, path: impl Into<String>) -> Self {
        self.sign_in = path.into();
        self
    }

    /// Replace the sign-out path.
    #[must_use]
    pub fn sign_out(mut self, path: impl Into<String>) -> Self {
        self.sign_out = path.into();
        self
    }

    /// Replace the current-session path.
    #[must_use]
    pub fn session(mut self, path: impl Into<String>) -> Self {
        self.session = path.into();
        self
    }

    /// Replace the session-list path.
    #[must_use]
    pub fn sessions(mut self, path: impl Into<String>) -> Self {
        self.sessions = path.into();
        self
    }

    /// Replace the revoke-others path. By default it is the list path, answered for
    /// `DELETE` while the list answers `GET`.
    #[must_use]
    pub fn sessions_others(mut self, path: impl Into<String>) -> Self {
        self.sessions_others = path.into();
        self
    }

    /// Replace the revoke-all path.
    #[must_use]
    pub fn sessions_all(mut self, path: impl Into<String>) -> Self {
        self.sessions_all = path.into();
        self
    }

    /// Replace the revoke-one path, which must keep one `{...}` placeholder for the
    /// session identifier. The default is `/sessions/{session_id}`.
    #[must_use]
    pub fn session_id(mut self, path: impl Into<String>) -> Self {
        self.session_id = path.into();
        self
    }

    /// Replace the change-password path.
    #[cfg(all(feature = "password", feature = "session"))]
    #[must_use]
    pub fn password_change(mut self, path: impl Into<String>) -> Self {
        self.password_change = path.into();
        self
    }

    /// Replace the change-email path.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn email_change(mut self, path: impl Into<String>) -> Self {
        self.email_change = path.into();
        self
    }

    /// Replace the delete-account path. The default is `/user`, answered for `DELETE`.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn user(mut self, path: impl Into<String>) -> Self {
        self.user = path.into();
        self
    }

    /// Replace the email-verification request path.
    #[must_use]
    pub fn email_verify_request(mut self, path: impl Into<String>) -> Self {
        self.email_verify_request = path.into();
        self
    }

    /// Replace the email-verification path.
    #[must_use]
    pub fn email_verify(mut self, path: impl Into<String>) -> Self {
        self.email_verify = path.into();
        self
    }

    /// Replace the email sign-in request path. Registered only with
    /// [`AuthRouter::on_proof`].
    #[cfg(feature = "email-signin")]
    #[must_use]
    pub fn email_signin_request(mut self, path: impl Into<String>) -> Self {
        self.email_signin_request = path.into();
        self
    }

    /// Replace the email sign-in path.
    #[cfg(feature = "email-signin")]
    #[must_use]
    pub fn email_signin(mut self, path: impl Into<String>) -> Self {
        self.email_signin = path.into();
        self
    }

    /// Replace the password-reset request path.
    #[must_use]
    pub fn password_reset_request(mut self, path: impl Into<String>) -> Self {
        self.password_reset_request = path.into();
        self
    }

    /// Replace the password-reset path.
    #[must_use]
    pub fn password_reset(mut self, path: impl Into<String>) -> Self {
        self.password_reset = path.into();
        self
    }

    /// Replace the membership-creation path.
    #[must_use]
    pub fn memberships(mut self, path: impl Into<String>) -> Self {
        self.memberships = path.into();
        self
    }

    /// Replace the invitation-creation path.
    #[must_use]
    pub fn invitations(mut self, path: impl Into<String>) -> Self {
        self.invitations = path.into();
        self
    }

    /// Replace the invitation-acceptance path.
    #[must_use]
    pub fn invitations_accept(mut self, path: impl Into<String>) -> Self {
        self.invitations_accept = path.into();
        self
    }

    /// Replace the API-key issuance path.
    #[must_use]
    pub fn api_keys(mut self, path: impl Into<String>) -> Self {
        self.api_keys = path.into();
        self
    }

    /// Replace the API-key lookup path.
    #[must_use]
    pub fn api_keys_verify(mut self, path: impl Into<String>) -> Self {
        self.api_keys_verify = path.into();
        self
    }

    /// Replace the API-key revoke path, which must keep one `{...}` placeholder for the
    /// key identifier. The default is `/api-keys/{id}`.
    #[must_use]
    pub fn api_keys_revoke(mut self, path: impl Into<String>) -> Self {
        self.api_keys_revoke = path.into();
        self
    }

    /// Replace the role-creation path.
    #[must_use]
    pub fn roles(mut self, path: impl Into<String>) -> Self {
        self.roles = path.into();
        self
    }

    /// Replace the permission-creation path.
    #[must_use]
    pub fn permissions(mut self, path: impl Into<String>) -> Self {
        self.permissions = path.into();
        self
    }

    /// Replace the group-creation path.
    #[must_use]
    pub fn groups(mut self, path: impl Into<String>) -> Self {
        self.groups = path.into();
        self
    }

    /// Replace the add-group-member path, which must keep one `{...}` placeholder for
    /// the group identifier. The default is `/groups/{id}/members`.
    #[must_use]
    pub fn group_members(mut self, path: impl Into<String>) -> Self {
        self.group_members = path.into();
        self
    }

    /// Replace the remove-group-member path, which must keep two `{...}` placeholders:
    /// the group identifier and then the membership identifier. The default is
    /// `/groups/{id}/members/{membership_id}`.
    #[must_use]
    pub fn group_member(mut self, path: impl Into<String>) -> Self {
        self.group_member = path.into();
        self
    }
}

/// The value every default handler extracts as its axum state.
///
/// It carries the shared store, the digest key, policy, and audit switch that build a
/// short-lived [`Auth`] per request, the tenant, the cookie and CSRF settings, and the
/// optional API-key prefix. Custom handlers receive it as `State<AuthState<S>>` and
/// read what they need through the accessors.
pub struct AuthState<S: 'static> {
    store: Arc<S>,
    key: Zeroizing<[u8; 32]>,
    policy: Policy,
    audit: bool,
    #[cfg(feature = "session")]
    session_cache: Arc<vaelspire_auth::SessionCache>,
    tenant: Id,
    settings: Settings,
    #[cfg(feature = "apikeys")]
    api_keys: Option<vaelspire_core::ApiKeyPrefix>,
    #[cfg(feature = "social")]
    social: Vec<SocialConfig>,
    #[cfg(feature = "oidc")]
    oidc: Vec<OidcConfig>,
}

impl<S: 'static> fmt::Debug for AuthState<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthState")
            .field("tenant", &self.tenant)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl<S: 'static> Clone for AuthState<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            key: self.key.clone(),
            policy: self.policy,
            audit: self.audit,
            #[cfg(feature = "session")]
            session_cache: Arc::clone(&self.session_cache),
            tenant: self.tenant,
            settings: self.settings.clone(),
            #[cfg(feature = "apikeys")]
            api_keys: self.api_keys.clone(),
            #[cfg(feature = "social")]
            social: self.social.clone(),
            #[cfg(feature = "oidc")]
            oidc: self.oidc.clone(),
        }
    }
}

impl<S: AuthStore + 'static> AuthState<S> {
    /// A fresh [`Auth`] borrowing the shared store for this request.
    ///
    /// The value is cheap: it copies the store pointer, the digest key, and the
    /// policy. Nothing is leaked, and the borrow ends with the state.
    #[must_use]
    pub fn auth(&self) -> Auth<'_, S> {
        let auth = Auth::new(&*self.store, *self.key, self.policy).auditing(self.audit);
        #[cfg(feature = "session")]
        let auth = auth.session_cache(Arc::clone(&self.session_cache));
        auth
    }

    /// The tenant a default handler uses when the route has no tenant in its body.
    #[must_use]
    pub fn tenant(&self) -> Id {
        self.tenant
    }

    /// The cookie name carrying the session bearer.
    #[must_use]
    pub fn session_cookie(&self) -> &str {
        &self.settings.session_cookie
    }

    /// The cookie name carrying the double-submit token.
    #[must_use]
    pub fn csrf_cookie(&self) -> &str {
        &self.settings.csrf_cookie
    }

    /// The configuration for one OIDC provider, if supplied.
    #[cfg(feature = "oidc")]
    #[must_use]
    pub fn oidc_config(&self, provider: OidcProvider) -> Option<&OidcConfig> {
        self.oidc
            .iter()
            .find(|config| config.provider() == provider)
    }

    /// The configuration for one social provider, when the application supplied it.
    #[cfg(feature = "social")]
    #[must_use]
    pub fn social_config(&self, provider: SocialProvider) -> Option<&SocialConfig> {
        self.social
            .iter()
            .find(|config| config.provider() == provider)
    }
}

struct Handlers<S: 'static> {
    #[cfg(feature = "password")]
    sign_up: Option<MethodRouter<AuthState<S>>>,
    #[cfg(all(feature = "password", feature = "session"))]
    sign_in: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    sign_out: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    session: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    sessions: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    sessions_others: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    sessions_all: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    session_id: Option<MethodRouter<AuthState<S>>>,
    #[cfg(all(feature = "password", feature = "session"))]
    password_change: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    email_change: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "session")]
    user: Option<MethodRouter<AuthState<S>>>,
    email_verify_request: Option<MethodRouter<AuthState<S>>>,
    email_verify: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "email-signin")]
    email_signin_request: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "email-signin")]
    email_signin: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "password")]
    password_reset_request: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "password")]
    password_reset: Option<MethodRouter<AuthState<S>>>,
    memberships: Option<MethodRouter<AuthState<S>>>,
    invitations: Option<MethodRouter<AuthState<S>>>,
    invitations_accept: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "apikeys")]
    api_keys: Option<MethodRouter<AuthState<S>>>,
    #[cfg(feature = "apikeys")]
    api_keys_verify: Option<MethodRouter<AuthState<S>>>,
    #[cfg(all(feature = "apikeys", feature = "session"))]
    api_keys_revoke: Option<MethodRouter<AuthState<S>>>,
    roles: Option<MethodRouter<AuthState<S>>>,
    permissions: Option<MethodRouter<AuthState<S>>>,
    groups: Option<MethodRouter<AuthState<S>>>,
    group_members: Option<MethodRouter<AuthState<S>>>,
    group_member: Option<MethodRouter<AuthState<S>>>,
}

impl<S: 'static> Handlers<S> {
    fn new() -> Self {
        Self {
            #[cfg(feature = "password")]
            sign_up: None,
            #[cfg(all(feature = "password", feature = "session"))]
            sign_in: None,
            #[cfg(feature = "session")]
            sign_out: None,
            #[cfg(feature = "session")]
            session: None,
            #[cfg(feature = "session")]
            sessions: None,
            #[cfg(feature = "session")]
            sessions_others: None,
            #[cfg(feature = "session")]
            sessions_all: None,
            #[cfg(feature = "session")]
            session_id: None,
            #[cfg(all(feature = "password", feature = "session"))]
            password_change: None,
            #[cfg(feature = "session")]
            email_change: None,
            #[cfg(feature = "session")]
            user: None,
            email_verify_request: None,
            email_verify: None,
            #[cfg(feature = "email-signin")]
            email_signin_request: None,
            #[cfg(feature = "email-signin")]
            email_signin: None,
            #[cfg(feature = "password")]
            password_reset_request: None,
            #[cfg(feature = "password")]
            password_reset: None,
            memberships: None,
            invitations: None,
            invitations_accept: None,
            #[cfg(feature = "apikeys")]
            api_keys: None,
            #[cfg(feature = "apikeys")]
            api_keys_verify: None,
            #[cfg(all(feature = "apikeys", feature = "session"))]
            api_keys_revoke: None,
            roles: None,
            permissions: None,
            groups: None,
            group_members: None,
            group_member: None,
        }
    }
}

/// Builds an axum [`Router`] over a store the application shares through an [`Arc`].
///
/// The application supplies the store, the 256-bit digest key, the tenant the
/// bodyless default handlers use, and the secure-cookie choice. The router owns the
/// [`Arc`] and builds a short-lived [`Auth`] from it inside each request, so the
/// store does not need a `'static` borrow and nothing is leaked. It opens no
/// database and holds no global state.
///
/// The mount fails closed: `cookie_secure` has no default, and the routes that mint a
/// token are absent until [`AuthRouter::on_proof`] is set. A state-changing request is
/// refused unless its `Origin` is local; [`AuthRouter::allowed_origins`] replaces that
/// set.
pub struct AuthRouter<S: 'static> {
    store: Arc<S>,
    key: Zeroizing<[u8; 32]>,
    policy: Policy,
    audit: bool,
    #[cfg(feature = "session")]
    session_cache: Arc<vaelspire_auth::SessionCache>,
    tenant: Id,
    settings: Settings,
    paths: Paths,
    handlers: Handlers<S>,
    roles: bool,
    rate_limit: (usize, Duration),
    #[cfg(feature = "apikeys")]
    api_keys: Option<vaelspire_core::ApiKeyPrefix>,
    #[cfg(feature = "social")]
    social: Vec<SocialConfig>,
    #[cfg(feature = "oidc")]
    oidc: Vec<OidcConfig>,
}

impl<S: 'static> fmt::Debug for AuthRouter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRouter")
            .field("tenant", &self.tenant)
            .field("paths", &self.paths)
            .field("settings", &self.settings)
            .field("roles", &self.roles)
            .finish_non_exhaustive()
    }
}

impl<S: AuthStore + 'static> AuthRouter<S> {
    /// Create a router whose bodyless routes operate in `tenant`.
    ///
    /// The router takes ownership of the [`Arc`] and does not require the store to be
    /// `'static` beyond the router itself. `digest_key` is the 256-bit key [`Auth`]
    /// derives session and proof digests from; it must be stable across restarts and
    /// come from the application's secret provider. `cookie_secure` marks both cookies
    /// `Secure`: choose `true` behind TLS, `false` only for a plain-HTTP development
    /// server. There is no default — a caller that does not choose gets no router.
    ///
    /// The policy defaults to [`Policy::default`] and audit is off; change them with
    /// [`AuthRouter::policy`] and [`AuthRouter::auditing`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use axum::Router;
    /// use axum::body::Body;
    /// use axum::http::{Request, header};
    /// use vaelspire_axum::AuthRouter;
    /// use vaelspire_core::{AuthStore, Id, Timestamp};
    /// use vaelspire_store_sqlite::open;
    /// use tower::ServiceExt;
    ///
    /// # async fn mount() -> Router {
    /// // One `Arc` shared by the router and anything else that needs the store.
    /// let store = Arc::new(open("app.db").await.expect("database"));
    ///
    /// // The tenant must already exist; the router never creates one.
    /// let tenant = Id::now_v7();
    /// store
    ///     .create_tenant(tenant, "app", Timestamp::now_utc())
    ///     .await
    ///     .expect("tenant");
    ///
    /// let app = AuthRouter::new(
    ///     Arc::clone(&store),
    ///     tenant,
    ///     // 32 bytes from the secret provider, not a literal in production.
    ///     [0u8; 32],
    ///     // Mandatory choice: `true` behind TLS, `false` on plain HTTP.
    ///     true,
    /// )
    /// // Set the hook before mounting, or the token-issuing routes do not exist.
    /// .on_proof(|_email, _kind, _token| {
    ///     // Hand the token to the mailer or invitation sender. Never log it.
    /// })
    /// .into_router();
    ///
    /// // A safe GET hands the browser the CSRF token. The cookie is not `HttpOnly`,
    /// // so script reads the value out of `document.cookie`.
    /// let response = app
    ///     .clone()
    ///     .oneshot(Request::get("/session").body(Body::empty()).expect("request"))
    ///     .await
    ///     .expect("response");
    /// let csrf = response
    ///     .headers()
    ///     .get_all(header::SET_COOKIE)
    ///     .iter()
    ///     .filter_map(|value| value.to_str().ok())
    ///     .find_map(|text| text.strip_prefix("neotales.csrf="))
    ///     .and_then(|rest| rest.split(';').next())
    ///     .expect("the CSRF cookie")
    ///     .to_owned();
    ///
    /// // The client copies that value into `x-csrf-token`; the double-submit check
    /// // compares the header with the cookie before the issue route runs. The request
    /// // also carries an `Origin` the default local-only set accepts.
    /// let request = Request::post("/email/verify/request")
    ///     .header(header::CONTENT_TYPE, "application/json")
    ///     .header(header::ORIGIN, "http://localhost")
    ///     .header(header::COOKIE, format!("neotales.csrf={csrf}"))
    ///     .header("x-csrf-token", &csrf)
    ///     .body(Body::from(r#"{"email":"user@example.test"}"#))
    ///     .expect("request");
    /// let _ = app.clone().oneshot(request).await.expect("response");
    ///
    /// app
    /// # }
    /// ```
    #[must_use]
    pub fn new(store: Arc<S>, tenant: Id, digest_key: [u8; 32], cookie_secure: bool) -> Self {
        Self {
            store,
            key: Zeroizing::new(digest_key),
            policy: Policy::default(),
            audit: false,
            #[cfg(feature = "session")]
            session_cache: Arc::new(vaelspire_auth::SessionCache::default()),
            tenant,
            settings: Settings::new(cookie_secure),
            paths: Paths::default(),
            handlers: Handlers::new(),
            roles: false,
            rate_limit: (30, Duration::from_secs(60)),
            #[cfg(feature = "apikeys")]
            api_keys: None,
            #[cfg(feature = "social")]
            social: Vec::new(),
            #[cfg(feature = "oidc")]
            oidc: Vec::new(),
        }
    }

    /// Replace the session, lockout, and proof policy. The default is [`Policy::default`].
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the process-local cookie cache lifetime; zero disables it. Default: five seconds.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn session_cache_duration(mut self, duration: Duration) -> Self {
        self.session_cache = Arc::new(vaelspire_auth::SessionCache::new(duration));
        self
    }

    /// Turn audit on or off. Off by default.
    ///
    /// When on, a workflow that supports audit writes one row per mutation; see
    /// [`Auth::auditing`] for the guarantees and their limits.
    #[must_use]
    pub fn auditing(mut self, enabled: bool) -> Self {
        self.audit = enabled;
        self
    }

    /// Set the fixed-window request limit for state-changing requests. Defaults to
    /// 30 requests per 60 seconds per connection IP (or one shared key without
    /// `ConnectInfo`). A maximum of zero fails closed and returns 429 for every
    /// state-changing request. Safe GET requests are not limited.
    #[must_use]
    pub fn rate_limit(mut self, max: usize, window: Duration) -> Self {
        self.rate_limit = (max, window);
        self
    }

    /// Replace the whole path set. Paths not named here keep their defaults.
    #[must_use]
    pub fn paths(mut self, paths: Paths) -> Self {
        self.paths = paths;
        self
    }

    /// Rename the session cookie. The default is [`DEFAULT_SESSION_COOKIE`].
    #[must_use]
    pub fn session_cookie(mut self, name: impl Into<String>) -> Self {
        self.settings.session_cookie = name.into();
        self
    }

    /// Rename the CSRF cookie. The default is [`DEFAULT_CSRF_COOKIE`].
    #[must_use]
    pub fn csrf_cookie(mut self, name: impl Into<String>) -> Self {
        self.settings.csrf_cookie = name.into();
        self
    }

    /// Choose the header that must echo the CSRF cookie. The default is `x-csrf-token`.
    #[must_use]
    pub fn csrf_header(mut self, name: HeaderName) -> Self {
        self.settings.csrf_header = name;
        self
    }

    /// Take the client IP from the first `X-Forwarded-For` entry when present.
    ///
    /// Off by default: the IP is then the connection address from `ConnectInfo`, which
    /// a client cannot forge. Only enable this behind a proxy that overwrites the
    /// header.
    #[must_use]
    pub fn trust_proxy(mut self, trust: bool) -> Self {
        self.settings.trust_proxy = trust;
        self
    }

    /// Replace the origins a state-changing request may come from.
    ///
    /// Each state-changing default handler reads the `Origin` header before its CSRF
    /// check and answers 403 `origin` when the value is not listed. The check runs on
    /// `POST`, `DELETE`, and the other state-changing routes only; `GET /session` and
    /// `GET /api-keys/verify` are never refused for it. The social `GET
    /// /social/{provider}/start` and `GET /social/{provider}/callback` routes are
    /// outside the check as well: both are browser navigations, and the callback's
    /// `Origin` is the provider or absent.
    ///
    /// Not calling this accepts only `http://localhost`, `http://127.0.0.1`, and
    /// `http://[::1]`, each on any port. That is localhost, not anywhere: an `https`
    /// local origin, a container hostname, or a LAN address needs an explicit entry.
    /// A request with no `Origin` header is refused, as is one whose `Origin` is `null`.
    ///
    /// A configured list is compared with the header value exactly: scheme, host, and
    /// port. `https://app.example.test` accepts that origin and not
    /// `https://app.example.test:8443`, `http://app.example.test`, or
    /// `https://sub.app.example.test`. There is no wildcard or suffix entry. Entries are
    /// used as written, so list the lowercase form the browser sends and leave off a
    /// trailing slash or path.
    ///
    /// An empty list fails closed: every state-changing request is refused, localhost
    /// included. Use it to mount the routes in front of something that supplies its own
    /// guard, or to turn the routes off without removing them.
    ///
    /// The rule does not replace CSRF: [`AuthRouter::csrf_disabled`] and
    /// [`AuthRouter::csrf_check`] change only the double-submit comparison. A handler
    /// you supply replaces the default one and is not wrapped in either check.
    #[must_use]
    pub fn allowed_origins<I, O>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = O>,
        O: AsRef<str>,
    {
        self.settings.origins = Some(
            origins
                .into_iter()
                .map(|origin| origin.as_ref().to_owned())
                .collect(),
        );
        self
    }

    /// Disable the CSRF check entirely. State-changing requests still need an allowed
    /// `Origin`, so one from an unlisted origin is refused.
    #[must_use]
    pub fn csrf_disabled(mut self) -> Self {
        self.settings.csrf = CsrfMode::Disabled;
        self
    }

    /// Replace the CSRF check with the application's own.
    ///
    /// The function receives the whole request, including the CSRF cookie and the
    /// header the application chose, and returns whether the request may proceed.
    #[must_use]
    pub fn csrf_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&Request) -> bool + Send + Sync + 'static,
    {
        self.settings.csrf = CsrfMode::Custom(Arc::new(check));
        self
    }

    /// Register role, permission, and group writes. Off by default.
    ///
    /// A tenant is created with `owner`, `admin`, and `member`; it arrives before this
    /// router exists, so this flag seeds nothing. Every other role or group name is
    /// stored as the application sends it.
    #[must_use]
    pub fn roles(mut self, enabled: bool) -> Self {
        self.roles = enabled;
        self
    }

    /// Supply the delivery hook for issued tokens.
    ///
    /// The hook receives the normalized email, a [`TokenKind`], and the token. It is
    /// the only way a default issue route surfaces the token; no route writes a token
    /// into a response body or a log line. An invitation arrives as
    /// [`TokenKind::Invitation`]; its token is the store's invitation token, not a
    /// one-time proof, so its digest domain is unchanged. An email sign-in proof
    /// arrives as [`TokenKind::EmailSignIn`] and is the same `EmailOtp` proof the
    /// store already keys.
    ///
    /// Without a hook the routes that mint a token are not registered at all:
    /// `POST /email/verify/request`, `POST /email/sign-in/request`,
    /// `POST /password/reset/request`, and `POST /invitations` answer 404. Set the
    /// hook before [`AuthRouter::into_router`]; a later call cannot mount them.
    #[must_use]
    pub fn on_proof<F>(mut self, sink: F) -> Self
    where
        F: Fn(&str, TokenKind, &Secret) + Send + Sync + 'static,
    {
        self.settings.token_sink = Some(Arc::new(sink));
        self
    }

    /// Configure the API-key issuer. Without it the API-key routes answer 503.
    ///
    /// `prefix` is the printable label every issued key starts with, 1–16 ASCII
    /// alphanumerics or `-`; `None` uses `nak`. The router shares its store and digest
    /// key with the issuer, so no second [`Arc`] or store borrow is needed.
    ///
    /// # Errors
    /// Returns `Conflict` for an invalid prefix, at build time rather than on the
    /// first request.
    #[cfg(feature = "apikeys")]
    pub fn api_keys(mut self, prefix: Option<&str>) -> Result<Self, AuthError> {
        self.api_keys = Some(vaelspire_core::ApiKeyPrefix::new(prefix)?);
        Ok(self)
    }

    /// Configure one OIDC provider; a later configuration replaces it.
    #[cfg(feature = "oidc")]
    #[must_use]
    pub fn oidc(mut self, config: OidcConfig) -> Self {
        self.oidc
            .retain(|existing| existing.provider() != config.provider());
        self.oidc.push(config);
        self
    }

    /// Configure one social provider. Call it once per provider to enable more than
    /// one; a second configuration for the same provider replaces the first.
    ///
    /// With the feature on and no configuration for a provider, its start and callback
    /// routes answer 503. Without the feature the routes are not registered at all.
    /// The routes are `GET /social/{provider}/start` and
    /// `GET /social/{provider}/callback`, with `provider` one of `github`, `google`,
    /// or `microsoft`.
    #[cfg(feature = "social")]
    #[must_use]
    pub fn social(mut self, config: SocialConfig) -> Self {
        let provider = config.provider();
        self.social
            .retain(|existing| existing.provider() != provider);
        self.social.push(config);
        self
    }

    /// Replace the sign-up handler.
    #[cfg(feature = "password")]
    #[must_use]
    pub fn sign_up<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.sign_up = Some(post(handler));
        self
    }

    /// Replace the sign-in handler.
    #[cfg(all(feature = "password", feature = "session"))]
    #[must_use]
    pub fn sign_in<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.sign_in = Some(post(handler));
        self
    }

    /// Replace the sign-out handler.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn sign_out<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.sign_out = Some(post(handler));
        self
    }

    /// Replace the current-session handler.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn session<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.session = Some(axum::routing::get(handler));
        self
    }

    /// Replace the session-list handler.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn sessions<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.sessions = Some(axum::routing::get(handler));
        self
    }

    /// Replace the revoke-one handler. It is the `DELETE` on the path that carries the
    /// session identifier.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn revoke_session<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.session_id = Some(axum::routing::delete(handler));
        self
    }

    /// Replace the revoke-others handler.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn revoke_others<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.sessions_others = Some(axum::routing::delete(handler));
        self
    }

    /// Replace the revoke-all handler.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn revoke_all<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.sessions_all = Some(axum::routing::delete(handler));
        self
    }

    /// Replace the change-password handler.
    #[cfg(all(feature = "password", feature = "session"))]
    #[must_use]
    pub fn password_change<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.password_change = Some(post(handler));
        self
    }

    /// Replace the change-email handler.
    #[cfg(feature = "session")]
    #[must_use]
    pub fn email_change<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.email_change = Some(post(handler));
        self
    }

    /// Replace the delete-account handler. It is the `DELETE` on [`Paths::user`].
    #[cfg(feature = "session")]
    #[must_use]
    pub fn delete_user<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.user = Some(axum::routing::delete(handler));
        self
    }

    /// Replace the email-verification request handler. Registered only with
    /// [`AuthRouter::on_proof`].
    #[must_use]
    pub fn email_verify_request<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.email_verify_request = Some(post(handler));
        self
    }

    /// Replace the email-verification handler.
    #[must_use]
    pub fn email_verify<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.email_verify = Some(post(handler));
        self
    }

    /// Replace the email sign-in request handler. Registered only with
    /// [`AuthRouter::on_proof`].
    #[cfg(feature = "email-signin")]
    #[must_use]
    pub fn email_signin_request<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.email_signin_request = Some(post(handler));
        self
    }

    /// Replace the email sign-in handler.
    #[cfg(feature = "email-signin")]
    #[must_use]
    pub fn email_signin<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.email_signin = Some(post(handler));
        self
    }

    /// Replace the password-reset request handler. Registered only with
    /// [`AuthRouter::on_proof`].
    #[cfg(feature = "password")]
    #[must_use]
    pub fn password_reset_request<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.password_reset_request = Some(post(handler));
        self
    }

    /// Replace the password-reset handler.
    #[cfg(feature = "password")]
    #[must_use]
    pub fn password_reset<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.password_reset = Some(post(handler));
        self
    }

    /// Replace the membership-creation handler.
    #[must_use]
    pub fn memberships<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.memberships = Some(post(handler));
        self
    }

    /// Replace the invitation-creation handler. Registered only with
    /// [`AuthRouter::on_proof`].
    #[must_use]
    pub fn invitations<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.invitations = Some(post(handler));
        self
    }

    /// Replace the invitation-acceptance handler.
    #[must_use]
    pub fn accept_invitation<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.invitations_accept = Some(post(handler));
        self
    }

    /// Replace the API-key issuance handler.
    #[cfg(feature = "apikeys")]
    #[must_use]
    pub fn api_key<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.api_keys = Some(post(handler));
        self
    }

    /// Replace the API-key lookup handler.
    #[cfg(feature = "apikeys")]
    #[must_use]
    pub fn api_key_verify<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.api_keys_verify = Some(axum::routing::get(handler));
        self
    }

    /// Replace the API-key revoke handler. It is the `DELETE` on [`Paths::api_keys_revoke`].
    #[cfg(all(feature = "apikeys", feature = "session"))]
    #[must_use]
    pub fn api_key_revoke<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.api_keys_revoke = Some(axum::routing::delete(handler));
        self
    }

    /// Replace the role-creation handler.
    #[must_use]
    pub fn role<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.roles = Some(post(handler));
        self
    }

    /// Replace the permission-creation handler.
    #[must_use]
    pub fn permission<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.permissions = Some(post(handler));
        self
    }

    /// Replace the group-creation handler.
    #[must_use]
    pub fn group<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.groups = Some(post(handler));
        self
    }

    /// Replace the add-group-member handler. It is the `POST` on
    /// [`Paths::group_members`].
    #[must_use]
    pub fn group_member<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.group_members = Some(post(handler));
        self
    }

    /// Replace the remove-group-member handler. It is the `DELETE` on
    /// [`Paths::group_member`].
    #[must_use]
    pub fn group_member_remove<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T, AuthState<S>>,
        T: 'static,
    {
        self.handlers.group_member = Some(axum::routing::delete(handler));
        self
    }

    /// Finish the router. This is the whole mount step.
    ///
    /// Without [`AuthRouter::on_proof`] the routes that mint a token are not
    /// registered: `POST /email/verify/request`, `POST /email/sign-in/request`,
    /// `POST /password/reset/request`, and `POST /invitations` answer 404. The consume
    /// routes, `POST /email/verify`, `POST /email/sign-in`, `POST /password/reset`, and
    /// `POST /invitations/accept`, are always registered when their workflow is
    /// compiled in.
    ///
    /// # Panics
    /// Panics when two routes were configured to the same path; axum refuses to
    /// register overlapping routes.
    #[allow(clippy::too_many_lines)]
    pub fn into_router(self) -> Router {
        let roles = self.roles;
        let state = AuthState {
            store: self.store,
            key: self.key,
            policy: self.policy,
            audit: self.audit,
            #[cfg(feature = "session")]
            session_cache: self.session_cache,
            tenant: self.tenant,
            settings: self.settings,
            #[cfg(feature = "apikeys")]
            api_keys: self.api_keys,
            #[cfg(feature = "social")]
            social: self.social,
            #[cfg(feature = "oidc")]
            oidc: self.oidc,
        };
        let has_hook = state.settings.token_sink.is_some();
        let paths = self.paths;
        let mut handlers = self.handlers;

        let mut router: Router<AuthState<S>> = Router::new();

        #[cfg(feature = "password")]
        {
            let handler = handlers
                .sign_up
                .take()
                .unwrap_or_else(|| post(crate::default::sign_up::<S>));
            router = router.route(&paths.sign_up, handler);
        }
        #[cfg(all(feature = "password", feature = "session"))]
        {
            let handler = handlers
                .sign_in
                .take()
                .unwrap_or_else(|| post(crate::default::sign_in::<S>));
            router = router.route(&paths.sign_in, handler);
        }
        #[cfg(all(feature = "mfa", feature = "session"))]
        {
            router = router.route("/mfa/enroll", post(crate::handlers::mfa_enroll::<S>));
            router = router.route("/mfa/confirm", post(crate::handlers::mfa_confirm::<S>));
            router = router.route("/mfa/finish", post(crate::handlers::mfa_finish::<S>));
        }
        #[cfg(feature = "passkey")]
        {
            router = router.route(
                "/passkey/register/begin",
                post(crate::handlers::passkey_register_begin::<S>),
            );
            router = router.route(
                "/passkey/register/finish",
                post(crate::handlers::passkey_register_finish::<S>),
            );
            router = router.route(
                "/passkey/login/begin",
                post(crate::handlers::passkey_login_begin::<S>),
            );
            router = router.route(
                "/passkey/login/finish",
                post(crate::handlers::passkey_login_finish::<S>),
            );
        }
        #[cfg(feature = "session")]
        {
            let handler = handlers
                .sign_out
                .take()
                .unwrap_or_else(|| post(crate::default::sign_out::<S>));
            router = router.route(&paths.sign_out, handler);
            let handler = handlers
                .session
                .take()
                .unwrap_or_else(|| axum::routing::get(crate::default::session::<S>));
            router = router.route(&paths.session, handler);

            // The list and the revoke-others route share one path by default; a
            // replaced path is registered on its own, so the default one is never
            // mounted as well.
            let list = handlers
                .sessions
                .take()
                .unwrap_or_else(|| axum::routing::get(crate::default::sessions::<S>));
            let others = handlers
                .sessions_others
                .take()
                .unwrap_or_else(|| axum::routing::delete(crate::default::revoke_others::<S>));
            if paths.sessions == paths.sessions_others {
                router = router.route(&paths.sessions, list.delete(others));
            } else {
                router = router.route(&paths.sessions, list);
                router = router.route(&paths.sessions_others, others);
            }
            let handler = handlers
                .sessions_all
                .take()
                .unwrap_or_else(|| axum::routing::delete(crate::default::revoke_all::<S>));
            router = router.route(&paths.sessions_all, handler);
            let handler = handlers
                .session_id
                .take()
                .unwrap_or_else(|| axum::routing::delete(crate::default::revoke_session::<S>));
            router = router.route(&paths.session_id, handler);

            // The signed-in account changes share the session cookie but not a feature:
            // changing a password needs `password`, while the address and the deletion do
            // not.
            #[cfg(feature = "password")]
            {
                let handler = handlers
                    .password_change
                    .take()
                    .unwrap_or_else(|| post(crate::default::change_password::<S>));
                router = router.route(&paths.password_change, handler);
            }
            let handler = handlers
                .email_change
                .take()
                .unwrap_or_else(|| post(crate::default::change_email::<S>));
            router = router.route(&paths.email_change, handler);
            let handler = handlers
                .user
                .take()
                .unwrap_or_else(|| axum::routing::delete(crate::default::delete_user::<S>));
            router = router.route(&paths.user, handler);
        }

        if has_hook {
            let handler = handlers
                .email_verify_request
                .take()
                .unwrap_or_else(|| post(crate::default::email_verify_request::<S>));
            router = router.route(&paths.email_verify_request, handler);
        }
        let handler = handlers
            .email_verify
            .take()
            .unwrap_or_else(|| post(crate::default::email_verify::<S>));
        router = router.route(&paths.email_verify, handler);

        #[cfg(feature = "email-signin")]
        {
            if has_hook {
                let handler = handlers
                    .email_signin_request
                    .take()
                    .unwrap_or_else(|| post(crate::default::email_signin_request::<S>));
                router = router.route(&paths.email_signin_request, handler);
            }
            let handler = handlers
                .email_signin
                .take()
                .unwrap_or_else(|| post(crate::default::email_signin::<S>));
            router = router.route(&paths.email_signin, handler);
        }

        #[cfg(feature = "password")]
        {
            if has_hook {
                let handler = handlers
                    .password_reset_request
                    .take()
                    .unwrap_or_else(|| post(crate::default::password_reset_request::<S>));
                router = router.route(&paths.password_reset_request, handler);
            }
            let handler = handlers
                .password_reset
                .take()
                .unwrap_or_else(|| post(crate::default::password_reset::<S>));
            router = router.route(&paths.password_reset, handler);
        }

        let handler = handlers
            .memberships
            .take()
            .unwrap_or_else(|| post(crate::default::create_membership::<S>));
        router = router.route(&paths.memberships, handler);
        if has_hook {
            let handler = handlers
                .invitations
                .take()
                .unwrap_or_else(|| post(crate::default::issue_invitation::<S>));
            router = router.route(&paths.invitations, handler);
        }
        let handler = handlers
            .invitations_accept
            .take()
            .unwrap_or_else(|| post(crate::default::accept_invitation::<S>));
        router = router.route(&paths.invitations_accept, handler);

        #[cfg(feature = "apikeys")]
        {
            let handler = handlers
                .api_keys
                .take()
                .unwrap_or_else(|| post(crate::default::issue_api_key::<S>));
            router = router.route(&paths.api_keys, handler);
            let handler = handlers
                .api_keys_verify
                .take()
                .unwrap_or_else(|| axum::routing::get(crate::default::verify_api_key::<S>));
            router = router.route(&paths.api_keys_verify, handler);
            #[cfg(feature = "session")]
            {
                let handler = handlers
                    .api_keys_revoke
                    .take()
                    .unwrap_or_else(|| axum::routing::delete(crate::default::revoke_api_key::<S>));
                router = router.route(&paths.api_keys_revoke, handler);
            }
        }

        if roles {
            let handler = handlers
                .roles
                .take()
                .unwrap_or_else(|| post(crate::default::create_role::<S>));
            router = router.route(&paths.roles, handler);
            let handler = handlers
                .permissions
                .take()
                .unwrap_or_else(|| post(crate::default::create_permission::<S>));
            router = router.route(&paths.permissions, handler);
            let handler = handlers
                .groups
                .take()
                .unwrap_or_else(|| post(crate::default::create_group::<S>));
            router = router.route(&paths.groups, handler);
            let handler = handlers
                .group_members
                .take()
                .unwrap_or_else(|| post(crate::default::add_group_member::<S>));
            router = router.route(&paths.group_members, handler);
            let handler = handlers
                .group_member
                .take()
                .unwrap_or_else(|| axum::routing::delete(crate::default::remove_group_member::<S>));
            router = router.route(&paths.group_member, handler);
        }

        #[cfg(feature = "social")]
        {
            router = router.route(
                "/social/{provider}/start",
                axum::routing::get(crate::social::social_start::<S>),
            );
            router = router.route(
                "/social/{provider}/callback",
                axum::routing::get(crate::social::social_callback::<S>),
            );
        }

        #[cfg(feature = "oidc")]
        {
            router = router.route(
                "/oidc/{provider}/start",
                axum::routing::get(crate::oidc::oidc_start::<S>),
            );
            router = router.route(
                "/oidc/{provider}/callback",
                axum::routing::get(crate::oidc::oidc_callback::<S>),
            );
        }

        let limiter = Arc::new(RateLimiter::new(self.rate_limit.0, self.rate_limit.1));
        #[cfg(feature = "session")]
        let router = router.layer(middleware::from_fn(session_refresh));
        router
            .with_state(state)
            .layer(middleware::from_fn_with_state(limiter, limit_requests))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ClientKey {
    Address(IpAddr),
    Shared,
}

struct WindowCount {
    started: Instant,
    count: usize,
}

struct RateLimiter {
    max: usize,
    window: Duration,
    counts: Mutex<HashMap<ClientKey, WindowCount>>,
}

impl RateLimiter {
    fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            counts: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, key: ClientKey) -> bool {
        if self.max == 0 {
            return false;
        }
        let now = Instant::now();
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        counts.retain(|_, entry| now.duration_since(entry.started) < self.window);
        let entry = counts.entry(key).or_insert(WindowCount {
            started: now,
            count: 0,
        });
        if now.duration_since(entry.started) >= self.window {
            entry.started = now;
            entry.count = 0;
        }
        if entry.count >= self.max {
            return false;
        }
        entry.count += 1;
        true
    }
}

async fn limit_requests(
    axum::extract::State(limiter): axum::extract::State<Arc<RateLimiter>>,
    request: Request,
    next: middleware::Next,
) -> Response {
    if request.method() == axum::http::Method::GET {
        return next.run(request).await;
    }
    let key = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(ClientKey::Shared, |ConnectInfo(address)| {
            ClientKey::Address(address.ip())
        });
    if limiter.allow(key) {
        next.run(request).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"rate limit"})),
        )
            .into_response()
    }
}

/// One request's audit metadata and auth workflows.
pub(crate) fn call_for<'a, S: AuthStore>(
    state: &'a AuthState<S>,
    request: &Request,
) -> Call<'a, S> {
    let mut call = state.auth().call();
    if let Some(ip) = client_ip(&state.settings, request) {
        call = call.ip(&ip);
    }
    if let Some(agent) = user_agent(request) {
        call = call.user_agent(&agent);
    }
    call
}

/// An API-key issuer borrowing this request's shared store, when one was configured.
///
/// The prefix was validated by [`AuthRouter::api_keys`], so construction cannot fail
/// here. The issuer follows the router's audit switch, so a revoke's row commits with
/// the revoke when auditing is on.
#[cfg(feature = "apikeys")]
pub(crate) fn api_keys_for<S: AuthStore>(
    state: &AuthState<S>,
) -> Option<vaelspire_auth::ApiKeys<'_, S>> {
    let prefix = state.api_keys.as_ref()?;
    vaelspire_auth::ApiKeys::new(&*state.store, *state.key, Some(prefix.as_str()))
        .ok()
        .map(|keys| keys.auditing(state.audit))
}

fn client_ip(settings: &Settings, request: &Request) -> Option<String> {
    if settings.trust_proxy
        && let Some(value) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        && let Some(first) = value.split(',').next()
    {
        let first = first.trim();
        if !first.is_empty() {
            return Some(first.to_owned());
        }
    }
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
}

fn user_agent(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(crate) fn now() -> Timestamp {
    Timestamp::now_utc()
}

pub(crate) fn auth_error(error: AuthError) -> Response {
    let (status, message) = match error {
        AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
        AuthError::NotFound => (StatusCode::NOT_FOUND, "not found"),
        AuthError::Invalid => (StatusCode::BAD_REQUEST, "invalid input"),
        AuthError::Conflict => (StatusCode::CONFLICT, "conflict"),
        AuthError::Store => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        AuthError::Unsupported => (StatusCode::NOT_IMPLEMENTED, "unsupported"),
    };
    fail(status, message)
}

pub(crate) fn fail(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

pub(crate) fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({ "status": "accepted" }))).into_response()
}

pub(crate) async fn json_body<T, S>(request: Request, state: &AuthState<S>) -> Result<T, Response>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    match Json::<T>::from_request(request, state).await {
        Ok(Json(value)) => Ok(value),
        Err(_) => Err(fail(StatusCode::BAD_REQUEST, "invalid request")),
    }
}

/// Refuse an unlisted origin, then run the CSRF check.
///
/// This is the one guard every state-changing default handler calls first. The origin
/// check runs before CSRF so a cross-site request is refused even when the CSRF mode was
/// replaced with something that accepts everything.
pub(crate) fn guard<S>(state: &AuthState<S>, request: &Request) -> Result<(), Response> {
    origin_guard(state, request)?;
    csrf_guard(state, request)
}

/// Refuse a request whose `Origin` is not in the router's set.
pub(crate) fn origin_guard<S>(state: &AuthState<S>, request: &Request) -> Result<(), Response> {
    if origin_ok(&state.settings, request) {
        Ok(())
    } else {
        Err(fail(StatusCode::FORBIDDEN, "origin"))
    }
}

fn origin_ok(settings: &Settings, request: &Request) -> bool {
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    match &settings.origins {
        None => localhost_origin(origin),
        Some(origins) => origins.iter().any(|allowed| allowed == origin),
    }
}

/// The default set: the three loopback names over plain HTTP, on any port.
///
/// The prefix is matched exactly, so `http://localhost.evil.example`,
/// `https://localhost`, and `http://localhost:80/path` are all refused.
fn localhost_origin(origin: &str) -> bool {
    ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|host| {
            origin.strip_prefix(host).is_some_and(|rest| {
                rest.is_empty()
                    || rest.strip_prefix(':').is_some_and(|port| {
                        !port.is_empty()
                            && port.bytes().all(|byte| byte.is_ascii_digit())
                            && port.parse::<u16>().is_ok()
                    })
            })
        })
}

pub(crate) fn csrf_guard<S>(state: &AuthState<S>, request: &Request) -> Result<(), Response> {
    if csrf_ok(&state.settings, request) {
        Ok(())
    } else {
        Err(fail(StatusCode::FORBIDDEN, "csrf"))
    }
}

fn csrf_ok(settings: &Settings, request: &Request) -> bool {
    match &settings.csrf {
        CsrfMode::Disabled => true,
        CsrfMode::Custom(check) => check(request),
        CsrfMode::DoubleSubmit => {
            let Some(cookie) = cookie(request, &settings.csrf_cookie) else {
                return false;
            };
            let Some(header) = request
                .headers()
                .get(&settings.csrf_header)
                .and_then(|value| value.to_str().ok())
            else {
                return false;
            };
            !cookie.is_empty() && cookie == header
        }
    }
}

pub(crate) fn cookie<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers()
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

#[cfg(feature = "session")]
pub(crate) fn ensure_csrf_cookie<S>(
    request: &Request,
    state: &AuthState<S>,
    response: &mut Response,
) {
    if cookie(request, &state.settings.csrf_cookie).is_none() {
        let token = Id::new_v4().simple().to_string();
        let value = cookie_value(&state.settings, &state.settings.csrf_cookie, &token, false);
        append_cookie(response, &value);
    }
}

#[cfg(feature = "session")]
pub(crate) fn session_cookie<S>(state: &AuthState<S>, token: &str) -> String {
    cookie_value(&state.settings, &state.settings.session_cookie, token, true)
}

#[cfg(feature = "session")]
type SessionRefresh = Arc<Mutex<Option<String>>>;

// A handler records a renewal only after resolving the session. A later handler may
// clear or replace the cookie, in which case that explicit response wins.
#[cfg(feature = "session")]
async fn session_refresh(mut request: Request, next: middleware::Next) -> Response {
    let refresh: SessionRefresh = Arc::new(Mutex::new(None));
    request.extensions_mut().insert(Arc::clone(&refresh));
    let mut response = next.run(request).await;
    if let Ok(mut value) = refresh.lock()
        && let Some(cookie) = value.take()
    {
        let name = cookie.split('=').next().unwrap_or("");
        let replaced = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| {
                value.to_str().is_ok_and(|value| {
                    value
                        .strip_prefix(name)
                        .is_some_and(|rest| rest.starts_with('='))
                })
            });
        if !replaced {
            append_cookie(&mut response, &cookie);
        }
    }
    response
}

#[cfg(feature = "session")]
pub(crate) fn cleared_session_cookie<S>(state: &AuthState<S>) -> String {
    cleared_cookie(&state.settings, &state.settings.session_cookie, true)
}

#[cfg(feature = "session")]
fn cookie_value(settings: &Settings, name: &str, value: &str, http_only: bool) -> String {
    let mut text = format!("{name}={value}; Path=/; SameSite=Lax");
    if http_only {
        text.push_str("; HttpOnly");
    }
    if settings.secure {
        text.push_str("; Secure");
    }
    text
}

#[cfg(feature = "session")]
fn cleared_cookie(settings: &Settings, name: &str, http_only: bool) -> String {
    let mut text = format!("{name}=; Path=/; SameSite=Lax; Max-Age=0");
    if http_only {
        text.push_str("; HttpOnly");
    }
    if settings.secure {
        text.push_str("; Secure");
    }
    text
}

#[cfg(feature = "session")]
pub(crate) fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(crate) fn parse_id(value: &str) -> Result<Id, Response> {
    Id::parse_str(value).map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid identifier"))
}

pub(crate) fn parse_time(value: &str) -> Result<Timestamp, Response> {
    Timestamp::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| fail(StatusCode::BAD_REQUEST, "invalid timestamp"))
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_CSRF_COOKIE, DEFAULT_SESSION_COOKIE, Paths};
    use axum::body::Body;
    use axum::extract::Request;

    fn request(cookie: Option<&str>) -> Request {
        let mut builder = Request::builder();
        if let Some(cookie) = cookie {
            builder = builder.header(axum::http::header::COOKIE, cookie);
        }
        builder.body(Body::empty()).expect("request")
    }

    #[test]
    fn defaults_are_the_documented_routes_and_names() {
        let paths = Paths::default();
        assert_eq!(paths.sign_up, "/sign-up");
        assert_eq!(paths.sign_in, "/sign-in");
        assert_eq!(paths.session, "/session");
        assert_eq!(DEFAULT_SESSION_COOKIE, "neotales.session");
        assert_eq!(DEFAULT_CSRF_COOKIE, "neotales.csrf");
    }

    #[test]
    fn cookie_reads_only_the_named_pair() {
        let request = request(Some("a=1; neotales.csrf=abc123; b=2"));
        assert_eq!(super::cookie(&request, "neotales.csrf"), Some("abc123"));
        assert_eq!(super::cookie(&request, "missing"), None);
    }

    #[test]
    fn an_empty_cookie_value_still_parses() {
        let request = request(Some("neotales.session="));
        assert_eq!(super::cookie(&request, "neotales.session"), Some(""));
    }

    fn with_origin(origin: Option<&str>) -> Request {
        let mut builder = Request::builder();
        if let Some(origin) = origin {
            builder = builder.header(axum::http::header::ORIGIN, origin);
        }
        builder.body(Body::empty()).expect("request")
    }

    #[test]
    fn the_default_origin_set_is_loopback_over_plain_http() {
        for origin in [
            "http://localhost",
            "http://localhost:3000",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://[::1]",
            "http://[::1]:5173",
        ] {
            assert!(super::localhost_origin(origin), "{origin} is loopback");
        }
        for origin in [
            "https://localhost",
            "https://127.0.0.1:3000",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://localhost:80/path",
            "http://localhost:",
            "http://localhost:port",
            "http://[::1]x",
            "null",
            "",
        ] {
            assert!(!super::localhost_origin(origin), "{origin} is not loopback");
        }
    }

    #[test]
    fn origin_is_refused_when_it_is_absent() {
        let settings = super::Settings::new(false);
        assert!(!super::origin_ok(&settings, &with_origin(None)));
        assert!(super::origin_ok(
            &settings,
            &with_origin(Some("http://localhost:3000"))
        ));
    }

    #[test]
    fn a_configured_origin_list_matches_scheme_host_and_port() {
        let mut settings = super::Settings::new(false);
        settings.origins = Some(vec!["https://app.example.test".to_owned()]);
        assert!(super::origin_ok(
            &settings,
            &with_origin(Some("https://app.example.test"))
        ));
        for origin in [
            "https://app.example.test:8443",
            "http://app.example.test",
            "https://sub.app.example.test",
            "https://app.example.test/",
            "https://app.example.test.evil.example",
            "null",
        ] {
            assert!(
                !super::origin_ok(&settings, &with_origin(Some(origin))),
                "{origin}"
            );
        }
        assert!(!super::origin_ok(&settings, &with_origin(None)));
    }

    #[test]
    fn an_empty_origin_list_refuses_localhost() {
        let mut settings = super::Settings::new(false);
        settings.origins = Some(Vec::new());
        assert!(!super::origin_ok(
            &settings,
            &with_origin(Some("http://localhost"))
        ));
        assert!(!super::origin_ok(
            &settings,
            &with_origin(Some("http://127.0.0.1:3000"))
        ));
    }
}
