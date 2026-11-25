//! Default route handlers.
//!
//! Each function is a normal axum handler over [`crate::AuthState`], so an application
//! can pass it to the matching [`crate::AuthRouter`] override method unchanged.

use std::fmt;

use axum::Json;
use axum::extract::Path;
use axum::extract::{Request, State};
use axum::http::StatusCode;
#[cfg(feature = "apikeys")]
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use vaelspire_auth::Secret;
#[cfg(feature = "session")]
use vaelspire_auth::SessionInfo;
#[cfg(feature = "password")]
use vaelspire_auth::hash_password;
#[cfg(all(feature = "password", feature = "session"))]
use vaelspire_auth::{SignInOutcome, verify_password};
#[cfg(any(feature = "password", feature = "apikeys"))]
use vaelspire_core::User;
use vaelspire_core::{AuthError, AuthStore, Membership, MembershipStatus, Purpose};
#[cfg(feature = "password")]
use zeroize::Zeroizing;

#[cfg(feature = "apikeys")]
use crate::api_keys_for;
#[cfg(any(feature = "password", feature = "email-signin"))]
use crate::session_cookie;
use crate::{
    AuthState, TokenKind, accepted, auth_error, call_for, fail, guard, json_body, now, parse_id,
    parse_time,
};
#[cfg(feature = "session")]
use crate::{append_cookie, cleared_session_cookie, cookie, ensure_csrf_cookie};

/// A password carried by a request body.
///
/// The value is held in [`Zeroizing`], so its bytes are cleared when the body drops.
/// One wrapper serves every request password — sign-up, sign-in, reset, current, and
/// new — so no route grows its own secret type.
///
/// [`Debug`] is hand-written because `zeroize` 1.9.0, the version this workspace pins,
/// prints the wrapped value from [`Zeroizing`]'s own `Debug`. This wrapper prints
/// neither the password nor its length.
#[cfg(feature = "password")]
#[derive(Deserialize)]
#[serde(from = "String")]
struct Password(Zeroizing<String>);

#[cfg(feature = "password")]
impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

#[cfg(feature = "password")]
impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password([redacted])")
    }
}

#[cfg(feature = "password")]
impl Password {
    /// The bytes to hash or verify, wiped when they are dropped.
    ///
    /// The original allocation moves into the returned buffer, so the password is not
    /// copied and the wrapper's own bytes are empty when it drops.
    fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        let value = std::mem::take(&mut *self.0);
        Zeroizing::new(value.into_bytes())
    }
}

#[cfg(feature = "password")]
#[derive(Debug, Deserialize)]
struct Credentials {
    email: String,
    password: Password,
}

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[cfg(feature = "password")]
#[derive(Debug, Deserialize)]
struct PasswordResetBody {
    token: String,
    password: Password,
}

#[cfg(all(feature = "password", feature = "session"))]
#[derive(Debug, Deserialize)]
struct ChangePasswordBody {
    current_password: Password,
    new_password: Password,
}

#[cfg(feature = "session")]
#[derive(Deserialize)]
struct ChangeEmailBody {
    email: String,
}

#[derive(Deserialize)]
struct MembershipBody {
    user_id: String,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct InvitationBody {
    email: String,
    expires_at: String,
    #[serde(default)]
    role_ids: Vec<String>,
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

#[derive(Deserialize)]
struct GroupMemberBody {
    membership_id: String,
}

#[cfg(feature = "apikeys")]
#[derive(Deserialize)]
struct ApiKeyBody {
    user_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_at: String,
}

#[cfg(feature = "password")]
fn user_json(user: &User) -> serde_json::Value {
    json!({
        "id": user.id.to_string(),
        "tenant_id": user.tenant_id.to_string(),
        "email": user.email,
    })
}

/// Run the sync password work off the async worker, so Argon2 never blocks a task.
///
/// The closure gets owned input and returns an [`AuthError`] the handler maps the same
/// way it maps a store error. A spawn-blocking error is the same internal failure the
/// handler already returns for a store failure. The password is never logged.
#[cfg(feature = "password")]
async fn on_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, AuthError> + Send + 'static,
) -> Result<T, Response> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result.map_err(auth_error),
        Err(_) => Err(fail(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

#[cfg(feature = "session")]
pub(crate) fn session_json(session: &vaelspire_core::Session) -> serde_json::Value {
    json!({
        "user_id": session.user_id.to_string(),
        "tenant_id": session.tenant_id.to_string(),
        "expires_at": session.expires_at.unix_timestamp(),
    })
}

fn membership_json(membership: &Membership) -> serde_json::Value {
    json!({
        "id": membership.id.to_string(),
        "tenant_id": membership.tenant_id.to_string(),
        "user_id": membership.user_id.to_string(),
        "status": membership.status.as_str(),
    })
}

fn dispatch_proof<S>(
    state: &AuthState<S>,
    email: &str,
    kind: TokenKind,
    result: Result<Secret, AuthError>,
) -> Response {
    match result {
        Ok(secret) => {
            if let Some(sink) = &state.settings.token_sink {
                sink(email, kind, &secret);
            }
            accepted()
        }
        Err(AuthError::Store) => auth_error(AuthError::Store),
        Err(_) => accepted(),
    }
}

/// Register an account.
#[cfg(feature = "password")]
pub async fn sign_up<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: Credentials = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let password = body.password.into_bytes();
    let hash = match on_blocking(move || hash_password(&password)).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    match call
        .sign_up(state.tenant(), &body.email, &hash, now())
        .await
    {
        Ok(user) => (
            StatusCode::CREATED,
            Json(json!({ "user": user_json(&user) })),
        )
            .into_response(),
        Err(error) => auth_error(error),
    }
}

/// Authenticate and set the session cookie.
#[cfg(all(feature = "password", feature = "session"))]
pub async fn sign_in<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: Credentials = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let attempt = match call.begin_sign_in(state.tenant(), &body.email, now()).await {
        Ok(attempt) => attempt,
        Err(error) => return auth_error(error),
    };
    let stored = attempt.password_hash().to_owned();
    let rehash = attempt.needs_rehash();
    let password = body.password.into_bytes();
    let checked = on_blocking(move || -> Result<(bool, Option<String>), AuthError> {
        if !verify_password(&password, &stored).unwrap_or(false) {
            return Ok((false, None));
        }
        let replacement_hash = if rehash {
            Some(hash_password(&password)?)
        } else {
            None
        };
        Ok((true, replacement_hash))
    })
    .await;
    let (verified, replacement) = match checked {
        Ok(checked) => checked,
        Err(response) => return response,
    };
    let outcome = if verified {
        SignInOutcome::Verified {
            replacement_hash: replacement.as_deref(),
        }
    } else {
        SignInOutcome::Failed
    };
    match call.finish_sign_in(attempt, outcome, now()).await {
        #[cfg(feature = "mfa")]
        Ok(vaelspire_auth::SignInResult::Session(issued)) => {
            let token = issued.token().expose().to_owned();
            let auth = state.auth();
            let mut response = match auth.resolve_session(&token, now()).await {
                Ok(session) => (StatusCode::OK, Json(session_json(&session))).into_response(),
                Err(_) => fail(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            };
            append_cookie(&mut response, &session_cookie(&state, &token));
            response
        }
        #[cfg(not(feature = "mfa"))]
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
        #[cfg(feature = "mfa")]
        Ok(vaelspire_auth::SignInResult::Pending(pending)) => (
            StatusCode::ACCEPTED,
            Json(json!({"mfa_required":true,"token":pending.token().expose()})),
        )
            .into_response(),
        Err(error) => auth_error(error),
    }
}

#[cfg(all(feature = "mfa", feature = "session"))]
#[derive(Deserialize)]
struct MfaCode {
    code: String,
}
#[cfg(all(feature = "mfa", feature = "session"))]
#[derive(Deserialize)]
struct MfaFinish {
    token: String,
    code: String,
}

#[cfg(all(feature = "mfa", feature = "session"))]
async fn mfa_user<S: AuthStore + 'static>(
    state: &AuthState<S>,
    token: String,
) -> Result<vaelspire_core::Id, Response> {
    state
        .auth()
        .resolve_session(&token, now())
        .await
        .map(|s| s.user_id)
        .map_err(auth_error)
}
#[cfg(all(feature = "mfa", feature = "session"))]
pub(crate) async fn mfa_enroll<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(r) = guard(&state, &request) {
        return r;
    }
    let token = match cookie(&request, state.session_cookie()) {
        Some(token) => token.to_owned(),
        None => return fail(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    let user = match mfa_user(&state, token).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    match state.auth().enroll_totp(user, "primary", &state.key).await {
        Ok(secret) => (StatusCode::OK, Json(json!({"secret":secret.expose()}))).into_response(),
        Err(e) => auth_error(e),
    }
}
#[cfg(all(feature = "mfa", feature = "session"))]
pub(crate) async fn mfa_confirm<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(r) = guard(&state, &request) {
        return r;
    }
    let token = match cookie(&request, state.session_cookie()) {
        Some(token) => token.to_owned(),
        None => return fail(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    let user = match mfa_user(&state, token).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let body: MfaCode = match json_body(request, &state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state
        .auth()
        .confirm_totp(user, "primary", &state.key, &body.code, now())
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => auth_error(e),
    }
}
#[cfg(all(feature = "mfa", feature = "session"))]
pub(crate) async fn mfa_finish<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(r) = guard(&state, &request) {
        return r;
    }
    let body: MfaFinish = match json_body(request, &state).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state
        .auth()
        .finish_mfa(&body.token, &body.code, "primary", &state.key, now())
        .await
    {
        Ok(issued) => {
            let token = issued.token().expose();
            let mut response = StatusCode::OK.into_response();
            append_cookie(&mut response, &session_cookie(&state, token));
            response
        }
        Err(e) => auth_error(e),
    }
}

#[cfg(feature = "passkey")]
#[derive(Deserialize)]
struct PasskeyParty {
    rp_id: String,
    origin: String,
}

#[cfg(feature = "passkey")]
#[derive(Deserialize)]
struct PasskeyLoginBegin {
    rp_id: String,
    origin: String,
    email: String,
}

#[cfg(feature = "passkey")]
#[derive(Deserialize)]
struct PasskeyFinish {
    rp_id: String,
    origin: String,
    credential: serde_json::Value,
}

#[cfg(feature = "passkey")]
async fn session_user<S: AuthStore + 'static>(
    state: &AuthState<S>,
    token: String,
) -> Result<vaelspire_core::Id, Response> {
    state
        .auth()
        .resolve_session(&token, now())
        .await
        .map(|session| session.user_id)
        .map_err(auth_error)
}

#[cfg(feature = "passkey")]
fn session_token<S: AuthStore + 'static>(
    state: &AuthState<S>,
    request: &Request,
) -> Result<String, Response> {
    cookie(request, state.session_cookie())
        .map(str::to_owned)
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "unauthorized"))
}

/// Start passkey registration for the signed-in account.
#[cfg(feature = "passkey")]
pub(crate) async fn passkey_register_begin<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = match session_token(&state, &request) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let user = match session_user(&state, token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    let body: PasskeyParty = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call
        .begin_passkey_registration(user, &body.rp_id, &body.origin, now())
        .await
    {
        Ok(challenge) => (StatusCode::OK, Json(challenge)).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Finish passkey registration for the signed-in account.
#[cfg(feature = "passkey")]
pub(crate) async fn passkey_register_finish<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let token = match session_token(&state, &request) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let user = match session_user(&state, token).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    let body: PasskeyFinish = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call
        .finish_passkey_registration(user, &body.rp_id, &body.origin, body.credential, now())
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Start passkey login. The body names the account and the relying party.
#[cfg(feature = "passkey")]
pub(crate) async fn passkey_login_begin<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: PasskeyLoginBegin = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call
        .begin_passkey_login(
            state.tenant(),
            &body.email,
            &body.rp_id,
            &body.origin,
            now(),
        )
        .await
    {
        Ok(challenge) => (StatusCode::OK, Json(challenge)).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Finish passkey login and set the session cookie.
#[cfg(feature = "passkey")]
pub(crate) async fn passkey_login_finish<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: PasskeyFinish = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call
        .finish_passkey_login(&body.rp_id, &body.origin, body.credential, now())
        .await
    {
        Ok(issued) => {
            let token = issued.token().expose().to_owned();
            let mut response = match state.auth().resolve_session(&token, now()).await {
                Ok(session) => (StatusCode::OK, Json(session_json(&session))).into_response(),
                Err(_) => fail(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            };
            append_cookie(&mut response, &session_cookie(&state, &token));
            response
        }
        Err(error) => auth_error(error),
    }
}

/// Revoke the presented session and clear its cookie.
#[cfg(feature = "session")]
pub async fn sign_out<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let token = cookie(&request, state.session_cookie()).map(str::to_owned);
    let result = match token {
        Some(token) => call.sign_out(&token, now()).await,
        None => Ok(()),
    };
    let mut response = match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    };
    append_cookie(&mut response, &cleared_session_cookie(&state));
    response
}

/// Return the current session, and set the CSRF cookie when it is missing.
#[cfg(feature = "session")]
pub async fn session<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    let mut response = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => (StatusCode::OK, Json(session_json(&session))).into_response(),
        Err(response) => response,
    };
    ensure_csrf_cookie(&request, &state, &mut response);
    response
}

/// Resolve the presented cookie, recording a renewal for the response when needed.
#[cfg(feature = "session")]
async fn presented<S: AuthStore>(
    state: &AuthState<S>,
    token: Option<String>,
    refresh: Option<crate::SessionRefresh>,
) -> Result<vaelspire_core::Session, Response> {
    let Some(token) = token else {
        return Err(fail(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    let (session, extended) = state
        .auth()
        .resolve_session_sliding(&token, now())
        .await
        .map_err(|_| fail(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if extended
        && let Some(refresh) = refresh
        && let Ok(mut refresh) = refresh.lock()
    {
        *refresh = Some(format!(
            "{}; Max-Age={}",
            crate::session_cookie(state, &token),
            state.policy.session_ttl.whole_seconds()
        ));
    }
    Ok(session)
}

/// The presented session's bearer value, when the request's cookies carry one.
#[cfg(feature = "session")]
fn presented_token<S: AuthStore>(state: &AuthState<S>, request: &Request) -> Option<String> {
    cookie(request, state.session_cookie()).map(str::to_owned)
}

/// The caller's sessions, with an identifier and an expiry each and no token.
#[cfg(feature = "session")]
fn session_list_json(sessions: &[SessionInfo]) -> serde_json::Value {
    json!({
        "sessions": sessions
            .iter()
            .map(|session| json!({
                "id": session.id.to_string(),
                "expires_at": session.expires_at.unix_timestamp(),
                "current": session.current,
            }))
            .collect::<Vec<_>>(),
    })
}

/// List the signed-in caller's live sessions, and set the CSRF cookie when missing.
#[cfg(feature = "session")]
pub async fn sessions<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    let mut response = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => match state.auth().list_sessions(&session, now()).await {
            Ok(sessions) => (StatusCode::OK, Json(session_list_json(&sessions))).into_response(),
            Err(error) => auth_error(error),
        },
        Err(response) => response,
    };
    ensure_csrf_cookie(&request, &state, &mut response);
    response
}

/// Revoke one of the signed-in caller's sessions by identifier.
///
/// Another account's identifier is a 404 and stays live. Revoking the presented session
/// clears its cookie.
#[cfg(feature = "session")]
pub async fn revoke_session<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let id = match parse_id(&id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    match call.revoke_session(&session, id, now()).await {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            if id == session.id {
                append_cookie(&mut response, &cleared_session_cookie(&state));
            }
            response
        }
        Err(error) => auth_error(error),
    }
}

/// Revoke every other live session of the signed-in caller, keeping its own cookie.
#[cfg(feature = "session")]
pub async fn revoke_others<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    match call.revoke_other_sessions(&session, now()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Revoke every live session of the signed-in caller, including the presented one, and
/// clear its cookie.
#[cfg(feature = "session")]
pub async fn revoke_all<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    match call.revoke_all_sessions(&session, now()).await {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            append_cookie(&mut response, &cleared_session_cookie(&state));
            response
        }
        Err(error) => auth_error(error),
    }
}

/// Issue an email-verification proof and hand it to the application's hook.
pub async fn email_verify_request<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: EmailBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let result = call
        .issue_proof(state.tenant(), &body.email, Purpose::VerifyEmail, now())
        .await;
    dispatch_proof(&state, &body.email, TokenKind::EmailVerification, result)
}

/// Spend an email-verification proof.
pub async fn email_verify<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: TokenBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call.verify_email(&body.token, now()).await {
        Ok(user) => (StatusCode::OK, Json(json!({ "user_id": user.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Issue an email sign-in proof and hand it to the application's hook.
///
/// The proof is the store's `EmailOtp` one-time token. A malformed email is the
/// caller's mistake and stays a `400`; an unknown account is concealed with the same
/// token-free `202` the other issue routes return.
#[cfg(feature = "email-signin")]
pub async fn email_signin_request<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: EmailBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    // The store keys the proof under the trimmed, lowercase address. Hand the hook
    // that same value so a padded address is not sent to a mail transport.
    let email = body.email.trim().to_lowercase();
    let result = call
        .issue_proof(state.tenant(), &email, Purpose::EmailOtp, now())
        .await;
    match result {
        Ok(secret) => {
            if let Some(sink) = &state.settings.token_sink {
                sink(&email, TokenKind::EmailSignIn, &secret);
            }
            accepted()
        }
        Err(AuthError::Invalid) => auth_error(AuthError::Invalid),
        Err(AuthError::Store) => auth_error(AuthError::Store),
        Err(_) => accepted(),
    }
}

/// Spend an email sign-in proof and set the session cookie.
#[cfg(feature = "email-signin")]
pub async fn email_signin<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: TokenBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call.sign_in_with_email_proof(&body.token, now()).await {
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

/// Issue a password-reset proof and hand it to the application's hook.
#[cfg(feature = "password")]
pub async fn password_reset_request<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: EmailBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let result = call
        .issue_proof(state.tenant(), &body.email, Purpose::ResetPassword, now())
        .await;
    dispatch_proof(&state, &body.email, TokenKind::PasswordReset, result)
}

/// Spend a password-reset proof and replace the password.
#[cfg(feature = "password")]
pub async fn password_reset<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: PasswordResetBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let password = body.password.into_bytes();
    let hash = match on_blocking(move || hash_password(&password)).await {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    match call.reset_password(&body.token, &hash, now()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Replace the signed-in caller's password, keeping its session and cookie.
///
/// The current password is verified and the new one hashed on a blocking executor, never
/// on the async worker. A wrong current password is 401 and leaves the stored hash
/// unchanged; a new password the caller got wrong is 400. Neither the audit row nor a
/// response carries either password.
#[cfg(all(feature = "password", feature = "session"))]
pub async fn change_password<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    let body: ChangePasswordBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let credential = match state.auth().credential(session.user_id).await {
        Ok(credential) => credential,
        Err(error) => return auth_error(error),
    };
    let stored = credential.password_hash.clone();
    let current = body.current_password.into_bytes();
    let new = body.new_password.into_bytes();
    let checked = on_blocking(move || -> Result<Option<String>, AuthError> {
        if !verify_password(&current, &stored).unwrap_or(false) {
            return Ok(None);
        }
        hash_password(&new).map(Some)
    })
    .await;
    let hash = match checked {
        Ok(Some(hash)) => hash,
        Ok(None) => return fail(StatusCode::UNAUTHORIZED, "unauthorized"),
        Err(response) => return response,
    };
    match call
        .change_password(&session, &credential.password_hash, &hash, now())
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Replace the signed-in caller's email and clear its verification.
///
/// A malformed address is 400; a live duplicate in the tenant is 409. The presented
/// session and its cookie stay.
#[cfg(feature = "session")]
pub async fn change_email<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    let body: ChangeEmailBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call.change_email(&session, &body.email, now()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Delete the signed-in caller's account, revoke every session, and clear the cookie.
///
/// The account row is kept and marked deleted. The deletion, the revocation of every live
/// session including the presented one, and the audit row commit together.
#[cfg(feature = "session")]
pub async fn delete_user<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let call = call_for(&state, &request);
    match call.delete_user(&session, now()).await {
        Ok(()) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            append_cookie(&mut response, &cleared_session_cookie(&state));
            response
        }
        Err(error) => auth_error(error),
    }
}

/// Create a membership for a user already in the router's tenant.
pub async fn create_membership<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: MembershipBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let user = match parse_id(&body.user_id) {
        Ok(user) => user,
        Err(response) => return response,
    };
    let status = match body.status.as_deref() {
        None => MembershipStatus::Active,
        Some(value) => match MembershipStatus::parse(value) {
            Ok(status) => status,
            Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid status"),
        },
    };
    match call
        .create_membership(state.tenant(), user, status, now())
        .await
    {
        Ok(membership) => (StatusCode::CREATED, Json(membership_json(&membership))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Issue an invitation and hand its token to the application's hook.
///
/// The response is the same token-free `202` the proof request routes return; the
/// token reaches only [`crate::AuthRouter::on_proof`].
pub async fn issue_invitation<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: InvitationBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let expires_at = match parse_time(&body.expires_at) {
        Ok(expires_at) => expires_at,
        Err(response) => return response,
    };
    let mut role_ids = Vec::with_capacity(body.role_ids.len());
    for id in &body.role_ids {
        match parse_id(id) {
            Ok(id) => role_ids.push(id),
            Err(response) => return response,
        }
    }
    match call
        .issue_invitation(state.tenant(), &body.email, expires_at, role_ids, now())
        .await
    {
        Ok(token) => {
            if let Some(sink) = &state.settings.token_sink {
                sink(&body.email, TokenKind::Invitation, &token);
            }
            accepted()
        }
        Err(error) => auth_error(error),
    }
}

/// Spend an invitation and return the membership it produced.
pub async fn accept_invitation<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let call = call_for(&state, &request);
    let body: TokenBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    match call.accept_invitation(&body.token, now()).await {
        Ok(membership) => (StatusCode::OK, Json(membership_json(&membership))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Store an application-chosen role name.
pub async fn create_role<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let body: NameBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let auth = state.auth();
    match auth.create_role(state.tenant(), &body.name).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Store an application-chosen permission name.
pub async fn create_permission<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let body: NameBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let auth = state.auth();
    match auth.create_permission(state.tenant(), &body.name).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Store an application-chosen group name in the router's tenant.
pub async fn create_group<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let body: NameBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let auth = state.auth();
    match auth.create_group(state.tenant(), &body.name, now()).await {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id.to_string() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Add a membership to a group in the router's tenant.
pub async fn add_group_member<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(group): Path<String>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let group = match parse_id(&group) {
        Ok(group) => group,
        Err(response) => return response,
    };
    let body: GroupMemberBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let membership = match parse_id(&body.membership_id) {
        Ok(membership) => membership,
        Err(response) => return response,
    };
    let auth = state.auth();
    match auth
        .add_group_member(state.tenant(), group, membership)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Remove a membership from a group in the router's tenant.
pub async fn remove_group_member<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path((group, membership)): Path<(String, String)>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let group = match parse_id(&group) {
        Ok(group) => group,
        Err(response) => return response,
    };
    let membership = match parse_id(&membership) {
        Ok(membership) => membership,
        Err(response) => return response,
    };
    let auth = state.auth();
    match auth
        .remove_group_member(state.tenant(), group, membership)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

/// Issue an API key and show the presented value once.
#[cfg(feature = "apikeys")]
pub async fn issue_api_key<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let Some(keys) = api_keys_for(&state) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "api keys are not configured",
        );
    };
    let body: ApiKeyBody = match json_body(request, &state).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let user_id = match parse_id(&body.user_id) {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let expires_at = match parse_time(&body.expires_at) {
        Ok(expires_at) => expires_at,
        Err(response) => return response,
    };
    let user = User {
        id: user_id,
        tenant_id: state.tenant(),
        email: String::new(),
    };
    match keys.issue(&user, body.scopes, expires_at, now()).await {
        Ok(key) => (StatusCode::CREATED, Json(json!({ "key": key.expose() }))).into_response(),
        Err(error) => auth_error(error),
    }
}

/// Authenticate a presented API key.
#[cfg(feature = "apikeys")]
pub async fn verify_api_key<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    request: Request,
) -> Response {
    let Some(keys) = api_keys_for(&state) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "api keys are not configured",
        );
    };
    let Some(token) = presented_key(&request) else {
        return fail(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match keys.lookup(&token, now()).await {
        Ok(key) => (
            StatusCode::OK,
            Json(json!({
                "id": key.id.to_string(),
                "tenant_id": key.tenant_id.to_string(),
                "user_id": key.user_id.to_string(),
                "prefix": key.prefix,
                "scopes": key.scopes,
                "expires_at": key.expires_at.unix_timestamp(),
            })),
        )
            .into_response(),
        Err(error) => auth_error(error),
    }
}

/// Revoke one of the signed-in caller's API keys by identifier.
///
/// The caller is the live session: another account's identifier, a repeated revoke, and
/// an expired key are all 404. The response is empty and never carries the secret.
#[cfg(all(feature = "apikeys", feature = "session"))]
pub async fn revoke_api_key<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    if let Err(response) = guard(&state, &request) {
        return response;
    }
    let session = match presented(
        &state,
        presented_token(&state, &request),
        request.extensions().get::<crate::SessionRefresh>().cloned(),
    )
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    let id = match parse_id(&id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let Some(keys) = api_keys_for(&state) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "api keys are not configured",
        );
    };
    match keys.revoke(&session, id, now()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => auth_error(error),
    }
}

#[cfg(feature = "apikeys")]
fn presented_key(request: &Request) -> Option<String> {
    if let Some(value) = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
    {
        return Some(value.to_owned());
    }
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::to_owned)
}

#[cfg(all(test, feature = "password"))]
mod tests {
    #[cfg(feature = "session")]
    use super::ChangePasswordBody;
    use super::{Credentials, Password, PasswordResetBody};

    /// A fixture that must never reach a `Debug` string or a failure message.
    const SECRET: &str = "fixture-password-not-for-output";

    #[test]
    fn a_request_password_redacts_itself() {
        let password = Password::from(String::from(SECRET));
        assert_eq!(format!("{password:?}"), "Password([redacted])");
    }

    #[test]
    fn every_password_body_redacts_its_password() {
        let credentials = Credentials {
            email: String::from("redaction@example.test"),
            password: Password::from(String::from(SECRET)),
        };
        let reset = PasswordResetBody {
            token: String::from("token"),
            password: Password::from(String::from(SECRET)),
        };

        let mut bodies = vec![format!("{credentials:?}"), format!("{reset:?}")];
        #[cfg(feature = "session")]
        bodies.push(format!(
            "{:?}",
            ChangePasswordBody {
                current_password: Password::from(String::from(SECRET)),
                new_password: Password::from(String::from(SECRET)),
            }
        ));

        for debug in bodies {
            assert!(
                !debug.contains(SECRET),
                "a body's Debug must not print a password"
            );
            assert!(debug.contains("[redacted]"), "the password field is marked");
        }
    }
}
