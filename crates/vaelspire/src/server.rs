//! Axum HTTP server wiring: auth routes, `/forward-auth`, `/metrics`, `/health`, and `/ready`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use vaelspire_auth::{ApiKeys, Auth, Policy, SessionCache};
use vaelspire_axum::AuthRouter;
use vaelspire_core::{AuthError, Id, Timestamp};
use vaelspire_store_sqlite::SqliteStore;
use zeroize::Zeroizing;

use crate::bootstrap::{check_store_ready, lookup_user_email};
use crate::config::ServerConfig;
use crate::metrics::{ForwardAuthMethod, Metrics};

/// Shared runtime state for Vaelspire's server routes (`/forward-auth`, `/metrics`, `/ready`).
#[derive(Clone)]
pub struct AppState {
    store: Arc<SqliteStore>,
    tenant_id: Id,
    digest_key: Zeroizing<[u8; 32]>,
    session_cache: Arc<SessionCache>,
    session_cookie: String,
    csrf_cookie: String,
    api_key_prefix: String,
    forward_auth_login_url: Option<String>,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("tenant_id", &self.tenant_id)
            .field("session_cookie", &self.session_cookie)
            .field("api_key_prefix", &self.api_key_prefix)
            .finish_non_exhaustive()
    }
}

/// Build the complete Axum [`Router`] for Vaelspire Core.
///
/// # Errors
/// Returns [`AuthError`] if configuration (such as `api_key_prefix`) is rejected.
pub fn build_router(
    store: Arc<SqliteStore>,
    tenant_id: Id,
    config: &ServerConfig,
) -> Result<Router, AuthError> {
    let metrics = Arc::new(Metrics::new());
    let session_cache = Arc::new(SessionCache::default());

    let mut auth_router = AuthRouter::new(
        Arc::clone(&store),
        tenant_id,
        *config.digest_key,
        config.cookie_secure,
    )
    .session_cookie(config.session_cookie.clone())
    .csrf_cookie(config.csrf_cookie.clone())
    .auditing(config.auditing)
    .roles(config.roles)
    .trust_proxy(config.trust_proxy)
    .rate_limit(config.rate_limit.0, config.rate_limit.1)
    .api_keys(Some(&config.api_key_prefix))?;

    if let Some(origins) = &config.allowed_origins {
        auth_router = auth_router.allowed_origins(origins.iter().map(String::as_str));
    }

    let state = AppState {
        store,
        tenant_id,
        digest_key: config.digest_key.clone(),
        session_cache,
        session_cookie: config.session_cookie.clone(),
        csrf_cookie: config.csrf_cookie.clone(),
        api_key_prefix: config.api_key_prefix.clone(),
        forward_auth_login_url: config.forward_auth_login_url.clone(),
        metrics: Arc::clone(&metrics),
    };

    let core_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(prometheus_metrics))
        .route("/.well-known/vaelspire", get(discovery))
        .route("/forward-auth", any(forward_auth))
        .with_state(state);

    let app = core_routes
        .merge(auth_router.into_router())
        .layer(middleware::from_fn_with_state(metrics, count_http_requests));

    Ok(app)
}

/// Bind and run the Vaelspire HTTP server until `SIGINT` or `SIGTERM`.
///
/// # Errors
/// Returns an error if binding the TCP socket or serving HTTP fails.
pub async fn serve(
    store: Arc<SqliteStore>,
    tenant_id: Id,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(store, tenant_id, &config)
        .map_err(|err| format!("failed to build Vaelspire router: {err:?}"))?;

    let listener = TcpListener::bind(config.bind).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(
        bind = %local_addr,
        tenant = %tenant_id,
        cookie_secure = config.cookie_secure,
        auditing = config.auditing,
        "Vaelspire Core listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Vaelspire Core shut down cleanly");
    Ok(())
}

async fn count_http_requests(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    metrics.record_http_status(response.status().as_u16());
    response
}

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": "vaelspire",
            "edition": "core",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

async fn ready(State(state): State<AppState>) -> Response {
    match check_store_ready(&state.store).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "store": "sqlite",
                "tenant_id": state.tenant_id.to_string(),
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unavailable",
                "store": "sqlite",
            })),
        )
            .into_response(),
    }
}

async fn prometheus_metrics(State(state): State<AppState>) -> Response {
    let body = state.metrics.render();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "service": "vaelspire",
        "edition": "core",
        "version": env!("CARGO_PKG_VERSION"),
        "tenant_id": state.tenant_id.to_string(),
        "cookies": {
            "session": state.session_cookie,
            "csrf": state.csrf_cookie,
        },
        "endpoints": {
            "health": "/health",
            "ready": "/ready",
            "metrics": "/metrics",
            "forward_auth": "/forward-auth",
            "sign_up": "/sign-up",
            "sign_in": "/sign-in",
            "sign_out": "/sign-out",
            "session": "/session",
            "sessions": "/sessions",
            "api_keys": "/api-keys",
        }
    }))
}

/// Reverse-proxy forward authentication endpoint for Caddy, Traefik, and Nginx.
///
/// Checks the session cookie first, then falls back to `Authorization: Bearer <key>`
/// or `X-API-Key: <key>`. On success returns `200 OK` with identity headers; on failure
/// returns `401 Unauthorized` (or `302 Found` to the configured `forward_auth_login_url`).
async fn forward_auth(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let now = Timestamp::now_utc();

    if let Some(session_token) = extract_cookie(&headers, &state.session_cookie) {
        let auth = Auth::new(state.store.as_ref(), *state.digest_key, Policy::default())
            .session_cache(Arc::clone(&state.session_cache));
        if let Ok(session) = auth.resolve_session(session_token, now).await {
            state
                .metrics
                .record_forward_auth(true, ForwardAuthMethod::Session);
            let email = lookup_user_email(&state.store, session.user_id)
                .await
                .ok()
                .flatten();
            return allow_response(
                session.user_id,
                session.tenant_id,
                email.as_deref(),
                "session",
                Some(("x-vaelspire-session-id", session.id)),
            );
        }
        state
            .metrics
            .record_forward_auth(false, ForwardAuthMethod::Session);
        return deny_response(state.forward_auth_login_url.as_deref());
    }

    if let Some(api_key_token) = extract_api_key(&headers) {
        if let Ok(keys) = ApiKeys::new(
            state.store.as_ref(),
            *state.digest_key,
            Some(&state.api_key_prefix),
        ) && let Ok(key) = keys.lookup(api_key_token, now).await
        {
            state
                .metrics
                .record_forward_auth(true, ForwardAuthMethod::ApiKey);
            let email = lookup_user_email(&state.store, key.user_id)
                .await
                .ok()
                .flatten();
            return allow_response(
                key.user_id,
                key.tenant_id,
                email.as_deref(),
                "api_key",
                Some(("x-vaelspire-api-key-id", key.id)),
            );
        }
        state
            .metrics
            .record_forward_auth(false, ForwardAuthMethod::ApiKey);
        return deny_response(state.forward_auth_login_url.as_deref());
    }

    state
        .metrics
        .record_forward_auth(false, ForwardAuthMethod::None);
    deny_response(state.forward_auth_login_url.as_deref())
}

fn allow_response(
    user_id: Id,
    tenant_id: Id,
    email: Option<&str>,
    method: &'static str,
    credential_header: Option<(&'static str, Id)>,
) -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    insert_header(headers, "x-vaelspire-user-id", &user_id.to_string());
    insert_header(headers, "x-vaelspire-tenant-id", &tenant_id.to_string());
    insert_header(headers, "x-vaelspire-auth-method", method);
    if let Some(email_val) = email {
        insert_header(headers, "x-vaelspire-email", email_val);
    }
    if let Some((name, cred_id)) = credential_header {
        insert_header(headers, name, &cred_id.to_string());
    }
    response
}

fn deny_response(login_url: Option<&str>) -> Response {
    if let Some(url) = login_url
        && let Ok(location) = HeaderValue::from_str(url)
    {
        return (
            StatusCode::FOUND,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({ "error": "unauthorized" })),
    )
        .into_response()
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(val) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), val);
    }
}

fn extract_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    for raw in headers.get_all(header::COOKIE) {
        let Ok(text) = raw.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let trimmed = pair.trim();
            if let Some((name, value)) = trimmed.split_once('=')
                && name.trim() == cookie_name
                && !value.is_empty()
            {
                return Some(value.trim());
            }
        }
    }
    None
}

fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = auth.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Bearer ")
            .or_else(|| trimmed.strip_prefix("bearer "))
        {
            let token = rest.trim();
            if !token.is_empty() {
                return Some(token);
            }
        }
    }
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
