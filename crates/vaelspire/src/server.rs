//! Axum HTTP server wiring: auth routes, OIDC `IdP`, SCIM 2.0 (Users & Groups), SAML metadata,
//! org-wide & per-app RBAC, self-service org `IdP` & domain policies, GDPR export/erasure,
//! `/forward-auth`, `/metrics`, `/health`, `/ready`, and optional embedded `SvelteKit` UI.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use vaelspire_alerts::AlertHandle;
use vaelspire_auth::{ApiKeys, Auth, Policy, SessionCache};
use vaelspire_axum::AuthRouter;
use vaelspire_core::privacy::{AuditIpMode, PiiLogMode, format_email_for_log};
use vaelspire_core::{AuthError, Id, Session, Timestamp};
use vaelspire_oidc::{OidcProvider, OidcProviderConfig};
use vaelspire_store_sqlite::SqliteStore;
use zeroize::Zeroizing;

use crate::bootstrap::{check_store_ready, lookup_user_email};
use crate::config::{ServerConfig, UiMode};
use crate::ext_store::ensure_extended_schema;
use crate::metrics::{ForwardAuthMethod, Metrics};
use crate::rbac::resolve_effective_access;
use crate::security::{AnomalyDetector, IpCidr, IpSource};
use crate::{gdpr, oidc_http, org, rbac, scim, ui};

/// Shared runtime state for Vaelspire's server routes.
#[derive(Clone)]
pub struct AppState {
    pub(crate) store: Arc<SqliteStore>,
    pub(crate) tenant_id: Id,
    pub(crate) digest_key: Zeroizing<[u8; 32]>,
    pub(crate) session_cache: Arc<SessionCache>,
    pub(crate) session_policy: Policy,
    pub(crate) session_cookie: String,
    pub(crate) csrf_cookie: String,
    pub(crate) api_key_prefix: String,
    pub(crate) forward_auth_login_url: Option<String>,
    pub(crate) issuer_url: String,
    pub(crate) ui_mode: UiMode,
    pub(crate) pii_log_mode: PiiLogMode,
    pub(crate) audit_ip_mode: AuditIpMode,
    pub(crate) ip_source: IpSource,
    pub(crate) trusted_proxies: Vec<IpCidr>,
    pub(crate) rp_id: Option<String>,
    pub(crate) rp_origin: Option<String>,
    pub(crate) oidc: Arc<OidcProvider>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) anomaly: Arc<AnomalyDetector>,
    pub(crate) alerts: Option<AlertHandle>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("tenant_id", &self.tenant_id)
            .field("session_cookie", &self.session_cookie)
            .field("api_key_prefix", &self.api_key_prefix)
            .field("issuer_url", &self.issuer_url)
            .field("ui_mode", &self.ui_mode)
            .field("pii_log_mode", &self.pii_log_mode)
            .field("audit_ip_mode", &self.audit_ip_mode)
            .finish_non_exhaustive()
    }
}

/// Convert [`ServerConfig`] session timeout settings into a [`Policy`].
#[must_use]
pub fn build_session_policy(config: &ServerConfig) -> Policy {
    let idle_secs = i64::try_from(config.session_idle_ttl.as_secs()).unwrap_or(86_400);
    let max_lifetime = config
        .session_max_lifetime
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .map(time::Duration::seconds);
    Policy {
        session_ttl: time::Duration::seconds(idle_secs.max(60)),
        session_sliding: config.session_sliding,
        session_max_lifetime: max_lifetime,
        ..Policy::default()
    }
}

/// Build the complete Axum [`Router`] for Vaelspire Core.
///
/// # Errors
/// Returns [`AuthError`] if configuration (such as `api_key_prefix`) or OIDC initialization fails.
pub fn build_router(
    store: Arc<SqliteStore>,
    tenant_id: Id,
    config: &ServerConfig,
) -> Result<Router, AuthError> {
    let oidc = Arc::new(
        OidcProvider::new(OidcProviderConfig::new(
            config.issuer_url.clone(),
            *config.digest_key,
        ))
        .map_err(|_| AuthError::Store)?,
    );
    build_router_with_oidc(store, tenant_id, config, oidc)
}

#[allow(clippy::too_many_lines)]
fn build_router_with_oidc(
    store: Arc<SqliteStore>,
    tenant_id: Id,
    config: &ServerConfig,
    oidc: Arc<OidcProvider>,
) -> Result<Router, AuthError> {
    let metrics = Arc::new(Metrics::new());
    let session_cache = Arc::new(SessionCache::default());
    let anomaly = Arc::new(AnomalyDetector::default());
    let session_policy = build_session_policy(config);

    let mut auth_router = AuthRouter::new(
        Arc::clone(&store),
        tenant_id,
        *config.digest_key,
        config.cookie_secure,
    )
    .policy(session_policy)
    .session_cookie(config.session_cookie.clone())
    .csrf_cookie(config.csrf_cookie.clone())
    .auditing(config.auditing)
    .roles(config.roles)
    .trust_proxy(config.trust_proxy || config.ip_source != IpSource::Direct)
    .rate_limit(config.rate_limit.0, config.rate_limit.1)
    .api_keys(Some(&config.api_key_prefix))?;

    if let Some(origins) = &config.allowed_origins {
        auth_router = auth_router.allowed_origins(origins.iter().map(String::as_str));
    }

    let alerts = match &config.alerts {
        Some(cfg) if !cfg.sinks.is_empty() => {
            let router = Arc::new(cfg.build_router().map_err(|_| AuthError::Store)?);
            Some(router.spawn_dispatcher(256))
        }
        _ => None,
    };

    let state = AppState {
        store,
        tenant_id,
        digest_key: config.digest_key.clone(),
        session_cache,
        session_policy,
        session_cookie: config.session_cookie.clone(),
        csrf_cookie: config.csrf_cookie.clone(),
        api_key_prefix: config.api_key_prefix.clone(),
        forward_auth_login_url: config.forward_auth_login_url.clone(),
        issuer_url: config.issuer_url.clone(),
        ui_mode: config.ui_mode,
        pii_log_mode: config.pii_log_mode,
        audit_ip_mode: config.audit_ip_mode,
        ip_source: config.ip_source,
        trusted_proxies: config.trusted_proxies.clone(),
        rp_id: config.rp_id.clone(),
        rp_origin: config.rp_origin.clone(),
        oidc,
        metrics: Arc::clone(&metrics),
        anomaly,
        alerts,
    };

    let core_routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(prometheus_metrics))
        .route("/.well-known/vaelspire", get(discovery))
        // OIDC 1.0 & SAML 2.0
        .route(
            "/.well-known/openid-configuration",
            get(oidc_http::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(oidc_http::jwks))
        .route("/oauth2/authorize", get(oidc_http::authorize_get))
        .route("/oauth2/token", post(oidc_http::token_endpoint))
        .route("/oauth2/userinfo", get(oidc_http::userinfo))
        .route("/oauth2/introspect", post(oidc_http::introspect))
        .route("/oauth2/revoke", post(oidc_http::revoke))
        .route("/saml/metadata", get(oidc_http::saml_metadata))
        .route(
            "/admin/oidc/clients",
            get(oidc_http::list_clients).post(oidc_http::create_client),
        )
        .route(
            "/admin/oidc/clients/{client_id}",
            delete(oidc_http::delete_client),
        )
        // SCIM 2.0 Directory Sync (Users & Groups)
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(scim::service_provider_config),
        )
        .route("/scim/v2/Users", get(scim::list_users).post(scim::create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(scim::get_user)
                .patch(scim::patch_user)
                .delete(scim::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(scim::list_groups).post(scim::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(scim::get_group)
                .patch(scim::patch_group)
                .delete(scim::delete_group),
        )
        // Org-Wide & Per-App RBAC
        .route(
            "/admin/rbac/roles",
            get(rbac::list_roles).post(rbac::create_role),
        )
        .route(
            "/admin/rbac/permissions",
            get(rbac::list_permissions).post(rbac::create_permission),
        )
        .route(
            "/admin/rbac/roles/{role_id}/permissions/{perm_id}",
            post(rbac::grant_permission_to_role).delete(rbac::revoke_permission_from_role),
        )
        .route(
            "/admin/rbac/groups",
            get(rbac::list_groups).post(rbac::create_group),
        )
        .route(
            "/admin/rbac/groups/{group_id}/members/{user_id}",
            post(rbac::add_group_member).delete(rbac::remove_group_member),
        )
        .route(
            "/admin/rbac/groups/{group_id}/roles/{role_id}",
            post(rbac::assign_role_to_group),
        )
        .route(
            "/admin/rbac/users/{user_id}/roles/{role_id}",
            post(rbac::assign_role_to_user),
        )
        .route(
            "/admin/rbac/users/{user_id}/effective",
            get(rbac::get_effective_access),
        )
        // Self-Service Org Portal (Policy, Domains, IdP, SCIM Tokens) & Home Realm Discovery
        .route("/auth/discover", post(org::discover_home_realm))
        .route(
            "/org/portal/policy",
            get(org::get_org_policy).put(org::update_org_policy),
        )
        .route(
            "/org/portal/domains",
            get(org::list_org_domains).post(org::add_org_domain),
        )
        .route(
            "/org/portal/domains/{id}/verify",
            post(org::verify_org_domain),
        )
        .route(
            "/org/portal/idps",
            get(org::list_org_idps).post(org::create_org_idp),
        )
        .route("/org/portal/idps/{id}/test", post(org::test_org_idp))
        .route("/org/portal/idps/{id}", delete(org::delete_org_idp))
        .route("/org/portal/scim-tokens", post(org::create_scim_token))
        // GDPR Data Portability & Erasure
        .route("/account/export", get(gdpr::export_own_account))
        .route("/account/erase", delete(gdpr::erase_own_account))
        .route("/admin/gdpr/erase/{user_id}", post(gdpr::admin_erase_user))
        // Reverse-proxy Forward-Auth
        .route("/forward-auth", any(forward_auth))
        .with_state(state);

    let app = ui::attach_ui_routes(core_routes.merge(auth_router.into_router()), config.ui_mode)
        .layer(middleware::from_fn_with_state(metrics, count_http_requests));

    Ok(app)
}

/// Bind and run the Vaelspire HTTP server until `SIGINT` or `SIGTERM`.
///
/// # Errors
/// Returns an error if schema initialization, socket binding, or serving HTTP fails.
pub async fn serve(
    store: Arc<SqliteStore>,
    tenant_id: Id,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_extended_schema(&store).await?;

    let oidc = Arc::new(
        OidcProvider::new(OidcProviderConfig::new(
            config.issuer_url.clone(),
            *config.digest_key,
        ))
        .map_err(|err| format!("failed to initialize OIDC provider: {err:?}"))?,
    );
    let restored = oidc_http::load_persisted_clients(&store, &oidc).await?;
    if restored > 0 {
        tracing::info!(
            count = restored,
            "restored persisted OIDC clients from sqlite"
        );
    }

    let app = build_router_with_oidc(store, tenant_id, &config, oidc)
        .map_err(|err| format!("failed to build Vaelspire router: {err:?}"))?;

    let listener = TcpListener::bind(config.bind).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(
        bind = %local_addr,
        issuer = %config.issuer_url,
        tenant = %tenant_id,
        cookie_secure = config.cookie_secure,
        ui_mode = config.ui_mode.as_str(),
        pii_log_mode = config.pii_log_mode.as_str(),
        audit_ip_mode = config.audit_ip_mode.as_str(),
        session_sliding = config.session_sliding,
        passkey_enabled = cfg!(feature = "passkey"),
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

/// Resolve an active browser session from `Cookie` headers using the configured sliding/hard policy.
pub(crate) async fn resolve_session_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<Session> {
    let token = extract_cookie(headers, &state.session_cookie)?;
    let auth = Auth::new(
        state.store.as_ref(),
        *state.digest_key,
        state.session_policy,
    )
    .session_cache(Arc::clone(&state.session_cache));
    auth.resolve_session(token, Timestamp::now_utc()).await.ok()
}

/// Check whether `headers` carry a valid session cookie OR valid API key.
pub(crate) async fn is_authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    if resolve_session_from_headers(state, headers).await.is_some() {
        return true;
    }
    if let Some(api_key) = extract_api_key(headers)
        && let Ok(keys) = ApiKeys::new(
            state.store.as_ref(),
            *state.digest_key,
            Some(&state.api_key_prefix),
        )
        && keys.lookup(api_key, Timestamp::now_utc()).await.is_ok()
    {
        return true;
    }
    false
}

/// Extract a raw `Authorization: Bearer <token>` header value.
pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let rest = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))?;
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
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
    let default_rp_id = state
        .issuer_url
        .split("://")
        .nth(1)
        .unwrap_or("localhost")
        .split(['/', ':'])
        .next()
        .unwrap_or("localhost");

    Json(json!({
        "service": "vaelspire",
        "edition": "core",
        "version": env!("CARGO_PKG_VERSION"),
        "issuer": state.issuer_url,
        "tenant_id": state.tenant_id.to_string(),
        "ui_mode": state.ui_mode.as_str(),
        "privacy": {
            "pii_log_mode": state.pii_log_mode.as_str(),
            "audit_ip_mode": state.audit_ip_mode.as_str(),
            "ip_source": state.ip_source.as_str(),
        },
        "session_policy": {
            "sliding": state.session_policy.session_sliding,
            "idle_secs": state.session_policy.session_ttl.whole_seconds(),
            "max_lifetime_secs": state.session_policy.session_max_lifetime.map(time::Duration::whole_seconds),
        },
        "passkey": {
            "enabled": cfg!(feature = "passkey"),
            "rp_id": state.rp_id.as_deref().unwrap_or(default_rp_id),
            "rp_origin": state.rp_origin.as_deref().unwrap_or(&state.issuer_url),
        },
        "alerts": {
            "enabled": state.alerts.is_some(),
            "sinks": state.alerts.as_ref().map_or_else(Vec::new, |h| {
                h.sink_names().into_iter().map(str::to_owned).collect()
            }),
        },
        "cookies": {
            "session": state.session_cookie,
            "csrf": state.csrf_cookie,
        },
        "endpoints": {
            "health": "/health",
            "ready": "/ready",
            "metrics": "/metrics",
            "forward_auth": "/forward-auth",
            "discover": "/auth/discover",
            "openid_configuration": "/.well-known/openid-configuration",
            "jwks": "/.well-known/jwks.json",
            "saml_metadata": "/saml/metadata",
            "scim_users": "/scim/v2/Users",
            "scim_groups": "/scim/v2/Groups",
            "rbac_roles": "/admin/rbac/roles",
            "rbac_permissions": "/admin/rbac/permissions",
            "rbac_groups": "/admin/rbac/groups",
            "org_portal_policy": "/org/portal/policy",
            "org_portal_domains": "/org/portal/domains",
            "org_portal_idps": "/org/portal/idps",
            "org_portal_scim_tokens": "/org/portal/scim-tokens",
            "gdpr_export": "/account/export",
            "gdpr_erase": "/account/erase",
            "sign_up": "/sign-up",
            "sign_in": "/sign-in",
            "sign_out": "/sign-out",
            "session": "/session",
            "sessions": "/sessions",
            "api_keys": "/api-keys",
            "admin_oidc_clients": "/admin/oidc/clients",
        }
    }))
}

async fn forward_auth(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let now = Timestamp::now_utc();
    let app_filter = headers
        .get("x-vaelspire-app-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(session_token) = extract_cookie(&headers, &state.session_cookie) {
        let auth = Auth::new(
            state.store.as_ref(),
            *state.digest_key,
            state.session_policy,
        )
        .session_cache(Arc::clone(&state.session_cache));
        if let Ok(session) = auth.resolve_session(session_token, now).await {
            state
                .metrics
                .record_forward_auth(true, ForwardAuthMethod::Session);
            let email = lookup_user_email(&state.store, session.user_id)
                .await
                .ok()
                .flatten();
            record_session_anomaly(&state, &headers, session.user_id, email.as_deref());
            let access = resolve_effective_access(
                &state.store,
                session.tenant_id,
                session.user_id,
                app_filter,
            )
            .await
            .ok();
            return allow_response(
                session.user_id,
                session.tenant_id,
                email.as_deref(),
                "session",
                Some(("x-vaelspire-session-id", session.id)),
                access.as_ref(),
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
            let access =
                resolve_effective_access(&state.store, key.tenant_id, key.user_id, app_filter)
                    .await
                    .ok();
            return allow_response(
                key.user_id,
                key.tenant_id,
                email.as_deref(),
                "api_key",
                Some(("x-vaelspire-api-key-id", key.id)),
                access.as_ref(),
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

fn record_session_anomaly(state: &AppState, headers: &HeaderMap, user_id: Id, email: Option<&str>) {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let client_ip =
        crate::security::extract_client_ip(None, headers, state.ip_source, &state.trusted_proxies)
            .map(|ip| ip.to_string());
    if let Some(kind) = state
        .anomaly
        .record_success(user_id, client_ip.as_deref(), ua)
    {
        state.metrics.record_anomaly(kind);
        crate::alerts::notify_anomaly(
            state.alerts.as_ref(),
            kind,
            Some(user_id),
            email,
            client_ip.as_deref(),
            state.pii_log_mode,
            state.audit_ip_mode,
        );
        let masked = email.map_or_else(
            || "[unknown]".to_owned(),
            |e| format_email_for_log(e, state.pii_log_mode),
        );
        tracing::warn!(
            user_id = %user_id,
            email = %masked,
            anomaly = kind.as_str(),
            "session anomaly observed on /forward-auth"
        );
    }
}

fn allow_response(
    user_id: Id,
    tenant_id: Id,
    email: Option<&str>,
    method: &'static str,
    credential_header: Option<(&'static str, Id)>,
    access: Option<&rbac::EffectiveAccess>,
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
    if let Some(acc) = access {
        if !acc.roles.is_empty() {
            insert_header(headers, "x-vaelspire-roles", &acc.roles.join(","));
        }
        if !acc.groups.is_empty() {
            insert_header(headers, "x-vaelspire-groups", &acc.groups.join(","));
        }
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
    if let Some(token) = extract_bearer_token(headers) {
        return Some(token);
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
