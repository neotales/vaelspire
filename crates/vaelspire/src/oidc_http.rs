//! OIDC 1.0, OAuth 2.0, SAML 2.0 metadata, and Admin OIDC Client HTTP routes.

use axum::Json;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::json;
use vaelspire_core::Timestamp;
use vaelspire_oidc::{
    AuthorizeRequest, AuthorizeSubject, GrantType, OidcError, RegisterClientInput,
};

use crate::bootstrap::lookup_user_email;
use crate::server::{AppState, extract_bearer_token, resolve_session_from_headers};

/// `GET /.well-known/openid-configuration`
pub async fn openid_configuration(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.oidc.discovery())
}

/// `GET /.well-known/jwks.json`
pub async fn jwks(State(state): State<AppState>) -> Response {
    match state.oidc.jwks() {
        Ok(set) => (
            StatusCode::OK,
            [(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            )],
            Json(set),
        )
            .into_response(),
        Err(err) => oidc_error_response(err),
    }
}

/// Query parameters for `GET /oauth2/authorize`.
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// Must be `"code"`.
    pub response_type: String,
    /// Registered OAuth `client_id`.
    pub client_id: String,
    /// Exact registered `redirect_uri`.
    pub redirect_uri: String,
    /// Space-delimited scopes.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Optional opaque CSRF state echoed back to client.
    pub state: Option<String>,
    /// Optional OIDC nonce echoed into ID token.
    pub nonce: Option<String>,
    /// Optional PKCE `S256` challenge.
    pub code_challenge: Option<String>,
    /// Optional PKCE method (`S256`).
    pub code_challenge_method: Option<String>,
    /// Set `approve=1` for programmatic / consented authorization code issuance.
    pub approve: Option<String>,
}

fn default_scope() -> String {
    "openid".to_owned()
}

/// `GET /oauth2/authorize` — validates client/PKCE and either issues an authorization code
/// (when signed in and approved) or returns consent/auth requirements.
pub async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    if query.response_type != "code" {
        return oidc_error_response(OidcError::InvalidRequest);
    }

    let Ok(client) = state.oidc.get_client(&query.client_id) else {
        return oidc_error_response(OidcError::InvalidClient);
    };
    if !client
        .redirect_uris
        .iter()
        .any(|u| u == &query.redirect_uri)
    {
        return oidc_error_response(OidcError::InvalidRequest);
    }

    let Some(session) = resolve_session_from_headers(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "login_required",
                "login_url": "/ui/login",
                "client_id": client.client_id,
                "client_name": client.name,
            })),
        )
            .into_response();
    };

    if query.approve.as_deref() != Some("1") {
        return (
            StatusCode::OK,
            Json(json!({
                "consent_required": true,
                "client_id": client.client_id,
                "client_name": client.name,
                "redirect_uri": query.redirect_uri,
                "scope": query.scope,
                "state": query.state,
            })),
        )
            .into_response();
    }

    let email = lookup_user_email(&state.store, session.user_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    let req = AuthorizeRequest {
        client_id: query.client_id,
        redirect_uri: query.redirect_uri.clone(),
        scope: query.scope,
        nonce: query.nonce,
        code_challenge: query.code_challenge,
        code_challenge_method: query.code_challenge_method,
    };
    let subject = AuthorizeSubject {
        user_id: session.user_id,
        tenant_id: session.tenant_id,
        email,
    };

    match state
        .oidc
        .create_authorization_code(&req, subject, Timestamp::now_utc())
    {
        Ok(code) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(json!({
                "code": code.as_str(),
                "redirect_uri": query.redirect_uri,
                "state": query.state,
            })),
        )
            .into_response(),
        Err(err) => oidc_error_response(err),
    }
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    grant_type: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// `POST /oauth2/token` — supports `application/x-www-form-urlencoded` and `application/json`,
/// plus HTTP Basic client authentication.
pub async fn token_endpoint(State(state): State<AppState>, request: Request) -> Response {
    let headers = request.headers().clone();
    let basic = parse_basic_auth(&headers);
    let Ok(body) = parse_form_or_json::<TokenBody>(request).await else {
        return oidc_error_response(OidcError::InvalidRequest);
    };

    let client_id = body
        .client_id
        .or_else(|| basic.as_ref().map(|(id, _)| id.clone()));
    let client_secret = body
        .client_secret
        .or_else(|| basic.as_ref().map(|(_, secret)| secret.clone()));

    let Some(client_id) = client_id else {
        return oidc_error_response(OidcError::InvalidClient);
    };

    let now = Timestamp::now_utc();
    let result = match body.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri)) = (body.code, body.redirect_uri) else {
                return oidc_error_response(OidcError::InvalidRequest);
            };
            state.oidc.exchange_authorization_code(
                &client_id,
                client_secret.as_deref(),
                &code,
                &redirect_uri,
                body.code_verifier.as_deref(),
                now,
            )
        }
        "refresh_token" => {
            let Some(refresh_token) = body.refresh_token else {
                return oidc_error_response(OidcError::InvalidRequest);
            };
            state.oidc.exchange_refresh_token(
                &client_id,
                client_secret.as_deref(),
                &refresh_token,
                body.scope.as_deref(),
                now,
            )
        }
        "client_credentials" => {
            let Some(secret) = client_secret.as_deref() else {
                return oidc_error_response(OidcError::InvalidClient);
            };
            state
                .oidc
                .exchange_client_credentials(&client_id, secret, body.scope.as_deref(), now)
        }
        _ => Err(OidcError::UnsupportedGrantType),
    };

    match result {
        Ok(tokens) => {
            state.metrics.record_oidc_token(&body.grant_type, true);
            (
                StatusCode::OK,
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(tokens),
            )
                .into_response()
        }
        Err(err) => {
            state.metrics.record_oidc_token(&body.grant_type, false);
            if body.grant_type == "refresh_token" && matches!(err, OidcError::InvalidGrant) {
                state
                    .metrics
                    .record_anomaly(crate::security::AnomalyKind::RefreshTokenReuse);
                crate::alerts::notify_anomaly(
                    state.alerts.as_ref(),
                    crate::security::AnomalyKind::RefreshTokenReuse,
                    None,
                    None,
                    None,
                    state.pii_log_mode,
                    state.audit_ip_mode,
                );
                tracing::warn!(client_id = %client_id, "oidc refresh grant denied (possible token reuse)");
            }
            oidc_error_response(err)
        }
    }
}

/// `GET /oauth2/userinfo` — includes effective org + per-app RBAC `roles`, `groups`, `permissions`.
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(bearer) = extract_bearer_token(&headers) else {
        return oidc_error_response(OidcError::InvalidToken);
    };
    match state.oidc.userinfo(bearer, Timestamp::now_utc()) {
        Ok(info) => {
            let mut payload = serde_json::to_value(&info).unwrap_or_else(|_| json!({}));
            if let Ok(user_id) = vaelspire_core::Id::parse_str(&info.sub)
                && let Ok(access) = crate::rbac::resolve_effective_access(
                    &state.store,
                    state.tenant_id,
                    user_id,
                    None,
                )
                .await
                && let Some(obj) = payload.as_object_mut()
            {
                obj.insert("roles".to_owned(), json!(access.roles));
                obj.insert("groups".to_owned(), json!(access.groups));
                obj.insert("permissions".to_owned(), json!(access.permissions));
            }
            (
                StatusCode::OK,
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(payload),
            )
                .into_response()
        }
        Err(err) => oidc_error_response(err),
    }
}

#[derive(Debug, Deserialize)]
struct SingleTokenBody {
    token: String,
}

/// `POST /oauth2/introspect` (RFC 7662)
pub async fn introspect(State(state): State<AppState>, request: Request) -> Response {
    let Ok(body) = parse_form_or_json::<SingleTokenBody>(request).await else {
        return oidc_error_response(OidcError::InvalidRequest);
    };
    match state.oidc.introspect(&body.token, Timestamp::now_utc()) {
        Ok(resp) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(resp),
        )
            .into_response(),
        Err(err) => oidc_error_response(err),
    }
}

/// `POST /oauth2/revoke` (RFC 7009)
pub async fn revoke(State(state): State<AppState>, request: Request) -> Response {
    let Ok(body) = parse_form_or_json::<SingleTokenBody>(request).await else {
        return oidc_error_response(OidcError::InvalidRequest);
    };
    match state.oidc.revoke(&body.token, Timestamp::now_utc()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => oidc_error_response(err),
    }
}

/// `GET /saml/metadata` — standards-clean SAML 2.0 `EntityDescriptor` XML metadata.
pub async fn saml_metadata(State(state): State<AppState>) -> Response {
    let issuer = xml_escape(&state.issuer_url);
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{issuer}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{issuer}/saml/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{issuer}/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"#
    );
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/samlmetadata+xml; charset=utf-8"),
        )],
        xml,
    )
        .into_response()
}

/// Public summary of a registered OAuth/OIDC client returned by `GET /admin/oidc/clients`.
#[derive(Debug, Serialize)]
struct ClientSummary {
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    grant_types: Vec<GrantType>,
    confidential: bool,
    require_pkce: bool,
}

/// Request payload for `POST /admin/oidc/clients`.
#[derive(Debug, Deserialize)]
pub struct CreateClientBody {
    /// Public client identifier.
    pub client_id: String,
    /// Display name.
    pub name: String,
    /// Exact redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed scopes (defaults to `["openid", "email", "profile", "offline_access"]`).
    #[serde(default = "default_client_scopes")]
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types.
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<GrantType>,
    /// Whether to mint a confidential client secret.
    #[serde(default = "default_true")]
    pub confidential: bool,
}

fn default_client_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "email".to_owned(),
        "profile".to_owned(),
        "offline_access".to_owned(),
    ]
}

fn default_grant_types() -> Vec<GrantType> {
    vec![
        GrantType::AuthorizationCode,
        GrantType::RefreshToken,
        GrantType::ClientCredentials,
    ]
}

const fn default_true() -> bool {
    true
}

/// `GET /admin/oidc/clients` — requires an authenticated session or API key.
pub async fn list_clients(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !crate::server::is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.oidc.list_clients() {
        Ok(clients) => {
            let summaries: Vec<ClientSummary> = clients
                .into_iter()
                .map(|c| ClientSummary {
                    confidential: c.is_confidential(),
                    client_id: c.client_id,
                    name: c.name,
                    redirect_uris: c.redirect_uris,
                    allowed_scopes: c.allowed_scopes,
                    grant_types: c.grant_types,
                    require_pkce: c.require_pkce,
                })
                .collect();
            Json(json!({ "clients": summaries })).into_response()
        }
        Err(err) => oidc_error_response(err),
    }
}

/// `POST /admin/oidc/clients` — requires an authenticated session or API key.
pub async fn create_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateClientBody>,
) -> Response {
    if !crate::server::is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let input = RegisterClientInput {
        client_id: body.client_id,
        name: body.name,
        tenant_id: state.tenant_id,
        redirect_uris: body.redirect_uris,
        allowed_scopes: body.allowed_scopes,
        grant_types: body.grant_types,
        confidential: body.confidential,
    };
    match state.oidc.register_client(input) {
        Ok(registered) => {
            // Persist client definition into vs_oidc_client (best-effort when extended schema is present).
            let _ = persist_oidc_client(&state.store, &registered.client).await;
            (
                StatusCode::CREATED,
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(json!({
                    "client_id": registered.client.client_id,
                    "name": registered.client.name,
                    "redirect_uris": registered.client.redirect_uris,
                    "allowed_scopes": registered.client.allowed_scopes,
                    "confidential": registered.client.is_confidential(),
                    "client_secret": registered.client_secret.as_ref().map(|s| s.as_str()),
                })),
            )
                .into_response()
        }
        Err(err) => oidc_error_response(err),
    }
}

async fn persist_oidc_client(
    store: &vaelspire_store_sqlite::SqliteStore,
    client: &vaelspire_oidc::OidcClient,
) -> Result<(), neotales_dbapi::DbError> {
    use crate::ext_store::{i64_param, id_param, opt_bytes_param, text_param};
    use neotales_dbapi::Pool;
    let redirects = serde_json::to_string(&client.redirect_uris).unwrap_or_else(|_| "[]".into());
    let scopes = serde_json::to_string(&client.allowed_scopes).unwrap_or_else(|_| "[]".into());
    let grants = serde_json::to_string(&client.grant_types).unwrap_or_else(|_| "[]".into());
    let now = Timestamp::now_utc().to_string();
    let params = [
        text_param(&client.client_id)?,
        id_param(client.tenant_id)?,
        text_param(&client.name)?,
        i64_param(i64::from(client.is_confidential()))?,
        opt_bytes_param(client.secret_digest())?,
        text_param(&redirects)?,
        text_param(&scopes)?,
        text_param(&grants)?,
        i64_param(i64::from(client.require_pkce))?,
        text_param(&now)?,
    ];
    store
        .provider()
        .execute_async(
            "INSERT OR REPLACE INTO vs_oidc_client \
             (client_id, tenant_id, name, confidential, secret_digest, redirect_uris_json, allowed_scopes_json, grant_types_json, require_pkce, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            neotales_dbapi::QueryOptions::new().bind_all(&params),
        )
        .await?;
    Ok(())
}

/// Reload all persisted OIDC clients from `vs_oidc_client` into `oidc` on server startup.
///
/// # Errors
/// Returns [`neotales_dbapi::DbError`] if reading `vs_oidc_client` fails.
pub async fn load_persisted_clients(
    store: &vaelspire_store_sqlite::SqliteStore,
    oidc: &vaelspire_oidc::OidcProvider,
) -> Result<usize, neotales_dbapi::DbError> {
    use neotales_dbapi::{Pool, QueryOptions};
    let rows = store
        .provider()
        .fetch_all_async(
            "SELECT client_id, tenant_id, name, secret_digest, redirect_uris_json, allowed_scopes_json, grant_types_json, require_pkce FROM vs_oidc_client",
            QueryOptions::new(),
        )
        .await?;
    let mut loaded = 0usize;
    for row in rows {
        let Ok(client_id) = row.read::<String>("client_id") else {
            continue;
        };
        let Ok(raw_tid) = row.read::<Vec<u8>>("tenant_id") else {
            continue;
        };
        let Ok(tenant_id) = vaelspire_core::Id::from_slice(&raw_tid) else {
            continue;
        };
        let name = row.read::<String>("name").unwrap_or_default();
        let secret_digest = row
            .read::<Vec<u8>>("secret_digest")
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        let redirect_uris: Vec<String> = row
            .read::<String>("redirect_uris_json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let allowed_scopes: Vec<String> = row
            .read::<String>("allowed_scopes_json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let grant_types: Vec<GrantType> = row
            .read::<String>("grant_types_json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(default_grant_types);
        let require_pkce = row.read::<i64>("require_pkce").unwrap_or(1) != 0;
        let client = vaelspire_oidc::OidcClient::from_persisted(
            client_id,
            name,
            tenant_id,
            redirect_uris,
            allowed_scopes,
            grant_types,
            secret_digest,
            require_pkce,
        );
        if oidc.restore_client(client).is_ok() {
            loaded += 1;
        }
    }
    Ok(loaded)
}

/// `DELETE /admin/oidc/clients/{client_id}` — removes an OIDC client from memory and `vs_oidc_client`.
pub async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(client_id): axum::extract::Path<String>,
) -> Response {
    use neotales_dbapi::{Pool, QueryOptions};
    if !crate::server::is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let removed = state.oidc.delete_client(&client_id).unwrap_or(false);
    if let Ok(cid_p) = crate::ext_store::text_param(&client_id) {
        let _ = state
            .store
            .provider()
            .execute_async(
                "DELETE FROM vs_oidc_client WHERE client_id = ?",
                QueryOptions::new().bind_all(&[cid_p]),
            )
            .await;
    }
    if removed {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn oidc_error_response(err: OidcError) -> Response {
    let status = match err {
        OidcError::InvalidClient | OidcError::InvalidToken => StatusCode::UNAUTHORIZED,
        OidcError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({ "error": err.code() })),
    )
        .into_response()
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = raw.trim().strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded.as_bytes()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_owned(), secret.to_owned()))
}

async fn parse_form_or_json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, ()> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.starts_with("application/json") {
        let Json(value) = <Json<T> as axum::extract::FromRequest<()>>::from_request(request, &())
            .await
            .map_err(|_| ())?;
        Ok(value)
    } else {
        let axum::Form(value) =
            <axum::Form<T> as axum::extract::FromRequest<()>>::from_request(request, &())
                .await
                .map_err(|_| ())?;
        Ok(value)
    }
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
