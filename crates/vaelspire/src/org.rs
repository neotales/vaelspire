//! Self-service organization `IdP` configuration, DNS domain verification,
//! email domain policies (`allow_public`, `business_domains_only`, `verified_domains_only`),
//! Home Realm Discovery (`POST /auth/discover`), and per-org SCIM 2.0 bearer tokens.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use neotales_dbapi::{DbType, Parameter, Pool, QueryOptions, Value};
use serde::{Deserialize, Serialize};
use serde_json::json;
use vaelspire_auth::token_digest;
use vaelspire_core::{Id, Timestamp};
use vaelspire_store_sqlite::SqliteStore;

use crate::ext_store::{i64_param, id_param, text_param};
use crate::server::{AppState, is_authenticated};

/// Public/consumer/disposable email domains rejected under `business_domains_only`.
const PUBLIC_EMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.uk",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "aol.com",
    "mail.com",
    "gmx.com",
    "gmx.net",
    "yandex.com",
    "yandex.ru",
    "tutanota.com",
    "tuta.io",
    "fastmail.com",
    "zoho.com",
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
];

/// Email domain enrollment policy for an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailPolicy {
    /// Any valid email address is accepted (including consumer domains like `gmail.com`).
    #[default]
    AllowPublic,
    /// Block consumer/free/disposable email domains; require a business domain.
    BusinessDomainsOnly,
    /// Restrict sign-up and membership strictly to DNS-verified organization domains.
    VerifiedDomainsOnly,
}

impl EmailPolicy {
    /// Stable database and API label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowPublic => "allow_public",
            Self::BusinessDomainsOnly => "business_domains_only",
            Self::VerifiedDomainsOnly => "verified_domains_only",
        }
    }

    /// Parse a policy label.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow_public" => Some(Self::AllowPublic),
            "business_domains_only" => Some(Self::BusinessDomainsOnly),
            "verified_domains_only" => Some(Self::VerifiedDomainsOnly),
            _ => None,
        }
    }
}

/// Organization policy record returned by `GET/PUT /org/portal/policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPolicy {
    /// Email domain policy (`allow_public`, `business_domains_only`, `verified_domains_only`).
    pub email_policy: EmailPolicy,
    /// Whether browser sessions slide on activity.
    pub session_sliding: bool,
    /// Idle session timeout in seconds.
    pub session_idle_secs: i64,
    /// Hard absolute maximum session lifetime in seconds.
    pub session_absolute_secs: i64,
    /// Keep local admin password/passkey login available if an upstream `IdP` is misconfigured.
    pub break_glass_enabled: bool,
}

impl Default for OrgPolicy {
    fn default() -> Self {
        Self {
            email_policy: EmailPolicy::AllowPublic,
            session_sliding: true,
            session_idle_secs: 86_400,
            session_absolute_secs: 604_800,
            break_glass_enabled: true,
        }
    }
}

/// Organization domain record for DNS TXT verification (`_vaelspire-verify.<domain>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgDomain {
    /// `UUIDv7` identifier.
    pub id: String,
    /// Lowercase normalized domain (e.g. `"acme.com"`).
    pub domain: String,
    /// Expected TXT record value (`vaelspire-site-verification=<token>`).
    pub txt_record_name: String,
    /// Token value for the DNS TXT record.
    pub verification_token: String,
    /// Whether ownership has been verified.
    pub verified: bool,
    /// Verification timestamp when verified.
    pub verified_at: Option<String>,
}

/// Self-service upstream OIDC or SAML 2.0 `IdP` configuration for an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct OrgIdp {
    /// `UUIDv7` identifier.
    pub id: String,
    /// Display name (e.g. `"Acme Okta SSO"`).
    pub name: String,
    /// `"oidc"` or `"saml"`.
    pub protocol: String,
    /// OIDC issuer URL (for `protocol == "oidc"`).
    pub issuer_url: String,
    /// OIDC client ID (for `protocol == "oidc"`).
    pub client_id: String,
    /// Whether a client secret is stored (never returned in plaintext).
    pub has_client_secret: bool,
    /// Whether SAML metadata XML is stored.
    pub has_metadata_xml: bool,
    /// Automatically provision users on first SSO sign-in.
    pub jit_provisioning: bool,
    /// Default role assigned to JIT-provisioned users.
    pub default_role: String,
    /// Claim or SAML attribute name carrying group names.
    pub group_claim: String,
    /// Whether this `IdP` is active for Home Realm Discovery.
    pub enabled: bool,
}

/// Check whether `domain` is a known public/consumer/disposable email provider.
#[must_use]
pub fn is_public_email_domain(domain: &str) -> bool {
    let lower = domain.trim().to_ascii_lowercase();
    PUBLIC_EMAIL_DOMAINS.contains(&lower.as_str())
}

/// Validate `email` against `policy` and the organization's verified domain list.
///
/// # Errors
/// Returns a human-readable policy rejection reason when `email` violates the policy.
pub fn validate_email_against_policy(
    email: &str,
    policy: EmailPolicy,
    verified_domains: &[String],
) -> Result<(), &'static str> {
    let domain = email
        .trim()
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty() && d.contains('.'))
        .ok_or("invalid email address")?;

    match policy {
        EmailPolicy::AllowPublic => Ok(()),
        EmailPolicy::BusinessDomainsOnly => {
            if is_public_email_domain(&domain) {
                Err(
                    "organization requires a business email domain (public email providers are disabled)",
                )
            } else {
                Ok(())
            }
        }
        EmailPolicy::VerifiedDomainsOnly => {
            if verified_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&domain))
            {
                Ok(())
            } else {
                Err("organization restricts accounts to verified company domains")
            }
        }
    }
}

/// Load the current [`OrgPolicy`] for `tenant_id` (falling back to defaults if not customized).
pub async fn load_org_policy(store: &SqliteStore, tenant_id: Id) -> OrgPolicy {
    let Ok(tid) = id_param(tenant_id) else {
        return OrgPolicy::default();
    };
    let Ok(row) = store
        .provider()
        .fetch_one_async(
            "SELECT email_policy, session_sliding, session_idle_secs, session_absolute_secs, break_glass_enabled \
             FROM vs_org_policy WHERE tenant_id = ? LIMIT 1",
            QueryOptions::new().bind_all(&[tid]),
        )
        .await
    else {
        return OrgPolicy::default();
    };
    OrgPolicy {
        email_policy: row
            .read::<String>("email_policy")
            .ok()
            .and_then(|s| EmailPolicy::parse(&s))
            .unwrap_or_default(),
        session_sliding: row.read::<i64>("session_sliding").unwrap_or(1) != 0,
        session_idle_secs: row.read::<i64>("session_idle_secs").unwrap_or(86_400),
        session_absolute_secs: row.read::<i64>("session_absolute_secs").unwrap_or(604_800),
        break_glass_enabled: row.read::<i64>("break_glass_enabled").unwrap_or(1) != 0,
    }
}

/// Verify whether `raw_token` is an active per-org SCIM bearer token for `tenant_id`.
pub async fn verify_scim_token(
    store: &SqliteStore,
    digest_key: &[u8; 32],
    tenant_id: Id,
    raw_token: &str,
) -> bool {
    if !raw_token.starts_with("vs_scim_") {
        return false;
    }
    let (digest, _) = token_digest(digest_key, "scim_token", raw_token);
    let Ok(tid) = id_param(tenant_id) else {
        return false;
    };
    let Ok(dig) = Parameter::new(DbType::Bytes, Value::Bytes(digest.to_vec())) else {
        return false;
    };
    store
        .provider()
        .fetch_one_async(
            "SELECT id FROM vs_scim_token WHERE tenant_id = ? AND token_digest = ? AND revoked_at IS NULL LIMIT 1",
            QueryOptions::new().bind_all(&[tid, dig]),
        )
        .await
        .is_ok()
}

/// `GET /org/portal/policy`
pub async fn get_org_policy(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(load_org_policy(&state.store, state.tenant_id).await).into_response()
}

/// `PUT /org/portal/policy`
pub async fn update_org_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<OrgPolicy>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if body.session_idle_secs < 60 || body.session_absolute_secs < body.session_idle_secs {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "session_idle_secs must be >= 60 and <= session_absolute_secs" }),
            ),
        )
            .into_response();
    }
    let now = Timestamp::now_utc().to_string();
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(state.tenant_id)?,
            text_param(body.email_policy.as_str())?,
            i64_param(i64::from(body.session_sliding))?,
            i64_param(body.session_idle_secs)?,
            i64_param(body.session_absolute_secs)?,
            i64_param(i64::from(body.break_glass_enabled))?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let sql = "INSERT INTO vs_org_policy \
        (tenant_id, email_policy, session_sliding, session_idle_secs, session_absolute_secs, break_glass_enabled, updated_at) \
        VALUES (?, ?, ?, ?, ?, ?, ?) \
        ON CONFLICT(tenant_id) DO UPDATE SET \
        email_policy = excluded.email_policy, \
        session_sliding = excluded.session_sliding, \
        session_idle_secs = excluded.session_idle_secs, \
        session_absolute_secs = excluded.session_absolute_secs, \
        break_glass_enabled = excluded.break_glass_enabled, \
        updated_at = excluded.updated_at";
    match state
        .store
        .provider()
        .execute_async(sql, QueryOptions::new().bind_all(&params))
        .await
    {
        Ok(_) => Json(body).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Request body for `POST /org/portal/domains`.
#[derive(Debug, Deserialize)]
pub struct AddDomainBody {
    /// Domain name (e.g. `"acme.com"`).
    pub domain: String,
}

/// `GET /org/portal/domains`
pub async fn list_org_domains(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(tid) = id_param(state.tenant_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(rows) = state
        .store
        .provider()
        .fetch_all_async(
            "SELECT id, domain, verification_token, verified_at FROM vs_org_domain WHERE tenant_id = ? ORDER BY domain ASC",
            QueryOptions::new().bind_all(&[tid]),
        )
        .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut domains = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(raw_id) = row.read::<Vec<u8>>("id") else {
            continue;
        };
        let Ok(id) = Id::from_slice(&raw_id) else {
            continue;
        };
        let domain = row.read::<String>("domain").unwrap_or_default();
        let verified_at = row
            .read::<String>("verified_at")
            .ok()
            .filter(|s| !s.is_empty());
        domains.push(OrgDomain {
            id: id.to_string(),
            txt_record_name: format!("_vaelspire-verify.{domain}"),
            domain,
            verification_token: row.read::<String>("verification_token").unwrap_or_default(),
            verified: verified_at.is_some(),
            verified_at,
        });
    }
    Json(json!({ "domains": domains })).into_response()
}

/// `POST /org/portal/domains`
pub async fn add_org_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AddDomainBody>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let domain = body.domain.trim().to_ascii_lowercase();
    if domain.is_empty()
        || !domain.contains('.')
        || domain.contains('/')
        || domain.contains(' ')
        || domain.len() > 253
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid domain name" })),
        )
            .into_response();
    }
    let id = Id::now_v7();
    let mut rand_bytes = [0u8; 18];
    if getrandom::fill(&mut rand_bytes).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let token = format!(
        "vaelspire-site-verification={}",
        URL_SAFE_NO_PAD.encode(rand_bytes)
    );
    let now = Timestamp::now_utc().to_string();
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(id)?,
            id_param(state.tenant_id)?,
            text_param(&domain)?,
            text_param(&token)?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .store
        .provider()
        .execute_async(
            "INSERT INTO vs_org_domain (id, tenant_id, domain, verification_token, created_at) VALUES (?, ?, ?, ?, ?)",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "domain already registered" })),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(OrgDomain {
            id: id.to_string(),
            txt_record_name: format!("_vaelspire-verify.{domain}"),
            domain,
            verification_token: token,
            verified: false,
            verified_at: None,
        }),
    )
        .into_response()
}

/// Optional body for `POST /org/portal/domains/{id}/verify` supplying the observed TXT token.
#[derive(Debug, Deserialize, Default)]
pub struct VerifyDomainBody {
    /// Expected `vaelspire-site-verification=...` TXT value confirming ownership.
    #[serde(default)]
    pub txt_value: Option<String>,
}

/// `POST /org/portal/domains/{id}/verify`
pub async fn verify_org_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(domain_id): Path<String>,
    body: Option<Json<VerifyDomainBody>>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(did) = Id::parse_str(&domain_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(tid), Ok(dp)) = (id_param(state.tenant_id), id_param(did)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(row) = state
        .store
        .provider()
        .fetch_one_async(
            "SELECT domain, verification_token FROM vs_org_domain WHERE tenant_id = ? AND id = ? LIMIT 1",
            QueryOptions::new().bind_all(&[tid.clone(), dp.clone()]),
        )
        .await
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let expected: String = row.read("verification_token").unwrap_or_default();
    let domain: String = row.read("domain").unwrap_or_default();
    if let Some(Json(ref payload)) = body
        && let Some(ref supplied) = payload.txt_value
        && supplied.trim() != expected
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "DNS TXT verification token mismatch" })),
        )
            .into_response();
    }
    let now = Timestamp::now_utc().to_string();
    let Ok(now_p) = text_param(&now) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .store
        .provider()
        .execute_async(
            "UPDATE vs_org_domain SET verified_at = ? WHERE tenant_id = ? AND id = ?",
            QueryOptions::new().bind_all(&[now_p, tid, dp]),
        )
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    Json(OrgDomain {
        id: did.to_string(),
        txt_record_name: format!("_vaelspire-verify.{domain}"),
        domain,
        verification_token: expected,
        verified: true,
        verified_at: Some(now),
    })
    .into_response()
}

/// Request body for `POST /org/portal/idps`.
#[derive(Debug, Deserialize)]
pub struct CreateOrgIdpBody {
    /// Human-readable `IdP` name.
    pub name: String,
    /// `"oidc"` or `"saml"`.
    pub protocol: String,
    /// OIDC issuer URL.
    #[serde(default)]
    pub issuer_url: String,
    /// OIDC client ID.
    #[serde(default)]
    pub client_id: String,
    /// OIDC client secret.
    #[serde(default)]
    pub client_secret: String,
    /// SAML 2.0 `EntityDescriptor` metadata XML.
    #[serde(default)]
    pub metadata_xml: String,
    /// Enable JIT user provisioning.
    #[serde(default = "default_true")]
    pub jit_provisioning: bool,
    /// Default role for JIT users.
    #[serde(default = "default_member")]
    pub default_role: String,
    /// Claim/attribute carrying groups.
    #[serde(default = "default_groups")]
    pub group_claim: String,
    /// Whether active for Home Realm Discovery.
    #[serde(default)]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}
fn default_member() -> String {
    "member".to_owned()
}
fn default_groups() -> String {
    "groups".to_owned()
}

/// `GET /org/portal/idps`
pub async fn list_org_idps(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(tid) = id_param(state.tenant_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(rows) = state
        .store
        .provider()
        .fetch_all_async(
            "SELECT id, name, protocol, issuer_url, client_id, client_secret, metadata_xml, \
             jit_provisioning, default_role, group_claim, enabled \
             FROM vs_org_idp WHERE tenant_id = ? ORDER BY created_at DESC",
            QueryOptions::new().bind_all(&[tid]),
        )
        .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut idps = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(raw_id) = row.read::<Vec<u8>>("id") else {
            continue;
        };
        let Ok(id) = Id::from_slice(&raw_id) else {
            continue;
        };
        idps.push(OrgIdp {
            id: id.to_string(),
            name: row.read::<String>("name").unwrap_or_default(),
            protocol: row.read::<String>("protocol").unwrap_or_default(),
            issuer_url: row.read::<String>("issuer_url").unwrap_or_default(),
            client_id: row.read::<String>("client_id").unwrap_or_default(),
            has_client_secret: !row
                .read::<String>("client_secret")
                .unwrap_or_default()
                .is_empty(),
            has_metadata_xml: !row
                .read::<String>("metadata_xml")
                .unwrap_or_default()
                .is_empty(),
            jit_provisioning: row.read::<i64>("jit_provisioning").unwrap_or(1) != 0,
            default_role: row.read::<String>("default_role").unwrap_or_default(),
            group_claim: row.read::<String>("group_claim").unwrap_or_default(),
            enabled: row.read::<i64>("enabled").unwrap_or(0) != 0,
        });
    }
    Json(json!({ "idps": idps })).into_response()
}

/// `POST /org/portal/idps`
pub async fn create_org_idp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateOrgIdpBody>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let protocol = body.protocol.trim().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "oidc" | "saml") || body.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "protocol must be 'oidc' or 'saml' and name must be non-empty" }),
            ),
        )
            .into_response();
    }
    let id = Id::now_v7();
    let now = Timestamp::now_utc().to_string();
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(id)?,
            id_param(state.tenant_id)?,
            text_param(body.name.trim())?,
            text_param(&protocol)?,
            text_param(body.issuer_url.trim())?,
            text_param(body.client_id.trim())?,
            text_param(body.client_secret.trim())?,
            text_param(body.metadata_xml.trim())?,
            i64_param(i64::from(body.jit_provisioning))?,
            text_param(body.default_role.trim())?,
            text_param(body.group_claim.trim())?,
            i64_param(i64::from(body.enabled))?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .store
        .provider()
        .execute_async(
            "INSERT INTO vs_org_idp \
             (id, tenant_id, name, protocol, issuer_url, client_id, client_secret, metadata_xml, \
              jit_provisioning, default_role, group_claim, enabled, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::CREATED,
        Json(OrgIdp {
            id: id.to_string(),
            name: body.name.trim().to_owned(),
            protocol,
            issuer_url: body.issuer_url.trim().to_owned(),
            client_id: body.client_id.trim().to_owned(),
            has_client_secret: !body.client_secret.trim().is_empty(),
            has_metadata_xml: !body.metadata_xml.trim().is_empty(),
            jit_provisioning: body.jit_provisioning,
            default_role: body.default_role.trim().to_owned(),
            group_claim: body.group_claim.trim().to_owned(),
            enabled: body.enabled,
        }),
    )
        .into_response()
}

/// `POST /org/portal/idps/{id}/test` — dry-run structural validation before activating SSO.
pub async fn test_org_idp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(idp_id): Path<String>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(iid) = Id::parse_str(&idp_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(tid), Ok(ip)) = (id_param(state.tenant_id), id_param(iid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok(row) = state
        .store
        .provider()
        .fetch_one_async(
            "SELECT protocol, issuer_url, client_id, metadata_xml FROM vs_org_idp WHERE tenant_id = ? AND id = ? LIMIT 1",
            QueryOptions::new().bind_all(&[tid, ip]),
        )
        .await
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let protocol = row.read::<String>("protocol").unwrap_or_default();
    let issuer = row.read::<String>("issuer_url").unwrap_or_default();
    let client_id = row.read::<String>("client_id").unwrap_or_default();
    let metadata_xml = row.read::<String>("metadata_xml").unwrap_or_default();

    let mut checks = Vec::new();
    let mut ok = true;
    if protocol == "oidc" {
        let issuer_ok = issuer.starts_with("https://") || issuer.starts_with("http://127.0.0.1");
        checks.push(json!({ "check": "issuer_url_https", "ok": issuer_ok }));
        let cid_ok = !client_id.is_empty();
        checks.push(json!({ "check": "client_id_present", "ok": cid_ok }));
        ok = issuer_ok && cid_ok;
    } else if protocol == "saml" {
        let has_entity = metadata_xml.contains("EntityDescriptor");
        let has_sso = metadata_xml.contains("SingleSignOnService");
        checks.push(json!({ "check": "saml_entity_descriptor", "ok": has_entity }));
        checks.push(json!({ "check": "saml_sso_service", "ok": has_sso }));
        ok = has_entity && has_sso;
    }

    Json(json!({
        "idp_id": iid.to_string(),
        "protocol": protocol,
        "ok": ok,
        "checks": checks,
    }))
    .into_response()
}

/// `DELETE /org/portal/idps/{id}`
pub async fn delete_org_idp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(idp_id): Path<String>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(iid) = Id::parse_str(&idp_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(tid), Ok(ip)) = (id_param(state.tenant_id), id_param(iid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "DELETE FROM vs_org_idp WHERE tenant_id = ? AND id = ?",
            QueryOptions::new().bind_all(&[tid, ip]),
        )
        .await
    {
        Ok(0) => StatusCode::NOT_FOUND.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Request body for `POST /org/portal/scim-tokens`.
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenBody {
    /// Human-readable label (e.g. `"Okta Production Sync"`).
    pub name: String,
}

/// `POST /org/portal/scim-tokens` — mint a per-org scoped SCIM 2.0 bearer token (revealed once).
pub async fn create_scim_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateScimTokenBody>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid token name" })),
        )
            .into_response();
    }
    let mut raw = [0u8; 32];
    if getrandom::fill(&mut raw).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let token = format!("vs_scim_{}", URL_SAFE_NO_PAD.encode(raw));
    let (digest, _) = token_digest(&state.digest_key, "scim_token", &token);
    let id = Id::now_v7();
    let now = Timestamp::now_utc().to_string();
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(id)?,
            id_param(state.tenant_id)?,
            text_param(name)?,
            Parameter::new(DbType::Bytes, Value::Bytes(digest.to_vec()))?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .store
        .provider()
        .execute_async(
            "INSERT INTO vs_scim_token (id, tenant_id, name, token_digest, created_at) VALUES (?, ?, ?, ?, ?)",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "id": id.to_string(),
            "name": name,
            "token": token,
            "created_at": now,
        })),
    )
        .into_response()
}

/// Request body for `POST /auth/discover` (Home Realm Discovery).
#[derive(Debug, Deserialize)]
pub struct DiscoverBody {
    /// Email address entered on the sign-in screen.
    pub email: String,
}

/// `POST /auth/discover` — Home Realm Discovery (never reveals whether a specific user exists).
pub async fn discover_home_realm(
    State(state): State<AppState>,
    Json(body): Json<DiscoverBody>,
) -> Response {
    let policy = load_org_policy(&state.store, state.tenant_id).await;
    let domain = body
        .email
        .trim()
        .rsplit_once('@')
        .map_or_default(|(_, d)| d.to_ascii_lowercase());

    let mut verified_domains = Vec::new();
    if let Ok(tid) = id_param(state.tenant_id)
        && let Ok(rows) = state
            .store
            .provider()
            .fetch_all_async(
                "SELECT domain FROM vs_org_domain WHERE tenant_id = ? AND verified_at IS NOT NULL",
                QueryOptions::new().bind_all(&[tid]),
            )
            .await
    {
        for r in rows {
            if let Ok(d) = r.read::<String>("domain") {
                verified_domains.push(d);
            }
        }
    }

    let policy_allowed =
        validate_email_against_policy(&body.email, policy.email_policy, &verified_domains);
    let domain_verified = verified_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&domain));

    if domain_verified
        && let Ok(tid) = id_param(state.tenant_id)
        && let Ok(row) = state
            .store
            .provider()
            .fetch_one_async(
                "SELECT id, name, protocol, issuer_url FROM vs_org_idp WHERE tenant_id = ? AND enabled = 1 LIMIT 1",
                QueryOptions::new().bind_all(&[tid]),
            )
            .await
    {
        let idp_id = row
            .read::<Vec<u8>>("id")
            .ok()
            .and_then(|b| Id::from_slice(&b).ok())
            .map(|id| id.to_string());
        return Json(json!({
            "mode": "sso",
            "domain_verified": true,
            "email_policy": policy.email_policy.as_str(),
            "allowed": policy_allowed.is_ok(),
            "break_glass_enabled": policy.break_glass_enabled,
            "idp": {
                "id": idp_id,
                "name": row.read::<String>("name").unwrap_or_default(),
                "protocol": row.read::<String>("protocol").unwrap_or_default(),
                "issuer_url": row.read::<String>("issuer_url").unwrap_or_default(),
            }
        }))
        .into_response();
    }

    Json(json!({
        "mode": "local",
        "domain_verified": domain_verified,
        "email_policy": policy.email_policy.as_str(),
        "allowed": policy_allowed.is_ok(),
        "reason": policy_allowed.err(),
        "break_glass_enabled": policy.break_glass_enabled,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_public_business_and_verified_domain_policies() {
        let verified = vec!["acme.com".to_owned()];

        assert!(
            validate_email_against_policy("user@gmail.com", EmailPolicy::AllowPublic, &verified)
                .is_ok()
        );
        assert!(
            validate_email_against_policy(
                "user@gmail.com",
                EmailPolicy::BusinessDomainsOnly,
                &verified
            )
            .is_err()
        );
        assert!(
            validate_email_against_policy(
                "user@startup.io",
                EmailPolicy::BusinessDomainsOnly,
                &verified
            )
            .is_ok()
        );
        assert!(
            validate_email_against_policy(
                "user@startup.io",
                EmailPolicy::VerifiedDomainsOnly,
                &verified
            )
            .is_err()
        );
        assert!(
            validate_email_against_policy(
                "alice@acme.com",
                EmailPolicy::VerifiedDomainsOnly,
                &verified
            )
            .is_ok()
        );
    }
}
