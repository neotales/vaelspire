//! SCIM 2.0 (RFC 7643 / RFC 7644) directory provisioning endpoints for Vaelspire Core:
//! `/scim/v2/ServiceProviderConfig`, `/scim/v2/Users`, and `/scim/v2/Groups`
//! (supporting per-org SCIM bearer tokens, sessions, and API keys).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use neotales_dbapi::{Pool, QueryOptions};
use serde::Deserialize;
use serde_json::{Value, json};
use vaelspire_auth::{Auth, Policy, hash_password};
use vaelspire_core::privacy::format_email_for_log;
use vaelspire_core::{Id, Timestamp};

use crate::bootstrap::{
    DirectoryUser, find_directory_user, list_tenant_users, soft_delete_directory_user,
};
use crate::ext_store::{id_param, opt_text_param, text_param};
use crate::org::{load_org_policy, validate_email_against_policy, verify_scim_token};
use crate::server::{AppState, extract_bearer_token, is_authenticated};

const SCIM_CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";
const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

async fn is_scim_authorized(state: &AppState, headers: &HeaderMap) -> bool {
    if let Some(bearer) = extract_bearer_token(headers)
        && verify_scim_token(&state.store, &state.digest_key, state.tenant_id, bearer).await
    {
        return true;
    }
    is_authenticated(state, headers).await
}

/// `GET /scim/v2/ServiceProviderConfig`
pub async fn service_provider_config() -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": false, "maxResults": 500 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "Per-Org SCIM Token / API Key",
                    "description": "Authenticate SCIM requests using a per-org SCIM bearer token (vs_scim_...), API key, or admin session."
                }
            ]
        }),
    )
}

/// `GET /scim/v2/Users`
pub async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    match list_tenant_users(&state.store, state.tenant_id, 200).await {
        Ok(users) => {
            let resources: Vec<_> = users.iter().map(user_to_scim).collect();
            scim_json(
                StatusCode::OK,
                json!({
                    "schemas": [SCIM_LIST_SCHEMA],
                    "totalResults": resources.len(),
                    "startIndex": 1,
                    "itemsPerPage": resources.len(),
                    "Resources": resources,
                }),
            )
        }
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

/// `GET /scim/v2/Users/{id}`
pub async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(user_id) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid user identifier");
    };
    match find_directory_user(&state.store, state.tenant_id, user_id).await {
        Ok(Some(user)) => scim_json(StatusCode::OK, user_to_scim(&user)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

/// SCIM 2.0 user creation payload (`POST /scim/v2/Users`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimCreateUser {
    /// Email address (used as SCIM `userName`).
    pub user_name: String,
    /// Optional initial password (if omitted, generates an unguessable 256-bit random secret).
    pub password: Option<String>,
}

/// `POST /scim/v2/Users`
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScimCreateUser>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();

    // Enforce organization email domain policy during SCIM provisioning too.
    let org_policy = load_org_policy(&state.store, state.tenant_id).await;
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
    if let Err(reason) =
        validate_email_against_policy(&body.user_name, org_policy.email_policy, &verified_domains)
    {
        return scim_error(StatusCode::BAD_REQUEST, reason);
    }

    let raw_pw = if let Some(pw) = body.password {
        pw
    } else {
        match crate::config::generate_hex_key() {
            Ok(k) => k.to_string(),
            Err(_) => return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "rng failure"),
        }
    };

    let Ok(Ok(hash)) = tokio::task::spawn_blocking(move || hash_password(raw_pw.as_bytes())).await
    else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid password");
    };

    let auth = Auth::new(state.store.as_ref(), *state.digest_key, Policy::default()).auditing(true);
    match auth
        .sign_up(
            state.tenant_id,
            &body.user_name,
            &hash,
            Timestamp::now_utc(),
        )
        .await
    {
        Ok(user) => {
            tracing::info!(
                user_id = %user.id,
                email = %format_email_for_log(&user.email, state.pii_log_mode),
                "scim user provisioned"
            );
            scim_json(
                StatusCode::CREATED,
                user_to_scim(&DirectoryUser {
                    id: user.id,
                    tenant_id: user.tenant_id,
                    email: user.email,
                    status: "active".to_owned(),
                }),
            )
        }
        Err(vaelspire_core::AuthError::Conflict) => {
            scim_error(StatusCode::CONFLICT, "user already exists")
        }
        Err(vaelspire_core::AuthError::Invalid) => {
            scim_error(StatusCode::BAD_REQUEST, "invalid userName email")
        }
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

/// SCIM 2.0 `PatchOp` request body for `PATCH /scim/v2/Users/{id}` and `PATCH /scim/v2/Groups/{id}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ScimPatchOp {
    /// List of SCIM patch operations.
    #[serde(default)]
    pub operations: Vec<ScimOperation>,
}

/// One operation inside a SCIM 2.0 `PatchOp`.
#[derive(Debug, Deserialize)]
pub struct ScimOperation {
    /// `"add"`, `"remove"`, or `"replace"`.
    pub op: String,
    /// Optional attribute path (e.g. `"active"`, `"members"`).
    #[serde(default)]
    pub path: Option<String>,
    /// Value payload (boolean, object, or array of `{ "value": "<id>" }`).
    #[serde(default)]
    pub value: Value,
}

/// `PATCH /scim/v2/Users/{id}` — supports `active: false` immediate offboarding & session revocation.
pub async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    Json(body): Json<ScimPatchOp>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(user_id) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid user identifier");
    };

    let mut deactivate = false;
    for op in &body.operations {
        let is_active_path = op
            .path
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case("active"));
        if (is_active_path && op.value.as_bool() == Some(false))
            || (op.path.is_none() && op.value.get("active").and_then(Value::as_bool) == Some(false))
        {
            deactivate = true;
        }
    }

    if deactivate {
        match soft_delete_directory_user(&state.store, state.tenant_id, user_id).await {
            Ok(true) => {
                // Immediately revoke all active sessions for offboarded user.
                if let (Ok(now_p), Ok(uid_p)) = (
                    text_param(&Timestamp::now_utc().to_string()),
                    id_param(user_id),
                ) {
                    let _ = state
                        .store
                        .provider()
                        .execute_async(
                            "UPDATE auth_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                            QueryOptions::new().bind_all(&[now_p, uid_p]),
                        )
                        .await;
                }
                tracing::info!(user_id = %user_id, "scim user deactivated and sessions revoked");
                return scim_json(
                    StatusCode::OK,
                    json!({
                        "schemas": [SCIM_USER_SCHEMA],
                        "id": user_id.to_string(),
                        "active": false,
                    }),
                );
            }
            Ok(false) => return scim_error(StatusCode::NOT_FOUND, "user not found"),
            Err(_) => return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
        }
    }

    match find_directory_user(&state.store, state.tenant_id, user_id).await {
        Ok(Some(user)) => scim_json(StatusCode::OK, user_to_scim(&user)),
        Ok(None) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

/// `DELETE /scim/v2/Users/{id}`
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(user_id) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid user identifier");
    };
    match soft_delete_directory_user(&state.store, state.tenant_id, user_id).await {
        Ok(true) => {
            if let (Ok(now_p), Ok(uid_p)) = (
                text_param(&Timestamp::now_utc().to_string()),
                id_param(user_id),
            ) {
                let _ = state
                    .store
                    .provider()
                    .execute_async(
                        "UPDATE auth_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                        QueryOptions::new().bind_all(&[now_p, uid_p]),
                    )
                    .await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

/// SCIM 2.0 group member reference.
#[derive(Debug, Deserialize)]
pub struct ScimMemberRef {
    /// User UUID string.
    pub value: String,
}

/// SCIM 2.0 group creation payload (`POST /scim/v2/Groups`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimCreateGroup {
    /// Group display name.
    pub display_name: String,
    /// Optional external `IdP` group ID.
    #[serde(default)]
    pub external_id: Option<String>,
    /// Optional initial member list.
    #[serde(default)]
    pub members: Vec<ScimMemberRef>,
}

/// `GET /scim/v2/Groups`
pub async fn list_groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(tid) = id_param(state.tenant_id) else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure");
    };
    let Ok(rows) = state
        .store
        .provider()
        .fetch_all_async(
            "SELECT id, name, external_id FROM vs_group WHERE tenant_id = ? ORDER BY name ASC",
            QueryOptions::new().bind_all(&[tid]),
        )
        .await
    else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure");
    };
    let mut resources = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(raw_id) = row.read::<Vec<u8>>("id") else {
            continue;
        };
        let Ok(gid) = Id::from_slice(&raw_id) else {
            continue;
        };
        let name = row.read::<String>("name").unwrap_or_default();
        let ext = row
            .read::<String>("external_id")
            .ok()
            .filter(|s| !s.is_empty());
        let members = load_group_members(&state, gid).await;
        resources.push(group_to_scim(gid, &name, ext.as_deref(), &members));
    }
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_LIST_SCHEMA],
            "totalResults": resources.len(),
            "startIndex": 1,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

/// `POST /scim/v2/Groups`
pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScimCreateGroup>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let name = body.display_name.trim();
    if name.is_empty() || name.len() > 128 {
        return scim_error(StatusCode::BAD_REQUEST, "invalid displayName");
    }
    let gid = Id::now_v7();
    let now = Timestamp::now_utc().to_string();
    let ext = body
        .external_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(gid)?,
            id_param(state.tenant_id)?,
            text_param(name)?,
            opt_text_param(ext)?,
            text_param(&now)?,
        ])
    })() else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure");
    };
    if state
        .store
        .provider()
        .execute_async(
            "INSERT INTO vs_group (id, tenant_id, name, external_id, created_at) VALUES (?, ?, ?, ?, ?)",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .is_err()
    {
        return scim_error(StatusCode::CONFLICT, "group already exists");
    }

    let mut member_ids = Vec::new();
    for member in &body.members {
        if let Ok(uid) = Id::parse_str(&member.value)
            && let (Ok(gp), Ok(up)) = (id_param(gid), id_param(uid))
            && state
                .store
                .provider()
                .execute_async(
                    "INSERT OR IGNORE INTO vs_group_member (group_id, user_id) VALUES (?, ?)",
                    QueryOptions::new().bind_all(&[gp, up]),
                )
                .await
                .is_ok()
        {
            member_ids.push(uid);
        }
    }

    scim_json(
        StatusCode::CREATED,
        group_to_scim(gid, name, ext, &member_ids),
    )
}

/// `GET /scim/v2/Groups/{id}`
pub async fn get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(gid) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid group identifier");
    };
    let (Ok(tid), Ok(gp)) = (id_param(state.tenant_id), id_param(gid)) else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure");
    };
    let Ok(row) = state
        .store
        .provider()
        .fetch_one_async(
            "SELECT name, external_id FROM vs_group WHERE tenant_id = ? AND id = ? LIMIT 1",
            QueryOptions::new().bind_all(&[tid, gp]),
        )
        .await
    else {
        return scim_error(StatusCode::NOT_FOUND, "group not found");
    };
    let name = row.read::<String>("name").unwrap_or_default();
    let ext = row
        .read::<String>("external_id")
        .ok()
        .filter(|s| !s.is_empty());
    let members = load_group_members(&state, gid).await;
    scim_json(
        StatusCode::OK,
        group_to_scim(gid, &name, ext.as_deref(), &members),
    )
}

/// `PATCH /scim/v2/Groups/{id}` — RFC 7644 `PatchOp` adding/removing group members.
pub async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
    Json(body): Json<ScimPatchOp>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(gid) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid group identifier");
    };
    let (Ok(tid), Ok(gp)) = (id_param(state.tenant_id), id_param(gid)) else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure");
    };
    let Ok(row) = state
        .store
        .provider()
        .fetch_one_async(
            "SELECT name, external_id FROM vs_group WHERE tenant_id = ? AND id = ? LIMIT 1",
            QueryOptions::new().bind_all(&[tid, gp.clone()]),
        )
        .await
    else {
        return scim_error(StatusCode::NOT_FOUND, "group not found");
    };

    for op in &body.operations {
        let action = op.op.to_ascii_lowercase();
        let path_lower = op.path.as_deref().unwrap_or("").to_ascii_lowercase();
        if path_lower.starts_with("members") {
            let ids = extract_member_ids(&op.value);
            for uid in ids {
                if let Ok(up) = id_param(uid) {
                    if action == "add" {
                        let _ = state
                            .store
                            .provider()
                            .execute_async(
                                "INSERT OR IGNORE INTO vs_group_member (group_id, user_id) VALUES (?, ?)",
                                QueryOptions::new().bind_all(&[gp.clone(), up]),
                            )
                            .await;
                    } else if action == "remove" {
                        let _ = state
                            .store
                            .provider()
                            .execute_async(
                                "DELETE FROM vs_group_member WHERE group_id = ? AND user_id = ?",
                                QueryOptions::new().bind_all(&[gp.clone(), up]),
                            )
                            .await;
                    }
                }
            }
        }
    }

    let name = row.read::<String>("name").unwrap_or_default();
    let ext = row
        .read::<String>("external_id")
        .ok()
        .filter(|s| !s.is_empty());
    let members = load_group_members(&state, gid).await;
    scim_json(
        StatusCode::OK,
        group_to_scim(gid, &name, ext.as_deref(), &members),
    )
}

/// `DELETE /scim/v2/Groups/{id}`
pub async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    if !is_scim_authorized(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    state.metrics.record_scim_op();
    let Ok(gid) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid group identifier");
    };
    let (Ok(tid), Ok(gp)) = (id_param(state.tenant_id), id_param(gid)) else {
        return scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure");
    };
    match state
        .store
        .provider()
        .execute_async(
            "DELETE FROM vs_group WHERE tenant_id = ? AND id = ?",
            QueryOptions::new().bind_all(&[tid, gp]),
        )
        .await
    {
        Ok(0) => scim_error(StatusCode::NOT_FOUND, "group not found"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

async fn load_group_members(state: &AppState, group_id: Id) -> Vec<Id> {
    let Ok(gp) = id_param(group_id) else {
        return Vec::new();
    };
    let Ok(rows) = state
        .store
        .provider()
        .fetch_all_async(
            "SELECT user_id FROM vs_group_member WHERE group_id = ?",
            QueryOptions::new().bind_all(&[gp]),
        )
        .await
    else {
        return Vec::new();
    };
    rows.into_iter()
        .filter_map(|r| Id::from_slice(&r.read::<Vec<u8>>("user_id").ok()?).ok())
        .collect()
}

fn extract_member_ids(val: &Value) -> Vec<Id> {
    let mut out = Vec::new();
    if let Some(arr) = val.as_array() {
        for item in arr {
            if let Some(raw) = item.get("value").and_then(Value::as_str)
                && let Ok(id) = Id::parse_str(raw)
            {
                out.push(id);
            }
        }
    } else if let Some(raw) = val.get("value").and_then(Value::as_str)
        && let Ok(id) = Id::parse_str(raw)
    {
        out.push(id);
    }
    out
}

fn user_to_scim(user: &DirectoryUser) -> Value {
    json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id.to_string(),
        "userName": user.email,
        "active": user.status != "suspended" && user.status != "deleted" && user.status != "erased",
        "emails": [{ "value": user.email, "primary": true }],
        "meta": {
            "resourceType": "User",
            "location": format!("/scim/v2/Users/{}", user.id),
        }
    })
}

fn group_to_scim(id: Id, name: &str, external_id: Option<&str>, members: &[Id]) -> Value {
    let member_list: Vec<Value> = members
        .iter()
        .map(|uid| {
            json!({
                "value": uid.to_string(),
                "$ref": format!("/scim/v2/Users/{uid}"),
            })
        })
        .collect();
    json!({
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": id.to_string(),
        "displayName": name,
        "externalId": external_id,
        "members": member_list,
        "meta": {
            "resourceType": "Group",
            "location": format!("/scim/v2/Groups/{id}"),
        }
    })
}

fn scim_json(status: StatusCode, value: Value) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(SCIM_CONTENT_TYPE),
        )],
        Json(value),
    )
        .into_response()
}

fn scim_error(status: StatusCode, detail: &str) -> Response {
    scim_json(
        status,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": status.as_u16().to_string(),
            "detail": detail,
        }),
    )
}
