//! Org-wide and per-application RBAC: roles, permissions, groups, permission-to-role
//! grants, group-to-role grants, and effective access resolution.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use neotales_dbapi::{Pool, QueryOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use vaelspire_core::{Id, Timestamp};
use vaelspire_store_sqlite::SqliteStore;

use crate::ext_store::{id_param, opt_text_param, text_param};
use crate::server::{AppState, is_authenticated};

/// Role record (org-wide when `app_id` is `None`, per-OIDC-app when `Some`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRole {
    /// `UUIDv7` role identifier.
    pub id: String,
    /// Optional OIDC `client_id` scoping this role to one application (`None` = org-wide).
    pub app_id: Option<String>,
    /// Role name (e.g. `"admin"`, `"vault-editor"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Permission record (org-wide when `app_id` is `None`, per-OIDC-app when `Some`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPermission {
    /// `UUIDv7` permission identifier.
    pub id: String,
    /// Optional OIDC `client_id` scoping this permission to one application.
    pub app_id: Option<String>,
    /// Permission name (e.g. `"secrets:read"`, `"billing:write"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Group record in a tenant (shared with SCIM 2.0 `/scim/v2/Groups`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacGroup {
    /// `UUIDv7` group identifier.
    pub id: String,
    /// Group name (e.g. `"engineering"`).
    pub name: String,
    /// Optional external directory ID (Okta / Entra ID).
    pub external_id: Option<String>,
}

/// Effective resolved RBAC projection for one user (optionally scoped to one `app_id`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EffectiveAccess {
    /// All active group names the user belongs to.
    pub groups: Vec<String>,
    /// Union of direct user roles and group-inherited roles (org-wide + matching `app_id`).
    pub roles: Vec<String>,
    /// Union of permissions granted to all effective roles.
    pub permissions: Vec<String>,
}

/// Resolve effective groups, roles (direct + group-inherited), and permissions for `user_id`.
///
/// When `app_id` is `Some(client_id)`, returns org-wide (`app_id IS NULL`) plus roles/permissions
/// scoped specifically to `client_id`. When `None`, returns all org-wide roles/permissions.
///
/// # Errors
/// Returns a database error if querying `SQLite` fails.
pub async fn resolve_effective_access(
    store: &SqliteStore,
    tenant_id: Id,
    user_id: Id,
    app_id: Option<&str>,
) -> Result<EffectiveAccess, neotales_dbapi::DbError> {
    let tid = id_param(tenant_id)?;
    let uid = id_param(user_id)?;

    // 1. Groups the user belongs to.
    let group_rows = store
        .provider()
        .fetch_all_async(
            "SELECT g.name FROM vs_group g \
             INNER JOIN vs_group_member gm ON gm.group_id = g.id \
             WHERE g.tenant_id = ? AND gm.user_id = ? ORDER BY g.name ASC",
            QueryOptions::new().bind_all(&[tid.clone(), uid.clone()]),
        )
        .await?;
    let mut groups = BTreeSet::new();
    for row in group_rows {
        if let Ok(name) = row.read::<String>("name") {
            groups.insert(name);
        }
    }

    // 2. Effective roles (direct + via group membership), filtered by org-wide or matching app_id.
    let role_rows = if let Some(app) = app_id {
        let app_p = text_param(app)?;
        store
            .provider()
            .fetch_all_async(
                "SELECT DISTINCT r.id, r.app_id, r.name FROM vs_app_role r \
                 WHERE r.tenant_id = ? AND (r.app_id IS NULL OR r.app_id = ?) AND ( \
                   EXISTS (SELECT 1 FROM vs_user_role ur WHERE ur.tenant_id = r.tenant_id AND ur.user_id = ? AND ur.role_id = r.id) \
                   OR EXISTS (SELECT 1 FROM vs_group_role gr INNER JOIN vs_group_member gm ON gm.group_id = gr.group_id WHERE gr.role_id = r.id AND gm.user_id = ?) \
                 )",
                QueryOptions::new().bind_all(&[tid.clone(), app_p, uid.clone(), uid.clone()]),
            )
            .await?
    } else {
        store
            .provider()
            .fetch_all_async(
                "SELECT DISTINCT r.id, r.app_id, r.name FROM vs_app_role r \
                 WHERE r.tenant_id = ? AND ( \
                   EXISTS (SELECT 1 FROM vs_user_role ur WHERE ur.tenant_id = r.tenant_id AND ur.user_id = ? AND ur.role_id = r.id) \
                   OR EXISTS (SELECT 1 FROM vs_group_role gr INNER JOIN vs_group_member gm ON gm.group_id = gr.group_id WHERE gr.role_id = r.id AND gm.user_id = ?) \
                 )",
                QueryOptions::new().bind_all(&[tid.clone(), uid.clone(), uid.clone()]),
            )
            .await?
    };

    let mut roles = BTreeSet::new();
    let mut role_ids: Vec<Vec<u8>> = Vec::new();
    for row in role_rows {
        let raw_id: Vec<u8> = row.read("id")?;
        let name: String = row.read("name")?;
        let scoped_app: Option<String> = row.read("app_id").ok();
        let label = match scoped_app {
            Some(ref app) if !app.is_empty() => format!("{app}:{name}"),
            _ => name,
        };
        roles.insert(label);
        role_ids.push(raw_id);
    }

    // 3. Permissions attached to those effective roles.
    let mut permissions = BTreeSet::new();
    for raw_role_id in role_ids {
        let rid = neotales_dbapi::Parameter::new(
            neotales_dbapi::DbType::Bytes,
            neotales_dbapi::Value::Bytes(raw_role_id),
        )?;
        let perm_rows = store
            .provider()
            .fetch_all_async(
                "SELECT p.app_id, p.name FROM vs_app_permission p \
                 INNER JOIN vs_app_role_permission rp ON rp.permission_id = p.id \
                 WHERE rp.role_id = ?",
                QueryOptions::new().bind_all(&[rid]),
            )
            .await?;
        for prow in perm_rows {
            let pname: String = prow.read("name")?;
            let scoped_app: Option<String> = prow.read("app_id").ok();
            let label = match scoped_app {
                Some(ref app) if !app.is_empty() => format!("{app}:{pname}"),
                _ => pname,
            };
            permissions.insert(label);
        }
    }

    Ok(EffectiveAccess {
        groups: groups.into_iter().collect(),
        roles: roles.into_iter().collect(),
        permissions: permissions.into_iter().collect(),
    })
}

/// Request payload for `POST /admin/rbac/roles` and `POST /admin/rbac/permissions`.
#[derive(Debug, Deserialize)]
pub struct CreateNamedScopeBody {
    /// Optional OIDC `client_id` (`None` = org-wide).
    #[serde(default)]
    pub app_id: Option<String>,
    /// Role or permission name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: String,
}

/// Request payload for `POST /admin/rbac/groups`.
#[derive(Debug, Deserialize)]
pub struct CreateGroupBody {
    /// Group name.
    pub name: String,
    /// Optional external directory ID.
    #[serde(default)]
    pub external_id: Option<String>,
}

/// Optional `app_id` query filter for listing roles, permissions, or effective access.
#[derive(Debug, Deserialize, Default)]
pub struct AppFilterQuery {
    /// Optional OIDC `client_id` filter.
    pub app_id: Option<String>,
}

/// `GET /admin/rbac/roles`
pub async fn list_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AppFilterQuery>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(tid) = id_param(state.tenant_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let rows = if let Some(ref app) = query.app_id {
        let Ok(ap) = text_param(app) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        state
            .store
            .provider()
            .fetch_all_async(
                "SELECT id, app_id, name, description FROM vs_app_role WHERE tenant_id = ? AND (app_id IS NULL OR app_id = ?) ORDER BY name ASC",
                QueryOptions::new().bind_all(&[tid, ap]),
            )
            .await
    } else {
        state
            .store
            .provider()
            .fetch_all_async(
                "SELECT id, app_id, name, description FROM vs_app_role WHERE tenant_id = ? ORDER BY name ASC",
                QueryOptions::new().bind_all(&[tid]),
            )
            .await
    };
    let Ok(rows) = rows else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(raw_id) = row.read::<Vec<u8>>("id") else {
            continue;
        };
        let Ok(id) = Id::from_slice(&raw_id) else {
            continue;
        };
        roles.push(AppRole {
            id: id.to_string(),
            app_id: row.read::<String>("app_id").ok().filter(|s| !s.is_empty()),
            name: row.read::<String>("name").unwrap_or_default(),
            description: row.read::<String>("description").unwrap_or_default(),
        });
    }
    Json(json!({ "roles": roles })).into_response()
}

/// `POST /admin/rbac/roles`
pub async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateNamedScopeBody>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid role name" })),
        )
            .into_response();
    }
    let id = Id::now_v7();
    let app_id = body
        .app_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let now = Timestamp::now_utc().to_string();
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(id)?,
            id_param(state.tenant_id)?,
            opt_text_param(app_id)?,
            text_param(name)?,
            text_param(body.description.trim())?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .store
        .provider()
        .execute_async(
            "INSERT INTO vs_app_role (id, tenant_id, app_id, name, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .is_err()
    {
        return (StatusCode::CONFLICT, Json(json!({ "error": "role already exists" })))
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(AppRole {
            id: id.to_string(),
            app_id: app_id.map(str::to_owned),
            name: name.to_owned(),
            description: body.description.trim().to_owned(),
        }),
    )
        .into_response()
}

/// `GET /admin/rbac/permissions`
pub async fn list_permissions(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
            "SELECT id, app_id, name, description FROM vs_app_permission WHERE tenant_id = ? ORDER BY name ASC",
            QueryOptions::new().bind_all(&[tid]),
        )
        .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut perms = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(raw_id) = row.read::<Vec<u8>>("id") else {
            continue;
        };
        let Ok(id) = Id::from_slice(&raw_id) else {
            continue;
        };
        perms.push(AppPermission {
            id: id.to_string(),
            app_id: row.read::<String>("app_id").ok().filter(|s| !s.is_empty()),
            name: row.read::<String>("name").unwrap_or_default(),
            description: row.read::<String>("description").unwrap_or_default(),
        });
    }
    Json(json!({ "permissions": perms })).into_response()
}

/// `POST /admin/rbac/permissions`
pub async fn create_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateNamedScopeBody>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid permission name" })),
        )
            .into_response();
    }
    let id = Id::now_v7();
    let app_id = body
        .app_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let now = Timestamp::now_utc().to_string();
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(id)?,
            id_param(state.tenant_id)?,
            opt_text_param(app_id)?,
            text_param(name)?,
            text_param(body.description.trim())?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if state
        .store
        .provider()
        .execute_async(
            "INSERT INTO vs_app_permission (id, tenant_id, app_id, name, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            QueryOptions::new().bind_all(&params),
        )
        .await
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "permission already exists" })),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(AppPermission {
            id: id.to_string(),
            app_id: app_id.map(str::to_owned),
            name: name.to_owned(),
            description: body.description.trim().to_owned(),
        }),
    )
        .into_response()
}

/// `POST /admin/rbac/roles/{role_id}/permissions/{perm_id}`
pub async fn grant_permission_to_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((role_id, perm_id)): Path<(String, String)>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Ok(rid), Ok(pid)) = (Id::parse_str(&role_id), Id::parse_str(&perm_id)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(rp), Ok(pp)) = (id_param(rid), id_param(pid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "INSERT OR IGNORE INTO vs_app_role_permission (role_id, permission_id) VALUES (?, ?)",
            QueryOptions::new().bind_all(&[rp, pp]),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// `DELETE /admin/rbac/roles/{role_id}/permissions/{perm_id}`
pub async fn revoke_permission_from_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((role_id, perm_id)): Path<(String, String)>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Ok(rid), Ok(pid)) = (Id::parse_str(&role_id), Id::parse_str(&perm_id)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(rp), Ok(pp)) = (id_param(rid), id_param(pid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "DELETE FROM vs_app_role_permission WHERE role_id = ? AND permission_id = ?",
            QueryOptions::new().bind_all(&[rp, pp]),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `GET /admin/rbac/groups`
pub async fn list_groups(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
            "SELECT id, name, external_id FROM vs_group WHERE tenant_id = ? ORDER BY name ASC",
            QueryOptions::new().bind_all(&[tid]),
        )
        .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut groups = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(raw_id) = row.read::<Vec<u8>>("id") else {
            continue;
        };
        let Ok(id) = Id::from_slice(&raw_id) else {
            continue;
        };
        groups.push(RbacGroup {
            id: id.to_string(),
            name: row.read::<String>("name").unwrap_or_default(),
            external_id: row
                .read::<String>("external_id")
                .ok()
                .filter(|s| !s.is_empty()),
        });
    }
    Json(json!({ "groups": groups })).into_response()
}

/// `POST /admin/rbac/groups`
pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupBody>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid group name" })),
        )
            .into_response();
    }
    let id = Id::now_v7();
    let now = Timestamp::now_utc().to_string();
    let ext = body
        .external_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Ok(params) = (|| -> Result<_, neotales_dbapi::DbError> {
        Ok([
            id_param(id)?,
            id_param(state.tenant_id)?,
            text_param(name)?,
            opt_text_param(ext)?,
            text_param(&now)?,
        ])
    })() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "group already exists" })),
        )
            .into_response();
    }
    (
        StatusCode::CREATED,
        Json(RbacGroup {
            id: id.to_string(),
            name: name.to_owned(),
            external_id: ext.map(str::to_owned),
        }),
    )
        .into_response()
}

/// `POST /admin/rbac/groups/{group_id}/members/{user_id}`
pub async fn add_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(String, String)>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Ok(gid), Ok(uid)) = (Id::parse_str(&group_id), Id::parse_str(&user_id)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(gp), Ok(up)) = (id_param(gid), id_param(uid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "INSERT OR IGNORE INTO vs_group_member (group_id, user_id) VALUES (?, ?)",
            QueryOptions::new().bind_all(&[gp, up]),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// `DELETE /admin/rbac/groups/{group_id}/members/{user_id}`
pub async fn remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(String, String)>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Ok(gid), Ok(uid)) = (Id::parse_str(&group_id), Id::parse_str(&user_id)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(gp), Ok(up)) = (id_param(gid), id_param(uid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "DELETE FROM vs_group_member WHERE group_id = ? AND user_id = ?",
            QueryOptions::new().bind_all(&[gp, up]),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `POST /admin/rbac/groups/{group_id}/roles/{role_id}`
pub async fn assign_role_to_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((group_id, role_id)): Path<(String, String)>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Ok(gid), Ok(rid)) = (Id::parse_str(&group_id), Id::parse_str(&role_id)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(gp), Ok(rp)) = (id_param(gid), id_param(rid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "INSERT OR IGNORE INTO vs_group_role (group_id, role_id) VALUES (?, ?)",
            QueryOptions::new().bind_all(&[gp, rp]),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// `POST /admin/rbac/users/{user_id}/roles/{role_id}`
pub async fn assign_role_to_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, role_id)): Path<(String, String)>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (Ok(uid), Ok(rid)) = (Id::parse_str(&user_id), Id::parse_str(&role_id)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Ok(tp), Ok(up), Ok(rp)) = (id_param(state.tenant_id), id_param(uid), id_param(rid)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state
        .store
        .provider()
        .execute_async(
            "INSERT OR IGNORE INTO vs_user_role (tenant_id, user_id, role_id) VALUES (?, ?, ?)",
            QueryOptions::new().bind_all(&[tp, up, rp]),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// `GET /admin/rbac/users/{user_id}/effective?app_id=...`
pub async fn get_effective_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(query): Query<AppFilterQuery>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(uid) = Id::parse_str(&user_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match resolve_effective_access(&state.store, state.tenant_id, uid, query.app_id.as_deref())
        .await
    {
        Ok(access) => Json(access).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
