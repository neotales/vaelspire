//! SCIM 2.0 (RFC 7643 / RFC 7644) directory provisioning endpoints for Vaelspire Core.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use vaelspire_auth::{Auth, Policy, hash_password};
use vaelspire_core::{Id, Timestamp};

use crate::bootstrap::{
    DirectoryUser, find_directory_user, list_tenant_users, soft_delete_directory_user,
};
use crate::server::{AppState, is_authenticated};

const SCIM_CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";
const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// `GET /scim/v2/ServiceProviderConfig`
pub async fn service_provider_config() -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": false },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": false, "maxResults": 500 },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "API Key / OAuth Bearer Token",
                    "description": "Authenticate SCIM requests using a Vaelspire API key or session."
                }
            ]
        }),
    )
}

/// `GET /scim/v2/Users`
pub async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_authenticated(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
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
    if !is_authenticated(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
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
    if !is_authenticated(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
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
        Ok(user) => scim_json(
            StatusCode::CREATED,
            user_to_scim(&DirectoryUser {
                id: user.id,
                tenant_id: user.tenant_id,
                email: user.email,
                status: "active".to_owned(),
            }),
        ),
        Err(vaelspire_core::AuthError::Conflict) => {
            scim_error(StatusCode::CONFLICT, "user already exists")
        }
        Err(vaelspire_core::AuthError::Invalid) => {
            scim_error(StatusCode::BAD_REQUEST, "invalid userName email")
        }
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

/// `DELETE /scim/v2/Users/{id}`
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_id): Path<String>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return scim_error(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let Ok(user_id) = Id::parse_str(&raw_id) else {
        return scim_error(StatusCode::BAD_REQUEST, "invalid user identifier");
    };
    match soft_delete_directory_user(&state.store, state.tenant_id, user_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => scim_error(StatusCode::NOT_FOUND, "user not found"),
        Err(_) => scim_error(StatusCode::INTERNAL_SERVER_ERROR, "store failure"),
    }
}

fn user_to_scim(user: &DirectoryUser) -> serde_json::Value {
    json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id.to_string(),
        "userName": user.email,
        "active": user.status != "suspended" && user.status != "deleted",
        "emails": [{ "value": user.email, "primary": true }],
        "meta": {
            "resourceType": "User",
            "location": format!("/scim/v2/Users/{}", user.id),
        }
    })
}

fn scim_json(status: StatusCode, value: serde_json::Value) -> Response {
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
