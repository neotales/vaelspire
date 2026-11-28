//! GDPR Right of Access (JSON export) and Right to Erasure (PII anonymization
//! preserving append-only `auth_audit` integrity via pseudonymous `actor_id`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use neotales_dbapi::{Pool, QueryOptions};
use serde_json::{Value, json};
use vaelspire_core::privacy::{erased_email_for_user, format_email_for_log};
use vaelspire_core::{AuditEvent, AuthStore, Id, Timestamp};
use vaelspire_store_sqlite::SqliteStore;

use crate::ext_store::{id_param, text_param};
use crate::rbac::resolve_effective_access;
use crate::server::{AppState, is_authenticated, resolve_session_from_headers};

/// Anonymize PII for `user_id`, revoke all active sessions/API keys/passkeys, and
/// append a pseudonymous `auth.user.gdpr_erased` audit event — never modifying
/// existing append-only `auth_audit` rows.
///
/// # Errors
/// Returns a database error if persistence fails.
pub async fn erase_user_gdpr(
    store: &SqliteStore,
    tenant_id: Id,
    user_id: Id,
) -> Result<bool, neotales_dbapi::DbError> {
    let tid = id_param(tenant_id)?;
    let uid = id_param(user_id)?;
    let erased_email = erased_email_for_user(user_id);
    let now_ts = Timestamp::now_utc();
    let now_str = now_ts.to_string();

    let affected = store
        .provider()
        .execute_async(
            "UPDATE auth_user \
             SET email = ?, username = NULL, display_name = NULL, status = 'erased', \
                 deleted_at = ?, updated_at = ? \
             WHERE tenant_id = ? AND id = ?",
            QueryOptions::new().bind_all(&[
                text_param(&erased_email)?,
                text_param(&now_str)?,
                text_param(&now_str)?,
                tid.clone(),
                uid.clone(),
            ]),
        )
        .await?;
    if affected == 0 {
        return Ok(false);
    }

    // Revoke active sessions, API keys, passkeys, and group/role links cleanly.
    let _ = store
        .provider()
        .execute_async(
            "UPDATE auth_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            QueryOptions::new().bind_all(&[text_param(&now_str)?, uid.clone()]),
        )
        .await;
    let _ = store
        .provider()
        .execute_async(
            "UPDATE auth_api_key SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            QueryOptions::new().bind_all(&[text_param(&now_str)?, uid.clone()]),
        )
        .await;
    let _ = store
        .provider()
        .execute_async(
            "DELETE FROM auth_passkey WHERE user_id = ?",
            QueryOptions::new().bind_all(std::slice::from_ref(&uid)),
        )
        .await;
    let _ = store
        .provider()
        .execute_async(
            "DELETE FROM vs_group_member WHERE user_id = ?",
            QueryOptions::new().bind_all(std::slice::from_ref(&uid)),
        )
        .await;
    let _ = store
        .provider()
        .execute_async(
            "DELETE FROM vs_user_role WHERE tenant_id = ? AND user_id = ?",
            QueryOptions::new().bind_all(&[tid, uid]),
        )
        .await;

    // Record pseudonymous GDPR erasure event in the append-only audit table.
    let event = AuditEvent {
        id: Id::now_v7(),
        tenant_id: Some(tenant_id),
        actor_id: Some(user_id),
        action: "auth.user.gdpr_erased".to_owned(),
        outcome: "ok".to_owned(),
        fields: Vec::new(),
    };
    let _ = store.insert_audit(&event, now_ts).await;
    Ok(true)
}

/// Build a GDPR Right of Access JSON export bundle for `user_id`.
///
/// # Errors
/// Returns a database error if querying `SQLite` fails.
pub async fn build_user_export(
    store: &SqliteStore,
    tenant_id: Id,
    user_id: Id,
) -> Result<Option<Value>, neotales_dbapi::DbError> {
    let tid = id_param(tenant_id)?;
    let uid = id_param(user_id)?;

    let user_row = store
        .provider()
        .fetch_one_async(
            "SELECT email, username, display_name, status, created_at, updated_at, deleted_at \
             FROM auth_user WHERE tenant_id = ? AND id = ? LIMIT 1",
            QueryOptions::new().bind_all(&[tid.clone(), uid.clone()]),
        )
        .await;
    let Ok(row) = user_row else {
        return Ok(None);
    };

    let email: String = row.read("email").unwrap_or_default();
    let status: String = row.read("status").unwrap_or_default();
    let created_at: String = row.read("created_at").unwrap_or_default();

    let sessions_rows = store
        .provider()
        .fetch_all_async(
            "SELECT id, created_at, expires_at, revoked_at FROM auth_session WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
            QueryOptions::new().bind_all(std::slice::from_ref(&uid)),
        )
        .await
        .unwrap_or_default();
    let sessions: Vec<Value> = sessions_rows
        .into_iter()
        .filter_map(|r| {
            let sid = Id::from_slice(&r.read::<Vec<u8>>("id").ok()?).ok()?;
            Some(json!({
                "id": sid.to_string(),
                "created_at": r.read::<String>("created_at").ok(),
                "expires_at": r.read::<String>("expires_at").ok(),
                "revoked_at": r.read::<String>("revoked_at").ok(),
            }))
        })
        .collect();

    let audit_rows = store
        .provider()
        .fetch_all_async(
            "SELECT id, action, outcome, ip, created_at FROM auth_audit WHERE actor_id = ? ORDER BY created_at DESC LIMIT 100",
            QueryOptions::new().bind_all(&[uid]),
        )
        .await
        .unwrap_or_default();
    let audit_events: Vec<Value> = audit_rows
        .into_iter()
        .filter_map(|r| {
            let aid = Id::from_slice(&r.read::<Vec<u8>>("id").ok()?).ok()?;
            Some(json!({
                "id": aid.to_string(),
                "action": r.read::<String>("action").ok(),
                "outcome": r.read::<String>("outcome").ok(),
                "ip": r.read::<String>("ip").ok(),
                "created_at": r.read::<String>("created_at").ok(),
            }))
        })
        .collect();

    let access = resolve_effective_access(store, tenant_id, user_id, None)
        .await
        .unwrap_or_default();

    Ok(Some(json!({
        "schema": "vaelspire.gdpr.export.v1",
        "exported_at": Timestamp::now_utc().to_string(),
        "user": {
            "id": user_id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "email": email,
            "status": status,
            "created_at": created_at,
        },
        "rbac": access,
        "sessions": sessions,
        "audit_events": audit_events,
    })))
}

/// `GET /account/export` — authenticated user exports their own GDPR data bundle.
pub async fn export_own_account(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = resolve_session_from_headers(&state, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    state.metrics.record_gdpr_export();
    tracing::info!(
        user_id = %session.user_id,
        tenant_id = %session.tenant_id,
        "gdpr account data export generated"
    );
    match build_user_export(&state.store, session.tenant_id, session.user_id).await {
        Ok(Some(bundle)) => Json(bundle).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `DELETE /account/erase` — authenticated user requests GDPR erasure of their own PII.
pub async fn erase_own_account(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = resolve_session_from_headers(&state, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let email = crate::bootstrap::lookup_user_email(&state.store, session.user_id)
        .await
        .ok()
        .flatten();
    match erase_user_gdpr(&state.store, session.tenant_id, session.user_id).await {
        Ok(true) => {
            state.metrics.record_gdpr_erasure();
            crate::alerts::notify_gdpr_erasure(
                state.alerts.as_ref(),
                session.user_id,
                "self-service",
            );
            let redacted = email.as_deref().map_or_else(
                || "[unknown]".to_owned(),
                |e| format_email_for_log(e, state.pii_log_mode),
            );
            tracing::info!(
                user_id = %session.user_id,
                email = %redacted,
                "gdpr self-service account erasure completed"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `POST /admin/gdpr/erase/{user_id}` — admin triggers GDPR erasure for a user.
pub async fn admin_erase_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    if !is_authenticated(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(uid) = Id::parse_str(&user_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let email = crate::bootstrap::lookup_user_email(&state.store, uid)
        .await
        .ok()
        .flatten();
    match erase_user_gdpr(&state.store, state.tenant_id, uid).await {
        Ok(true) => {
            state.metrics.record_gdpr_erasure();
            crate::alerts::notify_gdpr_erasure(state.alerts.as_ref(), uid, "admin");
            let redacted = email.as_deref().map_or_else(
                || "[unknown]".to_owned(),
                |e| format_email_for_log(e, state.pii_log_mode),
            );
            tracing::info!(
                user_id = %uid,
                email = %redacted,
                "gdpr admin account erasure completed"
            );
            Json(json!({ "status": "erased", "user_id": uid.to_string() })).into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
