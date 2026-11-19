//! Role & permission management endpoints.

use axum::extract::State;
use axum::Json;
use infinity_core::model::Role;
use infinity_core::rbac::{ROLE_ADMIN, ROLE_SUPERADMIN, ROLE_USER};
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

/// GET /admin/roles
pub async fn list(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("roles:read")?;
    let roles = store::list_roles(&st.db).await?;
    Ok(Json(json!({ "roles": roles })))
}

/// PUT /admin/roles — create or update a role.
pub async fn upsert(
    State(st): State<SharedState>,
    p: Principal,
    Json(role): Json<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("roles:write")?;
    if role.name.is_empty()
        || role.name.len() > 64
        || !role
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::BadRequest("invalid role name".into()));
    }
    // Built-in roles are immutable: overwriting e.g. `superadmin` could strip
    // its permissions and lock every administrator out.
    if [ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_USER].contains(&role.name.as_str()) {
        return Err(ApiError::BadRequest(
            "built-in roles cannot be modified".into(),
        ));
    }
    // Prevent permission escalation: a non-superadmin caller cannot mint a role
    // carrying permissions it does not already hold.
    let is_superadmin = p.permissions.iter().any(|perm| perm == "*:*");
    for perm in &role.permissions {
        if !infinity_core::rbac::is_valid_permission(perm) {
            return Err(ApiError::BadRequest(format!(
                "invalid permission format '{perm}': expected 'resource:action'"
            )));
        }
        if !is_superadmin && !infinity_core::rbac::any_permission(&p.permissions, perm) {
            return Err(ApiError::Forbidden(format!(
                "cannot grant permission '{perm}' that you do not hold"
            )));
        }
    }
    store::upsert_role(&st.db, &role).await?;
    store::audit(
        &st.db,
        &p.user_id,
        "role.upsert",
        Some(&role.name),
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}
