//! Admin user-management endpoints (RBAC-guarded).

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store::{self, NewUser};

/// Privileged roles that only a superadmin (`*:*`) may assign — prevents an
/// admin (which holds `users:*` but not `roles:write`) from escalating itself
/// or others to a higher tier.
const PRIVILEGED_ROLES: &[&str] = &["superadmin", "admin"];

fn assert_can_assign(p: &Principal, roles: &[String]) -> ApiResult<()> {
    let is_superadmin = p.permissions.iter().any(|perm| perm == "*:*");
    for role in roles {
        if PRIVILEGED_ROLES.contains(&role.as_str()) && !is_superadmin {
            return Err(ApiError::Forbidden(format!(
                "only a superadmin may assign the '{role}' role"
            )));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Deserialize)]
pub struct UpdateUser {
    pub disabled: Option<bool>,
    pub roles: Option<Vec<String>>,
}

/// GET /admin/users
pub async fn list(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:read")?;
    let users = store::list_users(&st.db).await?;
    Ok(Json(json!({ "users": users })))
}

/// POST /admin/users
pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:create")?;
    let email = req.email.trim();
    let username = req.username.trim();
    if email.is_empty()
        || !email.contains('@')
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(ApiError::BadRequest("invalid email address".into()));
    }
    if username.is_empty() || username.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest("invalid username".into()));
    }
    let roles = if req.roles.is_empty() {
        vec![infinity_core::rbac::ROLE_USER.to_string()]
    } else {
        req.roles
    };
    assert_can_assign(&p, &roles)?;
    for role in &roles {
        if store::get_role(&st.db, role).await?.is_none() {
            return Err(ApiError::BadRequest(format!("unknown role: {role}")));
        }
    }
    let hash = infinity_core::password::hash_password(&req.password)?;
    let id = store::create_user(
        &st.db,
        NewUser {
            email,
            username,
            display_name: req.display_name.as_deref(),
            password_hash: &hash,
            roles: &roles,
        },
    )
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
            ApiError::Conflict("email or username already exists".into())
        }
        other => other.into(),
    })?;
    store::audit(&st.db, &p.user_id, "user.create", Some(&id), None, None).await;
    Ok(Json(json!({ "id": id })))
}

/// PATCH /admin/users/:id
pub async fn update(
    State(st): State<SharedState>,
    p: Principal,
    Path(id): Path<String>,
    Json(req): Json<UpdateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:update")?;
    if store::get_user_row(&st.db, &id).await?.is_none() {
        return Err(ApiError::NotFound("user not found".into()));
    }
    let existing_roles = store::user_roles(&st.db, &id).await?;
    // Prevent a plain admin from disabling or modifying a superadmin/admin account.
    assert_can_assign(&p, &existing_roles)?;

    if let Some(disabled) = req.disabled {
        if id == p.user_id && disabled {
            return Err(ApiError::BadRequest(
                "cannot disable your own account".into(),
            ));
        }
        store::set_user_disabled(&st.db, &id, disabled).await?;
        if disabled {
            store::delete_user_sessions(&st.db, &id).await?;
            store::revoke_user_refresh_tokens(&st.db, &id).await?;
        }
    }
    if let Some(roles) = req.roles {
        if roles.is_empty() {
            return Err(ApiError::BadRequest("roles list cannot be empty".into()));
        }
        assert_can_assign(&p, &roles)?;
        for role in &roles {
            if store::get_role(&st.db, role).await?.is_none() {
                return Err(ApiError::BadRequest(format!("unknown role: {role}")));
            }
        }
        store::set_user_roles(&st.db, &id, &roles).await?;
    }
    store::audit(&st.db, &p.user_id, "user.update", Some(&id), None, None).await;
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /admin/users/:id
pub async fn delete(
    State(st): State<SharedState>,
    p: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("users:delete")?;
    if id == p.user_id {
        return Err(ApiError::BadRequest(
            "cannot delete your own account".into(),
        ));
    }
    if store::get_user_row(&st.db, &id).await?.is_none() {
        return Err(ApiError::NotFound("user not found".into()));
    }
    let existing_roles = store::user_roles(&st.db, &id).await?;
    // Prevent a plain admin from deleting a superadmin or fellow admin.
    assert_can_assign(&p, &existing_roles)?;

    store::delete_user_sessions(&st.db, &id).await?;
    store::revoke_user_refresh_tokens(&st.db, &id).await?;
    store::delete_user(&st.db, &id).await?;
    store::audit(&st.db, &p.user_id, "user.delete", Some(&id), None, None).await;
    Ok(Json(json!({ "ok": true })))
}
