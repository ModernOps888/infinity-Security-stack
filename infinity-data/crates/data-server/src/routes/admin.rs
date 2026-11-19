use axum::extract::{Path, State};
use axum::Json;
use data_core::rbac::{self, ROLE_SUPERADMIN};
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::routes::valid_name;
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub password: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertRole {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKey {
    pub name: String,
}

fn user_json(u: &store::UserRow, roles: Vec<String>) -> serde_json::Value {
    json!({"id": u.id, "email": u.email, "username": u.username, "display_name": u.display_name, "disabled": u.disabled != 0, "created_at": u.created_at, "roles": roles})
}

fn caller_is_superadmin(p: &Principal) -> bool {
    p.roles.iter().any(|r| r == ROLE_SUPERADMIN) || rbac::any_permission(&p.permissions, "*:*")
}

fn role_change_allowed(p: &Principal, roles: &[String]) -> bool {
    !roles.iter().any(|r| r == ROLE_SUPERADMIN) || caller_is_superadmin(p)
}

fn permission_grant_allowed(p: &Principal, permissions: &[String]) -> bool {
    caller_is_superadmin(p)
        || permissions
            .iter()
            .all(|permission| rbac::any_permission(&p.permissions, permission))
}

fn valid_permission(p: &str) -> bool {
    (1..=64).contains(&p.len())
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'*' | b'.'))
}

async fn validate_roles_exist(st: &SharedState, roles: &[String]) -> Result<(), ApiError> {
    if roles.len() > 64 {
        return Err(ApiError::BadRequest("too many roles".into()));
    }
    for r in roles {
        if !valid_name(r) {
            return Err(ApiError::BadRequest(format!("invalid role name: {r}")));
        }
        if !store::role_exists(&st.db, r).await? {
            return Err(ApiError::BadRequest(format!("unknown role: {r}")));
        }
    }
    Ok(())
}

async fn can_modify_target_user(
    st: &SharedState,
    principal: &Principal,
    target_id: &str,
) -> Result<(), ApiError> {
    if caller_is_superadmin(principal) {
        return Ok(());
    }
    let current_roles = store::user_roles(&st.db, target_id).await?;
    if current_roles.iter().any(|r| r == ROLE_SUPERADMIN) {
        return Err(ApiError::Forbidden(
            "only superadmin may modify superadmin accounts".into(),
        ));
    }
    let target_perms = store::user_permissions(&st.db, target_id).await?;
    if !permission_grant_allowed(principal, &target_perms) {
        return Err(ApiError::Forbidden(
            "cannot modify a user holding permissions you do not hold".into(),
        ));
    }
    Ok(())
}

/// A caller may only assign roles whose full permission set they already hold.
/// This mirrors `permission_grant_allowed` for the role-*assignment* paths so a
/// `users:write` holder cannot escalate by attaching a more privileged role
/// (e.g. `admin`) to themselves or another account.
async fn assigned_roles_allowed(
    st: &SharedState,
    principal: &Principal,
    roles: &[String],
) -> Result<(), ApiError> {
    if caller_is_superadmin(principal) {
        return Ok(());
    }
    let mut granted = Vec::new();
    for role in roles {
        granted.extend(store::role_permissions(&st.db, role).await?);
    }
    if permission_grant_allowed(principal, &granted) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "cannot assign a role that grants permissions you do not hold".into(),
        ))
    }
}

fn valid_email(email: &str) -> bool {
    if email.is_empty()
        || email.len() > 254
        || !email.is_ascii()
        || email.contains(char::is_whitespace)
    {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || email.matches('@').count() != 1
    {
        return false;
    }
    let local_valid = local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'));
    let domain_valid = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    local_valid && domain_valid
}

pub async fn list_users(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:read")?;
    let mut out = Vec::new();
    for u in store::list_users(&st.db).await? {
        let roles = store::user_roles(&st.db, &u.id).await?;
        out.push(user_json(&u, roles));
    }
    Ok(Json(json!({"users": out})))
}

pub async fn create_user(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:write")?;
    let email = req.email.trim().to_ascii_lowercase();
    let username = req.username.trim();
    if !valid_email(&email) {
        return Err(ApiError::BadRequest("valid email required".into()));
    }
    if !valid_name(username) {
        return Err(ApiError::BadRequest(
            "username must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if let Some(dn) = &req.display_name {
        if dn.len() > 128 || dn.chars().any(char::is_control) {
            return Err(ApiError::BadRequest(
                "display_name must be <= 128 non-control characters".into(),
            ));
        }
    }
    data_core::password::validate_user_password(&req.password)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if !role_change_allowed(&principal, &req.roles) {
        return Err(ApiError::Forbidden(
            "only superadmin may grant superadmin".into(),
        ));
    }
    let roles = if req.roles.is_empty() {
        vec![data_core::rbac::ROLE_USER.to_string()]
    } else {
        req.roles.clone()
    };
    validate_roles_exist(&st, &roles).await?;
    assigned_roles_allowed(&st, &principal, &roles).await?;
    if store::user_exists(&st.db, &email, username).await? {
        return Err(ApiError::Conflict(
            "user with that email or username already exists".into(),
        ));
    }
    let user = store::create_user(
        &st.db,
        &email,
        username,
        req.display_name.as_deref(),
        &req.password,
    )
    .await?;
    store::set_user_roles(&st.db, &user.id, &roles).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "user.create",
        Some(&user.id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"user": user_json(&user, roles)})))
}

pub async fn update_user(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    principal: Principal,
    Json(req): Json<UpdateUser>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:write")?;
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(ApiError::BadRequest("invalid user id".into()));
    }
    if id == principal.user_id && req.disabled == Some(true) {
        return Err(ApiError::BadRequest(
            "cannot disable your own account".into(),
        ));
    }
    let user = store::get_user(&st.db, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    can_modify_target_user(&st, &principal, &id).await?;
    if let Some(roles) = &req.roles {
        if !role_change_allowed(&principal, roles) {
            return Err(ApiError::Forbidden(
                "only superadmin may grant superadmin".into(),
            ));
        }
        validate_roles_exist(&st, roles).await?;
        assigned_roles_allowed(&st, &principal, roles).await?;
    }
    if let Some(disabled) = req.disabled {
        store::set_user_disabled(&st.db, &id, disabled).await?;
    }
    if let Some(roles) = req.roles {
        store::set_user_roles(&st.db, &id, &roles).await?;
    }
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "user.update",
        Some(&id),
        None,
        None,
        None,
    )
    .await;
    let updated = store::get_user(&st.db, &id).await?.unwrap_or(user);
    let roles = store::user_roles(&st.db, &id).await?;
    Ok(Json(json!({"user": user_json(&updated, roles)})))
}

pub async fn delete_user(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("users:write")?;
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(ApiError::BadRequest("invalid user id".into()));
    }
    if id == principal.user_id {
        return Err(ApiError::BadRequest(
            "cannot delete your own account".into(),
        ));
    }
    if store::get_user(&st.db, &id).await?.is_none() {
        return Err(ApiError::NotFound("user not found".into()));
    }
    can_modify_target_user(&st, &principal, &id).await?;
    store::delete_user(&st.db, &id).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "user.delete",
        Some(&id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn list_roles(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("roles:read")?;
    let mut out = Vec::new();
    for role in store::list_roles(&st.db).await? {
        out.push(json!({"name": role.name, "description": role.description, "permissions": store::role_permissions(&st.db, &role.name).await?}));
    }
    Ok(Json(json!({"roles": out})))
}

pub async fn upsert_role(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<UpsertRole>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("roles:write")?;
    if !valid_name(&req.name) {
        return Err(ApiError::BadRequest(
            "role name must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if req.description.len() > 512 || req.description.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "role description must be <= 512 non-control characters".into(),
        ));
    }
    if req.name == ROLE_SUPERADMIN && !caller_is_superadmin(&principal) {
        return Err(ApiError::Forbidden(
            "only superadmin may modify superadmin role".into(),
        ));
    }
    if req.permissions.len() > 256 {
        return Err(ApiError::BadRequest("too many permissions".into()));
    }
    for p in &req.permissions {
        if !valid_permission(p) {
            return Err(ApiError::BadRequest(format!("invalid permission: {p}")));
        }
    }
    if store::role_exists(&st.db, &req.name).await? {
        let existing_perms = store::role_permissions(&st.db, &req.name).await?;
        if !permission_grant_allowed(&principal, &existing_perms) {
            return Err(ApiError::Forbidden(
                "cannot modify a role holding permissions you do not hold".into(),
            ));
        }
    }
    if !permission_grant_allowed(&principal, &req.permissions) {
        return Err(ApiError::Forbidden(
            "cannot grant permissions caller does not hold".into(),
        ));
    }
    store::upsert_role(&st.db, &req.name, &req.description, &req.permissions).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "role.upsert",
        Some(&req.name),
        Some(json!({"permissions": req.permissions.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn list_api_keys(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("api_keys:read")?;
    Ok(Json(
        json!({"api_keys": store::list_api_keys(&st.db).await?}),
    ))
}

pub async fn create_api_key(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateApiKey>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("api_keys:write")?;
    let trimmed = req.name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "API key name must be 1-64 non-control characters".into(),
        ));
    }
    let (raw, info) = store::create_api_key(&st.db, trimmed).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "api_key.create",
        Some(&info.id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"api_key": info, "token": raw})))
}

pub async fn delete_api_key(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("api_keys:write")?;
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(ApiError::BadRequest("invalid API key id".into()));
    }
    if !store::delete_api_key(&st.db, &id).await? {
        return Err(ApiError::NotFound("API key not found".into()));
    }
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "api_key.delete",
        Some(&id),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}
