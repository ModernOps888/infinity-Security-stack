//! OAuth client (application) management endpoints.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store::{self, NewClient};
use crate::util::{random_token, sha256_hex, validate_redirect_uri};

#[derive(Deserialize)]
pub struct CreateClient {
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_grants")]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Public clients (SPA/native) use PKCE and receive no secret.
    #[serde(default)]
    pub public: bool,
}

fn default_grants() -> Vec<String> {
    vec!["authorization_code".into(), "refresh_token".into()]
}

/// GET /admin/clients
pub async fn list(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("clients:read")?;
    let clients = store::list_clients(&st.db).await?;
    Ok(Json(json!({ "clients": clients })))
}

const ALLOWED_GRANTS: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "password",
];

/// POST /admin/clients — returns the plaintext secret exactly once.
pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateClient>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("clients:create")?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest("invalid client name".into()));
    }
    if req.grant_types.is_empty()
        || !req
            .grant_types
            .iter()
            .all(|g| ALLOWED_GRANTS.contains(&g.as_str()))
    {
        return Err(ApiError::BadRequest("unsupported grant_types".into()));
    }
    let mut validated_uris = Vec::with_capacity(req.redirect_uris.len());
    for uri in &req.redirect_uris {
        let valid = validate_redirect_uri(uri).map_err(|e| ApiError::BadRequest(e.into()))?;
        validated_uris.push(valid);
    }
    if req.grant_types.iter().any(|g| g == "authorization_code") && validated_uris.is_empty() {
        return Err(ApiError::BadRequest(
            "authorization_code clients must register at least one redirect_uri".into(),
        ));
    }
    if req
        .scopes
        .iter()
        .any(|s| s.is_empty() || s.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        return Err(ApiError::BadRequest("invalid scope entry".into()));
    }

    let (secret, secret_hash) = if req.public {
        (None, None)
    } else {
        let s = random_token();
        let h = sha256_hex(&s);
        (Some(s), Some(h))
    };
    let client_id = store::create_client(
        &st.db,
        NewClient {
            name,
            secret_hash: secret_hash.as_deref(),
            redirect_uris: &validated_uris,
            grant_types: &req.grant_types,
            scopes: &req.scopes,
            public: req.public,
        },
    )
    .await?;
    store::audit(
        &st.db,
        &p.user_id,
        "client.create",
        Some(&client_id),
        None,
        None,
    )
    .await;
    Ok(Json(json!({
        "client_id": client_id,
        "client_secret": secret,
        "note": "Store the client_secret now; it will not be shown again.",
    })))
}

/// DELETE /admin/clients/:client_id
pub async fn delete(
    State(st): State<SharedState>,
    p: Principal,
    Path(client_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("clients:delete")?;
    if store::get_client_raw(&st.db, &client_id).await?.is_none() {
        return Err(ApiError::NotFound("client not found".into()));
    }
    store::delete_client(&st.db, &client_id).await?;
    store::audit(
        &st.db,
        &p.user_id,
        "client.delete",
        Some(&client_id),
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}
