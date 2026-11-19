use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use stream_core::bm25::{
    Bm25Index, MAX_DOC_TEXT_BYTES, MAX_QUERY_BYTES, MAX_SEARCH_OFFSET, MAX_TOP_K,
};
use stream_core::security::{validate_doc_id, validate_resource_name};

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateIndex {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_k() -> usize {
    10
}

pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateIndex>,
) -> ApiResult<Json<Value>> {
    p.require("search:create")?;
    validate_resource_name(&req.name)?;
    store::create_index(&st.db, &req.name)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                ApiError::Conflict("index already exists".into())
            }
            other => other.into(),
        })?;
    st.indexes
        .write()
        .await
        .insert(req.name.clone(), Bm25Index::new());
    Ok(Json(json!({"name": req.name})))
}

pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("search:read")?;
    let indexes: Vec<Value> = store::list_indexes(&st.db)
        .await?
        .into_iter()
        .map(|(name, created_at)| json!({"name":name,"created_at":created_at}))
        .collect();
    Ok(Json(json!({"indexes": indexes})))
}

pub async fn delete_index(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    p.require("search:delete")?;
    validate_resource_name(&name)?;
    if !store::delete_index(&st.db, &name).await? {
        return Err(ApiError::NotFound("index not found".into()));
    }
    st.indexes.write().await.remove(&name);
    Ok(Json(json!({"ok": true})))
}

pub async fn upsert_docs(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    p.require("search:write")?;
    validate_resource_name(&name)?;
    let docs = if let Some(arr) = body.as_array() {
        arr.clone()
    } else if let Some(arr) = body.get("docs").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        return Err(ApiError::BadRequest(
            "expected array or {docs:[...]}".into(),
        ));
    };
    if docs.is_empty() || docs.len() > st.config.max_search_docs_per_batch {
        return Err(ApiError::BadRequest(format!(
            "docs must contain 1..={} entries",
            st.config.max_search_docs_per_batch
        )));
    }

    // Validate all incoming documents (including depth/text limits) before
    // checking capacity or mutating SQLite / Bm25Index.
    let mut prepared = Vec::with_capacity(docs.len());
    let mut db_rows = Vec::with_capacity(docs.len());
    for doc in docs {
        let obj = doc
            .as_object()
            .ok_or_else(|| ApiError::BadRequest("doc must be object".into()))?;
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::BadRequest("doc.id string required".into()))?
            .to_string();
        validate_doc_id(&id)?;
        let mut fields = HashMap::new();
        for (k, v) in obj {
            if k != "id" {
                fields.insert(k.clone(), v.clone());
            }
        }
        let json_fields =
            serde_json::to_string(&fields).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        if json_fields.len() > MAX_DOC_TEXT_BYTES {
            return Err(ApiError::BadRequest(format!(
                "document fields exceed max size of {MAX_DOC_TEXT_BYTES} bytes"
            )));
        }
        let prepared_doc = Bm25Index::prepare_doc(id.clone(), fields)?;
        prepared.push(prepared_doc);
        db_rows.push((id, json_fields));
    }

    let mut idxs = st.indexes.write().await;
    let idx = idxs
        .get_mut(&name)
        .ok_or_else(|| ApiError::NotFound("index not found".into()))?;
    idx.check_batch_capacity(&prepared)?;
    store::upsert_docs_batch(&st.db, &name, &db_rows).await?;
    let indexed = prepared.len();
    for doc in prepared {
        idx.commit_prepared(doc);
    }
    Ok(Json(json!({"indexed": indexed})))
}

pub async fn query(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Query(q): Query<SearchQuery>,
) -> ApiResult<Json<Value>> {
    p.require("search:query")?;
    validate_resource_name(&name)?;
    if q.q.len() > MAX_QUERY_BYTES {
        return Err(ApiError::BadRequest("query too long".into()));
    }
    if q.k == 0 || q.k > MAX_TOP_K {
        return Err(ApiError::BadRequest(format!("k must be 1..={MAX_TOP_K}")));
    }
    if q.offset > MAX_SEARCH_OFFSET {
        return Err(ApiError::BadRequest(format!(
            "offset must be 0..={MAX_SEARCH_OFFSET}"
        )));
    }
    let hits = {
        let idxs = st.indexes.read().await;
        let idx = idxs
            .get(&name)
            .ok_or_else(|| ApiError::NotFound("index not found".into()))?;
        idx.search_with_offset(&q.q, q.k, q.offset)?
    };
    let mut out = Vec::new();
    for hit in hits {
        if !hit.score.is_finite() {
            continue;
        }
        if let Some(fields_json) = store::doc_fields(&st.db, &name, &hit.doc_id).await? {
            let fields: Value = serde_json::from_str(&fields_json).unwrap_or_else(|_| json!({}));
            out.push(json!({"id": hit.doc_id, "score": hit.score, "fields": fields}));
        }
    }
    Ok(Json(json!({"query": q.q, "hits": out})))
}
