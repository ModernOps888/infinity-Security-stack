use axum::extract::{Path, State};
use axum::Json;
use data_core::aggregation::{run_query_bounded, validate_query, Query, MAX_OUTPUT_ROWS};
use data_core::model::{TableColumn, TableInfo};
use data_core::security::valid_column_name;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashSet;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::routes::valid_name;
use crate::state::SharedState;
use crate::store;

const MAX_QUERY_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
pub struct CreateTable {
    pub name: String,
    #[serde(default)]
    pub columns: Vec<TableColumn>,
}

#[derive(Debug, Deserialize)]
pub struct InsertRows {
    pub rows: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TableQueryRequest {
    #[serde(flatten)]
    pub query: Query,
    #[serde(default)]
    pub limit: Option<usize>,
}

fn valid_column_type(ty: &str) -> bool {
    matches!(
        ty.trim().to_ascii_lowercase().as_str(),
        "string"
            | "text"
            | "number"
            | "float"
            | "int"
            | "integer"
            | "bool"
            | "boolean"
            | "json"
            | "timestamp"
    )
}

fn check_declared_columns(declared: &[TableColumn], query: &Query) -> Result<(), ApiError> {
    if declared.is_empty() {
        return Ok(());
    }
    let allowed: HashSet<&str> = declared.iter().map(|c| c.name.as_str()).collect();
    for f in &query.filters {
        if !allowed.contains(f.column.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown filter column: {}",
                f.column
            )));
        }
    }
    if let Some(cols) = &query.select {
        for c in cols {
            if !allowed.contains(c.as_str()) {
                return Err(ApiError::BadRequest(format!("unknown select column: {c}")));
            }
        }
    }
    if let Some(g) = &query.group_by {
        if !allowed.contains(g.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown group_by column: {g}"
            )));
        }
    }
    if let Some(agg) = &query.aggregate {
        if let Some(c) = &agg.column {
            if !allowed.contains(c.as_str()) {
                return Err(ApiError::BadRequest(format!(
                    "unknown aggregate column: {c}"
                )));
            }
        }
    }
    Ok(())
}

pub async fn list(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:read")?;
    let mut out = Vec::new();
    for t in store::list_tables(&st.db).await? {
        out.push(TableInfo {
            name: t.name.clone(),
            columns: t.columns,
            row_count: store::table_count(&st.db, &t.name).await?,
            created_at: t.created_at,
        });
    }
    Ok(Json(json!({"tables": out})))
}

pub async fn get_one(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:read")?;
    if !valid_name(&name) {
        return Err(ApiError::BadRequest("invalid table name".into()));
    }
    let t = store::get_table(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("table not found".into()))?;
    Ok(Json(
        json!({"name": t.name, "columns": t.columns, "row_count": store::table_count(&st.db, &name).await?, "created_at": t.created_at}),
    ))
}

pub async fn create(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateTable>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:write")?;
    let name = req.name.trim();
    if !valid_name(name) {
        return Err(ApiError::BadRequest(
            "table name must be 1-64 characters: letters, numbers, '_' or '-'".into(),
        ));
    }
    if req.columns.len() > 256 {
        return Err(ApiError::BadRequest("too many columns".into()));
    }
    let mut seen_cols = HashSet::new();
    for col in &req.columns {
        if !valid_name(&col.name) {
            return Err(ApiError::BadRequest(format!(
                "invalid column name: {}",
                col.name
            )));
        }
        if !seen_cols.insert(col.name.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate column name: {}",
                col.name
            )));
        }
        if !valid_column_type(&col.column_type) {
            return Err(ApiError::BadRequest(format!(
                "unsupported column type: {}",
                col.column_type
            )));
        }
    }
    if store::get_table(&st.db, name).await?.is_some() {
        return Err(ApiError::Conflict("table already exists".into()));
    }
    store::insert_table(&st.db, name, &req.columns).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "table.create",
        Some(name),
        Some(json!({"columns": req.columns.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "name": name})))
}

pub async fn delete_one(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("tables:write")?;
    if !valid_name(&name) {
        return Err(ApiError::BadRequest("invalid table name".into()));
    }
    if store::get_table(&st.db, &name).await?.is_none() {
        return Err(ApiError::NotFound("table not found".into()));
    }
    store::delete_table(&st.db, &name).await?;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "table.delete",
        Some(&name),
        None,
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn insert_rows(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
    Json(req): Json<InsertRows>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:write")?;
    if !valid_name(&name) {
        return Err(ApiError::BadRequest("invalid table name".into()));
    }
    if req.rows.is_empty() || req.rows.len() > 1000 {
        return Err(ApiError::BadRequest("rows length must be 1..=1000".into()));
    }
    for row in &req.rows {
        let Some(obj) = row.as_object() else {
            return Err(ApiError::BadRequest(
                "each row must be a JSON object".into(),
            ));
        };
        if obj.len() > 256 {
            return Err(ApiError::BadRequest("too many fields in row".into()));
        }
        for key in obj.keys() {
            if !valid_column_name(key) {
                return Err(ApiError::BadRequest(format!("invalid field name: {key}")));
            }
        }
    }
    match store::insert_rows_bounded(&st.db, &name, &req.rows, st.config.max_rows_per_table).await {
        Ok(()) => {}
        Err(store::InsertRowsError::TableNotFound) => {
            return Err(ApiError::NotFound("table not found".into()));
        }
        Err(store::InsertRowsError::LimitExceeded { max_rows }) => {
            return Err(ApiError::BadRequest(format!(
                "table row limit ({max_rows}) exceeded"
            )));
        }
        Err(store::InsertRowsError::Db(e)) => return Err(e.into()),
    }
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "rows.insert",
        Some(&name),
        Some(json!({"count": req.rows.len()})),
        None,
        None,
    )
    .await;
    Ok(Json(json!({"ok": true, "inserted": req.rows.len()})))
}

pub async fn query(
    State(st): State<SharedState>,
    Path(name): Path<String>,
    principal: Principal,
    Json(req): Json<TableQueryRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("data:read")?;
    if !valid_name(&name) {
        return Err(ApiError::BadRequest("invalid table name".into()));
    }
    let t = store::get_table(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("table not found".into()))?;
    validate_query(&req.query)?;
    check_declared_columns(&t.columns, &req.query)?;
    let limit = match req.limit {
        Some(l) if l == 0 || l > MAX_QUERY_LIMIT => {
            return Err(ApiError::BadRequest(format!(
                "query limit must be between 1 and {MAX_QUERY_LIMIT}"
            )));
        }
        Some(l) => l,
        None => MAX_QUERY_LIMIT.min(MAX_OUTPUT_ROWS),
    };
    let rows = store::load_rows_bounded(&st.db, &name, st.config.max_rows_per_table).await?;
    let result = run_query_bounded(&rows, &req.query, limit)?;
    Ok(Json(json!({"table": name, "rows": result})))
}
