use chrono::{Duration, Utc};
use data_core::hnsw::Point;
use data_core::model::{Metric, TableColumn};
use data_core::rbac::{ROLE_ADMIN, ROLE_SUPERADMIN, ROLE_USER};
use data_core::security::{random_token, sha256_hex};
use serde::Serialize;
use sqlx::{FromRow, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;

use crate::config::Config;

fn now() -> String {
    Utc::now().to_rfc3339()
}
fn future(secs: i64) -> String {
    (Utc::now() + Duration::seconds(secs)).to_rfc3339()
}

#[derive(Debug, FromRow)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub disabled: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CollectionRow {
    pub name: String,
    pub dim: usize,
    pub metric: Metric,
    pub created_at: String,
}

#[derive(Debug, FromRow)]
struct CollectionDbRow {
    name: String,
    dim: i64,
    metric: String,
    created_at: String,
}

#[derive(Debug, Clone)]
pub struct TableRowInfo {
    pub name: String,
    pub columns: Vec<TableColumn>,
    pub created_at: String,
}

#[derive(Debug, FromRow)]
struct TableDbRow {
    name: String,
    columns: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct RoleInfo {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct AuditRow {
    pub id: String,
    pub actor_user_id: Option<String>,
    pub event: String,
    pub target: Option<String>,
    pub detail_json: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
}

impl TryFrom<CollectionDbRow> for CollectionRow {
    type Error = anyhow::Error;
    fn try_from(r: CollectionDbRow) -> Result<Self, Self::Error> {
        let dim = usize::try_from(r.dim).map_err(|_| anyhow::anyhow!("invalid collection dim"))?;
        if dim == 0 || dim > data_core::hnsw::MAX_DIM {
            anyhow::bail!("collection dim out of bounds: {dim}");
        }
        Ok(Self {
            name: r.name,
            dim,
            metric: Metric::from_str(&r.metric).map_err(anyhow::Error::msg)?,
            created_at: r.created_at,
        })
    }
}

impl TryFrom<TableDbRow> for TableRowInfo {
    type Error = anyhow::Error;
    fn try_from(r: TableDbRow) -> Result<Self, Self::Error> {
        Ok(Self {
            name: r.name,
            columns: serde_json::from_str(&r.columns)?,
            created_at: r.created_at,
        })
    }
}

pub async fn seed(db: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    seed_roles(db).await?;
    // Purge expired sessions so the table cannot grow without bound.
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now())
        .execute(db)
        .await?;
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    if count.0 == 0 {
        data_core::password::validate_admin_password(&config.admin_password)?;
        let hash = data_core::password::hash_password(&config.admin_password)?;
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&id)
            .bind(&config.admin_email)
            .bind("admin")
            .bind("Infinity Data Administrator")
            .bind(hash)
            .bind(now())
            .execute(db)
            .await?;
        assign_role(db, &id, ROLE_SUPERADMIN).await?;
        audit(
            db,
            Some(&id),
            "admin.seed",
            Some("user:admin"),
            None,
            None,
            None,
        )
        .await;
        tracing::info!(email = %config.admin_email, "seeded initial admin account");
    }
    let key_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_keys")
        .fetch_one(db)
        .await?;
    if key_count.0 == 0 {
        let raw = format!("idat_{}", random_token());
        create_api_key_with_raw(db, "seed", &raw).await?;
        tracing::warn!(api_key = %raw, "seeded initial Infinity Data API key; shown once");
    }
    Ok(())
}

async fn seed_roles(db: &SqlitePool) -> sqlx::Result<()> {
    let roles = [
        (ROLE_SUPERADMIN, "Full platform administration", vec!["*:*"]),
        (
            ROLE_ADMIN,
            "Data and user administration",
            vec![
                "data:*",
                "collections:*",
                "tables:*",
                "users:*",
                "roles:read",
                "audit:read",
                "api_keys:*",
            ],
        ),
        (
            ROLE_USER,
            "Read/write data access",
            vec![
                "data:read",
                "data:write",
                "collections:read",
                "tables:read",
                "tables:write",
            ],
        ),
    ];
    for (name, desc, perms) in roles {
        sqlx::query("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)")
            .bind(name)
            .bind(desc)
            .execute(db)
            .await?;
        for perm in perms {
            sqlx::query(
                "INSERT OR IGNORE INTO role_permissions (role_name, permission) VALUES (?, ?)",
            )
            .bind(name)
            .bind(perm)
            .execute(db)
            .await?;
        }
    }
    Ok(())
}

pub async fn get_user_by_email(db: &SqlitePool, email: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT id, email, username, display_name, password_hash, disabled, created_at FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(db)
        .await
}

pub async fn get_user(db: &SqlitePool, id: &str) -> sqlx::Result<Option<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT id, email, username, display_name, password_hash, disabled, created_at FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn list_users(db: &SqlitePool) -> sqlx::Result<Vec<UserRow>> {
    sqlx::query_as::<_, UserRow>("SELECT id, email, username, display_name, password_hash, disabled, created_at FROM users ORDER BY created_at DESC")
        .fetch_all(db)
        .await
}

pub async fn user_exists(db: &SqlitePool, email: &str, username: &str) -> sqlx::Result<bool> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = ? OR username = ?")
        .bind(email)
        .bind(username)
        .fetch_one(db)
        .await?;
    Ok(row.0 > 0)
}

pub async fn create_user(
    db: &SqlitePool,
    email: &str,
    username: &str,
    display_name: Option<&str>,
    password: &str,
) -> anyhow::Result<UserRow> {
    let id = Uuid::new_v4().to_string();
    let hash = data_core::password::hash_password(password)?;
    sqlx::query("INSERT INTO users (id, email, username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id).bind(email).bind(username).bind(display_name).bind(hash).bind(now()).execute(db).await?;
    get_user(db, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("created user missing"))
}

pub async fn set_user_disabled(db: &SqlitePool, id: &str, disabled: bool) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET disabled = ? WHERE id = ?")
        .bind(if disabled { 1 } else { 0 })
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if disabled {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn delete_user_sessions(db: &SqlitePool, user_id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_user(db: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn assign_role(db: &SqlitePool, user_id: &str, role: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role_name) VALUES (?, ?)")
        .bind(user_id)
        .bind(role)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_user_roles(db: &SqlitePool, user_id: &str, roles: &[String]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for role in roles {
        sqlx::query("INSERT OR IGNORE INTO user_roles (user_id, role_name) VALUES (?, ?)")
            .bind(user_id)
            .bind(role)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn user_roles(db: &SqlitePool, user_id: &str) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|(r,)| r).collect())
}

pub async fn user_permissions(db: &SqlitePool, user_id: &str) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT rp.permission FROM role_permissions rp JOIN user_roles ur ON ur.role_name = rp.role_name WHERE ur.user_id = ? ORDER BY rp.permission"
    ).bind(user_id).fetch_all(db).await?;
    Ok(rows.into_iter().map(|(p,)| p).collect())
}

pub async fn list_roles(db: &SqlitePool) -> sqlx::Result<Vec<RoleInfo>> {
    sqlx::query_as::<_, RoleInfo>("SELECT name, description FROM roles ORDER BY name")
        .fetch_all(db)
        .await
}

pub async fn role_exists(db: &SqlitePool, role: &str) -> sqlx::Result<bool> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM roles WHERE name = ?")
        .bind(role)
        .fetch_one(db)
        .await?;
    Ok(row.0 > 0)
}

pub async fn role_permissions(db: &SqlitePool, role: &str) -> sqlx::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT permission FROM role_permissions WHERE role_name = ? ORDER BY permission",
    )
    .bind(role)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(p,)| p).collect())
}

pub async fn upsert_role(
    db: &SqlitePool,
    name: &str,
    description: &str,
    permissions: &[String],
) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO roles (name, description) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET description = excluded.description")
        .bind(name).bind(description).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM role_permissions WHERE role_name = ?")
        .bind(name)
        .execute(&mut *tx)
        .await?;
    for p in permissions {
        sqlx::query("INSERT INTO role_permissions (role_name, permission) VALUES (?, ?)")
            .bind(name)
            .bind(p)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn create_session(
    db: &SqlitePool,
    id_hash: &str,
    user_id: &str,
    ttl: i64,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(id_hash)
        .bind(user_id)
        .bind(future(ttl))
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn get_session_user(db: &SqlitePool, id_hash: &str) -> sqlx::Result<Option<String>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT user_id, expires_at FROM sessions WHERE id = ?")
            .bind(id_hash)
            .fetch_optional(db)
            .await?;
    match row {
        Some((uid, exp))
            if chrono::DateTime::parse_from_rfc3339(&exp)
                .map(|t| t > Utc::now())
                .unwrap_or(false) =>
        {
            Ok(Some(uid))
        }
        Some(_) => {
            let _ = delete_session(db, id_hash).await;
            Ok(None)
        }
        None => Ok(None),
    }
}

pub async fn delete_session(db: &SqlitePool, id_hash: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(id_hash)
        .execute(db)
        .await?;
    Ok(())
}

async fn create_api_key_with_raw(db: &SqlitePool, name: &str, raw: &str) -> sqlx::Result<String> {
    let id = Uuid::new_v4().to_string();
    let prefix = raw.chars().take(12).collect::<String>();
    let hash = sha256_hex(raw);
    sqlx::query(
        "INSERT INTO api_keys (id, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(prefix)
    .bind(hash)
    .bind(now())
    .execute(db)
    .await?;
    Ok(id)
}

pub async fn create_api_key(db: &SqlitePool, name: &str) -> sqlx::Result<(String, ApiKeyInfo)> {
    let raw = format!("idat_{}", random_token());
    let id = create_api_key_with_raw(db, name, &raw).await?;
    let info = get_api_key(db, &id).await?.expect("created key exists");
    Ok((raw, info))
}

pub async fn get_api_key(db: &SqlitePool, id: &str) -> sqlx::Result<Option<ApiKeyInfo>> {
    sqlx::query_as::<_, ApiKeyInfo>(
        "SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

pub async fn list_api_keys(db: &SqlitePool) -> sqlx::Result<Vec<ApiKeyInfo>> {
    sqlx::query_as::<_, ApiKeyInfo>(
        "SELECT id, name, prefix, created_at, last_used_at FROM api_keys ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
}

pub async fn delete_api_key(db: &SqlitePool, id: &str) -> sqlx::Result<bool> {
    let res = sqlx::query("DELETE FROM api_keys WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() > 0)
}

#[derive(Debug, FromRow)]
struct ApiKeyAuthRow {
    id: String,
    name: String,
    prefix: String,
    key_hash: String,
    created_at: String,
    last_used_at: Option<String>,
}

pub async fn verify_api_key(db: &SqlitePool, raw: &str) -> sqlx::Result<Option<ApiKeyInfo>> {
    if !raw.starts_with("idat_")
        || !(16..=256).contains(&raw.len())
        || raw.chars().any(char::is_control)
    {
        return Ok(None);
    }
    let prefix: String = raw.chars().take(12).collect();
    let candidate_hash = sha256_hex(raw);
    let rows = sqlx::query_as::<_, ApiKeyAuthRow>(
        "SELECT id, name, prefix, key_hash, created_at, last_used_at FROM api_keys WHERE prefix = ?",
    )
    .bind(&prefix)
    .fetch_all(db)
    .await?;
    let mut matched: Option<ApiKeyInfo> = None;
    for row in rows {
        if data_core::password::constant_time_eq(candidate_hash.as_bytes(), row.key_hash.as_bytes())
        {
            matched = Some(ApiKeyInfo {
                id: row.id,
                name: row.name,
                prefix: row.prefix,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            });
        }
    }
    if let Some(info) = &matched {
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(now())
            .bind(&info.id)
            .execute(db)
            .await?;
    }
    Ok(matched)
}

pub async fn insert_collection(
    db: &SqlitePool,
    name: &str,
    dim: usize,
    metric: Metric,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO collections (name, dim, metric, created_at) VALUES (?, ?, ?, ?)")
        .bind(name)
        .bind(dim as i64)
        .bind(metric.to_string())
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_collections(db: &SqlitePool) -> anyhow::Result<Vec<CollectionRow>> {
    let rows = sqlx::query_as::<_, CollectionDbRow>(
        "SELECT name, dim, metric, created_at FROM collections ORDER BY name",
    )
    .fetch_all(db)
    .await?;
    rows.into_iter().map(CollectionRow::try_from).collect()
}

pub async fn get_collection(db: &SqlitePool, name: &str) -> anyhow::Result<Option<CollectionRow>> {
    let row = sqlx::query_as::<_, CollectionDbRow>(
        "SELECT name, dim, metric, created_at FROM collections WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(db)
    .await?;
    row.map(CollectionRow::try_from).transpose()
}

pub async fn delete_collection(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM vector_points WHERE collection_name = ?")
        .bind(name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM collections WHERE name = ?")
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn upsert_points(
    db: &SqlitePool,
    collection: &str,
    points: &[Point],
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    let ts = now();
    for p in points {
        let vector_json = serde_json::to_string(&p.vector)?;
        let metadata_json = p.metadata.as_ref().map(|m| m.to_string());
        sqlx::query(
            "INSERT INTO vector_points (collection_name, id, vector_json, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(collection_name, id) DO UPDATE SET vector_json = excluded.vector_json, metadata_json = excluded.metadata_json, updated_at = excluded.updated_at"
        )
        .bind(collection).bind(&p.id).bind(vector_json).bind(metadata_json).bind(&ts).bind(&ts).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn load_points(db: &SqlitePool, collection: &str) -> anyhow::Result<Vec<Point>> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as("SELECT id, vector_json, metadata_json FROM vector_points WHERE collection_name = ? ORDER BY created_at")
        .bind(collection).fetch_all(db).await?;
    let mut points = Vec::with_capacity(rows.len());
    for (id, vector_json, metadata_json) in rows {
        let vector: Vec<f32> = serde_json::from_str(&vector_json)?;
        let metadata = metadata_json.and_then(|m| serde_json::from_str(&m).ok());
        points.push(Point {
            id,
            vector,
            metadata,
        });
    }
    Ok(points)
}

pub async fn vector_count(db: &SqlitePool, collection: Option<&str>) -> sqlx::Result<usize> {
    let c: (i64,) = if let Some(name) = collection {
        sqlx::query_as("SELECT COUNT(*) FROM vector_points WHERE collection_name = ?")
            .bind(name)
            .fetch_one(db)
            .await?
    } else {
        sqlx::query_as("SELECT COUNT(*) FROM vector_points")
            .fetch_one(db)
            .await?
    };
    Ok(usize::try_from(c.0).unwrap_or(0))
}

pub async fn insert_table(
    db: &SqlitePool,
    name: &str,
    columns: &[TableColumn],
) -> anyhow::Result<()> {
    let cols = serde_json::to_string(columns)?;
    sqlx::query("INSERT INTO analytics_tables (name, columns, created_at) VALUES (?, ?, ?)")
        .bind(name)
        .bind(cols)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_tables(db: &SqlitePool) -> anyhow::Result<Vec<TableRowInfo>> {
    let rows = sqlx::query_as::<_, TableDbRow>(
        "SELECT name, columns, created_at FROM analytics_tables ORDER BY name",
    )
    .fetch_all(db)
    .await?;
    rows.into_iter().map(TableRowInfo::try_from).collect()
}

pub async fn get_table(db: &SqlitePool, name: &str) -> anyhow::Result<Option<TableRowInfo>> {
    let row = sqlx::query_as::<_, TableDbRow>(
        "SELECT name, columns, created_at FROM analytics_tables WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(db)
    .await?;
    row.map(TableRowInfo::try_from).transpose()
}

pub async fn delete_table(db: &SqlitePool, name: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM analytics_tables WHERE name = ?")
        .bind(name)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug)]
pub enum InsertRowsError {
    TableNotFound,
    LimitExceeded { max_rows: usize },
    Db(sqlx::Error),
}

impl From<sqlx::Error> for InsertRowsError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

pub async fn insert_rows(
    db: &SqlitePool,
    table: &str,
    rows: &[serde_json::Value],
) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    for row in rows {
        sqlx::query(
            "INSERT INTO table_rows (id, table_name, row_json, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(table)
        .bind(row.to_string())
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Atomically verifies table existence, enforces `max_rows`, and inserts all rows
/// inside a single `BEGIN IMMEDIATE` transaction so concurrent callers cannot race
/// past `max_rows_per_table`.
pub async fn insert_rows_bounded(
    db: &SqlitePool,
    table: &str,
    rows: &[serde_json::Value],
    max_rows: usize,
) -> Result<(), InsertRowsError> {
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;
    let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM analytics_tables WHERE name = ?")
        .bind(table)
        .fetch_one(&mut *tx)
        .await?;
    if exists.0 == 0 {
        return Err(InsertRowsError::TableNotFound);
    }
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM table_rows WHERE table_name = ?")
        .bind(table)
        .fetch_one(&mut *tx)
        .await?;
    let existing = usize::try_from(count.0).unwrap_or(0);
    if existing.saturating_add(rows.len()) > max_rows {
        return Err(InsertRowsError::LimitExceeded { max_rows });
    }
    for row in rows {
        sqlx::query(
            "INSERT INTO table_rows (id, table_name, row_json, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(table)
        .bind(row.to_string())
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn load_rows(db: &SqlitePool, table: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    load_rows_bounded(db, table, data_core::aggregation::MAX_INPUT_ROWS).await
}

pub async fn load_rows_bounded(
    db: &SqlitePool,
    table: &str,
    limit: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let cap = i64::try_from(limit.clamp(1, data_core::aggregation::MAX_INPUT_ROWS))
        .unwrap_or(data_core::aggregation::MAX_INPUT_ROWS as i64);
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT row_json FROM table_rows WHERE table_name = ? ORDER BY created_at LIMIT ?",
    )
    .bind(table)
    .bind(cap)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(s,)| serde_json::from_str(&s).ok())
        .collect())
}

pub async fn table_count(db: &SqlitePool, table: &str) -> sqlx::Result<usize> {
    let c: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM table_rows WHERE table_name = ?")
        .bind(table)
        .fetch_one(db)
        .await?;
    Ok(usize::try_from(c.0).unwrap_or(0))
}

pub async fn stats_counts(db: &SqlitePool) -> sqlx::Result<(usize, usize, usize, usize, usize)> {
    let collections: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM collections")
        .fetch_one(db)
        .await?;
    let vectors: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vector_points")
        .fetch_one(db)
        .await?;
    let tables: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM analytics_tables")
        .fetch_one(db)
        .await?;
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM table_rows")
        .fetch_one(db)
        .await?;
    let users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    Ok((
        usize::try_from(collections.0).unwrap_or(0),
        usize::try_from(vectors.0).unwrap_or(0),
        usize::try_from(tables.0).unwrap_or(0),
        usize::try_from(rows.0).unwrap_or(0),
        usize::try_from(users.0).unwrap_or(0),
    ))
}

pub async fn audit(
    db: &SqlitePool,
    actor_user_id: Option<&str>,
    event: &str,
    target: Option<&str>,
    detail: Option<serde_json::Value>,
    ip: Option<&str>,
    user_agent: Option<&str>,
) {
    let _ = sqlx::query("INSERT INTO audit_log (id, actor_user_id, event, target, detail_json, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(actor_user_id)
        .bind(event)
        .bind(target)
        .bind(detail.map(|d| d.to_string()))
        .bind(ip)
        .bind(user_agent)
        .bind(now())
        .execute(db)
        .await
        .map_err(|e| tracing::warn!(error = %e, "audit write failed"));
}

pub async fn list_audit(db: &SqlitePool, limit: i64) -> sqlx::Result<Vec<AuditRow>> {
    sqlx::query_as::<_, AuditRow>("SELECT id, actor_user_id, event, target, detail_json, ip, user_agent, created_at FROM audit_log ORDER BY created_at DESC LIMIT ?")
        .bind(limit.clamp(1, 500)).fetch_all(db).await
}
