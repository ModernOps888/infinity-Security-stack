//! Infinity Data — single-node Rust-native analytics + vector database.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use data_core::hnsw::HnswIndex;
use data_server::config::Config;
use data_server::ratelimit::IpRateLimiter;
use data_server::state::AppState;
use data_server::throttle::LoginThrottle;
use data_server::{routes, store};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Warm the constant-time dummy Argon2id hash before accepting connections.
    data_core::password::warm_dummy_hash();

    let config = Config::load().context("loading configuration")?;
    std::fs::create_dir_all(&config.data_dir).context("creating data directory")?;
    let collections_dir = std::path::Path::new(&config.data_dir).join("collections");
    std::fs::create_dir_all(&collections_dir).context("creating collections directory")?;
    tracing::debug!(path = %collections_dir.display(), "collection data directory ready");

    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("connecting to database")?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("running migrations")?;
    store::seed(&db, &config)
        .await
        .context("seeding database")?;

    let indexes = rebuild_indexes(&db)
        .await
        .context("rebuilding vector indexes")?;
    tracing::info!(collections = indexes.len(), "loaded vector indexes");

    let bind = config.bind.clone();
    let global_limit = config.global_rate_limit_per_min;
    if !config.secure_cookies() && !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") {
        tracing::warn!(
            %bind,
            public_url = %config.public_url,
            "serving without Secure cookie flag on non-loopback bind; configure HTTPS public_url behind TLS proxy for production"
        );
    }
    tracing::info!(
        max_vectors_per_collection = config.max_vectors_per_collection,
        max_rows_per_table = config.max_rows_per_table,
        trusted_proxies = config.trusted_proxies.len(),
        "resource and proxy limits configured"
    );
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(indexes),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(global_limit),
    });
    tracing::info!(
        limit_per_min = global_limit,
        "global rate limiter configured"
    );

    // Security headers (CSP, HSTS, X-Frame-Options, nosniff, etc.), CORS, CSRF Origin
    // checks, body limits, and IP rate limiting are wired inside `routes::router` so
    // production and integration tests share the exact same middleware stack.
    let app = routes::router(state.clone()).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, dashboard = %state.config.public_url, "Infinity Data listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown signal received");
}

async fn rebuild_indexes(db: &sqlx::SqlitePool) -> anyhow::Result<HashMap<String, HnswIndex>> {
    let mut indexes = HashMap::new();
    for c in store::list_collections(db).await? {
        let mut index = HnswIndex::new(c.dim, c.metric, 16, 128)?;
        for point in store::load_points(db, &c.name).await? {
            index.insert(point)?;
        }
        indexes.insert(c.name, index);
    }
    Ok(indexes)
}
