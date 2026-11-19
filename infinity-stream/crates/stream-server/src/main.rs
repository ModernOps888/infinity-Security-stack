//! Infinity Stream — streaming log + BM25 search + realtime fan-out in one Rust binary.
//!
//! Thin binary entrypoint; all logic lives in the `stream_server` library
//! crate (`src/lib.rs`) so it can also be exercised directly by integration tests.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use stream_core::bm25::Bm25Index;
use stream_core::commit_log::CommitLog;
use tokio::sync::Semaphore;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use stream_server::config::Config;
use stream_server::state::AppState;
use stream_server::{ratelimit, store, throttle};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Warm the constant-time dummy Argon2id hash before serving login requests.
    stream_core::password::warm_dummy_hash();

    let config = Config::load().context("loading configuration")?;
    config.validate().context("validating configuration")?;
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating data directory {}", config.data_dir))?;

    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("connecting to database")?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("running migrations")?;

    if let Some(key) = store::seed(&db, &config)
        .await
        .context("seeding database")?
    {
        tracing::warn!("seeded initial API key (shown once): {}", key);
    }

    let log = CommitLog::open(&config.data_dir, config.segment_max_bytes)
        .context("opening commit log")?;
    let mut indexes: HashMap<String, Bm25Index> = HashMap::new();
    for (name, _) in store::list_indexes(&db).await.context("loading indexes")? {
        let mut idx = Bm25Index::new();
        for (id, fields_json) in store::docs_for_index(&db, &name).await? {
            let fields: HashMap<String, serde_json::Value> =
                serde_json::from_str(&fields_json).unwrap_or_default();
            if let Err(err) = idx.try_index(id, fields) {
                tracing::warn!(index = %name, error = %err, "skipped oversized or invalid indexed doc");
            }
        }
        indexes.insert(name, idx);
    }

    let bind = config.bind.clone();
    if !config.cookie_secure() && !bind.starts_with("127.0.0.1:") && !bind.starts_with("[::1]:") {
        tracing::warn!(
            %bind,
            public_url = %config.public_url,
            "serving without Secure cookie flag on non-loopback bind; set HTTPS public_url behind TLS proxy in production"
        );
    }
    tracing::info!(
        trusted_proxies = config.trusted_proxies.len(),
        ws_max_connections = config.ws_max_connections,
        global_rate_limit_per_min = config.global_rate_limit_per_min,
        "security policy initialized"
    );

    let ip_limiter = ratelimit::IpRateLimiter::new(config.global_rate_limit_per_min);
    let ws_semaphore = Arc::new(Semaphore::new(config.ws_max_connections));
    let state = Arc::new(AppState {
        db,
        config,
        log: tokio::sync::Mutex::new(log),
        indexes: tokio::sync::RwLock::new(indexes),
        broadcasts: tokio::sync::RwLock::new(HashMap::new()),
        produced_times: tokio::sync::Mutex::new(VecDeque::new()),
        login_throttle: throttle::LoginThrottle::default(),
        ip_limiter,
        ws_semaphore,
    });

    let app = stream_server::app(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity Stream listening — dashboard at the bind address");
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
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(ref mut sig) = sigterm {
                    sig.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown signal received; draining connections");
}
