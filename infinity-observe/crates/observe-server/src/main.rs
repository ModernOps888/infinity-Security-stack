//! Infinity Observe — production-grade observability in a single Rust binary.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use observe_server::config::Config;
use observe_server::state::AppState;
use observe_server::throttle::LoginThrottle;
use observe_server::{ratelimit, routes, store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::load().context("loading configuration")?;
    config.validate().context("validating configuration")?;
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating data_dir {}", config.data_dir))?;

    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
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

    store::seed(&db, &config)
        .await
        .context("seeding database")?;

    let bind = config.bind.clone();
    tracing::info!(
        allow_insecure_webhooks = config.allow_insecure_webhooks,
        allow_private_webhooks = config.allow_private_webhooks,
        trusted_proxies = config.trusted_proxies.len(),
        "security policy loaded"
    );
    let ip_limiter = ratelimit::IpRateLimiter::new(config.global_rate_limit_per_min);
    let state = Arc::new(AppState {
        db,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter,
    });

    // Core security layers (CORS, DefaultBodyLimit, CSP, HSTS, rate limit, CSRF guard)
    // are installed inside `routes::router` so tests and production match identically.
    let app = routes::router(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity Observe listening — dashboard at the bind address");
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
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received, draining connections");
}
