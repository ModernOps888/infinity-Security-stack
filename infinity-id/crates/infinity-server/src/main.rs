//! Infinity ID — secure-by-design identity provider (OIDC/OAuth2 + MFA + RBAC).
//!
//! Thin binary entrypoint; all logic lives in the `infinity_server` library
//! crate (`src/lib.rs`) so it can also be exercised by integration tests.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use infinity_core::keys::KeyRing;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use infinity_server::config::Config;
use infinity_server::state::AppState;
use infinity_server::throttle::LoginThrottle;
use infinity_server::{ratelimit, routes, store};

fn healthcheck_target(bind: &str) -> String {
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return format!("127.0.0.1:{}", addr.port());
        }
        return addr.to_string();
    }
    bind.to_string()
}

fn run_healthcheck(bind: &str) -> bool {
    let target = healthcheck_target(bind);
    let Ok(mut stream) = TcpStream::connect(&target) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    if stream
        .write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let head = String::from_utf8_lossy(&buf[..n]);
            head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200")
        }
        _ => false,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::load().context("loading configuration")?;
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        std::process::exit(if run_healthcheck(&config.bind) { 0 } else { 1 });
    }

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    std::fs::create_dir_all(&config.data_dir).ok();

    // Database (SQLite by default; create file if missing) + migrations.
    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .context("parsing database_url")?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .context("connecting to database")?;
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("running migrations")?;

    // Signing key ring (persisted so live tokens survive restarts and a
    // rotation doesn't invalidate tokens signed under the retired key).
    let key_path = std::path::Path::new(&config.data_dir).join("signing_key.pem");
    let retention_secs = config
        .refresh_token_ttl_secs
        .max(config.access_token_ttl_secs);
    let key =
        KeyRing::load_or_generate(&key_path, retention_secs).context("loading signing key")?;
    tracing::info!(
        kid = %key.active.kid,
        retired_keys = key.previous.len(),
        "loaded RS256 signing key ring"
    );

    store::seed(&db, &config)
        .await
        .context("seeding database")?;

    let bind = config.bind.clone();
    let ip_limiter = ratelimit::IpRateLimiter::new(config.global_rate_limit_per_min);
    let state = Arc::new(AppState {
        db,
        key: std::sync::RwLock::new(key),
        key_path,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter,
    });

    // `routes::router` applies the full security-header, CORS, rate-limit, and
    // request-body-limit middleware stack so tests and production match.
    let app = routes::router(state).layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity ID listening — dashboard at the bind address");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;
    Ok(())
}
