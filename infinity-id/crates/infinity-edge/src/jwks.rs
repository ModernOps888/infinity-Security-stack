//! JWKS fetch + token validation for the edge gateway, with live key rotation
//! refresh and strict `kid` + header pinning.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use infinity_core::token::{inspect_header, validate_with_components, Claims};
use serde::Deserialize;
use tokio::sync::Mutex;

const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);
const JWKS_MAX_TTL: Duration = Duration::from_secs(300);
const JWKS_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct JwkEntry {
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Deserialize)]
struct JwkDoc {
    keys: Vec<JwkEntry>,
}

struct CachedKeys {
    keys: Vec<JwkEntry>,
    fetched_at: Instant,
}

/// Cached public keys used to validate incoming access tokens.
pub struct JwksCache {
    jwks_url: String,
    issuer: String,
    http: reqwest::Client,
    inner: RwLock<CachedKeys>,
    refresh_lock: Mutex<()>,
}

impl JwksCache {
    /// Fetch the JWKS from Infinity ID using a redirect-disabled HTTP client.
    pub async fn fetch(url: &str, issuer: &str) -> anyhow::Result<Self> {
        crate::config::validate_http_target_url(url, false)?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()?;
        let keys = Self::fetch_keys(&http, url).await?;
        Ok(Self {
            jwks_url: url.to_string(),
            issuer: issuer.to_string(),
            http,
            inner: RwLock::new(CachedKeys {
                keys,
                fetched_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub fn from_entries_for_test(keys: Vec<JwkEntry>, issuer: &str) -> Self {
        Self {
            jwks_url: "http://127.0.0.1:0/.well-known/jwks.json".into(),
            issuer: issuer.to_string(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            inner: RwLock::new(CachedKeys {
                keys,
                fetched_at: Instant::now(),
            }),
            refresh_lock: Mutex::new(()),
        }
    }

    async fn fetch_keys(http: &reqwest::Client, url: &str) -> anyhow::Result<Vec<JwkEntry>> {
        let resp = http.get(url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("JWKS fetch returned status {}", resp.status());
        }
        let bytes = resp.bytes().await?;
        if bytes.len() > JWKS_MAX_BYTES {
            anyhow::bail!("JWKS document exceeds size limit");
        }
        let doc: JwkDoc = serde_json::from_slice(&bytes)?;
        Ok(doc.keys)
    }

    async fn maybe_refresh(&self, missing_kid: &str) {
        let should_refresh = {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            let unknown_kid = !guard.keys.iter().any(|k| k.kid == missing_kid);
            let expired = guard.fetched_at.elapsed() >= JWKS_MAX_TTL;
            (unknown_kid || expired) && guard.fetched_at.elapsed() >= JWKS_REFRESH_COOLDOWN
        };
        if !should_refresh {
            return;
        }
        let _lock = self.refresh_lock.lock().await;
        // Re-check inside lock so concurrent requests coalesce into one fetch.
        {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if guard.fetched_at.elapsed() < JWKS_REFRESH_COOLDOWN {
                return;
            }
        }
        if let Ok(keys) = Self::fetch_keys(&self.http, &self.jwks_url).await {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            guard.keys = keys;
            guard.fetched_at = Instant::now();
        }
    }

    /// Validate a token against the JWK matching its `kid` header; refreshes JWKS
    /// on unknown `kid` (rate-limited) so key rotation works without restart.
    pub async fn validate(&self, token: &str, audience: Option<&str>) -> Option<Claims> {
        let header = inspect_header(token).ok()?;
        let kid = header.kid?;

        if !self
            .inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .iter()
            .any(|k| k.kid == kid)
        {
            self.maybe_refresh(&kid).await;
        }

        let matching: Vec<JwkEntry> = {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            guard
                .keys
                .iter()
                .filter(|k| k.kid == kid)
                .cloned()
                .collect()
        };

        for key in matching {
            if let Ok(claims) =
                validate_with_components(token, &key.n, &key.e, &self.issuer, audience)
            {
                // Only genuine access tokens may authorize upstream calls —
                // reject id_tokens (which are exposed to browsers/SPAs).
                if claims.typ != "access" {
                    return None;
                }
                return Some(claims);
            }
        }
        None
    }
}
