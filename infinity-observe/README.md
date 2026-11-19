<div align="center">

# ∞ Infinity Observe

### Rust-native observability without the SaaS tax.

**Logs · Metrics · Traces · Alerts · Ingest API Keys · Embedded Admin Dashboard**

A fast, single-binary, self-hostable alternative to **Datadog, Splunk, New Relic and Sentry** — built for teams that want strong security controls, predictable cost and operational ownership.

[![Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

</div>

---

## Why Infinity Observe

Observability vendors make telemetry expensive exactly when you need it most: during incidents, scale events and noisy releases. Infinity Observe takes the opposite stance:

- **One secure Rust binary.** API, storage and dashboard ship together with no Node build or sidecar frontend.
- **Write paths are locked down.** Logs, metrics and traces require a bearer ingest API key.
- **Operator-first economics.** Store telemetry in your infrastructure and scale on hardware, not event-based invoices.
- **Security controls are included.** Argon2id, server-side sessions, RBAC, rate limits, hardened headers and generic error responses are built in.

> **Positioning:** Infinity Observe is part of the [**Infinity Stack**](../README.md) — Rust-native replacements for over-monetized SaaS infrastructure.

---

## 📸 The dashboard

The dark-theme admin console is embedded in the binary and served from `/`.

| Sign in | Overview |
|---|---|
| ![Login](docs/img/login.png) | ![Overview](docs/img/overview.png) |

| Logs | Metrics |
|---|---|
| ![Logs](docs/img/logs.png) | ![Metrics](docs/img/metrics.png) |

| Traces | Alerts |
|---|---|
| ![Traces](docs/img/traces.png) | ![Alerts](docs/img/alerts.png) |

Dashboard routes/views:

| View | Route / nav |
|---|---|
| Login | `/` unauthenticated |
| Overview | `/` → `Overview` |
| Logs | `/` → `Logs` |
| Metrics | `/` → `Metrics` |
| Traces | `/` → `Traces` |
| Alerts | `/` → `Alerts` |
| Settings / ingest keys | `/` → `Settings` |

---

## ✨ Features

### Telemetry ingest
- JSON ingest endpoints for logs, metrics and traces.
- Bearer API key required for every write.
- Request body limits, per-batch limits and field validation.
- Ingest API keys are shown once and stored only as SHA-256 hashes.

### Query and operations
- Log search by service, level, time and message tokens.
- Metric names, time series and quantile summaries.
- Trace listing and per-trace span waterfalls.
- Alert rules for error-log volume and metric p99 thresholds.
- Embedded dashboard for operators and incident responders.

### Access control
- Admin dashboard authentication with opaque server-side sessions.
- `HttpOnly` + `SameSite=Strict` cookies; `Secure` is set by default and omitted only for loopback (`http://localhost` / `http://127.*`) development.
- RBAC guards on query, alert and key-management APIs.

---

## 🔒 Security

Infinity Observe is hardened by default:

| Area | Hardening |
|---|---|
| **Password storage** | Argon2id (memory-hard OWASP parameters: 19 MiB, 2 passes, p=1); rejects weak/placeholder bootstrap admin passwords. |
| **First run** | If `OBSERVE_ADMIN_PASSWORD` is unset/empty, a strong random admin password is generated and printed once in startup logs. |
| **Sessions** | Opaque random token, hashed at rest, server-side expiration/revocation (purged at startup and lazily on expiry), session fixation invalidation on re-login, `HttpOnly`, `SameSite=Strict`, `Secure` by default (omitted only for exact loopback `http://localhost`, `127.0.0.0/8`, or `[::1]`), `Cache-Control: no-store`; 2-hour default TTL. |
| **RBAC** | Admin-only guards for alert mutation and ingest-key management; viewer role is read-only; unknown roles fail closed with zero permissions. |
| **Ingest auth** | Logs/metrics/traces require `Authorization: Bearer <ingest-key>`; keys are resolved via an **O(1) indexed hash lookup** with constant-time confirmation — auth cost doesn't grow with the number of keys. |
| **Brute force & XFF** | Per-account and per-IP login lockout plus global per-IP fixed-window rate limiting with memory-bounded maps; `X-Forwarded-For`/`X-Real-IP` ignored unless peer matches `trusted_proxies`. |
| **User enumeration** | Uniform login errors and dummy Argon2id verification for unknown users; disabled-account status is checked only after password verification. |
| **SSRF protection** | Alert webhooks require `https://` by default, block loopback/RFC1918/CGNAT/link-local/cloud metadata (`169.254.169.254`)/IPv6 ULA/mapped-IPv6/internal hostnames, disable HTTP redirects, and pin validated DNS IPs on dispatch (opt-in overrides via `allow_insecure_webhooks` / `allow_private_webhooks`). |
| **Transport & UI hardening** | Strict CSP (no `'unsafe-inline'`), HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Origin`/`Sec-Fetch-Site` CSRF guard, HTML-escaped SPA rendering. |
| **Error handling** | DB/internal errors are logged server-side (control-char sanitized) and returned to clients as generic JSON. |
| **SQL & Query safety** | All queries use `sqlx` bind parameters; `LIKE` search escapes `\`, `%`, `_` (`ESCAPE '\'`) and caps tokens/ranges/limits. |
| **Ingestion & DoS bounds** | Configurable `DefaultBodyLimit`, atomic transactional batching, attribute/tag cardinality & depth caps, CRLF/control/bidi sanitization, strict UTC timestamp & finite numeric/histogram validation. |
| **Agent safety** | `infinity-observe-agent` requires `https://` for non-loopback servers (`--allow-insecure-http` opt-in), disables redirects, redacts `ingest_key` in `Debug`, and batches file tails. |
| **Secret hygiene** | `.gitignore` excludes `data/`, `target/`, databases, keys, logs and `.env` files. |
| **JWTs/JWKS** | Infinity Observe does not issue JWTs; ingest uses opaque API keys and the dashboard uses server-side sessions. |
| **Dependency hardening** | `sqlx` upgraded `0.8 -> 0.9` (`sqlx 0.9.1`, `libsqlite3-sys 0.40.0` resolving `RUSTSEC-2026-0459`), `quinn-proto`/`quinn-udp`/`rustls`/`rustls-webpki`/`webpki-roots` updated, and `rsa` (`RUSTSEC-2023-0071`) completely removed from `Cargo.lock` (`cargo tree -i rsa` confirms absent). `cargo audit` passes with **0 active vulnerabilities** and `.cargo/audit.toml` `ignore = []` (`RUSTSEC-2026-0543` informational `chrono 0.4` unmaintained warning remains tracked). |

**TLS:** terminate HTTPS at a load balancer or reverse proxy. Session cookies are marked `Secure` by default for any non-loopback `OBSERVE_PUBLIC_URL`, so browsers only send them over HTTPS.

---

## 🏗️ Architecture

```text
infinity-observe/
├─ crates/
│  ├─ observe-core     # domain models, t-digest/histogram, Argon2id, RBAC
│  ├─ observe-server   # ingest/query/alerts API + embedded dashboard → bin: infinity-observe
│  └─ observe-agent    # lightweight collector/forwarder scaffold
└─ docs/img/           # screenshot targets referenced by this README
```

- **Storage:** SQLite via `sqlx` by default.
- **HTTP:** `axum`, `tower-http`, `hyper`.
- **Dashboard:** static SPA embedded with `rust-embed`.
- **Security model:** separate ingest API keys for telemetry writes; session-cookie auth for dashboard/admin APIs.

---

## 🚀 Quickstart

### Run locally (Rust)

```powershell
Set-Location path\to\infinity-observe
# Leave OBSERVE_ADMIN_PASSWORD unset to auto-generate a strong password on startup,
# or generate one explicitly:
$env:OBSERVE_ADMIN_PASSWORD = [Convert]::ToBase64String((1..24 | ForEach-Object { [byte](Get-Random -Maximum 256) }))
cargo run --bin infinity-observe
```

Open **http://localhost:8090** and sign in with:

- **Email:** `admin@infinity.local`
- **Password:** the value of `OBSERVE_ADMIN_PASSWORD`

If you do not set `OBSERVE_ADMIN_PASSWORD`, the server generates a random admin password and prints it once in the startup logs.

### Verify

```powershell
Invoke-RestMethod http://localhost:8090/health
```

Create or copy an ingest key from **Settings → Create ingest API key**, then ingest:

```powershell
$env:OBSERVE_INGEST_KEY = 'io_...'
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8090/v1/logs `
  -Headers @{ Authorization = "Bearer $env:OBSERVE_INGEST_KEY" } `
  -ContentType 'application/json' `
  -Body '[{"level":"INFO","service":"demo","message":"hello from Infinity Observe"}]'
```

---

## ⚙️ Configuration

Layered: built-in defaults → `Config.toml` → `OBSERVE_*` environment variables.

| Key / Env | Default | Description |
|---|---|---|
| `bind` / `OBSERVE_BIND` | `0.0.0.0:8090` | Listen address. |
| `public_url` / `OBSERVE_PUBLIC_URL` | `http://localhost:8090` | External URL; `https://` enables `Secure` cookies. |
| `database_url` / `OBSERVE_DATABASE_URL` | `sqlite://data/observe.db` | SQLite connection string. |
| `data_dir` / `OBSERVE_DATA_DIR` | `data` | Directory for local DB/data files. |
| `session_ttl_secs` / `OBSERVE_SESSION_TTL_SECS` | `7200` | Dashboard session lifetime. |
| `global_rate_limit_per_min` / `OBSERVE_GLOBAL_RATE_LIMIT_PER_MIN` | `600` | Per-IP request cap per minute (`0` disables). |
| `max_request_body_bytes` / `OBSERVE_MAX_REQUEST_BODY_BYTES` | `1048576` | Maximum JSON body size. |
| `admin_email` / `OBSERVE_ADMIN_EMAIL` | `admin@infinity.local` | Seed admin email on first run. |
| `admin_password` / `OBSERVE_ADMIN_PASSWORD` | generated if unset | Seed admin password on first run (weak/placeholder passwords rejected). |
| `cors_origins` / `OBSERVE_CORS_ORIGINS` | localhost origins | Allowed browser origins. |
| `allow_insecure_webhooks` / `OBSERVE_ALLOW_INSECURE_WEBHOOKS` | `false` | Opt-in to allow `http://` alert webhooks (`https://` only by default). |
| `allow_private_webhooks` / `OBSERVE_ALLOW_PRIVATE_WEBHOOKS` | `false` | Opt-in to allow private/loopback/link-local webhook IPs (blocked by default). |
| `trusted_proxies` / `OBSERVE_TRUSTED_PROXIES` | `[]` | Reverse-proxy IPs/CIDRs allowed to supply `X-Forwarded-For` / `X-Real-IP`. |

---

## API reference

### Public

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Liveness probe. |
| `GET` | `/` | session | Embedded dashboard SPA. |

### Dashboard/session

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | none | Login with `{ "email", "password" }`; sets session cookie. |
| `POST` | `/auth/logout` | session | Revoke current session. |
| `GET` | `/auth/me` | session | Current principal and permissions. |

### Ingest

All ingest endpoints require `Authorization: Bearer <ingest-key>`.

| Method | Path | Body |
|---|---|---|
| `POST` | `/v1/logs` | array of `{ timestamp?, level, service, message, attributes? }` |
| `POST` | `/v1/metrics` | array of `{ timestamp?, name, value, tags? }` |
| `POST` | `/v1/traces` | array of spans with `trace_id`, `span_id`, `name`, `service`, `start`, `end` or `duration_ms` |

### Query/admin

All query/admin endpoints require the dashboard session cookie.

| Method | Path | Permission |
|---|---|---|
| `GET` | `/v1/stats` | `stats:read` |
| `GET` | `/v1/logs` | `logs:read` |
| `GET` | `/v1/metrics/names` | `metrics:read` |
| `GET` | `/v1/metrics/series?name=...` | `metrics:read` |
| `GET` | `/v1/metrics/summary?name=...` | `metrics:read` |
| `GET` | `/v1/traces` | `traces:read` |
| `GET` | `/v1/traces/:trace_id` | `traces:read` |
| `GET` | `/v1/alerts` | `alerts:read` |
| `GET` | `/v1/alerts/rules` | `alerts:read` |
| `POST` | `/v1/alerts/rules` | `alerts:create` (optional SSRF-checked `webhook_url`) |
| `DELETE` | `/v1/alerts/rules/:id` | `alerts:delete` |
| `GET` | `/v1/keys` | `keys:read` |
| `POST` | `/v1/keys` | `keys:create` |
| `DELETE` | `/v1/keys/:id` | `keys:delete` |

---

## 🗺️ Roadmap

- [ ] OTLP/HTTP and OTLP/gRPC compatibility.
- [ ] Parquet/object-storage backend for cold telemetry.
- [ ] DataFusion/Arrow query acceleration.
- [ ] Dashboard-builder and saved views.
- [ ] Distributed rate limiting for multi-node deployments.
- [ ] Native Infinity ID SSO integration.

---

## License

Licensed under **Apache-2.0**.
