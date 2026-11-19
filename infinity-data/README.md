<div align="center">

# 🧠 Infinity Data

### Analytics + vector search, in one Rust binary.

**Vector collections (HNSW) · similarity search · tables · RBAC · admin dashboard**

A self-hostable alternative to **Snowflake, Databricks and Pinecone** — memory-safe, SQLite-simple, no per-credit billing.

[![Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

</div>

---

## Why Infinity Data

Data warehouses lock you in and bill exponentially for compute; managed vector databases are memory-bound and expensive at scale. Infinity Data gives you **vector similarity search (HNSW)** and simple **tabular analytics** behind one authenticated Rust binary you can run on a laptop or a cloud box.

> Part of the [**Infinity Stack**](../README.md) — open-source, Rust-native replacements for over-monetized SaaS.

---

## 📸 Dashboard

An embedded dark-theme admin console — no separate frontend to deploy.

| Sign in | Overview |
|---|---|
| ![Login](docs/img/login.png) | ![Overview](docs/img/overview.png) |

| Collections | Vector Search |
|---|---|
| ![Collections](docs/img/collections.png) | ![Search](docs/img/search.png) |

---

## ✨ Features

- **Vector collections** — create collections with a fixed dimension + distance metric (cosine / L2)
- **HNSW index** — fast approximate nearest-neighbour search
- **Similarity search** — top-k search with scores + metadata
- **Tables** — simple tabular storage + query for analytics
- **API keys** — scoped keys for programmatic ingest/query (constant-time verified)
- **RBAC + audit** — role-guarded admin, immutable audit trail
- **Secure by design** — Argon2id, sessions, rate limiting, hardened headers
- **One binary** — SQLite-backed; `cargo run` and you're live

---

## 🔒 Security

| Area | Hardening |
|---|---|
| Passwords | Argon2id (`m=19456, t=2, p=1`), 12-character minimum; weak/default/placeholder admin passwords rejected |
| API keys | Stored SHA-256 hashed, **O(1) indexed prefix lookup** (`idx_api_keys_prefix`) with **constant-time** comparison; scoped to data/collections/tables; invalid `Bearer` headers never fall back to cookies |
| Sessions | `HttpOnly` + `SameSite=Strict` cookies (+ `Secure` by default off exact loopback origins `localhost`/`127.*`/`[::1]`), server-side revocation on logout and account disable, session rotation/revocation on login (anti-fixation), 2-hour default TTL (`session_ttl_secs = 7200`), expired sessions purged at startup and on lookup |
| Access control | RBAC guard on admin + write/read paths; no unauthenticated data access |
| Privilege escalation | Callers may only assign roles / grant permissions they already hold; `superadmin` role and `superadmin` / higher-privileged accounts cannot be modified, disabled, or deleted by non-superadmins; existing roles holding unheld permissions cannot be overwritten |
| Account enumeration | Uniform `401` login errors; constant-time dummy Argon2id verification on unknown/malformed email; disabled-account status checked only **after** password verification |
| Input & DoS bounds | Strict identifier allowlists (`[A-Za-z0-9_-]`) + declared-column enforcement on table queries; `NaN`/`Infinity` rejected in vector insert/search/aggregation; bounded dimensions (`<= 4096`), `k` (`1..=100`), `ef` (`<= 4096`), collection vectors (`50,000` default), table rows (`100,000` default), query rows (`1000`), and `1 MiB` request body limit |
| Output encoding | Dashboard renders dynamic values with DOM `textContent` and URL-encodes collection path segments (`encodeURIComponent`) |
| Abuse & proxy trust | Per-account + per-IP login lockout, global per-IP rate limiting, bounded maps (`100,000` entries), and `X-Forwarded-For` ignored unless the TCP peer matches `trusted_proxies` |
| Transport & CSRF | Strict CSP (`script-src 'self'`, `style-src 'self'`, `object-src 'none'`), HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cache-Control: no-store` on API/auth/admin routes, and `Origin` checks on state-changing requests |
| CLI safety | `infinity-data-cli` enforces `https://` off loopback (unless `--allow-insecure-http`), disables redirects, validates collection segments, supports `DATA_PASSWORD`/stdin login, and redacts session cookies |
| Errors & SQL | Parameterized `sqlx` queries throughout; generic client error responses (`409` on conflicts; `500` details logged server-side only) |

> **Dependency hardening (`cargo audit`):** `sqlx` was upgraded `0.8` → `0.9` (`libsqlite3-sys` `0.40.0`, fixing RUSTSEC-2026-0459 / CVE-2026-119375) alongside SemVer updates (`quinn-proto`, `quinn-udp`, `rustls`, `rustls-webpki`, `webpki-roots`, `tokio`, `event-listener`, `chacha20`). Upgrading to `sqlx 0.9` also removed the unused transitive `rsa` entry (`RUSTSEC-2023-0071`) from `Cargo.lock` entirely (confirmed via `cargo tree -i rsa`, which reports no `rsa` package in the workspace graph). `.cargo/audit.toml` uses `ignore = []`, and `cargo audit` passes with **0 vulnerabilities** (and 1 informational `chrono 0.4` unmaintained warning, RUSTSEC-2026-0543).

---

## 🏗️ Architecture

```
infinity-data/
├─ crates/
│  ├─ data-core     # HNSW index, aggregation, model, password/RBAC/identifier security
│  ├─ data-server   # REST API + dashboard  → bin: infinity-data
│  └─ data-cli      # client / admin CLI     → bin: infinity-data-cli
└─ crates/data-server/migrations/   # SQLite schema + security indexes
```

---

## 🚀 Quickstart

```bash
cd infinity-data
DATA_ADMIN_PASSWORD="$(openssl rand -base64 24)Aa1!" cargo run --bin infinity-data
# open http://localhost:8094  (login: admin@infinity.local)
```

If you don't set `DATA_ADMIN_PASSWORD`, a strong password is generated and printed once. An initial API key is also printed once at first startup.

Default limits and security settings (`Config.toml` / `DATA_*` env): `session_ttl_secs = 7200`, `global_rate_limit_per_min = 600`, `max_vectors_per_collection = 50000`, `max_rows_per_table = 100000`, `trusted_proxies = []`.

---

## 📚 API reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/api/stats` | Collection / vector / table counts |
| `GET`/`POST` | `/api/collections` | List / create vector collections |
| `GET`/`DELETE` | `/api/collections/:name` | Get / delete a collection |
| `POST` | `/api/collections/:name/vectors` | Upsert vectors |
| `POST` | `/api/collections/:name/search` | k-NN similarity search |
| `GET`/`POST` | `/api/tables` | List / create tables |
| `POST` | `/api/tables/:name/rows` | Insert rows |
| `POST` | `/api/tables/:name/query` | Query rows |
| `GET`/`POST`/`DELETE` | `/admin/api-keys` | Manage API keys |
| `GET` | `/admin/audit` | Audit log |

### Vector upsert + search (example)

```bash
# Create a collection (dim 8, cosine)
curl -X POST http://localhost:8094/api/collections \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"products","dim":8,"metric":"cosine"}'

# Upsert vectors
curl -X POST http://localhost:8094/api/collections/products/vectors \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"points":[{"id":"p1","vector":[0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8],"metadata":{"text":"rust vector db"}}]}'

# Search
curl -X POST http://localhost:8094/api/collections/products/search \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"vector":[0.12,0.44,0.9,0.33,0.7,0.15,0.6,0.05],"k":5}'
```

---

## 🗺️ Roadmap

- [ ] SQL front-end + cost-based optimizer
- [ ] Object-storage (S3) columnar backend
- [ ] Disk-spilling HNSW for billion-scale
- [ ] Distributed coordination
- [ ] Auth & RBAC via **Infinity ID**

---

## License

[Apache-2.0](../LICENSE) © Infinity Stack.

> ⚠️ **Alpha software.** Change default credentials and serve over HTTPS before production use.
