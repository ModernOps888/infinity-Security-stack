<div align="center">

# ⚡ Infinity Stream

### Real-time streaming + search, in one Rust binary.

**Append-only commit log · BM25 full-text search · WebSocket pub/sub · Admin dashboard**

A fast, self-hostable alternative to **Kafka/Confluent, Elasticsearch, Algolia and Pusher** — without the JVM overhead, the ops burden, or usage-spike billing.

[![Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

</div>

---

## Why Infinity Stream

Event streaming and search are two of the most expensive, operationally-heavy layers of the stack. Kafka needs a JVM, ZooKeeper/KRaft, and a dedicated ops team. Elasticsearch is famously RAM-hungry. Algolia and Pusher bill aggressively on usage spikes. Infinity Stream folds **durable topics, full-text search, and realtime fan-out** into a single Rust binary you can run anywhere.

> Part of the [**Infinity Stack**](../README.md) — open-source, Rust-native replacements for over-monetized SaaS.

---

## 📸 Dashboard

A modern dark-theme console is embedded in the binary — no separate frontend to deploy.

| Sign in | Overview |
|---|---|
| ![Login](docs/img/login.png) | ![Overview](docs/img/overview.png) |

| Topics | BM25 Search |
|---|---|
| ![Topics](docs/img/topics.png) | ![Search](docs/img/search.png) |

---

## ✨ Features

- **Durable topics** — append-only commit log with partitions, offsets and consumer groups
- **BM25 search** — built-in inverted index (an Elasticsearch/Algolia-style search engine)
- **Realtime pub/sub** — WebSocket subscribe for presence / live fan-out
- **Producer/consumer API** — simple HTTP `produce` / `consume` / `commit`
- **API keys** — scoped keys for producers & consumers (constant-time verified)
- **RBAC + audit** — role-guarded admin, immutable audit trail
- **Secure by design** — Argon2id, session cookies, rate limiting, hardened headers
- **One binary** — SQLite-backed, `cargo run` and you're live

---

## 🔒 Security

| Area | Hardening |
|---|---|
| Passwords | Argon2id (`19456 KiB, t=2, p=1`), 1024-byte length cap, dummy verification against user enumeration, weak/placeholder admin passwords rejected at startup |
| API keys | Stored SHA-256 hashed, **O(1) indexed lookup** with **constant-time** comparison; **least-privilege data-plane scope** (produce/consume/search/create); key-management routes reject API keys; invalid `Bearer` headers never fall back to session cookies |
| Sessions | `HttpOnly` + `SameSite=Strict` cookies (+ `Secure` off loopback via strict URL check), session token rotation on login (fixation prevention), `Cache-Control: no-store` on auth/key responses, expired sessions purged on startup and lookup |
| Access control & CSRF | Strict `resource:action` RBAC guard (no implicit wildcards); `Origin` and `Sec-Fetch-Site` validation on state-changing requests |
| WebSockets | CSWSH protection via strict `Origin` allowlist validation (required for session cookies), topic existence verification, 64 KiB message / 16 KiB frame limits, bounded subscriber semaphore, and lag-backpressure / write-timeout handling |
| Path & commit log safety | Topic / index / group / doc-id validation rejecting traversal, slashes, null bytes, and Windows reserved device names; canonical path & symlink containment checks; CRC32-verified bounded frames and overflow-safe offsets |
| BM25 search | Bounded query bytes (`512`), query tokens (`64`), `k` (`100`), `offset` (`1000`), document nesting depth (`32`), index document cap (`100000`), and finite-score safety |
| Abuse & proxy boundary | Bounded per-account login lockout + bounded per-IP rate limiting that ignores `X-Forwarded-For` unless peer matches `trusted_proxies` |
| Transport & UI | Hardened CSP (`style-src 'self'`, `object-src 'none'`), HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, safe DOM `textContent` rendering in the console, and CLI TLS enforcement off loopback with redirects disabled |
| Errors | Generic client responses; internal errors logged server-side only |
| SQL | Parameterized queries throughout (`sqlx` 0.9) |
| Dependencies | Upgraded to `sqlx` 0.9.1 (`libsqlite3-sys` 0.40.0, resolving RUSTSEC-2026-0459 and removing `rsa` / RUSTSEC-2023-0071 from `Cargo.lock` entirely). `cargo audit` reports **0 active vulnerabilities** and **0 ignored CVEs** (`ignore = []` in `.cargo/audit.toml`, with 1 informational `unmaintained` warning on `chrono` 0.4 tracked for future migration) |

---

## 🏗️ Architecture

```
infinity-stream/
├─ crates/
│  ├─ stream-core     # commit log + BM25 index primitives, config, security
│  ├─ stream-server   # broker + search + WebSocket API + dashboard  → bin: infinity-stream
│  └─ stream-cli      # producer/consumer/admin CLI
└─ migrations/        # SQLite schema
```

---

## 🚀 Quickstart

```bash
cd infinity-stream
STREAM_ADMIN_PASSWORD="$(openssl rand -base64 24)" cargo run --bin infinity-stream
# open http://localhost:8092  (login: admin@infinity.local)
```

If you don't set `STREAM_ADMIN_PASSWORD`, a strong password is generated and printed once. An initial API key is also printed once at first startup.

---

## 📚 API reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET`/`POST` | `/v1/topics` | List / create topics |
| `POST` | `/v1/topics/:name/produce` | Produce records |
| `GET` | `/v1/topics/:name/consume` | Consume from an offset |
| `POST` | `/v1/topics/:name/commit` | Commit a consumer-group offset |
| `GET` | `/v1/topics/:name/subscribe` | WebSocket live subscribe |
| `GET`/`POST` | `/v1/indexes` | List / create search indexes |
| `POST` | `/v1/indexes/:name/docs` | Upsert documents |
| `GET` | `/v1/indexes/:name/search?q=…&k=…` | BM25 search |
| `GET`/`POST` | `/v1/keys` | List / create API keys |

### Produce + search (example)

```bash
# Produce
curl -X POST http://localhost:8092/v1/topics/orders/produce \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"records":[{"key":"o-1","value":{"amount":42.00,"status":"paid"}}]}'

# Index + search
curl -X POST http://localhost:8092/v1/indexes/products/docs \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"docs":[{"id":"p1","text":"rust powered streaming and search"}]}'

curl "http://localhost:8092/v1/indexes/products/search?q=rust&k=5" \
  -H "Authorization: Bearer $API_KEY"
```

---

## 🗺️ Roadmap

- [ ] Kafka wire-protocol compatibility layer
- [ ] Segment compaction + retention policies
- [ ] Distributed replication
- [ ] Phrase / fuzzy search operators
- [ ] Auth & ACLs via **Infinity ID**

---

## License

[Apache-2.0](../LICENSE) © Infinity Stack.

> ⚠️ **Alpha software.** Change default credentials and serve over HTTPS before production use.
