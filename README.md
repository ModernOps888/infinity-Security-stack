<div align="center">

# ∞ Infinity Stack

### Open-source, Rust-native replacements for over-monetized SaaS infrastructure.

Predictable performance. Memory safety. No GC pauses. Self-hostable. No per-seat tax.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-000000?logo=rust)](https://www.rust-lang.org/)
[![CI](https://github.com/ModernOps888/infinity-Security-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/ModernOps888/infinity-Security-stack/actions/workflows/ci.yml)

</div>

---

Rust's memory safety, C-like performance, and lack of garbage collection (predictable tail latency) make it the ideal tool to commoditize expensive cloud infrastructure. Infinity Stack spans four heavily-monopolized verticals — **identity, observability, data, and streaming** — each a self-hostable, security-hardened Rust service with an embedded admin dashboard.

## The products

| Product | Replaces | Status |
|---|---|---|
| **[∞ Infinity ID](./infinity-id/)** | Auth0 · Okta · OneLogin · Clerk | 🟢 **Flagship — runnable, hardened** |
| [Infinity Observe](./infinity-observe/) | Datadog · Splunk · New Relic · Sentry | 🟢 Runnable · hardened (alpha) |
| [Infinity Data](./infinity-data/) | Snowflake · Databricks · Pinecone | 🟢 Runnable · hardened (alpha) |
| [Infinity Stream](./infinity-stream/) | Kafka/Confluent · Elasticsearch · Algolia | 🟢 Runnable · hardened (alpha) |

Every service ships hardened by default — Argon2id (`19 MiB, t=2, p=1`) password storage with weak/placeholder bootstrap password rejection (CSPRNG generation when unset), opaque server-side sessions with `HttpOnly`/`SameSite=Strict` (+ `Secure` on HTTPS / off loopback) cookies, anti-fixation session rotation, and a **2-hour default TTL (`7200s`)**, strict `resource:action` RBAC, O(1) indexed SHA-256 API-key auth with constant-time confirmation in Observe/Data/Stream (and RS256 JWTs + constant-time hashed client secrets in Infinity ID), memory-bounded per-account lockout + per-IP rate limiting (with `trusted_proxies` `X-Forwarded-For` boundaries), CSRF `Origin`/`Sec-Fetch-Site` guards, hardened HTTP security headers (strict CSP without `'unsafe-inline'`, HSTS, `DENY`, `nosniff`, `Cache-Control: no-store`), and parameterized `sqlx` SQL.

All four workspaces are upgraded to `sqlx` `0.9` (`libsqlite3-sys >= 0.39.0`, fixing `RUSTSEC-2026-0459`), `Infinity ID` uses `rsa` `0.10` (`RUSTSEC-2023-0071` resolved) with `0600` key persistence and live JWKS rotation, and `Observe`/`Data`/`Stream` carry zero `rsa` dependencies in `Cargo.lock`. Every service's `.cargo/audit.toml` specifies `ignore = []` with **0 active CVEs and 0 ignored CVEs** in `cargo audit` (one informational `unmaintained` warning, `RUSTSEC-2026-0543` on `chrono` `0.4`, is tracked in [`SECURITY.md`](./SECURITY.md)). GitHub Actions CI enforces `cargo fmt --check`, `cargo check`, `cargo test`, `cargo clippy -- -D warnings`, `cargo audit`, and automated PII/secret/BOM/action-pin hygiene checks across all four workspaces.

See [`SECURITY.md`](./SECURITY.md) for the security architecture summary, vulnerability disclosure policy, and dependency audit ledger.

---

## ⭐ Infinity ID — the flagship

A secure-by-design IAM platform in a single fast binary: **OpenID Connect, OAuth 2.0, TOTP MFA, RBAC, an auth-aware edge gateway, and an embedded admin dashboard** — with every security feature included (no "SSO tax").

![Infinity ID dashboard](./infinity-id/docs/img/overview.png)

```bash
cd infinity-id
INFINITY_ADMIN_PASSWORD="$(openssl rand -base64 24)" cargo run --bin infinity-id
# open http://localhost:8080
```

👉 **See the full [Infinity ID README](./infinity-id/) for features, security model, API reference, and Docker deployment.**

---

## Design principles

- **Secure by design** — hardened defaults, not security-as-an-upsell.
- **Single binary, self-hostable** — SQLite for local, object storage / Postgres for scale.
- **Cost transparency** — your bill scales with hardware, not a vendor's margin.
- **All Rust** — safety and predictable latency without a garbage collector.

## Repository layout

```
infinity-Security-stack/
├─ infinity-id/         # identity + OAuth2/OIDC + edge gateway + dashboard (flagship)
├─ infinity-observe/    # observability — logs, metrics, traces, alerts + dashboard
├─ infinity-data/       # vector DB + analytics tables + dashboard
└─ infinity-stream/     # durable topics + BM25 search + dashboard
```

## License

[Apache-2.0](./LICENSE) © Infinity Stack.
