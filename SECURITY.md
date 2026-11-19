# Security Policy

## Supported Versions

Infinity Stack is currently pre-1.0 (`0.1.0` alpha) across all four workspaces. Security fixes are applied to the `main` branch.

| Component | Path | Version / Branch | Rust MSRV | Security Support |
|---|---|---|---|---|
| Infinity ID & Edge | `infinity-id/` | `0.1.0` (`main`) | `1.94.0` | Active |
| Infinity Observe & Agent | `infinity-observe/` | `0.1.0` (`main`) | `1.94.0` | Active |
| Infinity Data & CLI | `infinity-data/` | `0.1.0` (`main`) | `1.94.0` | Active |
| Infinity Stream & CLI | `infinity-stream/` | `0.1.0` (`main`) | `1.94.0` | Active |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues, pull requests, or discussions.**

Report vulnerabilities privately through GitHub Security Advisories:

- **Private Advisory Form:** <https://github.com/ModernOps888/infinity-Security-stack/security/advisories/new>

When submitting a report, please include:

1. Affected service (`infinity-id`, `infinity-observe`, `infinity-data`, `infinity-stream`, or CI/build tooling) and commit SHA.
2. Impact assessment and attack prerequisites (e.g., unauthenticated remote, authenticated role, SSRF/XSS/OIDC bypass, local file access).
3. Minimal proof-of-concept steps, HTTP requests, or unit/integration test reproduction.

**Response targets:**
- Acknowledgement within **48 hours**.
- Triage and severity assessment within **5 business days**.
- Coordinated remediation and advisory publication once a fix is verified on `main`.

---

## Security Architecture Summary

All four services share hardened defaults with zero paywalled security controls:

- **Authentication & Password Hardening:** Argon2id (`19456 KiB` / `19 MiB`, `t=2`, `p=1`, `Algorithm::Argon2id` pinned on verify), length caps against hashing DoS, constant-time dummy Argon2id verification on unknown users to prevent account enumeration, disabled-account status checked only after password verification, and startup rejection of weak/default/placeholder bootstrap admin passwords (with CSPRNG auto-generation when unset).
- **Sessions & CSRF Defense:** Cryptographically random opaque session tokens stored SHA-256 hashed at rest, `HttpOnly` + `SameSite=Strict` cookies (+ `Secure` enforced by default on HTTPS and off loopback: `localhost`, `127.0.0.1`, `[::1]`, `::1` in `infinity-id`, and `localhost`, `127.0.0.0/8`, `::1` in `infinity-data`, `infinity-observe`, and `infinity-stream`), `7200s` (2-hour) default TTL, expired session purging at startup and lookup, session rotation/invalidation on login and MFA elevation (anti-fixation), `Cache-Control: no-store` on auth/token/admin responses, and `Origin` / `Sec-Fetch-Site` validation (plus double-submit CSRF tokens in `infinity-id`).
- **Authorization & API Keys:** Strict `resource:action` RBAC enforcement (no implicit wildcard coercion), privilege-escalation guards (`superadmin` protection and callers restricted to permissions they already hold), and O(1) indexed SHA-256 API-key lookup verified in constant time (invalid `Authorization` headers never fall back to session cookies).
- **OIDC / OAuth2, MFA & Edge (`infinity-id`):** Mandatory PKCE (`S256` only; `plain` rejected), exact `redirect_uri` validation (blocking wildcards, fragments, CRLF, userinfo, and unsafe schemes), atomic single-use authorization codes bound to `client_id` + `redirect_uri`, refresh-token family rotation with reuse detection, pinned `RS256` + `kid` JWT validation (`exp`, `nbf`, `iss`, `aud`), `0600` signing-key persistence with zeroization on drop and live JWKS rotation, RFC 6238 TOTP MFA with atomic replay protection (`mfa_last_step`) and step-up disable checks, and an edge proxy stripping hop-by-hop/forged identity headers while blocking SSRF and path traversal.
- **Service-Specific Defenses:**
  - `infinity-observe`: SSRF-hardened alert webhooks (HTTPS default, private/CGNAT/link-local/metadata IP blocking, pre-connect DNS pinning, redirects disabled), `LIKE ... ESCAPE '\'` SQL escaping, bounded ingest cardinality, and CRLF/bidi control-character sanitization.
  - `infinity-data`: Declared-column and `[A-Za-z0-9_-]` identifier allowlists, `NaN`/`Infinity` rejection across HNSW vectors and aggregations, and strict bounds on vector dimensions, `top_k`, `ef_search`, collection sizes, and transactional table row caps.
  - `infinity-stream`: Canonical path and symlink containment with Windows reserved device name blocking, CRC32-verified bounded CommitLog frames, CSWSH `Origin`-validated WebSockets with backpressure and size limits, and bounded BM25 queries/indexes.
  - **CLI & Agent Clients:** Non-loopback `https://` enforcement (`--allow-insecure-http` explicit opt-in), disabled redirects, timeouts, and redacted secret `Debug` output.
- **Transport, Proxy Trust & Abuse Controls:** Strict CSP (`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` in `infinity-id`; `default-src 'self'` with `object-src 'none'`, `img-src 'self' data:`, and `connect-src 'self'` [plus `ws: wss:` for WebSockets in `infinity-stream`] in `infinity-data`, `infinity-observe`, and `infinity-stream`), HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `1 MiB` request body limits, memory-bounded login throttling and global per-IP rate limiting, and explicit `trusted_proxies` CIDRs required before honoring `X-Forwarded-For`.
- **CI/CD & Repo Hygiene:** Least-privilege `permissions: { contents: read }`, SHA-pinned GitHub Actions, automated `cargo fmt --check` / `check` / `test` / `clippy -- -D warnings` / `cargo audit` matrix, weekly Dependabot updates, `.gitleaks.toml`, and an automated CI hygiene check for BOMs, secrets, PII paths, emails, PNG metadata, and unpinned Actions.

---

## Dependency Audit & Accepted-Risk Ledger

Every workspace configures `.cargo/audit.toml` with **`ignore = []`** (**0 active CVEs, 0 ignored CVEs**).

| Advisory / Crate | Status | Scope | Details & Verification |
|---|---|---|---|
| `RUSTSEC-2026-0459` (`libsqlite3-sys < 0.39.0`) | **Resolved** | All 4 workspaces | Upgraded `sqlx` `0.8` → `0.9` (`0.9.1`), resolving `libsqlite3-sys` to `0.40.0`. |
| `RUSTSEC-2023-0071` (`rsa < 0.10.0`) | **Resolved** | All 4 workspaces | `infinity-id` upgraded `rsa` `0.9` → `0.10` (`0.10.0`). In `infinity-data`, `infinity-observe`, and `infinity-stream`, upgrading to `sqlx` `0.9` removed `rsa` from `Cargo.lock` entirely (`cargo tree -i rsa` matches no packages). |
| `RUSTSEC-2026-0258`, `RUSTSEC-2026-0381`, `RUSTSEC-2026-0382`, `RUSTSEC-2026-0538`, `quinn-*` / `rustls` | **Resolved** | All 4 workspaces | Remediated via SemVer `cargo update` (`h2`, `rustls`, `rustls-webpki`, `webpki-roots`, `quinn-proto`, `quinn-udp`, `tokio`, `event-listener`, `chacha20`). |
| `RUSTSEC-2026-0543` (`chrono 0.4`) | **Tracked (Informational)** | All 4 workspaces | Non-vulnerability `unmaintained` advisory (`chrono 0.4.45`, pinned by `sqlx` `0.9` `chrono` feature). No CVE; `cargo audit` exits `0` with 1 allowed warning. Tracked for future migration to `time` / `jiff`. |
