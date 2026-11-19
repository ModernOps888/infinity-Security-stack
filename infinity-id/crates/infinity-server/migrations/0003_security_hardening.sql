-- Security hardening schema additions:
-- 1) Refresh token family tracking so reuse detection revokes only the
--    compromised token family (while falling back cleanly for legacy rows).
-- 2) Expiry indexes for efficient purge of stale auth codes and sessions.
ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT;
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
