-- Optional webhook target on alert rules (SSRF-validated at creation and dispatch).
ALTER TABLE alert_rules ADD COLUMN webhook_url TEXT;
