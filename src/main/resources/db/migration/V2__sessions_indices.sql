CREATE INDEX idx_sessions_verifier_expires ON sessions (verifier_id, expires_at);
