-- V9__directory_records_revoked_at.sql: revocation timestamp for audit + pagination

ALTER TABLE directory_records ADD COLUMN revoked_at TIMESTAMPTZ NULL;

-- Grant same privileges as existing directory_records grants
GRANT SELECT, INSERT, UPDATE, DELETE ON directory_records TO wallet_app;
GRANT ALL PRIVILEGES ON directory_records TO wallet_admin;
