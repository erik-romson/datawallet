-- V1__init.sql: initial schema per plan.md §4.5

CREATE TABLE verifiers (
    verifier_id        UUID         NOT NULL PRIMARY KEY,
    handle             VARCHAR(64)  NOT NULL UNIQUE,
    display_name       VARCHAR(64),
    enc_public_key     BYTEA        NOT NULL,
    enc_key_id         BYTEA        NOT NULL,
    auth_public_key    BYTEA        NOT NULL,
    auth_key_id        BYTEA        NOT NULL,
    wrapped_enc_private_key_blob  BYTEA  NOT NULL,
    wrapped_auth_private_key_blob BYTEA  NOT NULL,
    kdf_salt           BYTEA        NOT NULL,
    kdf_params         JSONB        NOT NULL,
    status             VARCHAR(32)  NOT NULL DEFAULT 'active',
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE entries (
    entry_id           UUID         NOT NULL,
    version            INT          NOT NULL,
    issuer_id          UUID         NOT NULL,
    is_current         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ  NOT NULL,
    superseded_at      TIMESTAMPTZ,
    signed_envelope    BYTEA        NOT NULL,
    ciphertext_hash    BYTEA        NOT NULL,
    PRIMARY KEY (entry_id, version)
);
CREATE INDEX idx_entries_issuer_entry ON entries (issuer_id, entry_id);

CREATE TABLE entry_recipients (
    entry_id           UUID         NOT NULL,
    version            INT          NOT NULL,
    verifier_id        UUID         NOT NULL,
    verifier_key_id    BYTEA        NOT NULL,
    PRIMARY KEY (entry_id, version, verifier_id),
    FOREIGN KEY (entry_id, version) REFERENCES entries (entry_id, version) ON DELETE CASCADE
);
CREATE INDEX idx_entry_recipients_verifier ON entry_recipients (verifier_id);

CREATE TABLE directory_records (
    record_type        VARCHAR(32)  NOT NULL,
    subject_id         UUID         NOT NULL,
    key_id             BYTEA        NOT NULL,
    status             VARCHAR(32)  NOT NULL,
    valid_from         TIMESTAMPTZ  NOT NULL,
    valid_until        TIMESTAMPTZ  NOT NULL,
    issued_at          TIMESTAMPTZ  NOT NULL,
    root_key_id        BYTEA        NOT NULL,
    signed_record      BYTEA        NOT NULL,
    PRIMARY KEY (record_type, subject_id, key_id)
);
CREATE INDEX idx_directory_records_lookup ON directory_records (subject_id, status, valid_from, valid_until);

CREATE TABLE sessions (
    token_id           BYTEA        NOT NULL PRIMARY KEY,
    verifier_id        UUID         NOT NULL,
    issued_at          TIMESTAMPTZ  NOT NULL,
    expires_at         TIMESTAMPTZ  NOT NULL,
    revoked_at         TIMESTAMPTZ
);
CREATE INDEX idx_sessions_verifier ON sessions (verifier_id);

CREATE TABLE audit_log (
    seq                BIGSERIAL    PRIMARY KEY,
    ts                 TIMESTAMPTZ  NOT NULL DEFAULT now(),
    event_type         TEXT         NOT NULL,
    actor_id           UUID,
    entry_id           UUID,
    payload            JSONB,
    prev_hash          BYTEA,
    hash               BYTEA
);

CREATE TABLE auth_challenges (
    verifier_id        UUID         NOT NULL,
    nonce              BYTEA        NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ  NOT NULL,
    consumed_at        TIMESTAMPTZ,
    PRIMARY KEY (verifier_id, nonce)
);

CREATE TABLE auth_lockouts (
    verifier_id        UUID         NOT NULL PRIMARY KEY,
    consecutive_failures INT        NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE rate_limits (
    key                TEXT         NOT NULL PRIMARY KEY,
    tokens             DOUBLE PRECISION NOT NULL,
    refilled_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Append-only trigger for audit_log
CREATE OR REPLACE FUNCTION audit_log_block_mutate() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update_or_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutate();

-- Roles (IF NOT EXISTS for idempotent re-runs)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wallet_app') THEN
        CREATE ROLE wallet_app WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'wallet_admin') THEN
        CREATE ROLE wallet_admin WITH LOGIN;
    END IF;
END
$$;

-- wallet_app: DML on operational tables, INSERT+SELECT on audit_log
GRANT SELECT, INSERT, UPDATE, DELETE ON verifiers TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON entries TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON entry_recipients TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON directory_records TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_challenges TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_lockouts TO wallet_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO wallet_app;
GRANT INSERT, SELECT ON audit_log TO wallet_app;
GRANT USAGE, SELECT ON SEQUENCE audit_log_seq_seq TO wallet_app;

-- wallet_admin: full access for migrations and admin reads
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO wallet_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO wallet_admin;
