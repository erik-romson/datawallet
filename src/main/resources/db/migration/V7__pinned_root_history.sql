CREATE TABLE pinned_root_history (
    id             BIGSERIAL    PRIMARY KEY,
    applied_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    pinned_root_cbor BYTEA      NOT NULL
);

GRANT SELECT, INSERT ON pinned_root_history TO wallet_app;
GRANT USAGE, SELECT ON SEQUENCE pinned_root_history_id_seq TO wallet_app;
GRANT ALL PRIVILEGES ON pinned_root_history TO wallet_admin;
GRANT ALL PRIVILEGES ON SEQUENCE pinned_root_history_id_seq TO wallet_admin;
