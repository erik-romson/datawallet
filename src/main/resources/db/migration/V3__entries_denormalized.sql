ALTER TABLE entries
    ADD COLUMN issuer_label            TEXT,
    ADD COLUMN issuer_signing_key_id   BYTEA,
    ADD COLUMN description             TEXT;

CREATE INDEX idx_entries_current_created ON entries (is_current, created_at DESC, entry_id DESC);
