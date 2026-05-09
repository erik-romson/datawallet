-- V8__directory_record_chain.sql: parent-signature chain support

-- Add parent_key_id column (NULL = root-signed, non-NULL = intermediate-signed)
ALTER TABLE directory_records ADD COLUMN parent_key_id BYTEA NULL;

-- Allow record_type 'intermediate' and enforce the full enum
DO $$
BEGIN
    -- Drop existing record_type CHECK if present (V1 did not add one, but guard anyway)
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'directory_records'
          AND constraint_name = 'directory_records_record_type_chk'
    ) THEN
        ALTER TABLE directory_records DROP CONSTRAINT directory_records_record_type_chk;
    END IF;
END
$$;
ALTER TABLE directory_records ADD CONSTRAINT directory_records_record_type_chk
    CHECK (record_type IN ('verifier', 'issuer', 'intermediate'));

-- Index for parent chain lookups
CREATE INDEX idx_directory_records_parent ON directory_records (parent_key_id)
    WHERE parent_key_id IS NOT NULL;

-- Relax root_key_id to nullable (NULL when record is intermediate-signed)
ALTER TABLE directory_records ALTER COLUMN root_key_id DROP NOT NULL;

-- DB-layer XOR: exactly one of (root_key_id, parent_key_id) must be non-NULL
ALTER TABLE directory_records ADD CONSTRAINT directory_records_signer_xor
    CHECK ((parent_key_id IS NULL) <> (root_key_id IS NULL));

-- Grant same privileges as existing directory_records grants
GRANT SELECT, INSERT, UPDATE, DELETE ON directory_records TO wallet_app;
GRANT ALL PRIVILEGES ON directory_records TO wallet_admin;
