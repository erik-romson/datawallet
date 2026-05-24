-- V10__verifiers_discoverable.sql: opt-in verifier discovery for recipient picklist

ALTER TABLE verifiers ADD COLUMN discoverable BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE verifiers ADD CONSTRAINT verifiers_discoverable_needs_name
    CHECK (NOT discoverable OR display_name IS NOT NULL);

CREATE INDEX idx_verifiers_discoverable_order
    ON verifiers (created_at DESC, verifier_id DESC)
    WHERE discoverable AND status = 'active';
