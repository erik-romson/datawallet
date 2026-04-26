ALTER TABLE entries ADD CONSTRAINT entries_version_check CHECK (version >= 1);

CREATE UNIQUE INDEX entries_one_current_per_id ON entries(entry_id) WHERE is_current;
