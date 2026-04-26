-- Belt-and-suspenders: explicitly restrict wallet_app to INSERT and SELECT on audit_log.
-- V1 already grants only INSERT, SELECT, and the append-only trigger blocks all mutations
-- regardless of role. This migration makes the intent unambiguous and robust against
-- future privilege changes.
REVOKE UPDATE, DELETE ON audit_log FROM wallet_app;
GRANT INSERT, SELECT ON audit_log TO wallet_app;
