## Summary

- **Wire format changed?** Update `docs/specs/api.md`. If byte layouts changed,
  regenerate fixtures via `spec/tools/gen.py`
  (see `docs/how-to/regenerate-fixtures.md`).
- **Behaviour or flow changed?** Update the relevant mermaid diagram under
  `docs/explanation/` or the relevant tutorial under `docs/tutorials/`.
- **New endpoint?** Add the row to `docs/reference/http-api.md`.
- **New CLI command?** Add the row to `docs/reference/cli.md`.
- **New migration?** Confirm append-only: no edits to previously applied
  migrations, new file only (`V<n>__name.sql`).
- **Crypto invariants:** libsodium only; no `java.security.SecureRandom`;
  no re-serialising signed payloads server-side.

## Test plan

- [ ] `bash bin/test-all.sh` passes locally.
