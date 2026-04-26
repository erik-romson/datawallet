# Add a Flyway migration

Migrations are append-only. Once a migration file is applied to any
environment you must never edit it — Flyway records each file's checksum
and will refuse to start if a previously-applied file changes. New
behaviour always lives in a new file: `V<n>__name.sql`.

## Steps

1. **Pick the next migration number.** List
   `src/main/resources/db/migration/` and increment the highest `V<n>`
   prefix. The current highest is
   [`V7__pinned_root_history.sql`](../../src/main/resources/db/migration/V7__pinned_root_history.sql),
   so the next file is `V8__<name>.sql`.

2. **Name the file descriptively.** Use snake_case for the descriptive
   part: `V8__add_entry_expires_at.sql`. The name must describe what the
   migration does, not when it was written.

3. **Place it under `src/main/resources/db/migration/`.** Flyway scans
   that directory automatically on startup.

4. **Land constraints and data together.** If the migration adds a
   `NOT NULL` column or a `UNIQUE` constraint, the data being inserted by
   current application code must already satisfy it. When possible, add
   both the data change and the constraint in the same migration file.
   See
   [`V4__entries_constraints.sql`](../../src/main/resources/db/migration/V4__entries_constraints.sql)
   for an example of constraints added after the table already exists.

5. **Respect the two-role convention.** Grant DML (`SELECT`, `INSERT`,
   `UPDATE`, `DELETE`) to `wallet_app`. Grant DDL and admin reads to
   `wallet_admin`. See
   [`V7__pinned_root_history.sql`](../../src/main/resources/db/migration/V7__pinned_root_history.sql#L7-L10)
   for the canonical GRANT pattern.

6. **Run integration tests.** Testcontainers starts a fresh Postgres
   instance and replays every migration in version order. A broken
   migration will fail the entire test run immediately.

   ```sh
   # src/main/resources/db/migration/V8__add_entry_expires_at.sql
   mvn verify
   ```

## Don't

- Edit an already-applied migration. Flyway's checksum guard will reject
  the application on next start.
- Use `IF EXISTS` or `IF NOT EXISTS` to make a migration idempotent.
  Flyway runs each version exactly once; guards like these obscure bugs
  and hide schema drift.
- Create a `V<n>__rollback.sql`. Flyway is forward-only in this project.
  If a column needs to be removed, add a higher-numbered migration that
  drops it.

## See also

- [Add an HTTP endpoint](add-an-endpoint.md)
- [`specs/plan.md`](../specs/plan.md) — design rationale including the
  two-role Postgres model
