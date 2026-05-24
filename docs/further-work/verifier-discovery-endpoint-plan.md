# Plan: `GET /v1/verifiers` — verifier discovery (recipient picklist)

> Status: **DRAFT.** Adds a paginated, public, opt-in list of verifiers so a client
> (the egnedata app, via its backend) can let a user pick a recipient before sharing
> data. Companion to the egnedata "Share data" feature; the egnedata side is planned
> in `egnedata-kmp/tmp/shared-data-plan.md`.

## Why this is needed

Today datawallet has **no "list verifiers" endpoint** on purpose: the only verifier
lookup is `GET /v1/directory/verifiers/{handle}` (by exact handle) and
`GET /v1/verifiers/{handle}/login-blob`. This is deliberate enumeration-resistance —
you must already know a handle. The egnedata use case needs the opposite: *show the
user the verifiers they can send to.* So we add a discovery endpoint, but gate it on an
explicit opt-in so we don't turn the whole verifier table into a public directory.

## Core design decision: opt-in `discoverable` flag

Adding "list everyone" would reverse the existing privacy posture (handles are only
disclosed to someone who already knows them). Instead:

- New column `verifiers.discoverable BOOLEAN NOT NULL DEFAULT false`.
- `GET /v1/verifiers` returns **only** `discoverable = true AND status = 'active'`.
- A verifier opts in either at registration (new optional `discoverable` field, default
  `false`) or via operator/admin toggle. Default-false means existing rows and silent
  registrations never leak.

This keeps the "must opt in to be found" property while enabling the picklist.

## Trust boundary (do not skip)

The list is a **UX/discovery convenience, not a trust anchor.** The encryption key used
to seal data to a recipient MUST come from the root-quorum-verified directory record
(`GET /v1/directory/verifiers/{handle}` → verify against pinned roots, per
`crypto-formats.md §6–7`). The list response therefore carries identity + a *display*
fingerprint only; the consumer still fetches and verifies the directory record before
encrypting. Stated explicitly in the response DTO doc so no client treats list bytes as
authoritative.

## Endpoint

| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/v1/verifiers` | none (public, rate-limited by IP) | `VerifierList` (JSON, paginated) |

Auth = none, mirroring the other public read surfaces (`GET /v1/directory/**`,
`GET /v1/verifiers/{handle}/login-blob`). In architecture B the egnedata **backend**
calls this (and may cache it); it could also be called by the app directly. Either way
the contract is the same.

Query params (mirror `GET /v1/shared`, `api.md §3.5/§7`):
- `cursor=<opaque>` — server-issued, encodes `(created_at, verifier_id)`.
- `since=<RFC3339>` — only verifiers with `created_at ≥ since`.
- `limit=<1..100>` — default 50.
- Mixing `since` + `cursor` → `400 schema_violation` (same rule as `/shared`).
- **No** free-text search/filter — out of scope per `CLAUDE.md` ("server-side
  search/filter beyond `since`+cursor").

Order: `created_at DESC, verifier_id DESC` (stable for cursoring).

```jsonc
// VerifierList
{
  "items": [
    {
      "verifier_id": "<uuid>",
      "handle": "alice",
      "display_name": "Alice",            // non-null for discoverable verifiers (DB CHECK)
      "enc_key_id": "<b64url 16 bytes>",  // which enc key the directory record will carry
      "key_fingerprint": "JBSW-Y3DP-EHPK-3PXP", // crypto-formats.md §8 over enc_public_key — DISPLAY ONLY
      "created_at": "2026-04-25T08:30:00Z"
    }
  ],
  "next_cursor": "<opaque>"  // null when exhausted
}
```

`enc_public_key` is intentionally **not** returned — forcing the consumer through the
verified directory path removes any temptation to seal against the list. `key_fingerprint`
lets the UI show/confirm the same fingerprint the user would verify out-of-band.

## Implementation steps

1. **Migration `V10__verifiers_discoverable.sql`** (append-only):
   - `ALTER TABLE verifiers ADD COLUMN discoverable BOOLEAN NOT NULL DEFAULT false;`
   - **Require a display name when discoverable** (decided — open Q3): add a CHECK so a blank
     picklist row is impossible:
     `ALTER TABLE verifiers ADD CONSTRAINT verifiers_discoverable_needs_name CHECK (NOT discoverable OR display_name IS NOT NULL);`
     Add it in this same migration; existing rows are all `discoverable=false`, so the constraint
     holds on current data.
   - Partial index for the list query:
     `CREATE INDEX idx_verifiers_discoverable_order ON verifiers (created_at DESC, verifier_id DESC) WHERE discoverable AND status = 'active';`
   - Grants: the column/index is covered by the existing table-level grant
     `GRANT SELECT, INSERT, UPDATE, DELETE ON verifiers TO wallet_app` in `V1__init.sql:121`
     (not `V6`); no new grant needed.

2. **Entity** `domain/VerifierEntity.java`: add `boolean discoverable` field mapped to the
   new column.

3. **Repository** `domain/VerifierRepository.java`: add cursor queries mirroring
   `EntryRepository.findCurrentForVerifier*`:
   - `findDiscoverable(int limit)`
   - `findDiscoverableSince(Instant since, int limit)`
   - `findDiscoverableWithCursor(Instant cursorTs, UUID cursorId, int limit)`
   - All `WHERE discoverable AND status='active' ORDER BY created_at DESC, verifier_id DESC LIMIT :limit`.
   - Fetch `limit + 1` to detect `hasMore` (same trick as `SharedController`).

4. **DTO** `api/verifier/VerifierListDto.java`: record with
   `@JsonNaming(SnakeCaseStrategy)`, nested `Item` record. `key_fingerprint` computed via
   the existing §8 fingerprint helper (locate the one used elsewhere; if none is shared,
   add a small `KeyFingerprint` util in `crypto/` and reuse).

5. **Cursor**: reuse `api/shared/Cursor.java` as-is — the tuple is `(Instant, UUID)`,
   identical shape (8-byte epoch-ms + 16-byte UUID, base64url no-pad). If `Cursor` is
   package-private to `shared`, lift it to a shared package (`api/common/`) rather than
   duplicating; update the `shared` import. Note this refactor in the PR.

6. **Controller** `api/verifier/VerifierController.java` (or a new
   `VerifierDiscoveryController`): add
   `@GetMapping(produces=APPLICATION_JSON)` `list(since, cursor, limit)`. Clamp `limit`
   to `[1,100]`; reject `since`+`cursor` together with `schema_violation`; decode bad
   cursor → `bad_cursor` (code already exists in `ApiErrorAdvice`). Set the same
   `Cache-Control: no-store...`? No — this is non-sensitive public data; use
   `Cache-Control: public, max-age=300` like directory listings.

7. **Registration opt-in**: add optional `discoverable` (bool, default `false`) to
   `VerifierRegistrationDto` and persist it. **Reject `discoverable=true` with a missing/blank
   `display_name`** (`400 schema_violation`) so the error surfaces at the API edge, mirroring the
   DB CHECK in step 1. Opt-in is via the registration field only — **no admin toggle in v1** (Q1, resolved).

8. **Rate limit** `ratelimit/RateLimitPolicy.java`: add a `PolicyEntry`:
   `GET /v1/verifiers`, key = `ip(req)`, burst `20`, sustained `120/min`
   (between the by-handle directory limit and the per-verifier shared limit).

9. **Security** `security/SecurityConfig.java`: add `GET /v1/verifiers` to `permitAll`.
   Ensure the matcher distinguishes `GET /v1/verifiers` (list) from the existing
   `POST /v1/verifiers` (register) and `GET /v1/verifiers/{handle}/login-blob`.

## Spec + doc updates

- `docs/specs/api.md`:
  - §3.1 table: add `GET /v1/verifiers` row (or move discovery into §3.5 alongside other
    listing endpoints).
  - Add the `VerifierList` schema block + `discoverable` field on `VerifierRegistration`.
  - §6 rate-limit table: add the `GET /v1/verifiers` row.
  - §7: note the new cursor tuple `(created_at, verifier_id)`.
- `docs/specs/plan.md`: if it enumerates the privacy stance on verifier enumeration,
  add the opt-in `discoverable` rationale so the reversal is documented, not silent.
- No `crypto-formats.md` change (fingerprint §8 already specified; reused, not redefined).

## Tests

Integration test `api/verifier/VerifierDiscoveryIT.java` (Testcontainers, mirror
`SharedControllerIT`):
- Register verifiers: some `discoverable=true`, some `false` → list returns only the
  discoverable, active ones.
- `status != 'active'` discoverable verifier is excluded.
- Pagination: `limit` clamped; `next_cursor` round-trips; full walk yields every
  discoverable verifier exactly once with no overlap.
- `since` filters by `created_at`.
- `since` + `cursor` together → `400 schema_violation`.
- Malformed cursor → `400 bad_cursor`.
- `key_fingerprint` matches the §8 fixture rendering for a known enc key.

Keep BATS/e2e out of this unless the e2e suite already asserts the recipient picklist.

## Open questions

1. **Opt-in mechanism** — RESOLVED: **registration field only**, default-false, **no admin toggle
   in v1** (the column exists, so an admin override can be added later with no schema change).
2. **Who calls it** — RESOLVED: **the app calls `GET /v1/verifiers` directly** (no egnedata backend
   proxy/cache). `Cache-Control: public, max-age=300` is therefore a client-side hint; rate-limit
   is by client IP (watch carrier-NAT aggregation at pilot).
3. **`display_name` required when discoverable** — RESOLVED: **yes.** Enforced via a DB CHECK
   (step 1) plus a registration-time `400` (step 7).
4. **Pagination + rate-limit numbers** — RESOLVED: **keep the recommended defaults** (limit 50,
   max 100; `GET /v1/verifiers` IP-keyed, burst 20, 120/min). Tune at pilot.
