# Data Wallet — API contract (companion to `plan.md`)

This document fills the HTTP surface gaps identified in the plan review. It is normative for v1: server and clients MUST match it byte-for-byte on the canonical paths.

## 1. Wire format

Two content types only.

| Content | `Content-Type` | Encoding |
|---------|----------------|----------|
| Signed envelopes (upload + download) and signed directory records | `application/cbor` | Raw canonical CBOR (RFC 8949 §4.2.1). Wire bytes == signed bytes == DB `BYTEA`. No re-encoding anywhere on the path. |
| Everything else (auth, account, listing, errors, admin) | `application/json` | UTF-8 JSON. Binary fields are **base64url without padding** (RFC 4648 §5). |

Rationale: signed CBOR cannot be JSON-wrapped without breaking signatures (or paying a base64 round-trip on every read). JSON is fine for ergonomic non-signed surfaces. Both stacks already need both libraries (Jackson + jackson-dataformat-cbor; `dart:convert` + package:cbor`).

`Accept` negotiation is not required — each endpoint has a single response type.

## 2. URL versioning

All endpoints prefixed with `/v1/`. v2 will be a sibling prefix; no in-place breaking changes.

## 3. Endpoint surface

### 3.1 Verifier registration, account & discovery

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| `POST` | `/v1/verifiers` | none | `VerifierRegistration` (JSON) | `201 Created` + `{verifier_id}` |
| `GET`  | `/v1/verifiers` | none | — | `VerifierList` (JSON, paginated) |
| `GET`  | `/v1/verifiers/{handle}/login-blob` | none | — | `LoginBlob` (JSON) |
| `POST` | `/v1/verifiers/{verifier_id}/password` | session | `PasswordChange` (JSON) | `204 No Content` |
| `POST` | `/v1/verifiers/{verifier_id}/rotate-keys` | session + signed challenge | `KeyRotation` (JSON) | `204 No Content` |

```jsonc
// VerifierRegistration
{
  "handle": "alice",
  "display_name": "Alice",                       // optional, max 64 chars; required when discoverable=true
  "discoverable": false,                         // optional, default false; opt-in to GET /v1/verifiers listing
  "enc_public_key":   "<b64url 32 bytes>",
  "enc_key_id":       "<b64url 16 bytes>",       // random per key, opaque to server
  "auth_public_key":  "<b64url 32 bytes>",
  "auth_key_id":      "<b64url 16 bytes>",
  "wrapped_enc_private_key_blob":  "<b64url canonical CBOR>",
  "wrapped_auth_private_key_blob": "<b64url canonical CBOR>",
  "kdf_salt":   "<b64url 16 bytes>",
  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19},
  "client_password_score": 3                     // zxcvbn 0-4, advisory
}

// VerifierList — public discovery picklist for issuers
{
  "items": [
    {
      "verifier_id":     "<uuidv7>",
      "handle":          "alice",
      "display_name":    "Alice",
      "enc_key_id":      "<b64url 16 bytes>",
      "key_fingerprint": "ABCD-EFGH-IJKL-MNOP",  // §8 rendering of enc public key
      "created_at":      "2026-04-25T08:30:00Z"
    }
  ],
  "next_cursor": "<opaque>"  // null when exhausted
}
```

`GET /v1/verifiers` returns only `status='active'` AND `discoverable=true` rows, ordered `created_at DESC, verifier_id DESC`. Cache-Control: `public, max-age=300`. The response **never** includes `enc_public_key` — clients derive trust from `key_fingerprint` only.

Query params (same contract as §3.5 and §7): `since=<RFC3339>`, `cursor=<opaque>`, `limit=<1..100>` (default 50). `since` and `cursor` are mutually exclusive (`400 schema_violation` if both supplied).

// LoginBlob (returned to anyone who asks — accepted risk H1)
{
  "verifier_id": "<uuid>",
  "auth_public_key":  "<b64url 32 bytes>",
  "auth_key_id":      "<b64url 16 bytes>",
  "wrapped_enc_private_key_blob":  "<b64url canonical CBOR>",
  "wrapped_auth_private_key_blob": "<b64url canonical CBOR>",
  "kdf_salt":   "<b64url 16 bytes>",
  "kdf_params": {"alg":"argon2id","m":268435456,"t":3,"p":1,"version":19}
}

// PasswordChange — old KEK proven by client; server only stores re-wrapped blobs
{
  "wrapped_enc_private_key_blob":  "<b64url>",
  "wrapped_auth_private_key_blob": "<b64url>",
  "kdf_salt":   "<b64url 16 bytes>",
  "kdf_params": {...}
}

// KeyRotation — new keypairs, old keys flipped to "revoked" in the directory
{
  "enc_public_key":  "<b64url>", "enc_key_id":  "<b64url>",
  "auth_public_key": "<b64url>", "auth_key_id": "<b64url>",
  "wrapped_enc_private_key_blob":  "<b64url>",
  "wrapped_auth_private_key_blob": "<b64url>",
  "kdf_salt": "<b64url>", "kdf_params": {...},
  "old_enc_key_id":  "<b64url>",
  "old_auth_key_id": "<b64url>"
}
```

Server enforces: handle regex (§ `crypto-formats.md`), `kdf_params` ≥ floor (`m≥256MiB` native / `m≥64MiB` web; web origin detected via `Origin` header), uniqueness on `handle`. On rotation, all `sessions` rows for `verifier_id` are deleted and the verifier re-logs in.

### 3.2 Authentication

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| `POST` | `/v1/auth/challenge` | none | `{verifier_id}` | `{nonce, expires_at}` |
| `POST` | `/v1/auth/verify`    | none | `{verifier_id, nonce, signature}` | `{session_token, expires_at}` |
| `POST` | `/v1/auth/logout`    | session | — | `204 No Content` |

`nonce` is 32 random bytes, base64url, single-use, 60 s TTL, bound to `verifier_id` in a server-side `auth_challenges` table keyed by `(verifier_id, nonce)` with `consumed_at`. Verify deletes the row (or sets `consumed_at`) atomically before returning 200.

`signature` is over `"datawallet-auth-v1\x00" || nonce_bytes` — see `crypto-formats.md §4`.

`session_token` is 32 random bytes base64url (opaque). Sent on subsequent requests as `Authorization: Bearer <token>`. Logout deletes the row in `sessions`.

### 3.3 Issuer ingest & lifecycle

Issuer authentication: **mTLS** (default) or **bearer JWT** (mobile profile). Exactly one mode is active per deployment, controlled by `datawallet.security.issuer-mtls` and `datawallet.security.issuer-bearer.enabled` (mutually exclusive; both `true` is a startup error).

- **mTLS mode** (`issuer-mtls=true`, default): the client cert's `CN` (or `subjectAltName.URI` of the form `urn:datawallet:issuer:<issuer_id>`) declares the issuer principal. The server matches that principal to `envelope.issuer_id`.
- **Bearer mode** (`issuer-mtls=false`, `issuer-bearer.enabled=true`): the issuer sends `Authorization: Bearer <jwt>` where the JWT is minted by the intermediate signing service. JWT shape: `alg=EdDSA`, `iss=urn:datawallet:issuer:<issuer_id>`, `aud` exact-match against configured audience, `exp` with max lifetime 5 min, `cnf.jkt` = JWK thumbprint of the issuer's Ed25519 signing key. The server verifies the JWT signature against the active intermediate public key, validates `aud` and timing, and binds the issuer via `cnf.jkt` to the directory-registered signing key. Bearer is **transport auth only** — envelope integrity still rests on the per-envelope Ed25519 signature verified at ingest.

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/v1/entries`             | raw canonical CBOR envelope | `201 Created` + `{entry_id, version}` (JSON) |
| `PUT`  | `/v1/entries/{entry_id}`  | raw canonical CBOR envelope | `200 OK` + `{entry_id, version}` (JSON) |
| `POST` | `/v1/issuers/{issuer_id}/rotate-signing-key` | `{new_public_key, new_key_id, old_key_id}` | `204 No Content` (operator publishes the directory record out-of-band) |

Allow-list update == `PUT` with a new envelope whose `version` field equals `previous + 1` and whose canonical CBOR carries a fresh data key + re-encrypted ciphertext (§5.9 of plan). Server enforces monotonic `version`, rejects rewrap-only attempts (heuristic: `ciphertext` hash unchanged from prior version triggers `409 Conflict` with `code: rewrap_only_forbidden`).

Concurrency: `PUT /entries/{id}` takes `SELECT … FOR UPDATE` on the current row (`is_current=true`); a conflicting concurrent writer gets `409 version_conflict` with the current `version` echoed back. Optimistic alternative is acceptable but the chosen scheme MUST be implemented identically server-side.

### 3.4 Directory

Directory records are signed CBOR. The wrapper is JSON only when listing.

| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/v1/directory/verifiers/{handle}` | none | `DirectoryEnvelope` (JSON wrapper around base64url signed CBOR record) |
| `GET` | `/v1/directory/issuers/{issuer_id}` | none | `DirectoryEnvelope` (multiple records — current `active` plus `superseded`/`revoked` within retention) |
| `GET` | `/v1/directory/root` | none | `{roots: [{root_key_id, public_key, valid_from, valid_until, status}]}` and any in-flight `root-update` records (signed CBOR, base64url) |

```jsonc
// DirectoryEnvelope
{
  "records": [
    {
      "key_id": "<b64url>",
      "status": "active",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "issued_at":  "2026-04-25T00:00:00Z",
      "signed_record": "<b64url canonical CBOR (the record itself, root-signed)>"
    }
  ]
}
```

The `signed_record` bytes are what the client verifies against the pinned root quorum. JSON fields outside `signed_record` are advisory and MUST NOT influence trust decisions.

### 3.5 Verifier retrieval

| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/v1/shared` | session | `SharedList` (JSON, paginated) |
| `GET` | `/v1/shared/{entry_id}` | session | raw canonical CBOR envelope (`application/cbor`) |

```jsonc
// SharedList
{
  "items": [
    {
      "entry_id": "<uuidv7>",
      "issuer_id": "<uuid>",
      "issuer_label": "ACME Bank",       // hint only, never authoritative
      "issuer_signing_key_id": "<b64url>",
      "created_at": "2026-04-25T08:30:00Z",
      "description": "Loan offer #4128"  // server-visible cleartext
    }
  ],
  "next_cursor": "<opaque>"  // null when exhausted
}
```

Query params:
- `since=<RFC3339>` — only entries with `created_at ≥ since`.
- `cursor=<opaque>` — server-issued, encodes `(created_at, entry_id)` for stable order.
- `limit=<1..100>` — default 50.

Order: `created_at DESC, entry_id DESC` (UUIDv7 keeps this monotonic with insertion).

### 3.6 Operator / admin

mTLS with operator cert (separate CA OU from issuers).

| Method | Path | Body | Response |
|--------|------|------|----------|
| `POST` | `/v1/admin/directory` | signed CBOR record (`application/cbor`) | `201 Created` |
| `POST` | `/v1/admin/root-update` | signed CBOR root-update record | `201 Created` |
| `GET`  | `/v1/admin/audit?since_seq=N&limit=M` | — | `AuditPage` (JSON) — includes hash-chain head |
| `GET`  | `/v1/admin/directory/revoked-issuers` | — | `[{install_uuid, key_id, valid_until, revoked_at}]` (JSON array) |
| `GET`  | `/v1/admin/directory/active-issuers?cursor=&limit=` | — | `ActiveIssuerPage` (JSON, paginated) |

Server validates root-quorum signatures on `root-update` against currently-pinned roots before accepting.

`GET /v1/admin/directory/active-issuers` returns only eligible records for republishing:
`record_type='issuer' AND status='active' AND pending_revocation=false`. Rotation-targeted keys
(`pending_revocation=true`) are excluded — they must age out, not be kept fresh.

```jsonc
// ActiveIssuerPage
{
  "items": [
    {
      "subject_id":    "<uuid>",            // install UUID
      "key_id":        "<b64url 16 bytes>",
      "valid_from":    1714000000000,        // UTC ms since epoch
      "valid_until":   1745536000000,
      "issued_at":     1714000000000,
      "signed_record": "<b64url CBOR>"      // current signed directory record
    }
  ],
  "next_cursor": "<opaque>"  // null when exhausted
}
```

Query params: `cursor=<opaque>`, `limit=<1..100>` (default 50). Ordered `issued_at DESC, subject_id DESC`.

## 4. Error model

All non-CBOR error responses use a single envelope, regardless of endpoint:

```jsonc
{
  "error": {
    "code": "snake_case_stable_token",
    "message": "human readable, English, no PII",
    "details": { "...": "..." }      // optional, code-specific
  },
  "trace_id": "<opaque, 16 bytes b64url>"
}
```

CBOR endpoints (entries upload, shared download) return JSON errors with the same shape on failure, with `Content-Type: application/json`.

### Status code map

| Status | When | Example `code` |
|--------|------|----------------|
| `400 Bad Request` | malformed CBOR/JSON, schema violation, bad base64 | `malformed_body`, `schema_violation` |
| `401 Unauthorized` | missing/invalid session, mTLS handshake failed | `auth_required`, `auth_invalid_signature` |
| `403 Forbidden` | authenticated but not authorized (issuer mismatch on PUT, non-recipient on GET) | `issuer_mismatch`, `not_a_recipient` |
| `404 Not Found` | unknown handle, unknown entry, no directory record | `handle_not_found`, `entry_not_found` |
| `409 Conflict` | duplicate handle, duplicate `entry_id`, version conflict, rewrap-only | `handle_taken`, `entry_id_taken`, `version_conflict`, `rewrap_only_forbidden` |
| `410 Gone` | entry was purged (older superseded version requested) | `entry_purged` |
| `422 Unprocessable Entity` | signature invalid, unknown `version`, KDF below floor, key not active at `created_at` | `signature_invalid`, `version_unsupported`, `kdf_below_floor`, `signing_key_not_active` |
| `429 Too Many Requests` | rate-limited | `rate_limited` (`Retry-After` header set) |
| `500 Internal Server Error` | unexpected | `internal` |
| `503 Service Unavailable` | maintenance, DB unavailable | `unavailable` |

`410 Gone` distinguishes "the verifier was a recipient of a prior version that has now been purged" from `404` (never existed) — useful for client UX and audit.

## 5. Headers, CORS, and caching

### 5.1 Security headers (all responses)

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=(), usb=()
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
```

### 5.2 Cache control

Sensitive endpoints (`/v1/auth/*`, `/v1/verifiers/*/login-blob`, `/v1/shared*`, `/v1/entries*`):
```
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
```

Logout response additionally sets:
```
Clear-Site-Data: "cache", "storage"
```

Discovery endpoint (`GET /v1/verifiers`) and directory records MAY be cached briefly:
```
Cache-Control: public, max-age=300
```
Clients still apply the §4.3 freshness window (7 days) — HTTP caching is purely about load.

### 5.3 CORS

Allowed origins configured per-deployment. Pilot:
```
Access-Control-Allow-Origin: <web-origin>     // exact match, never *
Access-Control-Allow-Credentials: false       // bearer in header, not cookies
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
Access-Control-Max-Age: 600
```

`Authorization` header carries the bearer token — no cookies, so no CSRF surface and no `SameSite` config needed.

## 6. Rate limiting

Token bucket per key, stored in PostgreSQL (no Redis dep in v1) using a `rate_limits(key, tokens, refilled_at)` table with `SELECT … FOR UPDATE` on each request — simple, correct, fine at pilot scale (<10 RPS).

| Endpoint | Key | Burst | Sustained |
|----------|-----|-------|-----------|
| `POST /v1/auth/challenge` | `(ip, verifier_id)` | 5 | 30/min |
| `POST /v1/auth/verify`    | `(ip, verifier_id)` | 5 | 30/min |
| `GET /v1/verifiers` | `ip` | 20 | 120/min |
| `GET /v1/verifiers/{handle}/login-blob` | `(ip, handle)` | 5 | 60/min |
| `GET /v1/directory/verifiers/{handle}` | `ip` | 20 | 600/min |
| `GET /v1/shared`, `GET /v1/shared/{id}` | `verifier_id` | 20 | 300/min |
| `POST /v1/entries`, `PUT /v1/entries/{id}` | `issuer_id` | 10 | 300/min |

Progressive lockout: after 10 consecutive `auth_invalid_signature` for the same `verifier_id`, lock for 15 min (row in `auth_lockouts`); reset on first successful verify. Returns `423 Locked` with `Retry-After`.

`X-Forwarded-For` is trusted only when arriving on the load-balancer-private listener (server config — out of scope here, but flagged so deploy doesn't trust client-supplied IP).

## 7. Pagination contract

All list endpoints that return `next_cursor`:
- Cursor is opaque, server-issued, base64url. Format MAY change without notice.
- Cursor encodes the order tuple: `(created_at, entry_id)` for `/shared`; `(created_at, verifier_id)` for `/v1/verifiers`.
- Repeating a cursor is idempotent within retention.
- Mixing `since` and `cursor` in the same call is a `400 schema_violation`.

## 8. Health / observability

| Path | Auth | Purpose |
|------|------|---------|
| `GET /actuator/health/liveness`  | none | process up |
| `GET /actuator/health/readiness` | none | DB reachable, migrations applied |
| `GET /actuator/info`             | none | build info, git SHA |
| `GET /actuator/prometheus`       | mTLS operator | metrics scrape |

Readiness MUST fail if any pinned root has `valid_until < now()` and no `root-update` is in flight — this is the boot-time check that the service is still trustable.

## 9. Out of scope for v1

- Refresh tokens (re-login is the path).
- Multi-active auth keys per verifier (single active enc + single active auth).
- Streaming / chunked uploads (envelopes are small).
- Server-side search / filter beyond `since`.
- WebSocket push notifications (clients poll `/shared?since=`).
