# Security review map

The threat model and design rationale live in [`specs/plan.md`](../../specs/plan.md).
This page is a structured pointer map: every security property the system claims
to enforce links to the file that enforces it. No claim appears here without a
citation.

## Threat model

The full threat model is in [`specs/plan.md` §1](../../specs/plan.md#1-threat-model-and-security-guarantees).
The actor list is: issuer (signs and uploads envelopes), verifier (fetches and
decrypts envelopes), server (stores and routes opaque bytes), network attacker
(passive or active on the wire), and compromised database (can read stored rows
but not plaintext). The server is explicitly not trusted with plaintext; see
[`../../explanation/trust-model.md`](../../explanation/trust-model.md) for the
chain of signed assertions that enforces this.

## Hard rules (reproduced)

The following rules are stated in `CLAUDE.md` under "Hard rules". Each item
includes a brief "Where it is enforced" citation.

- **Crypto sources: libsodium only.** Never `java.security.SecureRandom` or
  `dart:math.Random` for keys, nonces, or session tokens.
  *Where it is enforced:* all random bytes flow through
  [`crypto/Random.java#L7-L14`](../../../src/main/java/com/erikromson/datawallet/crypto/Random.java#L7-L14),
  which delegates exclusively to `CryptoProvider.sodium().randombytes_buf`.

- **Signed payloads are canonical CBOR bytes.** Wire bytes = DB bytes = signed
  bytes. The server never re-serialises signed data.
  *Where it is enforced:* entries are persisted as-received in the
  `signed_envelope BYTEA` column (see
  [`V1__init.sql#L20-L30`](../../../src/main/resources/db/migration/V1__init.sql#L20-L30));
  the ingest service reads and stores the raw bytes without parsing for
  re-encoding. Canonical serialisation is defined in
  [`specs/crypto-formats.md`](../../specs/crypto-formats.md).

- **Migrations are append-only.** New file `V<n>__name.sql`; previously applied
  migrations are never edited.
  *Where it is enforced:* Flyway versioned-migration discipline; the existing
  migration files under
  [`src/main/resources/db/migration/`](../../../src/main/resources/db/migration/)
  are the source of truth.

- **Two Postgres roles.** `wallet_app` for DML; `wallet_admin` for migrations
  and admin reads.
  *Where it is enforced:* role creation and grants in
  [`V1__init.sql#L108-L134`](../../../src/main/resources/db/migration/V1__init.sql#L108-L134).

- **Auth is opaque 32-byte bearer tokens.** No cookies, no CSRF surface, no
  refresh tokens — re-login is the recovery path.
  *Where it is enforced:* token extraction and session lookup in
  [`security/BearerAuthFilter.java#L39-L58`](../../../src/main/java/com/erikromson/datawallet/security/BearerAuthFilter.java#L39-L58).

- **Time is UTC milliseconds since epoch** as `uint` in CBOR/JSON;
  `TIMESTAMPTZ` in Postgres.
  *Where it is enforced:* session and audit timestamps are stored as
  `TIMESTAMPTZ` (see `V1__init.sql`); the audit service truncates to
  millisecond precision in
  [`audit/HashChainAuditService.java#L59-L61`](../../../src/main/java/com/erikromson/datawallet/audit/HashChainAuditService.java#L59-L61)
  to prevent sub-millisecond round-trip drift in the hash chain.

## Where each property is enforced

| Property | Enforced by | Spec reference |
|---|---|---|
| Bearer-token validation | [`security/BearerAuthFilter.java#L39-L58`](../../../src/main/java/com/erikromson/datawallet/security/BearerAuthFilter.java#L39-L58) | [`specs/plan.md` §4.4](../../specs/plan.md#44-session-token) |
| Argon2id KDF (key derivation) | [`crypto/Argon2id.java#L16-L37`](../../../src/main/java/com/erikromson/datawallet/crypto/Argon2id.java#L16-L37) | [`specs/plan.md` §6](../../specs/plan.md#6-verifier-account-creation-and-login) |
| Argon2id parameter floor (min cost) | [`api/verifier/Argon2idFloor.java`](../../../src/main/java/com/erikromson/datawallet/api/verifier/Argon2idFloor.java) | [`specs/plan.md` §6](../../specs/plan.md#argon2id-parameter-floor-h2) |
| Nonce sourcing via libsodium | [`crypto/Random.java#L7-L14`](../../../src/main/java/com/erikromson/datawallet/crypto/Random.java#L7-L14) | [`specs/crypto-formats.md`](../../specs/crypto-formats.md) |
| mTLS issuer cert authentication | [`security/X509IssuerPrincipalResolver.java#L19-L50`](../../../src/main/java/com/erikromson/datawallet/security/X509IssuerPrincipalResolver.java#L19-L50) | [`specs/plan.md` §3](../../specs/plan.md#3-keys-and-trust-distribution) |
| Audit hash chain (tamper-evident log) | [`audit/HashChainAuditService.java#L50-L66`](../../../src/main/java/com/erikromson/datawallet/audit/HashChainAuditService.java#L50-L66) | [`specs/plan.md` §8.1](../../specs/plan.md#81-audit-log) |
| Audit log append-only trigger | [`V1__init.sql#L99-L106`](../../../src/main/resources/db/migration/V1__init.sql#L99-L106) | [`specs/plan.md` §4.5](../../specs/plan.md#45-server-persistence-model) |
| Token-bucket rate limiting | [`ratelimit/RateLimitService.java#L44-L65`](../../../src/main/java/com/erikromson/datawallet/ratelimit/RateLimitService.java#L44-L65) | [`specs/plan.md` §10](../../specs/plan.md#10-tasks) |
| Authentication lockout (progressive) | [`ratelimit/AuthLockoutService.java#L50-L64`](../../../src/main/java/com/erikromson/datawallet/ratelimit/AuthLockoutService.java#L50-L64) | [`specs/plan.md` §6](../../specs/plan.md#6-verifier-account-creation-and-login) |
| Two-role DB enforcement | [`V1__init.sql#L108-L134`](../../../src/main/resources/db/migration/V1__init.sql#L108-L134) | [`specs/plan.md` §4.5](../../specs/plan.md#45-server-persistence-model) |
| Directory record signature verification | [`directory/DirectoryRecordVerifier.java`](../../../src/main/java/com/erikromson/datawallet/directory/DirectoryRecordVerifier.java) | [`specs/plan.md` §4.3](../../specs/plan.md#43-directory-record) |

## Audit log

The audit log is an append-only hash chain stored in the `audit_log` table.
Each event is written by
[`audit/HashChainAuditService.java`](../../../src/main/java/com/erikromson/datawallet/audit/HashChainAuditService.java)
in a dedicated `REQUIRES_NEW` transaction (line 50), computing
`hash_n = SHA256(prev_hash || canonical_cbor(event))` over the previous chain
head before committing (lines 50–66). Concurrent writers are serialised by a
`SELECT … FOR UPDATE` on the chain-head row. A database-level `BEFORE UPDATE OR
DELETE` trigger in
[`V1__init.sql#L99-L106`](../../../src/main/resources/db/migration/V1__init.sql#L99-L106)
provides defence-in-depth against direct row mutation. The log is readable only
by the `wallet_admin` role through
[`api/admin/AdminAuditController.java`](../../../src/main/java/com/erikromson/datawallet/api/admin/AdminAuditController.java)
(`GET /v1/admin/audit`); verifier bearer tokens cannot reach this endpoint.

## What the server cannot do

The following properties mirror the claims in
[`../../explanation/trust-model.md`](../../explanation/trust-model.md); each
links to the code that enforces the boundary.

- **Mint a directory entry.** Only the offline root keypair can produce a valid
  root signature. The server stores and verifies directory records against the
  pinned root via
  [`directory/DirectoryRecordVerifier.java`](../../../src/main/java/com/erikromson/datawallet/directory/DirectoryRecordVerifier.java)
  but cannot create one.

- **Decrypt an envelope.** The content key is sealed with X25519 SealedBox
  ([`crypto/SealedBox.java`](../../../src/main/java/com/erikromson/datawallet/crypto/SealedBox.java))
  to the verifier's public key. The corresponding private key never leaves the
  verifier's device; the server stores only the opaque CBOR bytes.

- **Impersonate an issuer.** Issuer identity is resolved from a client
  certificate via
  [`security/X509IssuerPrincipalResolver.java`](../../../src/main/java/com/erikromson/datawallet/security/X509IssuerPrincipalResolver.java).
  A certificate the issuer does not hold cannot be forged at the server level.

- **Replay share events silently.** Every share event extends the audit hash
  chain in
  [`audit/HashChainAuditService.java`](../../../src/main/java/com/erikromson/datawallet/audit/HashChainAuditService.java).
  Omitting or reordering an entry breaks the chain, which is detectable by an
  external checker reading the audit log.

## Out of scope

The system makes no claims about the following; they are explicitly deferred.
See [`../../explanation/architecture.md#out-of-scope`](../../explanation/architecture.md#out-of-scope)
for the full list with rationale.

OPAQUE/aPAKE login, password recovery, refresh tokens, multi-active auth keys
per verifier, WebSocket push, streaming uploads, FROST/MuSig2, TLS
channel-binding of session tokens, per-column TDE, off-heap/`mlock` buffers,
server-side search/filter beyond `since`+cursor, mixed-script Unicode handles,
audit-anchor external publication, multi-module Maven split, dedicated issuer
Flutter app, web client UX polish.

## See also

- [`../../explanation/architecture.md`](../../explanation/architecture.md) — actors, trust boundaries, and operational surface
- [`../../explanation/trust-model.md`](../../explanation/trust-model.md) — root → directory → issuer/verifier signature chain
- [`../crypto.md`](../crypto.md) — cryptographic format reference
- [`../http-api.md`](../http-api.md) — HTTP endpoint reference
- [`../../specs/plan.md`](../../specs/plan.md) — design rationale, threat model, and lifecycle
- [`../../specs/api.md`](../../specs/api.md) — wire-format and HTTP behaviour spec
- [`../../specs/crypto-formats.md`](../../specs/crypto-formats.md) — byte-level layout spec
