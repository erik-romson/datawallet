# Data Wallet — future work to support egnedata "Share data"

> Scope: everything **server-side** (Spring server + `intermediate/` + specs + fixtures)
> required for the egnedata-kmp app to act as a per-user, **device-held-key** issuer that
> signs/encrypts on-device and uploads to a chosen verifier. The mobile-app side is
> planned separately (see `tmp/egnedata-share-data.prompt.md` → `egnedata-kmp/tmp/shared-data-plan.md`).
>
> Architecture locked: per-user issuer; Ed25519 signing key lives **on the device**; the
> app does **all** signing + encryption; the `intermediate` is used **only** to enroll the
> device key (sign + publish the issuer directory record) and mint the issuer token;
> issuer upload auth is **bearer**, not mTLS.

## Workstream A — Verifier discovery endpoint `GET /v1/verifiers`

Full plan already written: `tmp/verifier-discovery-endpoint-plan.md`. In brief:
- `V10` migration: opt-in `discoverable BOOLEAN DEFAULT false` + partial index.
- New public, paginated, opt-in list endpoint (cursor pattern reused from `/v1/shared`).
- Returns identity + display fingerprint only — **not** the enc public key; sealing keys
  still come from the root-verified directory record.
- Entity/repo/DTO/controller, rate-limit policy, `SecurityConfig` permitAll, `api.md`
  update, registration opt-in field, integration test.

Status: **specified, not implemented.** Blocks the app's recipient picklist.

## Workstream B — Make bearer issuer-auth a first-class, specified path

The code already has `BearerIssuerPrincipalResolver` (active when
`datawallet.security.issuer-mtls=false` + `datawallet.security.issuer-bearer.enabled=true`):
it verifies a JWT minted by the `intermediate` against the intermediate's Ed25519 key and
checks the `jkt` claim matches the issuer's published signing key. But `api.md §3.3` says
**"mTLS required"** on issuer paths, so per `CLAUDE.md` ("spec wins") this must be promoted
from a hidden toggle to a documented contract before use.

1. **`api.md §3.3` update** — specify bearer issuer-auth: JWT shape, `jkt` binding to the
   issuer signing key, lifetime, the `Authorization: Bearer` header on `POST/PUT /v1/entries`,
   and that mTLS becomes optional/alternative for issuer paths.
2. **`plan.md` threat model update** — record the rationale that makes dropping mTLS
   acceptable here: the signing key is **device-held** and every envelope is independently
   Ed25519-signed and verified against the published directory record, so the bearer token
   is *transport* auth only — a stolen token cannot forge a valid envelope without the
   device key. Cover token lifetime, revocation (intermediate denylist), replay/audience.
3. **`IssuerSecurityConfig` wiring** — the `@Order(1)` chain currently enforces `.x509()` +
   `.authenticated()` on `/v1/entries/**` and `/v1/issuers/**`. Make this **conditional on
   `issuer-mtls`**: in bearer mode the chain must authenticate via the bearer JWT, not
   require a client cert. Verify `X509IssuerPrincipalResolver` (default) and
   `BearerIssuerPrincipalResolver` (bearer) swap correctly and the filter chain matches.
4. **Config defaults per environment** — set `issuer-mtls=false`, `issuer-bearer.enabled=true`
   where the app issues. Document the deployment/proxy change (issuer paths no longer need
   client-cert termination).
5. **Rate-limit keying** — confirm `POST/PUT /v1/entries` limits key on `issuer_id` derived
   from the JWT (not a cert), and tune for many low-volume per-user issuers.
6. **Security review sign-off** on the above.

Status: **partially built (resolver exists), unspecified + unwired for prod.** Blocks the
app's upload.

## Workstream C — Intermediate per-user enrollment

The `intermediate/` service already implements the per-user issuer flow: `POST /enroll`
(attestation + pubkey → `DirectoryRecordSigner.signIssuerRecord` with `parent_key_id` =
intermediate → publish to `POST /v1/admin/directory`), `POST /token` (signed record → JWT
with `jkt`), `POST /revoke`. Signer backends: `GcpKmsSignerPort` (prod, HSM/KMS),
`SoftSigner` (test). Remaining work:

1. **Attestation scheme** — confirm exactly what `EnrollService` validates against the
   install UUID, and ensure **Android** (Play Integrity / Key Attestation) is supported and
   documented. Define what the app must produce. (iOS App Attest is later.)
2. **`key_id` derivation** — confirm `DirectoryRecordSigner.computeKeyId(publicKey)` (exact
   bytes) and document it so the on-device app computes the identical `issuer_signing_key_id`
   used in the envelope.
3. **Directory-record freshness at scale** — per-user issuer records carry `valid_until` and
   clients reject `now() > issued_at + 7d`; the operator must republish every ≤ 3.5 days
   (`crypto-formats.md §6`). Confirm the intermediate's `@EnableScheduling` republish loop
   covers **all** enrolled per-user issuers, not just intermediates; if not, build it.
   Capacity-check: this scales with active user count.
4. **Revocation lifecycle** — wire account deletion / key compromise → `POST /revoke` →
   publish a `revoked` directory record. Define the trigger from the egnedata side.
5. **Token issuance** — confirm `/token` lifetime, refresh story, and denylist behavior for
   per-user issuers (the app will refresh per share or per session).
6. **Enrollment trust** — confirm whether the app calls the intermediate directly or via the
   egnedata backend; either way crypto stays on-device. (Current intermediate design is
   app-direct with attestation.)

Status: **mostly built; needs Android attestation confirmation, scale review, and the
revocation trigger.**

## Workstream D — Cross-stack fixtures for the issuer envelope

The egnedata Kotlin app becomes a **third** stack that must match `spec/fixtures/*`
byte-for-byte (today: Java + Flutter). Server-side responsibility because fixtures + the
generator live here.

1. **Extend `spec/tools/gen.py`** to emit issuer-envelope fixtures matching the egnedata
   payload shape: binary `ciphertext` (the zip is binary, not the utf8 of the §5 example),
   single- and multi-recipient `recipient_wrappings`, deterministic UUIDv7 (`§10`) and
   fingerprint (`§8`) vectors. Never hand-edit `.cbor` — regenerate.
2. **`fixtures.md`** — document that Kotlin is now a stack-of-record for the issuer-side
   constructions and which fixtures it must pass.

Status: **new.** The app's parity tests depend on these vectors.

## Workstream E — Entry ingest confirmations for this use case

1. **Binary payload** — confirm/serve that `ciphertext` may be arbitrary bytes (secretbox is
   byte-oriented; the §5 example just happens to show utf8) and document it.
2. **Size limits** — envelopes are "small" and streaming is out of scope; set/confirm the
   max request body size for `POST /v1/entries` to comfortably fit the zip.
3. **`issuer_label` / `description`** — both are server-visible cleartext; define what
   egnedata sets (label = user display name?) and confirm length rules (`≤64` / `≤256` NFC
   codepoints).
4. **Create vs update** — egnedata is create-only; confirm the monotonic-`version` /
   `rewrap_only_forbidden` rules don't trip the first-upload path.

## Workstream F — Scale & observability

- Directory-record table growth + republish load scales with active issuers (Workstream C).
- Audit-log volume per upload; per-issuer rate limits.
- Capacity review before pilot at expected user counts.

## Sequencing — what blocks the mobile app

```
A (verifier list)  ─┐
B (bearer auth)    ─┼─►  app can enroll, pick a recipient, and upload
C (enrollment)     ─┤
D (fixtures)       ─┘    app's on-device codec can be parity-tested
E, F                     hardening / pilot-readiness (parallel)
```

The app feature cannot complete until **A**, **B**, **C**, and **D** land. **E**/**F** are
hardening and can proceed in parallel.

## Open questions

1. Verifier opt-in mechanism (registration field vs admin toggle) — Workstream A.
2. Exact Android attestation scheme the intermediate accepts — Workstream C.
3. Token lifetime + refresh cadence — Workstream B/C.
4. Account-deletion → revocation trigger ownership (app, backend, or operator) — Workstream C.
5. Does the app talk to the intermediate directly or via an egnedata backend relay? (Crypto
   stays on-device regardless.)
