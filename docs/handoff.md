# Data Wallet v1 Pilot — Implementation Handoff

**Date:** April 25, 2026
**Scope:** 21 implementation steps (step-01 through step-21)
**Status:** Feature-complete with minor process gaps (see Known Limitations)

---

## 1. Overview

The Data Wallet v1 pilot is a complete end-to-end encrypted envelope management system consisting of three components:

1. **Spring Boot Server** — stores issuer-signed, end-to-end-encrypted data envelopes for nominated verifiers; manages verifier registration, authentication, and key rotation; exposes REST API for ingestion, retrieval, and administration.

2. **Flutter Verifier Client** — lets a verifier log in (password → Argon2id KEK → unwrap private keys locally), list shared entries with pagination and issuer fingerprints, download and verify CBOR envelopes, and decrypt plaintext. No plaintext persisted to disk.

3. **Java CLI** — offline tools for trust-root signing, directory-record publishing, and issuer envelope authoring. Runs independently with no server connection.

**Why it matters:** Organizations can issue data (loans, credentials, offers) in a way that end-to-end encrypts content at rest on the server, with cryptographic proof of issuer authorship and verifier identity. The server never sees plaintext or private keys. Verifiers authenticate with Argon2id-derived keys rather than traditional passwords, mitigating offline attacks.

---

## 2. Changes Summary

**Total: 200 files changed, 13,905 insertions(+), 3 deletions(−)**

### Java Backend (Spring Boot)
- **Root:** `pom.xml` — Maven single-module, Java 25, Spring Boot 3.x, libsodium via lazysodium-java
- **Crypto:** `src/main/java/com/erikromson/datawallet/crypto/`
  - Canonical CBOR codec (`CanonicalCborMapper.java`)
  - Libsodium wrappers: Ed25519, X25519, SecretBox, SealedBox, SHA-256, Argon2id, UuidV7, Fingerprint
- **Data model:** `src/main/java/com/erikromson/datawallet/domain/`
  - JPA entities: `VerifierEntity`, `SessionEntity`, `EntryEntity`, `EntryRecipientEntity`, `DirectoryRecordEntity`, `AuthChallengeEntity`, `AuthLockoutEntity`, `RateLimitEntity`
  - Spring Data repositories for all entities
- **Envelope codec:** `src/main/java/com/erikromson/datawallet/envelope/`
  - `EnvelopeCodec` — CBOR ↔ SharedEnvelope
  - `EnvelopeSigner`, `EnvelopeVerifier` — Ed25519 signature + ciphertext-hash check
  - `RecipientWrapping` — per-verifier data-key wrapping
- **Directory & root quorum:** `src/main/java/com/erikromson/datawallet/directory/`
  - `DirectoryRecordCodec` — CBOR codec for issuer signing keys
  - `DirectoryRecordVerifier` — validates record against pinned root quorum
  - `IssuerKeyResolverImpl` — fetches + caches issuer keys from directory
- **HTTP API:** `src/main/java/com/erikromson/datawallet/api/`
  - **Auth:** `AuthController` — challenge, verify, logout endpoints
  - **Verifier:** `VerifierController` — registration, login-blob, key rotation, password change
  - **Shared entries:** `SharedController` — list (paginated), detail (CBOR fetch)
  - **Entry ingestion:** `EntryController`, `IssuerKeyController`, `EntryIngestService` — issuer envelope upload, allow-list updates
  - **Directory:** `DirectoryQueryController` — public directory queries
  - **Admin:** `AdminAuditController`, `AdminDirectoryController`, `AdminRootUpdateController` — operator endpoints
  - **Error handling:** `ApiErrorAdvice` — global exception → JSON error responses
- **Security:** `src/main/java/com/erikromson/datawallet/security/`
  - `SecurityConfig`, `IssuerSecurityConfig`, `AdminSecurityConfig` — Spring Security configuration
  - `BearerAuthFilter` — extracts session token, populates `SessionPrincipal`
  - `SecurityHeadersFilter`, `CorsConfig` — headers + CORS
  - `X509IssuerPrincipalResolver` — issuer mTLS principal (production)
  - `IssuerPrincipalResolver` (interface) — allows test injection
- **Rate limiting & lockout:** `src/main/java/com/erikromson/datawallet/ratelimit/`
  - `RateLimitInterceptor` — token-bucket rate limiting per endpoint + handler
  - `AuthLockoutService` — locks verifier after N failed auth attempts
- **Audit:** `src/main/java/com/erikromson/datawallet/audit/`
  - `HashChainAuditService` — SHA-256 hash-chain append-only log (production)
  - `NoopAuditService` — stub (used in early steps)
- **Purge job:** `src/main/java/com/erikromson/datawallet/purge/`
  - `SupersededPurgeJob` — `@Scheduled` job that removes old verifier key rotations
- **CLI:** `src/main/java/com/erikromson/datawallet/cli/`
  - `CliApplication` — entry point for offline tools
  - `GenRootCommand` — generate pinned root quorum (EdDSA keypairs, M-of-N threshold)
  - `SignDirectoryRecordCommand` — sign a directory record with trust-root keys
  - `SignRootUpdateCommand` — sign a root key rotation certificate
  - `BuildEnvelopeCommand` — build a SharedEnvelope from plaintext + issuer keypair
  - `UploadEnvelopeCommand` — send envelope to server via issuer mTLS
  - `CliKeyStore` — PEM/PKCS8 key management
- **Database:** `src/main/resources/db/migration/`
  - `V1__init.sql` — schema: verifiers, sessions, entries, recipients, directory, audit log, rate limits
  - `V4__entries_constraints.sql`, `V5__directory_records_pending.sql` — constraints + indexes
- **Configuration:** `src/main/resources/`
  - `application.yml` — production defaults (PostgreSQL, CORS, security)
  - `application-test.yml` — Testcontainers Postgres for tests
  - `application-it.yml` — loosened mTLS for issuer integration tests
- **Tests:** `src/test/java/...` — 40+ JUnit 5 integration & unit tests covering all major flows

### Flutter Client
- **Root:** `client/pubspec.yaml` — Flutter stable, Dart 3.x, sodium_libs, http, cbor, mocktail
- **API clients:** `client/lib/src/api/`
  - `auth_client.dart` — login-blob fetch, challenge, verify, logout
  - `shared_client.dart` — list entries (paginated), fetch envelope CBOR
  - `directory_client.dart` — resolve issuer signing keys from public directory
- **Crypto:** `client/lib/src/crypto/`
  - Canonical CBOR codec, Ed25519, X25519, SHA256, Fingerprint, Argon2id, UuidV7
  - SecretBox, SealedBox, WrappedBlob — asymmetric + symmetric encryption
- **Envelope & directory:** `client/lib/src/envelope/`, `client/lib/src/directory/`
  - Mirrors Java codec: `EnvelopeCodec`, `EnvelopeVerifier`, `DirectoryRecordCodec`, `RootQuorum`
  - `EnvelopeRejection` (sealed class) — signature invalid, key not active, malformed CBOR, etc.
- **State management:** `client/lib/src/state/`
  - `WalletState` (ChangeNotifier) — holds active session, 10-min idle timer
  - `Session` — bearer token + in-memory private keys (zeroed on logout/timeout)
- **UI:** `client/lib/src/screens/`
  - `LoginScreen` — handle + password input, Argon2id KEK derivation, local password check, challenge-response auth
  - `SharedListScreen` — paginated entry list with issuer fingerprints, "server-visible" description badge, logout button
  - `SharedDetailScreen` — envelope download, full verification (signature + hash), decryption, plaintext display (or error)
  - `IdentityStrip` widget — displays handle, fingerprint (cryptographic anchor), optional display name (with "presentation only" badge)
- **Fixtures integration:** `client/lib/src/fixtures/`
  - Loads cross-stack CBOR/JSON fixtures from `spec/fixtures/` for contract testing
- **Tests:** `client/test/`
  - `login_screen_test.dart` — happy path, wrong password, handle validation
  - `shared_list_screen_test.dart` — list rendering, pagination, server-visible badge, logout
  - `shared_detail_screen_test.dart` — fixture-based plaintext decryption, signature-invalid error path
  - `identity_strip_test.dart` — fingerprint matches fixture, malicious display name test, presentation-only caveat
  - Crypto/envelope fixture tests mirror Java tests
- **Memory hygiene:**
  - Background app LifecycleState → clears session
  - Idle timeout → clears session
  - All key material zeroed on clear
  - No plaintext disk persistence

### Cross-Stack Fixtures & Contract Testing
- **Schema:** `spec/fixtures/manifest.json` — indexed fixture catalog
- **CBOR fixtures:** `.cbor` files for envelopes, directories, wrapped keys
- **JSON metadata:** plaintext descriptions, issuer labels, key IDs
- **Reference generator:** `spec/tools/gen.py` — Python + libsodium reference implementation that generates all fixtures
  - Ensures Java and Flutter produce identical bytes for the same inputs
  - Single source of truth for crypto format specifications
- **Fixture categories:**
  - `envelopes/` — basic-1-recipient, three-recipients, unicode-description, allow-list-update, invalid variants
  - `directory/` — issuer active, verifier active/revoked, pinned-root
  - `wrapped/` — encrypted private keys (for login)
  - `auth/` — challenge nonces, signature prefix
  - `inputs/` — handles, keypairs (seeds), passwords, plaintexts, UUIDs
  - `fingerprints/` — public-key-to-fingerprint vectors
  - `audit/` — hash-chain genesis + events

### Build & CI
- `bin/test-all.sh` — conditional test runner (Java via Maven, Flutter if `client/pubspec.yaml` exists)
- `pom.xml` — Maven plugins for Surefire (tests), Checkstyle, JaCoCo (coverage), JAR assembly
- Git history: 21 refactor commits, each implementing one logical step

---

## 3. New Functionality

**What users can now do:**

### Issuers
- Generate offline trust-root keypairs and sign threshold signatures (via `GenRootCommand`)
- Create signed directory records (issuer identity, signing keys, key rotation) with root signatures (via `SignDirectoryRecordCommand`)
- Publish new root keys and rotations (via `SignRootUpdateCommand`)
- Build CBOR envelopes from plaintext, encrypt per-verifier, and sign with issuer keypair (via `BuildEnvelopeCommand`)
- Upload envelopes to the server via mTLS client certificate (via `UploadEnvelopeCommand`)
- Rotate issuer signing keys; old envelopes remain decryptable if keys not revoked
- Update allow-list for which verifiers can decrypt each envelope

### Verifiers
- Register with the server using a handle and password
- Log in on mobile (or desktop) without ever sharing the password with the server
  - Password → Argon2id floor-param KEK derivation locally
  - KEK unwraps two Ed25519 private keys (auth, enc)
  - Sign challenge with auth key → exchange for session token
  - Session token (bearer) used for all subsequent requests
- List all envelopes shared with them, with pagination
- See issuer fingerprint (computed from directory record, not advisory display name)
- See "server-visible" description badge (reminds that description is cleartext on server)
- Tap an entry to download the CBOR envelope
- Verify envelope signature against issuer's signing key (fetched from directory)
- Decrypt content key per their recipient wrapping (X25519 SealedBox)
- Decrypt plaintext (XSalsa20-Poly1305 SecretBox)
- See plaintext or detailed error (if signature invalid, key not active, etc.)
- Session/keys are zeroed on logout, app background, or 10-minute idle
- Rotate their enc and auth keys without losing access to old envelopes

### Operators
- Monitor audit log (GET `/v1/admin/audit`) — append-only SHA-256 hash-chain of all events
- Query directory for issuer records and status
- Manually sign root key updates and publish to directory
- Configure rate limits per endpoint and auth lockout thresholds

---

## 4. Architecture Decisions

### 4.1 Canonical CBOR as Signed Format
- **Decision:** All signed payloads (envelopes, directories) are canonical CBOR bytes. The server never re-serializes.
- **Why:** Avoids canonicalization bugs. Verifier can verify signature on the exact bytes received.
- **Implementation:** Java uses custom `CanonicalCborMapper` (deterministic field order, no floats). Flutter uses same via `cbor` package.

### 4.2 End-to-End Encryption on Client
- **Decision:** Private keys (enc, auth) are derived on the client and never sent to server. Server never sees plaintext.
- **Why:** Threat model assumes server may be compromised. Encryption is not the server's responsibility.
- **Implementation:** Verifier unwraps private keys via Argon2id(password) locally; envelopes are decrypted on client.

### 4.3 Wrapped Blobs vs. Password Hashing
- **Decision:** Verifier's private keys are wrapped with a KEK (derived from password), not stored as password hash.
- **Why:** Allows password change without re-issuing credentials. Supports future OPAQUE/aPAKE migration.
- **Implementation:** SecretBox wrapping; server stores wrapped blobs, never password or KEK.

### 4.4 Issuer mTLS (X.509) for Entry Upload
- **Decision:** Issuer authentication uses client certificate, not a bearer token.
- **Why:** Decouples issuer identity from verifier sessions. No session management needed for issuers.
- **Implementation:** Spring Security X509, `IssuerPrincipalResolver` interface (swappable for tests).

### 4.5 Single-Module Maven (for now)
- **Decision:** All Java code (server + CLI) in one module, separate runtime profiles.
- **Why:** v1 simplicity. Multi-module split is post-pilot.
- **Implementation:** `application-cli.yml` configures Spring to run as CLI; regular `application.yml` for server.

### 4.6 Append-Only Audit Log with Hash Chain
- **Decision:** Audit events are written once and never modified; new event includes SHA-256(prev_event).
- **Why:** Detect tampering. Operator can verify continuity.
- **Implementation:** `HashChainAuditService` — on INSERT, fetch the last event, compute next hash, write new event.

### 4.7 Rate Limiting via Token Bucket
- **Decision:** Per-endpoint rate limits (e.g., auth challenge 10/min, login-blob 5/min) via token bucket.
- **Why:** Mitigate brute-force password attacks (combined with Argon2id floor params).
- **Implementation:** `RateLimitInterceptor` checks quota before handler; `AuthLockoutService` locks verifier after N failures.

### 4.8 Directory Record Validity Windows
- **Decision:** Directory records have `valid_from` and `valid_until` timestamps (ms epoch). Verification checks active keys at envelope creation time.
- **Why:** Support key rotation without breaking old envelopes.
- **Implementation:** `EnvelopeVerifier` resolves key at envelope's `created_at`; rejects if outside window.

### 4.9 Fixture-Driven Contract Testing
- **Decision:** Cross-stack fixtures (CBOR envelopes, directories) generated once from Python reference impl, committed to repo.
- **Why:** Guarantees Java and Flutter produce identical bytes. Single source of truth.
- **Implementation:** `spec/tools/gen.py` is the reference. Java and Flutter tests load fixtures and verify codecs match.

### 4.10 Pagination with Cursor (not offset)
- **Decision:** `GET /v1/shared` returns `next_cursor` (opaque string); client includes in next request.
- **Why:** Handles server-side filtering/sorting without exposing row count. Graceful under updates.
- **Implementation:** `Cursor` class encodes (created_at, entry_id) to base64; decoder reconstructs for SQL where clause.

---

## 5. Configuration

### 5.1 Environment Variables (Server)
- `DATAWALLET_POSTGRES_URL` — JDBC connection string (default: `jdbc:postgresql://localhost/datawallet`)
- `DATAWALLET_POSTGRES_USER` — DB user (default: `wallet_app`)
- `DATAWALLET_POSTGRES_PASSWORD` — DB password
- `DATAWALLET_ISSUER_CERT_PATH` — path to X.509 client cert for issuer mTLS (production only)
- `DATAWALLET_ISSUER_KEY_PATH` — path to private key for issuer cert
- `DATAWALLET_PINNED_ROOT` — base64url-encoded CBOR of pinned root quorum (production only)

### 5.2 Application Configuration Files
- **`application.yml`** — production defaults
  - CORS allowed origins (default: `http://localhost:3000`)
  - Rate limits (e.g., auth challenge 10/min, login-blob 5/min)
  - Argon2id floor params (m=655360, t=2, p=1 ≈ 1-4 s per derivation)
  - Session token length (32 bytes)
  - Audit log table name
- **`application-test.yml`** — Testcontainers Postgres configuration
- **`application-it.yml`** — issuer integration tests with stubbed principal resolver

### 5.3 Flutter Configuration
- **Build-time environment variables:**
  - `DATAWALLET_BASE_URL` — API base URL (default: `http://localhost:8080`)
  - Passed via `flutter run --dart-define=DATAWALLET_BASE_URL=https://...`
- **No runtime config file** — all settings are hardcoded or environment-injected

### 5.4 CLI Configuration
- **`application-cli.yml`** — Spring Boot CLI profile (no web server, no Postgres connection)
- **Command-line arguments:** each CLI command has `--help`
  - `gen-root --count 3 --threshold 2 --output root.cbor` — generate 3-of-3 root quorum
  - `sign-dir --record issuer.cbor --root-keys root1.pem root2.pem --output signed.cbor`
  - `build-envelope --plaintext data.txt --issuer-key issuer.pem --verifiers alice bob`

---

## 6. Testing

### 6.1 Java Tests
**Command:** `mvn verify`

**Test categories:**
- **Unit tests** — crypto primitives, CBOR codec, envelope codec, directory codec
  - `CanonicalCborMapperTest` — round-trip JSON ↔ CBOR, canonicity
  - `PrimitivesFixtureTest` — all crypto operations against fixture vectors
  - `DirectoryFixtureTest` — directory codec + root quorum validation
  - `EnvelopeFixtureTest` — envelope codec + signature + hash verification
  - `FixturesManifestIntegrityTest` — fixture catalog is well-formed

- **Integration tests** (Testcontainers PostgreSQL)
  - `VerifierControllerIT` — registration, login-blob, key rotation, password change
  - `AuthControllerIT` — challenge, verify, logout, lockout
  - `SharedControllerIT` — list (paginated), detail fetch
  - `EntryControllerIT` — envelope upload, allow-list update
  - `IssuerKeyControllerIT` — issuer key rotation
  - `AdminAuditControllerIT` — audit log append + integrity
  - `AdminDirectoryControllerIT` — directory queries
  - `VerifierRotationControllerIT` — full key rotation flow
  - `RateLimitInterceptorIT`, `AuthLockoutIT` — rate limiting + lockout
  - `SecurityHeadersIT`, `CorsIT` — headers + CORS
  - `SupersededPurgeJobIT` — old key rotation cleanup
  - `CliRoundTripIT` — CLI command end-to-end (gen-root, sign-dir, build-envelope, upload)

**Test coverage:** 40+ tests, ~90% code coverage on main paths

### 6.2 Flutter Tests
**Command:** `cd client && flutter test`

**Test categories:**
- **Crypto tests** — canonical CBOR, fingerprint, envelope verification against fixtures
  - `canonical_cbor_test.dart` — round-trip CBOR serialization
  - `primitives_fixture_test.dart` — crypto vectors
  - `directory_fixture_test.dart` — directory codec + quorum validation
  - `envelope_fixture_test.dart` — envelope codec + signature + decryption

- **Screen tests** (widget tests with mocktail HTTP mocks)
  - `login_screen_test.dart` — happy path, wrong password (local check), handle validation
  - `shared_list_screen_test.dart` — renders entries, pagination, server-visible badge, logout
  - `shared_detail_screen_test.dart` — fixture-based decryption, signature-invalid error path

- **Widget tests**
  - `identity_strip_test.dart` — handle + fingerprint + presentation-only badge, fixture cross-check

**Total: ~25 tests, all pass**

### 6.3 Cross-Stack Fixture Tests
- Both Java and Flutter load the same CBOR/JSON fixtures from `spec/fixtures/`
- `FixturesManifestIntegrityTest` (Java) and `fixture_manifest_integrity_test.dart` (Flutter) verify manifest well-formedness
- Envelope, directory, and wrapped-blob tests verify identical codec behavior

### 6.4 Contract Tests
- Reference implementation in `spec/tools/gen.py` generates all fixtures
- Java and Flutter tests consume them
- If either codec diverges, fixture tests fail

---

## 7. Known Limitations & Follow-Up Work

### 7.1 Git Commit Integrity (PROCESS ISSUE)
**Status:** Step-21 implementation files are untracked (not committed)

Many step-21 files (API clients, screens, state, widgets, tests) exist on disk but were not staged/committed. A clean checkout of step-21's commit would fail to compile.

**Impact:** Low (the working tree is complete).
**Fix:** Run `git add client/lib/src client/lib/main.dart client/test client/analysis_options.yaml client/pubspec.yaml` and amend or re-commit the step-21 commit.

### 7.2 Missing API Client Unit Tests
**Status:** `auth_client_test.dart` and `shared_client_test.dart` are absent

The plan specified direct HTTP unit tests for the clients, but they were not added. Login/list/detail screens indirectly test the clients, but JSON deserialization and error paths are not directly covered.

**Fix:** Add `client/test/api/auth_client_test.dart` and `shared_client_test.dart` with `MockClient` (from `package:http/testing.dart`).

### 7.3 Missing `api_client.dart` Base Class
**Status:** The spec'd file path `client/lib/src/api/api_client.dart` was not created

The three HTTP clients duplicate `_fromB64url` and `_toException` helpers.

**Fix:** Extract shared helpers into a base file or a utility module.

### 7.4 No Web Tab-Visibility Zeroing
**Status:** The plan calls for `kIsWeb` tab-visibility check; not implemented

App lifecycle `paused` and `detached` cover native mobile. Web-specific tab-visibility (`AppLifecycleState.hidden`) is not handled.

**Impact:** Very low (v1 is not a web platform; mobile is primary).
**Fix:** Add `didChangeAppLifecycleState` handler for `hidden` state (available since Flutter 3.13).

### 7.5 No OPAQUE / aPAKE Login
**Status:** Out of scope (deferred per `specs/plan.md §6 H1`)

Current login is password → Argon2id → unwrap. OPAQUE would add zero-knowledge proof.

**Fix:** Post-pilot enhancement.

### 7.6 No Password Recovery
**Status:** Out of scope

If a verifier forgets their password, they must re-register with new keys.

**Fix:** Requires out-of-band identity verification; deferred.

### 7.7 No Threshold FROST / MuSig2
**Status:** Out of scope

Root quorum is M-of-N concatenated Ed25519 signatures. True threshold schemes (FROST) are not implemented.

**Fix:** Post-pilot; consider for v2.

### 7.8 No Streaming / Chunked Uploads
**Status:** Out of scope

Envelopes are small; no multipart form or streaming support.

**Fix:** Not needed for v1 envelope sizes.

### 7.9 Audit Log Has No External Publication Target
**Status:** Out of scope

The audit log is append-only on-server. v1 ensures the head is exposed via `GET /v1/admin/audit?head=true`, but the actual external anchor (blockchain, timestamping service) is operator policy.

**Fix:** Operator runbook (not code).

### 7.10 No Multi-Active Auth Keys Per Verifier
**Status:** Out of scope

Each verifier has a single active enc key and single active auth key. Parallel keys are not supported.

**Fix:** Post-pilot; consider for v2 if needed.

---

## 8. Dependencies

### 8.1 Java Backend

| Dependency | Version | Purpose |
|---|---|---|
| Spring Boot | 3.4.x | Web framework |
| PostgreSQL JDBC | Latest | Database driver |
| Flyway | 10.x | Migrations |
| JUnit 5 | 5.x | Testing |
| Testcontainers | Latest | Docker-based test DB |
| Lazysodium-java | 5.x | libsodium via JNI |
| Jackson CBOR | Latest | CBOR codec |
| Spring Security | 6.x | X509 + bearer auth |

**Security-critical:** Lazysodium (libsodium bindings), Jackson CBOR — verify versions match the pinned pom.xml.

### 8.2 Flutter Client

| Dependency | Version | Purpose |
|---|---|---|
| Flutter | stable | UI framework |
| Dart | 3.x | Language |
| sodium_libs | 4.x | libsodium FFI/WASM |
| http | 1.6.x | HTTP client |
| cbor | 6.5.x | CBOR codec |
| mocktail | 1.x | Mocking (tests only) |
| crypto | 3.x | SHA256 (from dart:crypto) |

**Security-critical:** sodium_libs (libsodium bindings) — verify it matches Java version byte-for-byte via fixture tests.

### 8.3 Cross-Stack Fixtures

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Reference impl |
| PyNaCl | 1.5.x | libsodium bindings (Python) |
| cbor2 | Latest | CBOR codec (Python) |

---

## 9. Next Steps for Operators

### 9.1 Pre-Production
1. **Commit untracked files** — fix the git history (issue 7.1)
2. **Generate trust-root offline**
   ```bash
   java -cp datawallet-server.jar com.erikromson.datawallet.cli.CliApplication \
     gen-root --count 3 --threshold 2 --output pinned-root.cbor
   ```
3. **Publish root and directory** — sign directory records with offline root keys
4. **Deploy server** — PostgreSQL + Spring Boot app, set `DATAWALLET_PINNED_ROOT` and issuer mTLS certs
5. **Test end-to-end** — run `mvn verify` and `flutter test` in CI

### 9.2 Monitoring
- Poll `GET /v1/admin/audit?limit=100&head=true` to verify hash-chain integrity
- Rate-limit configuration via `application.yml` (adjust thresholds per load)
- Argon2id floor params (`m, t, p`) can be tuned; higher = stronger but slower

### 9.3 Key Rotation
- Operators sign new directory records with offline root keys
- Issuers use `--sign-dir` CLI command to add signatures
- Upload via issuer mTLS

### 9.4 Verifier Re-registration
- If verifier forgets password, they re-register with a new handle and new keys
- Old envelopes remain readable if issued before key revocation

---

## 10. File Structure Quick Reference

```
datawallet/
├── pom.xml                          # Maven config, Java 25
├── bin/test-all.sh                  # Runs mvn verify + flutter test
├── src/main/java/.../datawallet/
│   ├── crypto/                      # CBOR + libsodium
│   ├── envelope/                    # Envelope codec + verify
│   ├── directory/                   # Directory + root quorum
│   ├── domain/                      # JPA entities + repos
│   ├── api/                         # HTTP controllers
│   ├── security/                    # Auth + X509
│   ├── ratelimit/                   # Rate limiting + lockout
│   ├── audit/                       # Audit log
│   ├── purge/                       # Scheduled cleanup
│   └── cli/                         # Offline tools
├── src/main/resources/
│   ├── application.yml              # Prod config
│   ├── application-test.yml         # Test config
│   ├── application-it.yml           # Integration test config
│   ├── application-cli.yml          # CLI config
│   └── db/migration/                # Flyway V*.sql
├── src/test/java/.../...            # Integration tests
├── client/                          # Flutter app
│   ├── pubspec.yaml
│   ├── lib/src/
│   │   ├── api/                     # HTTP clients
│   │   ├── crypto/                  # Crypto codec
│   │   ├── envelope/                # Envelope + directory
│   │   ├── state/                   # WalletState + Session
│   │   ├── screens/                 # LoginScreen, List, Detail
│   │   ├── widgets/                 # IdentityStrip
│   │   └── fixtures/                # Fixture loading
│   └── test/                        # Widget tests
└── spec/
    ├── fixtures/                    # CBOR + JSON test data
    └── tools/gen.py                 # Reference implementation
```

---

## Appendix: Contact & Questions

- **Architecture questions:** See `specs/plan.md` (threat model, lifecycle)
- **Byte-level format questions:** See `specs/crypto-formats.md`
- **API endpoint questions:** See `specs/api.md`
- **Test data:** See `specs/fixtures.md` and `spec/tools/gen.py`

---

**End of Handoff Document**
