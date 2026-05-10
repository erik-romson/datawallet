# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this repo is

Data Wallet: a Spring Boot **server** + an HSM-backed **intermediate** signing service + Flutter verifier client + Java CLI. **Each Java deployable is a top-level Maven project** at the repo root (`./pom.xml` for the server, `intermediate/pom.xml` for the intermediate). Both inherit from a shared uber-pom at `parent/pom.xml` that pins dependency and plugin versions in lockstep. Flutter project under `client/`; cross-stack fixtures under `spec/`.

Authoritative specs (in priority order, most-specific wins):

1. `docs/specs/crypto-formats.md` — byte layouts
2. `docs/specs/api.md` — wire formats and HTTP behavior
3. `docs/specs/plan.md` — design, threat model, lifecycle
4. `docs/specs/fixtures.md` — fixture catalog

If code disagrees with a spec, the spec wins; fix the code (and the fixture if a byte-format bug). Never hand-edit `spec/fixtures/*.cbor` — regenerate via `spec/tools/gen.py`.

## Build commands

```sh
bash bin/test-all.sh        # full test pipeline (Java + Flutter when client present)
mvn verify                  # Java only
(cd client && flutter test) # Flutter only
bash bin/start-e2e.sh       # full Docker e2e (~5 min)
```

The Flutter phase is conditional on `client/pubspec.yaml` existing, so Java-only changes don't require Flutter to be installed.

Integration tests use Testcontainers; Docker must be running.

## Java environment

- Java 25 (pinned via `pom.xml`). The SessionStart hook auto-switches via SDKMAN.
- Spring Boot 3.x, libsodium via `lazysodium-java`.
- Package root: `com.erikromson.datawallet`. Do not move it.

## Flutter environment

- Stable channel, Dart 3.x.
- Crypto via `sodium_libs` (FFI native, WASM web).
- HTTP via `package:http`. Mocks via `mocktail` in tests.

## Hard rules

- **Maven layout:** each deployable JAR has its own top-level `pom.xml`. The shared uber-pom at `parent/pom.xml` (`packaging=pom`, no `<modules>`) is inherited by every deployable's pom and is the only place dependency and plugin versions are declared. Deployables build independently — `mvn -f <deployable>/pom.xml verify`.
- **Crypto sources:** libsodium only. Never `java.security.SecureRandom` or `dart:math.Random` for keys, nonces, or session tokens.
- **Signed payloads are canonical CBOR bytes.** Wire bytes = DB `BYTEA` bytes = signed bytes. Never re-serialize on the server.
- **Wire format split:** signed payloads use `application/cbor`; everything else is JSON with binary fields as base64url *without padding*.
- **Cross-stack equality:** Java and Flutter must produce identical bytes for every fixture. If they diverge, fix the codec or regenerate the fixture via `gen.py` — do not patch around it.
- **Migrations are append-only.** New file `V<n>__name.sql`. Never edit a previously applied migration. Add constraints in the same migration that needs them.
- **Two Postgres roles:** `wallet_app` for DML; `wallet_admin` for migrations and admin reads.
- **Auth:** opaque 32-byte bearer tokens. No cookies, no CSRF surface, no refresh tokens (re-login is the path).
- **Time:** UTC milliseconds since epoch as `uint` in CBOR/JSON; `TIMESTAMPTZ` in Postgres.
- **AuditService is an interface.** Controllers call it via the stable interface; never inline audit writes.
- **`IssuerPrincipalResolver` is an interface.** Production uses Spring Security X509; tests inject a stub via `application-it.yml`.

## Style

- **No comments-as-prose.** Single-line comments only when *why* is non-obvious. Never describe *what*; well-named identifiers do that.
- **No backwards-compat shims** unless explicitly requested. This is greenfield; rename/delete freely.
- **No defensive validation at internal boundaries.** Validate at system edges only (HTTP, CLI args, DB read of external bytes).
- **Tests are independent.** No inter-test ordering. Use `@Transactional` or explicit cleanup.

## Out of scope (don't implement these without explicit ask)

OPAQUE/aPAKE login, password recovery, refresh tokens, multi-active auth keys per verifier, WebSocket push, streaming uploads, FROST/MuSig2, TLS channel-binding of session tokens, per-column TDE, off-heap/`mlock` buffers, server-side search/filter beyond `since`+cursor, mixed-script Unicode handles, audit-anchor external publication, multi-module Maven split, dedicated issuer Flutter app, web client UX polish.

See `docs/specs/plan.md` "Out of Scope" for rationale.

## Where to look

| Topic | Path |
|---|---|
| HTTP controllers | `src/main/java/.../api/` |
| JPA entities + repos | `src/main/java/.../domain/` |
| Crypto primitives (Java) | `src/main/java/.../crypto/` |
| Envelope codec (Java) | `src/main/java/.../envelope/` |
| Directory + root quorum (Java) | `src/main/java/.../directory/` |
| Security (mTLS, bearer, headers) | `src/main/java/.../security/` |
| Rate limit + lockout | `src/main/java/.../ratelimit/` |
| Audit hash chain | `src/main/java/.../audit/` |
| CLI commands | `src/main/java/.../cli/` |
| Flyway migrations | `src/main/resources/db/migration/` |
| Flutter UI | `client/lib/src/{screens,widgets}/` |
| Flutter HTTP clients | `client/lib/src/api/` |
| Flutter crypto/envelope/directory | `client/lib/src/{crypto,envelope,directory}/` |
| Flutter session/state | `client/lib/src/state/` |
| Cross-stack fixtures | `spec/fixtures/` |
| Reference generator | `spec/tools/gen.py` |
| Spec docs | `docs/specs/{plan,api,crypto-formats,fixtures}.md` |
| Implementation handoff | `docs/handoff.md` |

## Common workflows

**Adding an HTTP endpoint:** controller in `api/`, DTOs co-located, integration test in `src/test/java/.../api/<area>/`. Update `api.md` if it's a wire-format change.

**Changing a byte format:** update `docs/specs/crypto-formats.md` first, regenerate fixtures via `spec/tools/gen.py`, then update both Java and Flutter codecs to match. Both stacks' fixture tests must pass.

**Adding a migration:** new `V<n>__name.sql` file. If it adds a constraint, the data being inserted by current code must already satisfy it.

**Adding a Flutter screen:** files under `client/lib/src/screens/`, widget tests under `client/test/`. Mock HTTP via `mocktail`. Never persist plaintext or private keys to disk; zero key material on logout/idle/background.

## Environment hooks

A SessionStart hook auto-switches Java via SDKMAN to match `pom.xml`. The hook output appears at session start; nothing to configure manually.
