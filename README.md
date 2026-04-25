# Data Wallet

End-to-end encrypted, issuer-signed envelope storage with verifier-side decryption. v1 pilot.

## What it is

A three-component system:

- **Spring Boot server** — stores encrypted envelopes and signed directory records; never sees plaintext or private keys.
- **Flutter verifier client** — log in (Argon2id → unwrap private keys locally), list shared entries, decrypt and display plaintext.
- **Java CLI** — offline trust-root signing, directory-record publishing, issuer envelope authoring.

All crypto via libsodium. Signed payloads are canonical CBOR bytes; everything else is JSON with binary fields as base64url (no padding). Bearer auth over TLS, no cookies.

See `docs/specs/plan.md`, `docs/specs/api.md`, `docs/specs/crypto-formats.md`, and `docs/specs/fixtures.md` for authoritative specs.

## Repository layout

```
datawallet/
├── pom.xml                            # Maven single-module, Java 25, Spring Boot 3.x
├── bin/test-all.sh                    # mvn verify + (conditional) flutter test
├── src/main/java/com/wilhelmsen/cbslink/plugin/datawallet/
│   ├── crypto/         envelope/      directory/    domain/
│   ├── api/            security/      ratelimit/    audit/
│   ├── purge/          cli/
│   └── DataWalletApplication.java
├── src/main/resources/
│   ├── application.yml                # production
│   ├── application-test.yml           # Testcontainers Postgres
│   ├── application-it.yml             # stubbed mTLS for issuer ingest tests
│   ├── application-cli.yml            # CLI profile (no web, no DB)
│   └── db/migration/V*.sql            # Flyway, append-only
├── src/test/java/...                  # JUnit 5 + Testcontainers
├── client/                            # Flutter app (Dart 3.x, sodium_libs)
│   ├── lib/src/{api,crypto,envelope,directory,state,screens,widgets,fixtures}
│   └── test/
└── spec/
    ├── fixtures/                      # canonical CBOR + JSON, manifest-indexed
    └── tools/gen.py                   # Python + pynacl reference generator
```

## Prerequisites

- Java 25 (managed via SDKMAN; project pins via `pom.xml` `maven.compiler.release`)
- Maven 3.9+
- Docker (for Testcontainers Postgres)
- Flutter stable, Dart 3.x (only required if building/testing the client)
- Python 3.10+ with `pynacl` and `cbor2` (only required if regenerating fixtures)
- libsodium installed locally (lazysodium-java loads it; sodium_libs ships its own)

## Build and test

```sh
bash bin/test-all.sh        # mvn verify + flutter test (if client/pubspec.yaml exists)
mvn verify                  # Java only
(cd client && flutter test) # Flutter only
bin/start-bats.sh           # end-to-end BATS suite (Postgres + server + CLI)
```

Integration tests boot a Postgres container per class. The first run pulls images.

The BATS suite (`bats/end_to_end.bats`) drives the full stack: brings up Postgres, builds and starts the server with `--dev`, then walks `bin/cli.sh` through register-verifier → init-dev-trust → share-with-verifier and asserts the corresponding rows in `verifiers`, `pinned_root_history`, `directory_records`, `entries`, `entry_recipients`, and `audit_log` after each step. `bin/start-bats.sh` owns the server lifecycle (bats's process tree can't keep a child JVM alive).

## Running the server

The server expects a PostgreSQL instance and a few required env vars. The minimal local setup:

```sh
# 1. Start Postgres (one-shot Docker container)
docker run -d --name datawallet-pg \
  -e POSTGRES_DB=datawallet \
  -e POSTGRES_USER=wallet_app \
  -e POSTGRES_PASSWORD=devpw \
  -p 5432:5432 \
  postgres:16

# 2. Build the JAR
mvn -DskipTests package

# 3. Run with required env vars
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/datawallet \
SPRING_DATASOURCE_USERNAME=wallet_app \
SPRING_DATASOURCE_PASSWORD=devpw \
DATAWALLET_WEB_ORIGIN=http://localhost:3000 \
java -jar target/datawallet-*.jar
```

The server listens on **port 8443** (HTTP in dev; configure TLS termination upstream for production). Health check at `GET /actuator/health`.

For dev iteration without packaging:

```sh
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/datawallet \
SPRING_DATASOURCE_USERNAME=wallet_app \
SPRING_DATASOURCE_PASSWORD=devpw \
mvn spring-boot:run
```

Flyway runs migrations automatically on startup (Java 25 may print a Hibernate `ddl-auto: validate` notice — that's expected).

### Server env vars

| Variable | Required | Purpose |
|---|---|---|
| `SPRING_DATASOURCE_URL` | yes | JDBC URL |
| `SPRING_DATASOURCE_USERNAME` | yes | DB user (production uses `wallet_app`) |
| `SPRING_DATASOURCE_PASSWORD` | yes | DB password |
| `DATAWALLET_WEB_ORIGIN` | no | CORS allow-list for the Flutter web client (e.g. `http://localhost:3000`) |
| `DATAWALLET_ADMIN_OU` | no | X.509 OU required for admin mTLS (default `operators`) |

Production additionally needs the pinned root quorum loaded into the `pinned_root_history` table (use `datawallet-cli sign-root-update` and an admin endpoint) and issuer/admin client certificate trust stores configured at the TLS-terminating proxy.

Two Postgres roles in production: `wallet_app` (DML on operational tables, INSERT+SELECT on `audit_log`) and `wallet_admin` (migrations + admin reads).

### Profiles

Production never picks up `*-test.yml` or `*-it.yml`. `application-it.yml` swaps `IssuerPrincipalResolver` for a stub so ingest tests run without client certs. `application-cli.yml` disables web/DB autoconfig for the CLI.

## Running the Flutter client

The verifier app needs the server's base URL passed at build time.

```sh
cd client
flutter pub get

# Pick a target device first
flutter devices

# Run against a local server (default base URL is http://localhost:8080 — override
# to match the server's actual port, e.g. 8443):
flutter run --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
```

Common targets:

```sh
flutter run -d macos    --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
flutter run -d chrome   --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
flutter run -d <ios-id> --dart-define=DATAWALLET_BASE_URL=http://localhost:8443
```

For production, build a release artifact:

```sh
flutter build apk    --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
flutter build ios    --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
flutter build web    --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
flutter build macos  --dart-define=DATAWALLET_BASE_URL=https://wallet.example.com
```

The first launch shows the login screen. There is no in-app sign-up — verifiers are registered by an issuer/operator first (via the API or CLI), then log in with the resulting handle and password.

## Conventions

- **Java package:** `com.wilhelmsen.cbslink.plugin.datawallet`. Stable from step 01.
- **Wire format:** signed payloads are `application/cbor` (raw canonical bytes — server never re-serializes them); everything else is `application/json` with binary fields as base64url without padding.
- **Time:** UTC milliseconds since epoch (`uint`) on the wire and in CBOR; `TIMESTAMPTZ` in Postgres.
- **Crypto sources:** libsodium only. Never `java.security.SecureRandom` or `dart:math.Random` for keys, nonces, or session tokens.
- **Migrations:** append-only. New file `V<n>__name.sql`; never edit a previously applied V file. Constraints land in the same migration that needs them.
- **Comments:** explain *why*, never *what*. No prose docblocks.
- **Tests:** independent. Each `@SpringBootTest` cleans up via `@Transactional` or explicit teardown; no inter-test ordering.

## Fixtures

Cross-stack contract tests load fixtures from `spec/fixtures/`. Both Java and Flutter must produce identical bytes. To change a fixture:

1. Edit `spec/tools/gen.py`.
2. Run the generator to regenerate `spec/fixtures/**`.
3. Commit all derived files together.

Never hand-edit `spec/fixtures/*.cbor`.

## CLI

The CLI lives in the same JAR as the server but uses the `cli` Spring profile (no web server, no DB autoconfig). Wrapper script: `bin/cli.sh`.

```sh
bin/cli.sh --help              # list all commands
bin/cli.sh <command> --help    # per-command flags
```

Available commands:

| Command | Purpose |
|---|---|
| `gen-root` | Generate a root quorum keypair set + pinned-root.cbor |
| `sign-directory` | Sign a directory record with one or more root keys |
| `sign-root-update` | Sign a root-update with the old root keys |
| `build-envelope` | Encrypt plaintext for verifier recipients + sign |
| `upload-envelope` | POST a CBOR envelope to the server (via mTLS) |
| `register-verifier` | Register a new verifier (handle + password) |
| `init-dev-trust` | Generate dev trust roots + issuer keys, seed Postgres |
| `share-with-verifier` | Encrypt + sign + upload an envelope to a verifier |

The last three are dev-mode helpers. `register-verifier` works against any running server. `init-dev-trust` and `share-with-verifier --dev` need the server running with `bin/start.sh --dev` so the `it` profile + stub issuer principal resolver are wired (issuer mTLS off).

End-to-end demo:

```sh
bin/start.sh --dev                                                   # terminal 1
bin/start-client.sh                                                  # terminal 2
bin/cli.sh register-verifier --url http://localhost:8443 \
  --handle erik --password                                           # terminal 3
bin/cli.sh init-dev-trust \
  --jdbc-url jdbc:postgresql://localhost:5432/datawallet \
  --jdbc-user wallet_app --jdbc-password --passphrase
bin/cli.sh share-with-verifier --url http://localhost:8443 \
  --to erik --plaintext "Hello, erik" --description "Greeting" \
  --jdbc-url jdbc:postgresql://localhost:5432/datawallet \
  --jdbc-user wallet_app --jdbc-password --passphrase --dev
```

Log in as `erik` in the browser to see the entry.

## Out of scope for v1

OPAQUE/aPAKE login, password recovery, refresh tokens, multi-active auth keys, push notifications, streaming uploads, threshold signature schemes (FROST/MuSig2), TLS-binding of session tokens, per-column TDE, off-heap key buffers, server-side search, mixed-script handles, audit anchor publication target, multi-module Maven layout. See `docs/specs/plan.md` for the full list and rationale.

## Further reading

- `docs/specs/plan.md` — design, threat model, data model, lifecycle
- `docs/specs/api.md` — endpoints, status codes, headers, rate limits
- `docs/specs/crypto-formats.md` — byte layouts (KEK, wrapped blobs, envelope, directory, fingerprint, audit chain, root quorum)
- `docs/specs/fixtures.md` — fixture catalog and contract-test design
- `docs/handoff.md` — implementation handoff with architecture decisions and known gaps
