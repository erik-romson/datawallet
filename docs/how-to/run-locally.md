# Run locally

This page shows you how to boot the Data Wallet stack on your machine: one
Postgres container managed by Docker and one Spring Boot server. The Flutter
client is optional unless you need to exercise the UI.

## Prerequisites

- **Docker** (any recent version). The Docker daemon must be running before any
  command below.
- **JDK 25** managed via SDKMAN. The version is pinned in
  [`pom.xml`](../../pom.xml). Switch to it with `sdk use java 25-...` or let
  the session hook in `CLAUDE.md` do it automatically.
- **Maven** (any recent version, invoked as `mvn`).
- **Flutter stable channel** only if you intend to run the Flutter client. The
  Dart SDK version is pinned in
  [`client/pubspec.yaml`](../../client/pubspec.yaml).

## Bring the stack up

```sh
bash bin/start.sh
```

The script is idempotent: it reuses an existing Postgres container and server
JAR when they are already present. The three phases it runs are described in
[`bin/start.sh#L3-L6`](../../bin/start.sh#L3-L6):

1. Start (or reuse) the `datawallet-pg` Docker container on port **5432**.
2. Build the server JAR with `mvn package -DskipTests` when none is found under
   `target/`.
3. Launch the server in the foreground on port **8443**.

Press **Ctrl-C** to stop the server. The Postgres container keeps running.

### Flags

All flags are documented in [`bin/start.sh#L8-L14`](../../bin/start.sh#L8-L14).

| Flag | Effect |
|---|---|
| *(none)* | Idempotent start: reuse existing container and JAR. |
| `--dev` | Activates the `it` Spring profile and disables issuer mTLS, so test issuers are accepted without client certificates ([`bin/start.sh#L45-L51`](../../bin/start.sh#L45-L51)). Required for `init-dev-trust` and `share-with-verifier` workflows. |
| `--rebuild` | Removes the Postgres container, rebuilds the JAR from source, then starts fresh ([`bin/start.sh#L37-L40`](../../bin/start.sh#L37-L40)). |
| `--no-server` | Brings up Postgres only and exits; the server is not started ([`bin/start.sh#L126-L129`](../../bin/start.sh#L126-L129)). Used internally by `bin/start-bats.sh`. |

## Verify it's healthy

Once the server is running, probe the readiness endpoint:

```sh
curl -s -o /dev/null -w "%{http_code}" http://localhost:8443/v1/verifiers/probe/login-blob
```

Any non-`000` HTTP status code confirms the server is accepting connections. To
run a full smoke check with the BATS suite, see [Run the BATS suite](run-bats.md).

## Ports and env vars

`bin/start.sh` reads the following variables and falls back to the listed
defaults ([`bin/start.sh#L20-L27`](../../bin/start.sh#L20-L27)). Override any
of them by exporting the variable before calling the script.

| Variable | Purpose |
|---|---|
| `POSTGRES_PORT` | Host port mapped to the Postgres container (default: `5432`). |
| `POSTGRES_DB` | Database name created inside the container (default: `datawallet`). |
| `POSTGRES_USER` | Postgres role used by the application (default: `wallet_app`). |
| `POSTGRES_PASSWORD` | Password for `POSTGRES_USER` (default: `devpw`). |
| `DATAWALLET_PG_CONTAINER` | Docker container name (default: `datawallet-pg`). |
| `DATAWALLET_PG_IMAGE` | Docker image pulled when creating a new container (default: `postgres:16`). |
| `DATAWALLET_WEB_ORIGIN` | Value of the `Access-Control-Allow-Origin` header (default: `http://localhost:3000`). |

The BATS suite reads a parallel set of variables from
[`bats/lib/util.bash#L35-L43`](../../bats/lib/util.bash#L35-L43):
`DW_SERVER_URL`, `DW_PG_CONTAINER`, `DW_PG_USER`, `DW_PG_PASSWORD`,
`DW_PG_DB`, `DW_LOG_DIR`, and `DW_STATE_DIR`. Their defaults match the values
above.

## Troubleshooting

- **Port 8443 already in use.** A stale server process from a previous run is
  still bound to the port. Kill it with `lsof -ti :8443 | xargs kill`, then
  retry.
- **Port 5432 already in use.** A local Postgres instance is occupying the
  default port. Stop it, or export `POSTGRES_PORT` to a free port before
  running the script.
- **Wrong JDK on PATH.** The script invokes whichever `java` it finds first.
  Run `sdk use java 25-...` to switch to the pinned version before calling
  `bin/start.sh`.
- **Stale `target/batstest/` directory.** Leftover state from a previous test
  run can cause the BATS suite to report unexpected failures. Delete
  `target/batstest/` and restart.

## See also

- [Run the BATS suite](run-bats.md) — run `bats/happy_path.bats` and
  `bats/end_to_end.bats` through a managed server lifecycle.
- [First share tutorial](../tutorials/first-share.md) — walk through a
  complete issuer-to-verifier flow against a running stack.
- [README](../README.md)
