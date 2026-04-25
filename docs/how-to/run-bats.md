# Run the BATS suite

This page shows you how to run the Data Wallet end-to-end BATS tests.
[`bin/start-bats.sh`](../../bin/start-bats.sh) manages the server lifecycle for
you: it ensures Postgres is up, builds the JAR if needed, starts the server
with `--dev` settings, runs both test files, and shuts the server down on exit
([`bin/start-bats.sh#L3-L13`](../../bin/start-bats.sh#L3-L13)).

Postgres must be running before you invoke the suite. If it is not, see
[Run locally](run-locally.md) — in particular the `--no-server` flag and the
troubleshooting section there.

## Prerequisites

- All prerequisites from [Run locally](run-locally.md): Docker (daemon
  running), JDK 25 via SDKMAN, and Maven.
- **BATS** itself (the `bats` binary must be on your PATH).
- **bats-support**, **bats-assert**, and **bats-file** libraries. The suite
  loads them from `/usr/local/lib/bats/` via
  [`bats/lib/util.bash#L29-L33`](../../bats/lib/util.bash#L29-L33). Install
  them under that path or export `BATS_LIB_PATH` pointing to their parent
  directory before running.
- **curl** (used by the server-readiness probe).

## Run the suite

```sh
bash bin/start-bats.sh
```

The wrapper runs both test files in sequence
([`bin/start-bats.sh#L118-L120`](../../bin/start-bats.sh#L118-L120)):

- [`bats/happy_path.bats`](../../bats/happy_path.bats) — the registration and
  share happy path. The [first share tutorial](../tutorials/first-share.md)
  walks through this file step by step.
- [`bats/end_to_end.bats`](../../bats/end_to_end.bats) — fuller end-to-end
  scenarios covering additional flows.

### Flags

| Flag | Effect |
|---|---|
| *(none)* | Reuse any existing JAR; start the server fresh. |
| `--rebuild` | Force `mvn clean package` before starting the server ([`bin/start-bats.sh#L54-L57`](../../bin/start-bats.sh#L54-L57)). Use this after changing Java source. |

## Run a single test file

To run one file directly — with the server already running via
`bin/start.sh --dev` in another terminal:

```sh
bats bats/happy_path.bats
```

```sh
bats bats/end_to_end.bats
```

The tests call `dw_require_server` at setup time, which fails with a helpful
message if the server is not reachable
([`bats/lib/util.bash#L61-L68`](../../bats/lib/util.bash#L61-L68)).

## Common failures

- **Postgres not running.** The wrapper delegates Postgres startup to
  `bin/start.sh --no-server`; if Docker is not running that step fails. Start
  Docker Desktop and retry.
- **Stale `DW_STATE_DIR`.** Leftover data in `target/batstest/` from a previous
  run can cause assertions to fail. Delete `target/batstest/` and rerun.
- **Wrong JDK on PATH.** The suite checks for Java 25 at startup
  ([`bats/lib/util.bash#L81-L88`](../../bats/lib/util.bash#L81-L88)). Switch
  with `sdk use java 25-...` and retry.
- **BATS libraries not found.** If `bats_load_library bats-support` fails,
  confirm the libraries are installed under `/usr/local/lib/bats/` or export
  `BATS_LIB_PATH` to their parent directory before running.

## See also

- [Run locally](run-locally.md) — bring up Postgres and the server manually,
  including the ports and env vars table.
- [First share tutorial](../tutorials/first-share.md) — walk through the
  happy-path scenario that `bats/happy_path.bats` exercises.
- [README](../README.md)
