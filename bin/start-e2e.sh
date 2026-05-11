#!/usr/bin/env bash
# Start the full Docker e2e stack and run BATS.
#
# Usage: bash bin/start-e2e.sh [--rebuild] [--down]
#
# --rebuild  Force a no-cache Docker image rebuild.
# --down     Tear down the stack after the BATS run (default: leave it running).
#
# Prereqs: docker, bats, curl, mvn, java 25

set -euo pipefail
cd "$(dirname "$0")/.."

REBUILD=0
DOWN=0
for arg in "$@"; do
    case "$arg" in
        --rebuild) REBUILD=1 ;;
        --down)    DOWN=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $arg" >&2; exit 2 ;;
    esac
done

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
require docker
require bats
require curl
require mvn
require java

LOG_DIR="target/batstest/logs"
STATE_DIR="target/batstest/dev-state"
mkdir -p "$LOG_DIR"
rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"

# 1. Build the JARs (host CLI needs them for bootstrap; Docker reuses cached layers).
echo "[start-e2e] building JARs..."
mvn -B -DskipTests package > "$LOG_DIR/build-server.log" 2>&1
mvn -B -f intermediate/pom.xml -DskipTests package > "$LOG_DIR/build-intermediate.log" 2>&1

# 2. Generate intermediate seed before any Docker activity (pure JVM RNG, no DB writes).
INTERMEDIATE_SIGNER_SEED_HEX=$(bash bin/cli.sh init-dev-trust --print-seed-only)
export INTERMEDIATE_SIGNER_SEED_HEX

# 3. Build Docker images (cached unless --rebuild).
COMPOSE="docker compose -f docker-compose.e2e.yml"
if [ "$REBUILD" -eq 1 ]; then
    $COMPOSE build --no-cache > "$LOG_DIR/docker-build.log" 2>&1
else
    $COMPOSE build > "$LOG_DIR/docker-build.log" 2>&1
fi

# 4. Always start from a clean volume.
$COMPOSE down -v >/dev/null 2>&1 || true

capture_logs() { $COMPOSE logs > "$LOG_DIR/compose.log" 2>&1 || true; }
teardown()     { $COMPOSE down -v >/dev/null 2>&1 || true; }

# Always capture logs on any exit; tear down on interrupt or when --down is set.
trap 'capture_logs' EXIT
trap 'capture_logs; teardown; exit 130' INT TERM

# 5. Start pg, then server. Server runs Flyway on startup — tables must exist before bootstrap.
echo "[start-e2e] starting pg..."
$COMPOSE up -d --wait --wait-timeout 120 pg

echo "[start-e2e] starting server (Flyway)..."
$COMPOSE up -d server

# 6. Wait for the server to be alive (any HTTP response, even 503 while root is missing).
echo "[start-e2e] waiting for server to be alive..."
for _ in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:8443/actuator/health 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        echo "[start-e2e] server alive (HTTP $code)"
        break
    fi
    sleep 1
done

# 7. Bootstrap: insert root + intermediate into pg. Tables now exist (Flyway ran in step 5-6).
echo "[start-e2e] bootstrapping trust roots..."
bash bin/cli.sh init-dev-trust \
    --intermediate-seed-hex "$INTERMEDIATE_SIGNER_SEED_HEX" \
    --jdbc-url "jdbc:postgresql://localhost:5433/datawallet" \
    --jdbc-user wallet_admin \
    --jdbc-password adminpw \
    --state-dir "$STATE_DIR" \
    --passphrase e2e-passphrase > "$LOG_DIR/init-dev-trust.log" 2>&1

# 8. Wait for server health UP. PinnedRootReadinessIndicator calls reloadFromDbIfStale so it
#    picks up the root inserted in step 7 within the next health check cycle.
echo "[start-e2e] waiting for server health UP..."
for _ in $(seq 1 90); do
    s=$(curl -s --max-time 2 http://localhost:8443/actuator/health 2>/dev/null || true)
    if echo "$s" | grep -q '"status":"UP"'; then
        echo "[start-e2e] server is UP"
        break
    fi
    sleep 1
done

# 9. Start intermediate with the seed injected via env.
echo "[start-e2e] starting intermediate..."
$COMPOSE up -d intermediate

echo "[start-e2e] waiting for intermediate health UP..."
intermediate_up=0
for _ in $(seq 1 90); do
    i=$(curl -s --max-time 2 http://localhost:8444/actuator/health 2>/dev/null || true)
    if echo "$i" | grep -q '"status":"UP"'; then
        echo "[start-e2e] intermediate is UP"
        intermediate_up=1
        break
    fi
    sleep 1
done
if [ "$intermediate_up" -eq 0 ]; then
    echo "[start-e2e] ERROR: intermediate never reached UP after 90s" >&2
    exit 1
fi

# 10. Run the BATS suite. Failures propagate; stack stays up unless --down was given.
echo "[start-e2e] running bats..."
bats bats/end_to_end.bats --print-output-on-failure

if [ "$DOWN" -eq 1 ]; then
    echo "[start-e2e] tearing down..."
    teardown
fi
