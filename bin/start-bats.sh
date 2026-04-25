#!/usr/bin/env bash
#
# Run the end-to-end BATS suite.
#
# Lifecycle managed here (NOT inside bats) because bats's setup_file process
# tree kills child JVMs. This wrapper:
#
#   1. Brings up Postgres (via bin/start.sh --no-server, idempotent)
#   2. Builds the JAR if missing
#   3. Starts the server with --dev settings in the background, waits for ready
#   4. Runs `bats bats/end_to_end.bats`
#   5. Stops the server (Postgres keeps running)
#
# Usage:
#   bin/start-bats.sh                # run all bats tests
#   bin/start-bats.sh --rebuild      # force a fresh JAR build first

set -euo pipefail
cd "$(dirname "$0")/.."

REBUILD=0
for arg in "$@"; do
    case "$arg" in
        --rebuild) REBUILD=1 ;;
        -h|--help)
            sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}
require docker
require java
require mvn
require bats
require curl

LOG_DIR="target/batstest/logs"
mkdir -p "$LOG_DIR"
SERVER_PID_FILE="target/batstest/server.pid"

# 1. Postgres
echo "[start-bats] ensuring Postgres..."
bash bin/start.sh --no-server > "$LOG_DIR/start-pg.log" 2>&1

# 2. JAR
if [ "$REBUILD" -eq 1 ]; then
    echo "[start-bats] --rebuild: mvn clean package"
    mvn -B -DskipTests clean package > "$LOG_DIR/build.log" 2>&1
fi
JAR=$(ls -1 target/datawallet-*.jar 2>/dev/null | grep -v '\.original$' | head -n1 || true)
if [ -z "$JAR" ]; then
    echo "[start-bats] mvn package..."
    mvn -B -DskipTests package > "$LOG_DIR/build.log" 2>&1
    JAR=$(ls -1 target/datawallet-*.jar | grep -v '\.original$' | head -n1)
fi

# 3. Server (clean any stale instance, then start fresh)
if lsof -ti :8443 >/dev/null 2>&1; then
    echo "[start-bats] killing stale server on :8443"
    lsof -ti :8443 | xargs -r kill -9 2>/dev/null || true
    sleep 1
fi

echo "[start-bats] starting server (dev profile)..."
SPRING_DATASOURCE_URL="jdbc:postgresql://localhost:5432/datawallet" \
SPRING_DATASOURCE_USERNAME="wallet_app" \
SPRING_DATASOURCE_PASSWORD="devpw" \
DATAWALLET_WEB_ORIGIN="http://localhost:3000" \
java \
    -Dspring.profiles.active=it \
    -Ddatawallet.security.issuer-mtls=false \
    -jar "$JAR" > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$SERVER_PID_FILE"

cleanup() {
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[start-bats] stopping server (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        # graceful shutdown timeout
        for _ in 1 2 3 4 5; do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$SERVER_PID_FILE"
}
trap cleanup EXIT INT TERM

echo "[start-bats] waiting for server..."
for i in $(seq 1 60); do
    # curl prints %{http_code} as "000" on connection failure already, so we
    # don't add `|| echo`; we just default an empty result.
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
        "http://localhost:8443/v1/verifiers/probe/login-blob" 2>/dev/null || true)
    code=${code:-000}
    if [ "$code" != "000" ]; then
        echo "[start-bats] server up (probe HTTP $code)"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[start-bats] server failed to start; tail of server.log:" >&2
        tail -30 "$LOG_DIR/server.log" >&2 || true
        exit 1
    fi
    sleep 1
done

# 4. Tests
echo "[start-bats] running bats..."
bats bats/happy_path.bats bats/end_to_end.bats
