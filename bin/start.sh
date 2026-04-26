#!/usr/bin/env bash
#
# Start the Data Wallet stack locally:
#   1. Postgres in Docker (skipped if container already exists/running)
#   2. Server JAR (skipped if target/datawallet-*.jar exists)
#   3. Server process (foreground)
#
# Usage:
#   bin/start.sh                # idempotent: reuse existing container + JAR
#   bin/start.sh --dev          # also activates 'it' profile + disables issuer mTLS
#                               # (needed for init-dev-trust / share-with-verifier)
#   bin/start.sh --rebuild      # tear down PG, repackage JAR, then start fresh
#   bin/start.sh --no-server    # only ensure Postgres is up (e.g. for tests)
#   bin/start.sh --help

set -euo pipefail

# --- defaults ----------------------------------------------------------------

PG_CONTAINER="${DATAWALLET_PG_CONTAINER:-datawallet-pg}"
PG_IMAGE="${DATAWALLET_PG_IMAGE:-postgres:16}"
PG_DB="${POSTGRES_DB:-datawallet}"
PG_USER="${POSTGRES_USER:-wallet_app}"
PG_PASSWORD="${POSTGRES_PASSWORD:-devpw}"
PG_PORT="${POSTGRES_PORT:-5432}"

WEB_ORIGIN="${DATAWALLET_WEB_ORIGIN:-http://localhost:3000}"

REBUILD=0
START_SERVER=1
DEV=0

# --- args --------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild)
            REBUILD=1
            shift
            ;;
        --no-server)
            START_SERVER=0
            shift
            ;;
        --dev)
            # Activates 'it' profile (StubIssuerPrincipalResolver reads
            # X-Test-Issuer-Id) and disables issuer mTLS, so init-dev-trust /
            # share-with-verifier work without client certs.
            DEV=1
            shift
            ;;
        -h|--help)
            sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Run '$0 --help' for usage." >&2
            exit 2
            ;;
    esac
done

cd "$(dirname "$0")/.."

# --- preflight ---------------------------------------------------------------

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

require docker
require mvn
require java

if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is not running. Start Docker Desktop and retry." >&2
    exit 1
fi

# --- 1. Postgres -------------------------------------------------------------

container_exists() {
    docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"
}

container_running() {
    docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"
}

if [ "$REBUILD" -eq 1 ] && container_exists; then
    echo "[pg] --rebuild: removing existing container '$PG_CONTAINER'"
    docker rm -f "$PG_CONTAINER" >/dev/null
fi

if container_running; then
    echo "[pg] container '$PG_CONTAINER' already running — reusing"
elif container_exists; then
    echo "[pg] starting stopped container '$PG_CONTAINER'"
    docker start "$PG_CONTAINER" >/dev/null
else
    echo "[pg] launching new container '$PG_CONTAINER' on port $PG_PORT"
    docker run -d \
        --name "$PG_CONTAINER" \
        -e POSTGRES_DB="$PG_DB" \
        -e POSTGRES_USER="$PG_USER" \
        -e POSTGRES_PASSWORD="$PG_PASSWORD" \
        -p "$PG_PORT:5432" \
        "$PG_IMAGE" >/dev/null
fi

# Wait for Postgres readiness (max ~30s)
echo "[pg] waiting for Postgres to accept connections"
for i in $(seq 1 30); do
    if docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
        echo "[pg] ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[pg] Postgres did not become ready within 30s" >&2
        exit 1
    fi
    sleep 1
done

if [ "$START_SERVER" -eq 0 ]; then
    echo "[done] --no-server requested; Postgres is up at localhost:$PG_PORT"
    exit 0
fi

# --- 2. Server JAR -----------------------------------------------------------

JAR_GLOB="target/datawallet-*.jar"
# shellcheck disable=SC2086
existing_jar=$(ls -1 $JAR_GLOB 2>/dev/null | grep -v '\.original$' | head -n 1 || true)

if [ "$REBUILD" -eq 1 ]; then
    echo "[build] --rebuild: mvn clean package"
    mvn -B -DskipTests clean package
    existing_jar=$(ls -1 $JAR_GLOB 2>/dev/null | grep -v '\.original$' | head -n 1)
elif [ -n "$existing_jar" ]; then
    echo "[build] reusing existing artifact: $existing_jar"
else
    echo "[build] no JAR found — running mvn package"
    mvn -B -DskipTests package
    existing_jar=$(ls -1 $JAR_GLOB 2>/dev/null | grep -v '\.original$' | head -n 1)
fi

if [ -z "$existing_jar" ]; then
    echo "[build] expected $JAR_GLOB after package phase but found none" >&2
    exit 1
fi

# --- 3. Run server -----------------------------------------------------------

echo "[server] starting $existing_jar (port 8443)"
if [ "$DEV" -eq 1 ]; then
    echo "[server] --dev: profile=it, issuer-mtls=false (X-Test-Issuer-Id accepted)"
fi
echo "[server] press Ctrl-C to stop. Postgres container will keep running."
echo

JVM_ARGS=()
if [ "$DEV" -eq 1 ]; then
    JVM_ARGS+=("-Dspring.profiles.active=it")
    JVM_ARGS+=("-Ddatawallet.security.issuer-mtls=false")
fi

exec env \
    SPRING_DATASOURCE_URL="jdbc:postgresql://localhost:$PG_PORT/$PG_DB" \
    SPRING_DATASOURCE_USERNAME="$PG_USER" \
    SPRING_DATASOURCE_PASSWORD="$PG_PASSWORD" \
    DATAWALLET_WEB_ORIGIN="$WEB_ORIGIN" \
    java "${JVM_ARGS[@]}" -jar "$existing_jar"
