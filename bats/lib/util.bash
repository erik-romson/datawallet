#!/usr/bin/env bash
#
# Shared helpers for Data Wallet bats tests. Source this from a test file:
#
#   load 'lib/util.bash'
#
# Loads the standard bats libraries (support, assert, file) so test files
# don't need to repeat the BATS_LIB_PATH dance.
#
# Provides:
#   dw_psql <sql>          — run psql against the dev Postgres container
#   dw_wait_for_http <url> — block until the URL responds (any non-000 code)
#   dw_require_server      — fail-with-helpful-message if server isn't reachable
#   dw_clean_test_data     — wipe operational tables (keeps the schema)
#   dw_check_prereqs       — fail-fast on missing docker / java 25 / curl
#
# Constants exported:
#   DW_PROJECT_DIR  DW_SERVER_URL  DW_PG_*  DW_LOG_DIR  DW_STATE_DIR

# see https://github.com/ztombol/bats-docs#installation
# expected folder structure
# /usr/local/lib/bats
# ├── bats-assert
# ├── bats-detik
# ├── bats-file
# └── bats-support
# otherwise set BATS_LIB_PATH

export BATS_LIB_PATH="/usr/local/lib/bats/:${BATS_LIB_PATH:-}"

bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file

DW_PROJECT_DIR="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
DW_SERVER_URL="${DW_SERVER_URL:-http://localhost:8443}"
DW_PG_CONTAINER="${DW_PG_CONTAINER:-datawallet-pg}"
DW_PG_USER="${DW_PG_USER:-wallet_app}"
DW_PG_PASSWORD="${DW_PG_PASSWORD:-devpw}"
DW_PG_DB="${DW_PG_DB:-datawallet}"
DW_LOG_DIR="$DW_PROJECT_DIR/target/batstest/logs"
DW_STATE_DIR="$DW_PROJECT_DIR/target/batstest/dev-state"

dw_psql() {
    docker exec -e PGPASSWORD="$DW_PG_PASSWORD" "$DW_PG_CONTAINER" \
        psql -U "$DW_PG_USER" -d "$DW_PG_DB" -At -c "$1"
}

dw_wait_for_http() {
    local url="$1"
    local i code
    for i in $(seq 1 60); do
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || true)
        code=${code:-000}
        if [ "$code" != "000" ]; then return 0; fi
        sleep 1
    done
    return 1
}

dw_require_server() {
    if ! dw_wait_for_http "$DW_SERVER_URL/v1/verifiers/probe-handle/login-blob"; then
        fail "Server not reachable at $DW_SERVER_URL.

Run the suite via bin/start-bats.sh, which manages the server lifecycle.
Or in a separate terminal: bin/start.sh --dev"
    fi
}

dw_clean_test_data() {
    dw_psql "DELETE FROM entry_recipients;" >/dev/null
    dw_psql "DELETE FROM entries;" >/dev/null
    dw_psql "DELETE FROM directory_records;" >/dev/null
    dw_psql "DELETE FROM pinned_root_history;" >/dev/null
    dw_psql "DELETE FROM sessions;" >/dev/null
    dw_psql "DELETE FROM auth_challenges;" >/dev/null
    dw_psql "DELETE FROM auth_lockouts;" >/dev/null
    dw_psql "DELETE FROM verifiers;" >/dev/null
}

dw_check_prereqs() {
    command -v docker >/dev/null 2>&1 || fail "docker is required"
    docker info >/dev/null 2>&1 || fail "Docker daemon is not running"
    command -v java >/dev/null 2>&1 || fail "java is required"
    local jv
    jv=$(java -version 2>&1 | head -1)
    echo "$jv" | grep -qE 'version "25(\.|")' || fail "Java 25 required, got: $jv"
    command -v curl >/dev/null 2>&1 || fail "curl is required"
}
