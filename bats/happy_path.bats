#!/usr/bin/env bats
#
# Narrative happy-path test. Each step is one CLI invocation; the assertions
# are intentionally minimal (CLI exit code only) — the goal is to exercise the
# full end-to-end story, not to deeply verify intermediate state. Use
# `bats/end_to_end.bats` for the granular DB-state assertions.
#
# The story:
#   1. operator: bootstrap dev trust
#   2. verifier: register
#   3. issuer:   share an envelope with the verifier
#   4. verifier: list entries, see the new one
#   5. verifier: fetch + decrypt that entry, get the original plaintext back

load 'lib/util.bash'

HANDLE="happy_alice"
PASSWORD="happy-password-floor"
PASSPHRASE="happy-key-passphrase"
PLAINTEXT="hello from the issuer 👋"

JDBC="--jdbc-url jdbc:postgresql://localhost:5432/$DW_PG_DB
      --jdbc-user $DW_PG_USER
      --jdbc-password $DW_PG_PASSWORD"

setup_file() {
    dw_check_prereqs
    bash "$DW_PROJECT_DIR/bin/start.sh" --no-server > "$DW_LOG_DIR/start-pg.log" 2>&1 \
        || fail "Postgres setup failed"
    dw_clean_test_data
    rm -rf "$DW_STATE_DIR"
    mkdir -p "$DW_STATE_DIR"
    dw_require_server
}

cli() {
    bash "$DW_PROJECT_DIR/bin/cli.sh" "$@"
}

@test "operator: init-dev-trust seeds the trust chain" {
    run cli init-dev-trust \
        $JDBC \
        --state-dir "$DW_STATE_DIR" \
        --passphrase "$PASSPHRASE"
    assert_success
}

@test "verifier: register on the server" {
    run cli register-verifier \
        --url "$DW_SERVER_URL" \
        --handle "$HANDLE" \
        --password "$PASSWORD"
    assert_success
}

@test "issuer: share an envelope with the verifier" {
    run cli share-with-verifier \
        --url "$DW_SERVER_URL" \
        --to "$HANDLE" \
        --plaintext "$PLAINTEXT" \
        --description "happy-path test entry" \
        $JDBC \
        --state-dir "$DW_STATE_DIR" \
        --passphrase "$PASSPHRASE" \
        --dev
    assert_success
}

@test "verifier: list shared entries — sees one" {
    run cli verifier-fetch \
        --url "$DW_SERVER_URL" \
        --handle "$HANDLE" \
        --password "$PASSWORD"
    assert_success
    # one entry id printed (UUID-shaped)
    assert_line --regexp '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
}

@test "verifier: decrypt the entry, recovers the original plaintext" {
    local entry_id
    entry_id=$(cli verifier-fetch \
        --url "$DW_SERVER_URL" \
        --handle "$HANDLE" \
        --password "$PASSWORD" | head -n1)
    [ -n "$entry_id" ] || fail "no entry id returned"

    run cli verifier-fetch \
        --url "$DW_SERVER_URL" \
        --handle "$HANDLE" \
        --password "$PASSWORD" \
        --entry-id "$entry_id"
    assert_success
    assert_output --partial "$PLAINTEXT"
}
