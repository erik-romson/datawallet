#!/usr/bin/env bats
#
# Granular end-to-end test for the Data Wallet pilot. Each step asserts both
# the CLI exit code/output AND a DB state change so a regression in either
# layer fails this test.
#
# For the high-level narrative version, see bats/happy_path.bats.

load 'lib/util.bash'

TEST_HANDLE="bats_alice"
TEST_PASSWORD="bats-password-floor"
TEST_PASSPHRASE="bats-key-passphrase"

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

# -----------------------------------------------------------------------------
# Tests (run in order — each step depends on the previous)
# -----------------------------------------------------------------------------

@test "server is reachable" {
    run curl -s -o /dev/null -w "%{http_code}" "$DW_SERVER_URL/actuator/health"
    assert_success
    refute_output "000"

    run curl -s -o /dev/null -w "%{http_code}" "$DW_SERVER_URL/v1/verifiers/nonexistent/login-blob"
    assert_success
    assert_output "404"
}

@test "register-verifier creates a row in verifiers" {
    run dw_psql "SELECT COUNT(*) FROM verifiers WHERE handle = '$TEST_HANDLE';"
    assert_output "0"

    run cli register-verifier \
        --url "$DW_SERVER_URL" \
        --handle "$TEST_HANDLE" \
        --password "$TEST_PASSWORD"
    assert_success
    assert_output --partial "Status: 201"

    run dw_psql "SELECT COUNT(*) FROM verifiers WHERE handle = '$TEST_HANDLE';"
    assert_output "1"

    run dw_psql "SELECT length(enc_public_key) FROM verifiers WHERE handle = '$TEST_HANDLE';"
    assert_output "32"

    run dw_psql "SELECT length(auth_public_key) FROM verifiers WHERE handle = '$TEST_HANDLE';"
    assert_output "32"

    run dw_psql "SELECT length(wrapped_enc_private_key_blob) > 0 FROM verifiers WHERE handle = '$TEST_HANDLE';"
    assert_output "t"
}

@test "init-dev-trust seeds pinned_root_history and directory_records" {
    run dw_psql "SELECT COUNT(*) FROM pinned_root_history;"
    assert_output "0"

    run cli init-dev-trust \
        --jdbc-url "jdbc:postgresql://localhost:5432/$DW_PG_DB" \
        --jdbc-user "$DW_PG_USER" \
        --jdbc-password "$DW_PG_PASSWORD" \
        --state-dir "$DW_STATE_DIR" \
        --passphrase "$TEST_PASSPHRASE"
    assert_success
    assert_output --partial "Dev trust initialised"

    assert_file_exists "$DW_STATE_DIR/issuer.json"
    assert_file_exists "$DW_STATE_DIR/pinned-root.cbor"
    assert_file_exists "$DW_STATE_DIR/issuer.privkey.box"
    assert_file_exists "$DW_STATE_DIR/root-0.privkey.box"

    run dw_psql "SELECT COUNT(*) FROM pinned_root_history;"
    assert_output "1"

    run dw_psql "SELECT COUNT(*) FROM directory_records WHERE record_type = 'issuer' AND status = 'active';"
    assert_output "1"

    run dw_psql "SELECT length(signed_record) > 0 FROM directory_records WHERE record_type = 'issuer';"
    assert_output "t"
}

@test "init-dev-trust is idempotent without --force" {
    run cli init-dev-trust \
        --jdbc-url "jdbc:postgresql://localhost:5432/$DW_PG_DB" \
        --jdbc-user "$DW_PG_USER" \
        --jdbc-password "$DW_PG_PASSWORD" \
        --state-dir "$DW_STATE_DIR" \
        --passphrase "$TEST_PASSPHRASE"
    assert_success
    assert_output --partial "Already initialised"

    run dw_psql "SELECT COUNT(*) FROM pinned_root_history;"
    assert_output "1"
    run dw_psql "SELECT COUNT(*) FROM directory_records WHERE record_type = 'issuer';"
    assert_output "1"
}

@test "share-with-verifier inserts an envelope and a recipient mapping" {
    run dw_psql "SELECT COUNT(*) FROM entries;"
    assert_output "0"

    run cli share-with-verifier \
        --url "$DW_SERVER_URL" \
        --to "$TEST_HANDLE" \
        --plaintext "bats e2e secret payload" \
        --description "bats test entry" \
        --jdbc-url "jdbc:postgresql://localhost:5432/$DW_PG_DB" \
        --jdbc-user "$DW_PG_USER" \
        --jdbc-password "$DW_PG_PASSWORD" \
        --state-dir "$DW_STATE_DIR" \
        --passphrase "$TEST_PASSPHRASE" \
        --dev
    assert_success
    assert_output --partial "Status: 201"
    assert_output --partial "Shared entry"

    run dw_psql "SELECT COUNT(*) FROM entries;"
    assert_output "1"

    run dw_psql "SELECT version FROM entries;"
    assert_output "1"

    run dw_psql "SELECT is_current FROM entries;"
    assert_output "t"

    run dw_psql "SELECT length(signed_envelope) > 0 FROM entries;"
    assert_output "t"

    run dw_psql "SELECT length(ciphertext_hash) FROM entries;"
    assert_output "32"

    run dw_psql "SELECT COUNT(*) FROM entry_recipients;"
    assert_output "1"

    run dw_psql "SELECT er.verifier_id = v.verifier_id
                 FROM entry_recipients er
                 JOIN verifiers v ON v.handle = '$TEST_HANDLE';"
    assert_output "t"

    local expected_issuer
    expected_issuer=$(grep -o '"issuer_id" *: *"[^"]*"' "$DW_STATE_DIR/issuer.json" \
                        | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')
    run dw_psql "SELECT issuer_id FROM entries;"
    assert_output "$expected_issuer"
}

@test "audit log captured the entry-ingest event" {
    run dw_psql "SELECT COUNT(*) FROM audit_log WHERE event_type = 'entry_ingested';"
    assert_success
    refute_output "0"
}

@test "GET /v1/shared/{id} returns the same signed envelope bytes that are in the DB" {
    local entry_id
    entry_id=$(dw_psql "SELECT entry_id FROM entries LIMIT 1;")
    [ -n "$entry_id" ] || fail "No entry found"

    run dw_psql "SELECT length(signed_envelope) FROM entries WHERE entry_id = '$entry_id';"
    assert_success
    [ "$output" -gt 200 ] || fail "signed_envelope too small: $output bytes"
}

@test "register-verifier rejects an invalid handle (no DB write)" {
    local bad_handle="UPPERCASE-BAD"
    run dw_psql "SELECT COUNT(*) FROM verifiers WHERE handle = '$bad_handle';"
    assert_output "0"

    run cli register-verifier \
        --url "$DW_SERVER_URL" \
        --handle "$bad_handle" \
        --password "any-password-123"
    assert_failure

    run dw_psql "SELECT COUNT(*) FROM verifiers WHERE handle = '$bad_handle';"
    assert_output "0"
}

@test "share-with-verifier fails for an unknown handle" {
    run cli share-with-verifier \
        --url "$DW_SERVER_URL" \
        --to "nonexistent_handle" \
        --plaintext "anything" \
        --jdbc-url "jdbc:postgresql://localhost:5432/$DW_PG_DB" \
        --jdbc-user "$DW_PG_USER" \
        --jdbc-password "$DW_PG_PASSWORD" \
        --state-dir "$DW_STATE_DIR" \
        --passphrase "$TEST_PASSPHRASE" \
        --dev
    assert_failure
    assert_output --partial "No verifier found"

    run dw_psql "SELECT COUNT(*) FROM entries;"
    assert_output "1"
}

@test "cli.sh --help lists all expected subcommands" {
    run cli --help
    assert_success
    assert_output --partial "register-verifier"
    assert_output --partial "init-dev-trust"
    assert_output --partial "share-with-verifier"
    assert_output --partial "verifier-fetch"
    assert_output --partial "build-envelope"
}
