#!/usr/bin/env bats
#
# End-to-end test for the Data Wallet mobile-app issuer flow.
# Runs against the full Docker stack started by bin/start-e2e.sh.
# Each scenario asserts both HTTP/CLI behaviour and DB state.

load 'lib/util.bash'
load 'lib/mobile.bash'

DW_PASSPHRASE="e2e-passphrase"
TEST_HANDLE="e2e_alice"
TEST_PASSWORD="e2e-password-floor"
PLAINTEXT="e2e mobile hello 👋"

setup_file() {
    dw_check_prereqs
    rm -rf "$DW_STATE_DIR"
    mkdir -p "$DW_STATE_DIR"
    # Stack is started by bin/start-e2e.sh before bats runs; confirm both actuators are UP.
    dw_wait_for_actuator http://localhost:8443/actuator/health
    dw_wait_for_actuator http://localhost:8444/actuator/health
    dw_clean_test_data
}

cli() { bash "$DW_PROJECT_DIR/bin/cli.sh" "$@"; }

@test "01 stack is healthy" {
    run curl -s -o /dev/null -w "%{http_code}" http://localhost:8443/actuator/health
    assert_output "200"
    run curl -s -o /dev/null -w "%{http_code}" http://localhost:8444/actuator/health
    assert_output "200"

    run dw_psql "SELECT COUNT(*) FROM pinned_root_history;"
    assert_output "1"

    run dw_psql "SELECT COUNT(*) FROM directory_records WHERE record_type='intermediate' AND status='active';"
    assert_output "1"

    # Regression guard: zero legacy root-signed issuer rows.
    run dw_psql "SELECT COUNT(*) FROM directory_records WHERE record_type='issuer' AND parent_key_id IS NULL;"
    assert_output "0"
}

@test "02 verifier self-registers" {
    run cli register-verifier --url "$DW_SERVER_URL" --handle "$TEST_HANDLE" --password "$TEST_PASSWORD"
    assert_success
    assert_output --partial "Status: 201"

    run dw_psql "SELECT COUNT(*) FROM verifiers WHERE handle='$TEST_HANDLE';"
    assert_output "1"
}

@test "03 issuer self-enrolls against intermediate" {
    run install_enroll "$DW_STATE_DIR" "http://localhost:8444"
    assert_success

    assert_file_exists "$DW_STATE_DIR/install.privkey.box"
    assert_file_exists "$DW_STATE_DIR/install.signed_record.cbor"

    run dw_psql "SELECT COUNT(*) FROM directory_records WHERE record_type='issuer';"
    assert_output "1"

    # Issuer and intermediate have different key_ids.
    run dw_psql "SELECT
        (SELECT key_id FROM directory_records WHERE record_type='issuer' LIMIT 1)
        = (SELECT key_id FROM directory_records WHERE record_type='intermediate' LIMIT 1);"
    assert_output "f"

    # Issuer's parent_key_id matches the intermediate's key_id.
    run dw_psql "SELECT
        (SELECT parent_key_id FROM directory_records WHERE record_type='issuer' LIMIT 1)
        = (SELECT key_id FROM directory_records WHERE record_type='intermediate' LIMIT 1);"
    assert_output "t"
}

@test "04 issuer sends a text envelope to the verifier" {
    run install_share "$DW_STATE_DIR" "http://localhost:8444" "$DW_SERVER_URL" "$TEST_HANDLE" "$PLAINTEXT"
    assert_success
    assert_line --regexp '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

    run dw_psql "SELECT COUNT(*) FROM entries;"
    assert_output "1"

    run dw_psql "SELECT COUNT(*) FROM entry_recipients er
                 JOIN verifiers v ON v.verifier_id = er.verifier_id
                 WHERE v.handle = '$TEST_HANDLE';"
    assert_output "1"
}

@test "05 verifier fetches the entry id" {
    run cli verifier-fetch --url "$DW_SERVER_URL" --handle "$TEST_HANDLE" --password "$TEST_PASSWORD"
    assert_success
    assert_line --regexp '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
}

@test "06 verifier decrypts the envelope, recovers the plaintext" {
    local entry_id
    entry_id=$(cli verifier-fetch --url "$DW_SERVER_URL" --handle "$TEST_HANDLE" --password "$TEST_PASSWORD" | head -n1)
    [ -n "$entry_id" ] || fail "no entry id"

    run cli verifier-fetch --url "$DW_SERVER_URL" --handle "$TEST_HANDLE" --password "$TEST_PASSWORD" --entry-id "$entry_id"
    assert_success
    assert_output --partial "$PLAINTEXT"
}

@test "07 audit log captured the entry-ingest event" {
    run dw_psql "SELECT COUNT(*) FROM audit_log WHERE event_type='entry_ingested';"
    assert_success
    refute_output "0"
}
