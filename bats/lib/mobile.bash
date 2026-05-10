#!/usr/bin/env bash
#
# Mobile-flow helpers for the e2e BATS suite. Source after util.bash.
#
# Provides:
#   install_enroll <state_dir> <intermediate_url>
#   install_share  <state_dir> <intermediate_url> <server_url> <to_handle> <plaintext>

# install_enroll <state_dir> <intermediate_url>
# Echoes the install_uuid on stdout.
install_enroll() {
    local state_dir="$1"
    local int_url="$2"
    bash "$DW_PROJECT_DIR/bin/cli.sh" enroll \
        --intermediate-url "$int_url" \
        --state-dir "$state_dir" \
        --passphrase "$DW_PASSPHRASE"
}

# install_share <state_dir> <intermediate_url> <server_url> <to_handle> <plaintext>
# Echoes the entry id on stdout.
install_share() {
    local state_dir="$1" int_url="$2" srv_url="$3" to="$4" plaintext="$5"
    bash "$DW_PROJECT_DIR/bin/cli.sh" share \
        --intermediate-url "$int_url" \
        --server-url "$srv_url" \
        --state-dir "$state_dir" \
        --passphrase "$DW_PASSPHRASE" \
        --to "$to" \
        --plaintext "$plaintext"
}
