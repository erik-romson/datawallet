#!/usr/bin/env bash
#
# Run a Data Wallet CLI command (offline tools: gen-root, sign-directory,
# sign-root-update, build-envelope, upload-envelope, register-verifier,
# init-dev-trust, share-with-verifier).
#
# The server JAR doubles as the CLI: same JVM, same crypto code, different
# Spring profile + main class. This wrapper hides the launcher invocation.
#
# Usage:
#   bin/cli.sh <command> [args...]
#   bin/cli.sh register-verifier --url http://localhost:8443 --handle erik
#   bin/cli.sh --help
#
# If the JAR doesn't exist, this builds it via mvn package (no tests).

set -euo pipefail
cd "$(dirname "$0")/.."

JAR_GLOB="target/datawallet-*.jar"
# shellcheck disable=SC2086
JAR=$(ls -1 $JAR_GLOB 2>/dev/null | grep -v '\.original$' | head -n 1 || true)

if [ -z "$JAR" ]; then
    echo "[cli] no JAR found — running mvn package" >&2
    mvn -B -DskipTests package
    JAR=$(ls -1 $JAR_GLOB | grep -v '\.original$' | head -n 1)
fi

exec java \
    -Dloader.main=com.erikromson.datawallet.cli.CliApplication \
    -Dspring.profiles.active=cli \
    -Dspring.main.banner-mode=off \
    -Dlogging.level.root=WARN \
    -cp "$JAR" \
    org.springframework.boot.loader.launch.PropertiesLauncher \
    "$@"
