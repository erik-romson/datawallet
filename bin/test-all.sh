#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mvn -B verify

if [ -f client/pubspec.yaml ]; then
    echo "--- Flutter test phase ---"
    (cd client && flutter pub get && flutter test)
fi
