#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mvn -B verify

# JWT interop check — confirms hand-rolled JWS is RFC 7519/8037 compliant
if [ -f spec/tools/jwt_interop_check.py ]; then
    echo "--- JWT interop check ---"
    if [ -d .venv ]; then
        .venv/bin/python spec/tools/jwt_interop_check.py
    elif command -v python3 &>/dev/null; then
        python3 spec/tools/jwt_interop_check.py
    else
        echo "SKIP: python3 not found"
    fi
fi

if [ -f intermediate/pom.xml ]; then
    echo "--- Intermediate test phase ---"
    mvn -B -f intermediate/pom.xml verify
fi

if [ -f client/pubspec.yaml ]; then
    echo "--- Flutter test phase ---"
    (cd client && flutter pub get && flutter test)
fi
