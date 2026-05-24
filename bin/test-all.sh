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

# Fixture drift check — committed fixtures must match gen.py output
echo "--- Fixture drift check ---"
if [ -d spec/tools/.venv ]; then
    spec/tools/.venv/bin/python3 spec/tools/gen.py --check
elif command -v python3 &>/dev/null; then
    python3 spec/tools/gen.py --check
else
    echo "ERROR: python3 not available; fixture drift check cannot run" >&2
    exit 1
fi

if [ -f intermediate/pom.xml ]; then
    echo "--- Intermediate test phase ---"
    mvn -B -f intermediate/pom.xml verify
fi

if [ -f client/pubspec.yaml ]; then
    echo "--- Flutter test phase ---"
    (cd client && flutter pub get && flutter test)
fi
