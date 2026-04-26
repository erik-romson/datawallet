#!/usr/bin/env bash
#
# Start the Flutter verifier client in Chrome against a local server.
#
# Steps (each skipped if already done):
#   1. flutter pub get        (skipped if .dart_tool/package_config.json exists)
#   2. dart run sodium:update_web --sumo
#                             (skipped if client/web/sodium.js already exists)
#   3. flutter run -d chrome --web-port=$PORT
#
# Usage:
#   bin/start-client.sh                          # idempotent
#   bin/start-client.sh --rebuild                # flutter clean + redo all steps
#   DATAWALLET_BASE_URL=... bin/start-client.sh  # override server URL
#   FLUTTER_WEB_PORT=4000 bin/start-client.sh    # override Chrome port
#
# IMPORTANT: the chosen port must match the server's DATAWALLET_WEB_ORIGIN
# (default http://localhost:3000) or the browser will block requests via CORS.

set -euo pipefail

PORT="${FLUTTER_WEB_PORT:-3000}"
BASE_URL="${DATAWALLET_BASE_URL:-http://localhost:8443}"
REBUILD=0

while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild)
            REBUILD=1
            shift
            ;;
        -h|--help)
            sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
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
cd client

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

require flutter
require dart

if [ "$REBUILD" -eq 1 ]; then
    echo "[client] --rebuild: flutter clean"
    flutter clean
fi

# 1. pub get
if [ ! -f .dart_tool/package_config.json ] || [ "$REBUILD" -eq 1 ]; then
    echo "[client] flutter pub get"
    flutter pub get
else
    echo "[client] packages already resolved (.dart_tool/package_config.json) — skipping pub get"
fi

# 2. sodium web payload
if [ ! -f web/sodium.js ] || [ "$REBUILD" -eq 1 ]; then
    echo "[client] dart run sodium:update_web --sumo"
    dart run sodium:update_web --sumo
else
    echo "[client] web/sodium.js already present — skipping update_web"
fi

# 3. run
echo "[client] flutter run -d chrome --web-port=$PORT (server: $BASE_URL)"
echo "[client] reach the app at http://localhost:$PORT"
exec flutter run -d chrome \
    --web-port="$PORT" \
    --dart-define=DATAWALLET_BASE_URL="$BASE_URL"
