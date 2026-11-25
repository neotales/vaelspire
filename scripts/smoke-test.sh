#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$ROOT_DIR/.env" ]; then
  # shellcheck disable=SC1091
  set -a && source "$ROOT_DIR/.env" && set +a
fi

BASE_URL="${1:-http://${VAELSPIRE_BIND:-127.0.0.1:8080}}"
EMAIL="${VAELSPIRE_ADMIN_EMAIL:-admin@vaelspire.local}"
PASSWORD="${VAELSPIRE_ADMIN_PASSWORD:-change-me-local-dev-password}"
COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

echo "==> 1. Checking /health and /ready on $BASE_URL"
curl -fsS "$BASE_URL/health" | grep -q '"status":"ok"'
curl -fsS "$BASE_URL/ready" | grep -q '"status":"ready"'
echo "    OK"

echo "==> 2. Checking /metrics (Prometheus exposition)"
curl -fsS "$BASE_URL/metrics" | grep -q 'vaelspire_build_info'
echo "    OK"

echo "==> 3. Confirming anonymous /forward-auth returns 401"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/forward-auth")"
[ "$STATUS" = "401" ] || { echo "expected 401, got $STATUS" >&2; exit 1; }
echo "    OK (401)"

echo "==> 4. Fetching CSRF cookie via GET /session"
curl -s -c "$COOKIES" -o /dev/null "$BASE_URL/session"
CSRF="$(awk '$6 == "neotales.csrf" { print $7 }' "$COOKIES")"
[ -n "$CSRF" ] || { echo "failed to read neotales.csrf cookie" >&2; exit 1; }

echo "==> 5. Signing in as $EMAIL"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
  -b "$COOKIES" -c "$COOKIES" \
  -H "Origin: http://localhost" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/sign-in")"
[ "$STATUS" = "200" ] || { echo "sign-in failed with HTTP $STATUS" >&2; exit 1; }
echo "    OK (200)"

echo "==> 6. Verifying authenticated /forward-auth returns 200 + identity headers"
FWD_HEADERS="$(curl -s -D - -o /dev/null -b "$COOKIES" "$BASE_URL/forward-auth")"
echo "$FWD_HEADERS" | head -n 1 | grep -q "200"
echo "$FWD_HEADERS" | grep -iq "x-vaelspire-user-id:"
echo "$FWD_HEADERS" | grep -iq "x-vaelspire-email: $EMAIL"
echo "$FWD_HEADERS" | grep -iq "x-vaelspire-auth-method: session"
echo "    OK (200 + X-Vaelspire-* headers)"

echo "==> 7. Signing out and confirming /forward-auth returns 401 again"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -b "$COOKIES" -c "$COOKIES" \
  -H "Origin: http://localhost" \
  -H "x-csrf-token: $CSRF" \
  "$BASE_URL/sign-out")"
[ "$STATUS" = "204" ] || { echo "sign-out failed with HTTP $STATUS" >&2; exit 1; }

STATUS="$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" "$BASE_URL/forward-auth")"
[ "$STATUS" = "401" ] || { echo "expected 401 after sign-out, got $STATUS" >&2; exit 1; }
echo "    OK (revoked)"

echo ""
echo "All Vaelspire smoke checks passed!"
