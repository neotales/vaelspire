#!/usr/bin/env bash
set -euo pipefail

# Vaelspire Interactive & Automated Demo Launcher
# Usage:
#   ./scripts/demo.sh               # Build UI + binary, run live checks, keep server up for demo
#   ./scripts/demo.sh --check-only  # Run all live checks and shut down cleanly (CI / verification)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_ONLY=false
PORT="${VAELSPIRE_DEMO_PORT:-8080}"
DEMO_DIR="${VAELSPIRE_DEMO_DIR:-/tmp/vaelspire-demo}"
ADMIN_EMAIL="admin@vaelspire.demo"
ADMIN_PASS="vaelspire-demo-pass-123!"

for arg in "$@"; do
  case "$arg" in
    --check-only) CHECK_ONLY=true ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

echo "==> [1/5] Ensuring SvelteKit UI bundle (ui/build)..."
if [[ ! -f "$ROOT_DIR/ui/build/index.html" ]]; then
  pnpm --dir "$ROOT_DIR/ui" install --frozen-lockfile || pnpm --dir "$ROOT_DIR/ui" install
  pnpm --dir "$ROOT_DIR/ui" run build
fi

echo "==> [2/5] Building vaelspire binary with --features embed-ui..."
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
CARGO_TARGET_DIR="$TARGET_DIR" cargo build \
  --manifest-path "$ROOT_DIR/Cargo.toml" \
  -p vaelspire --features embed-ui --offline
BIN="$TARGET_DIR/debug/vaelspire"

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
DB_PATH="$DEMO_DIR/demo.sqlite"
KEY_HEX="$("$BIN" keygen)"

echo "==> [3/5] Running migrations and bootstrapping demo admin ($ADMIN_EMAIL)..."
"$BIN" migrate --sqlite "$DB_PATH"
"$BIN" admin bootstrap \
  --sqlite "$DB_PATH" \
  --tenant-name "vaelspire-demo" \
  --email "$ADMIN_EMAIL" \
  --password "$ADMIN_PASS"

echo "==> [4/5] Starting Vaelspire on http://127.0.0.1:${PORT} (--ui-mode embedded)..."
VAELSPIRE_AUTH_KEY="$KEY_HEX" \
  "$BIN" serve \
  --bind "127.0.0.1:${PORT}" \
  --sqlite "$DB_PATH" \
  --tenant-name "vaelspire-demo" \
  --issuer "http://127.0.0.1:${PORT}" \
  --allowed-origins "http://127.0.0.1:${PORT}" \
  --insecure-http \
  --ui-mode embedded \
  > "$DEMO_DIR/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

BASE_URL="http://127.0.0.1:${PORT}"
for _ in $(seq 1 40); do
  if curl -fsS "${BASE_URL}/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -fsS "${BASE_URL}/ready" >/dev/null

echo "==> [5/5] Running live end-to-end demo checks..."
COOKIE_JAR="$DEMO_DIR/cookies.txt"

# 1. Health, UI HTML, OIDC Discovery, JWKS, SAML metadata
curl -fsS "${BASE_URL}/health" | grep -q '"status":"ok"'
curl -fsS "${BASE_URL}/ui/" | grep -q 'Vaelspire'
curl -fsS "${BASE_URL}/.well-known/openid-configuration" | grep -q '"jwks_uri"'
curl -fsS "${BASE_URL}/.well-known/jwks.json" | grep -q '"Ed25519"'
curl -fsS "${BASE_URL}/saml/metadata" | grep -q 'EntityDescriptor'

# 2. Prime CSRF cookie & sign in
curl -sS -c "$COOKIE_JAR" "${BASE_URL}/session" >/dev/null || true
CSRF_TOKEN="$(awk '$6 == "neotales.csrf" { print $7 }' "$COOKIE_JAR")"
curl -fsS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -H "Origin: ${BASE_URL}" \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: ${CSRF_TOKEN}" \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${BASE_URL}/sign-in" >/dev/null

# 3. Forward-Auth allows authenticated session & emits trusted headers
FWD_HEADERS="$(curl -fsSI -b "$COOKIE_JAR" "${BASE_URL}/forward-auth")"
echo "$FWD_HEADERS" | grep -qi 'x-vaelspire-user-id:'
echo "$FWD_HEADERS" | grep -qi "x-vaelspire-email: ${ADMIN_EMAIL}"

# 4. Register Vaelsgard OIDC client & test NHI client_credentials token
CLIENT_RESP="$(curl -fsS -b "$COOKIE_JAR" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"vaelsgard","name":"Vaelsgard App","confidential":true,"redirect_uris":["http://127.0.0.1:3000/auth/callback"],"allowed_scopes":["openid","email","profile","agent:read"]}' \
  "${BASE_URL}/admin/oidc/clients")"
CLIENT_SECRET="$(echo "$CLIENT_RESP" | sed -n 's/.*"client_secret":"\([^"]*\)".*/\1/p')"
test -n "$CLIENT_SECRET"

TOKEN_RESP="$(curl -fsS -u "vaelsgard:${CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=agent:read" \
  "${BASE_URL}/oauth2/token")"
echo "$TOKEN_RESP" | grep -q '"access_token"'

# 5. Provision a SCIM 2.0 user & verify listing
curl -fsS -b "$COOKIE_JAR" \
  -H "Content-Type: application/scim+json" \
  -d '{"userName":"alice@vaelspire.demo","password":"alice-demo-password-123!","active":true}' \
  "${BASE_URL}/scim/v2/Users" | grep -q 'alice@vaelspire.demo'

# 6. Verify Prometheus metrics recorded requests
curl -fsS "${BASE_URL}/metrics" | grep -q 'vaelspire_forward_auth_total'

echo ""
echo "✅ ALL LIVE DEMO CHECKS PASSED!"
echo "   • Embedded Web UI:     ${BASE_URL}/ui/"
echo "   • Admin Console:       ${BASE_URL}/ui/admin"
echo "   • OIDC Discovery:      ${BASE_URL}/.well-known/openid-configuration"
echo "   • JWKS (Ed25519):      ${BASE_URL}/.well-known/jwks.json"
echo "   • SAML Metadata:       ${BASE_URL}/saml/metadata"
echo "   • Prometheus Metrics:  ${BASE_URL}/metrics"
echo "   • Demo Admin Login:    ${ADMIN_EMAIL} / ${ADMIN_PASS}"
echo "   • Registered Client:   vaelsgard (OIDC + NHI verified)"

if [[ "$CHECK_ONLY" == "true" ]]; then
  echo "==> --check-only requested; shutting down cleanly."
  exit 0
fi

echo ""
echo "Press Ctrl+C to stop the demo server..."
wait "$SERVER_PID"
