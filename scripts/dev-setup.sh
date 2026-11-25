#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Checking Rust toolchain..."
command -v cargo >/dev/null 2>&1 || {
  echo "error: cargo is required (install Rust 1.100+ via rustup or mise)" >&2
  exit 1
}

mkdir -p .vaelspire

echo "==> Building vaelspire single binary..."
cargo build -p vaelspire

BIN="$ROOT_DIR/target/debug/vaelspire"

if [ ! -f .env ]; then
  echo "==> Generating .env with fresh 256-bit VAELSPIRE_AUTH_KEY..."
  KEY="$("$BIN" keygen)"
  umask 077
  sed "s|^VAELSPIRE_AUTH_KEY=.*|VAELSPIRE_AUTH_KEY=${KEY}|" .env.example > .env
  echo "    Created .env (mode 600). Edit VAELSPIRE_ADMIN_PASSWORD before sharing."
else
  echo "==> Keeping existing .env"
fi

# shellcheck disable=SC1091
set -a && source .env && set +a

echo "==> Running SQLite migrations..."
"$BIN" migrate

echo "==> Bootstrapping default tenant and admin account..."
"$BIN" admin bootstrap \
  --email "${VAELSPIRE_ADMIN_EMAIL:-admin@vaelspire.local}" \
  --password "${VAELSPIRE_ADMIN_PASSWORD:-change-me-local-dev-password}"

cat <<'EOF'

Vaelspire Core is ready!

Next steps:
  1. Start the server:   ./scripts/quickstart.sh
  2. Run a live check:   ./scripts/smoke-test.sh
  3. Browse docs site:   cd docs && pnpm install && pnpm dev
EOF
