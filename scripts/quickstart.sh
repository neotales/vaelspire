#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ] || [ ! -x "$ROOT_DIR/target/debug/vaelspire" ]; then
  "$ROOT_DIR/scripts/dev-setup.sh"
fi

# shellcheck disable=SC1091
set -a && source .env && set +a

echo "==> Starting Vaelspire Core on http://${VAELSPIRE_BIND:-127.0.0.1:8080} ..."
exec "$ROOT_DIR/target/debug/vaelspire" serve
