#!/usr/bin/env bash
# Joining devices end to end (headless Chrome + virtual passkeys + the real CLI): an
# account made in the browser, a terminal that joins it, a phone that joins by QR link,
# the recovery key making the manage policy 2 of 3, and a device that needs two approvals.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
K="$ROOT/target/debug/kith"
D="$ROOT/.kith-demo/join"
PORT=${HUB_PORT:-7793}
export KITH_ISSUER=http://localhost:$PORT
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
port_free() { if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $1 is already in use (a stale demo server?)"; exit 1; fi; }
wait_for() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.1; done; echo "timeout: $1"; exit 1; }

cargo build -q -p kith-cli
(cd packages/js && npm install --silent >/dev/null)
port_free $PORT
rm -rf "$D" && mkdir -p "$D/shots"
$K hub serve --addr 127.0.0.1:$PORT --data "$D/hub" --signup > "$D/hub.log" 2>&1 & PIDS+=($!)
wait_for "$KITH_ISSUER/.well-known/openid-configuration"

echo "== joining devices (Chrome, virtual authenticators, kith CLI)"
(cd packages/js && KITH_BIN="$K" DEMO="$D" SHOTS="$D/shots" node examples/join-e2e.ts)
echo "== join demo passed (screenshots in $D/shots)"
