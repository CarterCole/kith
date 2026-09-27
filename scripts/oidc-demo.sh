#!/usr/bin/env bash
# OpenID Connect end to end in a real browser (headless Chrome + virtual passkey):
# enroll a passkey from the browser, sign in to an openid-client relying party,
# SSO, prompt=login, acr step-up, logout.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
K="$ROOT/target/debug/kith"
D="$ROOT/.kith-demo/oidc"
PORT=${HUB_PORT:-7790}
export KITH_ISSUER=http://localhost:$PORT KITH_HUB=http://localhost:$PORT
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
port_free() { if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $1 is already in use (a stale demo server?)"; exit 1; fi; }
wait_for() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.1; done; echo "timeout: $1"; exit 1; }

cargo build -q -p kith-cli
(cd packages/js && npm install --silent >/dev/null)
for p in $PORT 3000; do port_free $p; done
rm -rf "$D" && mkdir -p "$D/shots"
$K --home "$D/ada" init > "$D/ada.did" 2>/dev/null
sed -e "s|__ADA__|$(cat "$D/ada.did")|g" -e "s|__BOB__|did:kith:none|g" examples/policy/bundle.template.json > "$D/bundle.json"
$K hub serve --addr 127.0.0.1:$PORT --data "$D/hub" --bundle "$D/bundle.json" --clients examples/oidc/clients.json > "$D/hub.log" 2>&1 & PIDS+=($!)
wait_for "$KITH_ISSUER/.well-known/openid-configuration"
$K --home "$D/ada" publish >/dev/null 2>&1
(cd packages/js && exec node examples/oidc-rp.ts > "$D/rp.log" 2>&1) & PIDS+=($!)
wait_for http://localhost:3000/

echo "== browser end to end (Chrome, virtual authenticator)"
(cd packages/js && KITH_HOME="$D/ada" KITH_BIN="$K" SHOTS="$D/shots" node examples/browser-e2e.ts)
echo "== OIDC demo passed (screenshots in $D/shots)"
