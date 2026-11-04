#!/usr/bin/env bash
# Browser sign-up end to end (headless Chrome + virtual passkey): from an app's
# sign-in to "Create an account", a recovery key and a passkey made in the browser,
# then signing in as the new identity; and sign-up through a provider (a mock OpenID
# Connect server).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
K="$ROOT/target/debug/kith"
D="$ROOT/.kith-demo/signup"
PORT=${HUB_PORT:-7791}
export KITH_ISSUER=http://localhost:$PORT
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
port_free() { if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $1 is already in use (a stale demo server?)"; exit 1; fi; }
wait_for() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.1; done; echo "timeout: $1"; exit 1; }

cargo build -q -p kith-cli
(cd packages/js && npm install --silent >/dev/null)
for p in $PORT 3000 7792; do port_free $p; done
rm -rf "$D" && mkdir -p "$D/shots"
(cd packages/js && exec node examples/mock-oidc-provider.ts > "$D/provider.log" 2>&1) & PIDS+=($!)
wait_for http://localhost:7792/.well-known/openid-configuration
cat > "$D/upstreams.json" <<JSON
[{"id": "mock", "name": "Mock ID", "issuer": "http://localhost:7792", "client_id": "hub", "client_secret": "s", "scope": "openid"}]
JSON
$K hub serve --addr 127.0.0.1:$PORT --data "$D/hub" --clients examples/oidc/clients.json --upstreams "$D/upstreams.json" --signup > "$D/hub.log" 2>&1 & PIDS+=($!)
wait_for "$KITH_ISSUER/.well-known/openid-configuration"
(cd packages/js && exec node examples/oidc-rp.ts > "$D/rp.log" 2>&1) & PIDS+=($!)
wait_for http://localhost:3000/

echo "== sign-up in a browser (Chrome, virtual authenticator)"
(cd packages/js && SHOTS="$D/shots" node examples/signup-e2e.ts)
echo "== sign-up demo passed (screenshots in $D/shots)"
