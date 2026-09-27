#!/usr/bin/env bash
# End to end: hub + JS (Yoga) API + Python (Ariadne) API, driven by the CLI and the
# JS passkey client. Every query runs against both APIs and must match.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
K="$ROOT/target/debug/kith"
D="$ROOT/.kith-demo/e2e"
HUB_PORT=${HUB_PORT:-7799}
export KITH_HUB=http://localhost:$HUB_PORT
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
port_free() { if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then echo "port $1 is already in use (a stale demo server?)"; exit 1; fi; }
wait_for() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.1; done; echo "timeout waiting for $1"; exit 1; }

cargo build -q -p kith-cli
(cd packages/js && npm install --silent >/dev/null)
(cd packages/python && uv sync -q)
rm -rf "$D" && mkdir -p "$D"

step "identities and policy bundle"
$K --home "$D/ada" init --wallet > "$D/ada.did" 2>/dev/null
$K --home "$D/bob" init > "$D/bob.did" 2>/dev/null
sed -e "s|__ADA__|$(cat "$D/ada.did")|g" -e "s|__BOB__|$(cat "$D/bob.did")|g" examples/policy/bundle.template.json > "$D/bundle.json"
echo "ada $(cat "$D/ada.did")"; echo "bob $(cat "$D/bob.did")"

step "start hub, JS API (:4001), Python API (:4002)"
for p in $HUB_PORT 4001 4002; do port_free $p; done
$K hub serve --addr 127.0.0.1:$HUB_PORT --data "$D/hub" --bundle "$D/bundle.json" > "$D/hub.log" 2>&1 & PIDS+=($!)
wait_for "$KITH_HUB/.well-known/jwks.json"
(cd packages/js && KITH_BUNDLE="$D/bundle.json" PORT=4001 exec node examples/server.ts > "$D/js.log" 2>&1) & PIDS+=($!)
(cd packages/python && KITH_BUNDLE="$D/bundle.json" PORT=4002 exec uv run python examples/server.py > "$D/py.log" 2>&1) & PIDS+=($!)
wait_for http://127.0.0.1:4001/graphql; wait_for http://127.0.0.1:4002/
$K --home "$D/ada" publish >/dev/null 2>&1; $K --home "$D/bob" publish >/dev/null 2>&1

# q HOME QUERY [AUD] – run against both APIs, require identical results, print one.
q() {
  local tok body js py
  tok=$($K --home "$1" token --aud api://invoices)
  body=$(python3 -c 'import json,sys;print(json.dumps({"query":sys.argv[1]}))' "$2")
  js=$(curl -s -H "authorization: Bearer $tok" -H 'content-type: application/json' -d "$body" http://127.0.0.1:4001/graphql)
  py=$(curl -s -H "authorization: Bearer $tok" -H 'content-type: application/json' -d "$body" http://127.0.0.1:4002/)
  python3 - "$js" "$py" <<'PY'
import json, sys
def norm(s):
    r = json.loads(s)
    errs = sorted((e.get("extensions", {}).get("code"), tuple(e.get("path") or [])) for e in r.get("errors") or [])
    return {"data": r.get("data"), "errors": errs}
js, py = norm(sys.argv[1]), norm(sys.argv[2])
print(json.dumps(js["data"]), "errors:", [f"{c} at {'.'.join(map(str, p))}" for c, p in js["errors"]] or "none")
if js != py:
    print("MISMATCH between JS and Python APIs:\n js:", js, "\n py:", py); sys.exit(1)
PY
}

step "no token → UNAUTHENTICATED"
curl -s -H 'content-type: application/json' -d '{"query":"{ me { did } }"}' http://127.0.0.1:4001/graphql; echo

step "Ada, software key (AAL1): billing-reader sees all rows, internal notes denied"
$K --home "$D/ada" login --aud api://invoices
q "$D/ada" '{ me { aal roles } invoices { id internalNotes } }'
q "$D/ada" 'mutation { payInvoice(id: "inv_1", amount: 1200) { status } }'

step "Ada steps up with TOTP (AAL2): dynamic role billing-admin → notes + pay under limit"
SECRET=$($K --home "$D/ada" totp enroll | python3 -c "import sys,json;print(json.load(sys.stdin)['secret'])")
$K --home "$D/ada" totp confirm "$($K totp code "$SECRET")" >/dev/null
sleep $((31 - $(date +%s) % 30))
$K --home "$D/ada" login --aud api://invoices --totp "$($K totp code "$SECRET")"
q "$D/ada" '{ me { aal roles } invoices { id internalNotes } }'
q "$D/ada" 'mutation { payInvoice(id: "inv_1", amount: 1200) { status } }'
q "$D/ada" 'mutation { payInvoice(id: "inv_3", amount: 25000) { status } }'

step "Bob (staff by email domain, not finance): only his own row"
$K --home "$D/bob" login --method challenge --aud api://invoices
q "$D/bob" '{ me { roles } invoices { id ownerEmail } }'
q "$D/bob" '{ invoice(id: "inv_1") { id } }'

step "Ada delegates Query.*, Invoice.read and Mutation.* to Bob; policy still forbids delegated mutations"
DT=$($K --home "$D/ada" delegate --to "$(cat "$D/bob.did")" --action 'Query.*' --action 'Invoice.read' --action 'Mutation.*')
cp -r "$D/bob" "$D/bob-as-ada"
$K --home "$D/bob-as-ada" login --delegation "$DT" --aud api://invoices
q "$D/bob-as-ada" '{ me { did actor } invoices { id } }'
q "$D/bob-as-ada" 'mutation { payInvoice(id: "inv_1", amount: 5) { status } }'

step "browser-style passkey: create, enroll (proof of possession), login, call API"
(cd packages/js && KITH_HOME="$D/ada" KITH_BIN="$K" node examples/passkey-e2e.ts)

step "demo complete"
