#!/usr/bin/env bash
# Policy DAG, revocations and freshness against a local hub signing heartbeats with
# the real drand quicknet beacon (spec §8). Usage: scripts/policy-dag-demo.sh
# Set KITH_DEMO_ANCHOR=1 to also submit the policy root's digest to the public
# OpenTimestamps calendars (sends one hash to them).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p kith-cli
K="$PWD/target/debug/kith"
D="$PWD/.kith-demo/policy-dag"
PORT=${PORT:-7790}
export KITH_HUB=http://localhost:$PORT
rm -rf "$D" && mkdir -p "$D"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "identities: Acme (an org is just an identity), Ada, Bob"
$K --home "$D/acme" init > "$D/acme.did" 2>/dev/null
$K --home "$D/ada" init > "$D/ada.did" 2>/dev/null
$K --home "$D/bob" init > "$D/bob.did" 2>/dev/null
ACME=$(cat "$D/acme.did"); ADA=$(cat "$D/ada.did")
sed -e "s|__ADA__|$ADA|g" -e "s|__BOB__|$(cat "$D/bob.did")|g" examples/policy/bundle.template.json > "$D/bundle.json"

$K hub serve --addr 127.0.0.1:$PORT --data "$D/hub" --policy-org "$ACME" --beacon drand --heartbeat 3 > "$D/hub.log" 2>&1 &
HUB=$!
trap 'kill $HUB 2>/dev/null' EXIT
for _ in $(seq 50); do curl -sf "$KITH_HUB/v1/hub" >/dev/null && break; sleep 0.1; done
for who in acme ada bob; do $K --home "$D/$who" publish; done

step "Acme publishes its bundle as a DAG and commits the root in its KEL"
$K --home "$D/acme" policy publish "$D/bundle.json" --blocks-dir "$D/blocks"
echo "$(ls "$D/blocks" | wc -l | tr -d ' ') content-addressed blocks (ipfs dag import-able)"

step "Acme lets the hub sign heartbeats (a device that can only revoke)"
$K --home "$D/acme" policy add-revoker

step "a JS session that only reads Query.invoices fetches a slice, checked against Acme's KEL"
$K --home "$D/ada" policy slice --org "$ACME" --action Query.invoices

step "Ada's grants, straight from the DAG"
$K --home "$D/ada" policy grants --org "$ACME" | python3 -c "import sys,json; g=json.load(sys.stdin); print({k: g[k] for k in ('groups','roles','revoked')}); print('policies:', [p['id'] for p in g['policies']])"

step "the hub issues tokens from the DAG"
$K --home "$D/ada" login --aud api://invoices

step "freshness: heartbeats carry drand rounds, verified here with BLS12-381"
sleep 4
$K --home "$D/ada" revocations --org "$ACME"

step "Acme revokes Ada from finance (pushed, signed, hash-chained)"
$K --home "$D/acme" revoke member "$ADA" Group::finance

step "billing-reader goes too (it came through group:finance), in the DAG view…"
$K --home "$D/ada" policy grants --org "$ACME" | python3 -c "import sys,json; g=json.load(sys.stdin); print({k: g[k] for k in ('groups','roles','revoked')})"
step "…and in new tokens"
$K --home "$D/ada" login --aud api://invoices

step "the same view under different sync budgets"
echo "payments service (60 s):";  $K --home "$D/ada" revocations --org "$ACME" --max-staleness 60 | python3 -c "import sys,json; print(json.load(sys.stdin)['freshness'])"
echo "a budget of 0 s:";          $K --home "$D/ada" revocations --org "$ACME" --fresh-for 0 --max-staleness 0 | python3 -c "import sys,json; print(json.load(sys.stdin)['freshness'])"

if [ "${KITH_DEMO_ANCHOR:-}" = 1 ]; then
  step "OpenTimestamps: anchor the policy root event (confirmation takes hours)"
  $K --home "$D/acme" anchor stamp --out "$D/policy-root.ots"
  $K anchor upgrade "$D/policy-root.ots" || true
fi
step "done"
