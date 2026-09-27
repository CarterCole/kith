#!/usr/bin/env bash
# Exercises every CLI flow against a local hub. Usage: scripts/cli-flows.sh
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p kith-cli
K="$PWD/target/debug/kith"
D="$PWD/.kith-demo/cli"
PORT=${PORT:-7788}
export KITH_HUB=http://localhost:$PORT
rm -rf "$D" && mkdir -p "$D"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "create identities (Ada uses an Ethereum wallet as a recovery signer)"
$K --home "$D/ada" init --wallet > "$D/ada.did" 2>/dev/null
$K --home "$D/bob" init > "$D/bob.did" 2>/dev/null
sed -e "s|__ADA__|$(cat "$D/ada.did")|g" -e "s|__BOB__|$(cat "$D/bob.did")|g" examples/policy/bundle.template.json > "$D/bundle.json"

$K hub serve --addr 127.0.0.1:$PORT --data "$D/hub" --bundle "$D/bundle.json" > "$D/hub.log" 2>&1 &
HUB=$!
trap 'kill $HUB 2>/dev/null' EXIT
for _ in $(seq 50); do curl -sf "$KITH_HUB/.well-known/jwks.json" >/dev/null && break; sleep 0.1; done
$K --home "$D/ada" publish && $K --home "$D/bob" publish

step "session-chain login with a software key (AAL1: billing-reader, not billing-admin)"
$K --home "$D/ada" login --aud api://invoices

step "TOTP: enroll, confirm, step up to AAL2 (dynamic role billing-admin appears)"
SECRET=$($K --home "$D/ada" totp enroll | python3 -c "import sys,json;print(json.load(sys.stdin)['secret'])")
$K --home "$D/ada" totp confirm "$($K totp code "$SECRET")" >/dev/null
echo "waiting for the next TOTP window…"; sleep $((31 - $(date +%s) % 30))
$K --home "$D/ada" login --aud api://invoices --totp "$($K totp code "$SECRET")"

step "challenge login (SIWE-style) signed by a device key"
$K --home "$D/bob" login --method challenge --aud api://invoices

step "enroll a passkey device and use it on another machine"
$K --home "$D/ada" device add --name phone --kind passkey --out "$D/phone.json"
$K --home "$D/phone" device import "$D/phone.json"
$K --home "$D/phone" login --aud api://invoices
$K --home "$D/phone" login --method challenge --aud api://invoices

step "private alias: commit, prove to one audience, verify"
$K --home "$D/ada" alias new gaming
$K --home "$D/ada" alias prove gaming --aud https://shop.example > "$D/proof.json"
$K --home "$D/bob" alias verify "$D/proof.json" --aud https://shop.example
if $K --home "$D/bob" alias verify "$D/proof.json" --aud https://other.example 2>/dev/null; then echo "FAIL: proof accepted for wrong audience"; exit 1; fi
echo "rejected for the wrong audience (good)"

step "delegation: Ada lets Bob read invoices on her behalf"
DT=$($K --home "$D/ada" delegate --to "$(cat "$D/bob.did")" --action 'Query.*' --action 'Invoice.read')
$K --home "$D/bob" login --delegation "$DT" --aud api://invoices
$K --home "$D/bob" whoami --aud api://invoices | python3 -c "import sys,json;c=json.load(sys.stdin);print('sub=',c['sub'],'\nact=',c['act'],'\ncap=',c['cap'])"

step "revoke the phone; its sessions stop working"
PHONE=$(python3 -c "import json;print(json.load(open('$D/phone.json'))['device']['id'])")
$K --home "$D/ada" device revoke "$PHONE"
rm -f "$D/phone/identity.json.tmp"
python3 - "$D/phone/identity.json" <<'PY'
import json,sys; p=sys.argv[1]; v=json.load(open(p)); v["tokens"]={}; json.dump(v,open(p,"w"))
PY
if $K --home "$D/phone" login --aud api://invoices 2>/dev/null; then echo "FAIL: revoked device logged in"; exit 1; fi
echo "revoked device refused (good)"

step "recovery: make the hub's TOTP-gated co-signer a recovery signer, then recover with 1 paper key + TOTP"
$K --home "$D/ada" rotate --add-cosigner
python3 - "$D/ada/identity.json" <<'PY'
import json,sys; p=sys.argv[1]; v=json.load(open(p)); v["recovery"]=v["recovery"][:1]; json.dump(v,open(p,"w"))
PY
echo "(deleted one of the two local recovery keys)"
if $K --home "$D/ada" rotate 2>/dev/null; then echo "FAIL: rotated without enough signers"; exit 1; fi
echo "one key alone cannot rotate (good)"
sleep $((31 - $(date +%s) % 30))
$K --home "$D/ada" rotate --revoke-devices --totp "$($K totp code "$SECRET")"
$K --home "$D/ada" status | python3 -c "import sys,json;s=json.load(sys.stdin);print('seq',s['seq'],'devices',s['devices'],'revoked',s['revoked'])"

step "all CLI flows passed"
