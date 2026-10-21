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
# On macOS, keys go to the login keychain (and this device's key into the Secure
# Enclave); each run makes new identities, so drop their keychain items at the end.
cleanup() { kill "${HUB:-}" "${WFS:-}" 2>/dev/null || true; for h in ada bob phone; do $K --home "$D/$h" keys forget --yes 2>/dev/null || true; done; }
trap cleanup EXIT

step "create identities (Ada uses an Ethereum wallet as a recovery signer; Bob keeps his keys in a file for now)"
$K --home "$D/ada" init --wallet > "$D/ada.did"
$K --home "$D/bob" init --keystore file > "$D/bob.did" 2>/dev/null
$K --home "$D/ada" keys list | python3 -c 'import sys,json;print("ada keys:", ", ".join(k["role"]+"="+k["where"] for k in json.load(sys.stdin)["keys"]))'
sed -e "s|__ADA__|$(cat "$D/ada.did")|g" -e "s|__BOB__|$(cat "$D/bob.did")|g" examples/policy/bundle.template.json > "$D/bundle.json"

$K hub serve --addr 127.0.0.1:$PORT --data "$D/hub" --bundle "$D/bundle.json" > "$D/hub.log" 2>&1 &
HUB=$!
for _ in $(seq 50); do curl -sf "$KITH_HUB/.well-known/jwks.json" >/dev/null && break; sleep 0.1; done
$K --home "$D/ada" publish && $K --home "$D/bob" publish

step "session-chain login with this device's key alone (AAL1: billing-reader, not billing-admin)"
$K --home "$D/ada" login --aud api://invoices

step "TOTP: enroll, confirm, step up to AAL2 (dynamic role billing-admin appears)"
SECRET=$($K --home "$D/ada" totp enroll | python3 -c "import sys,json;print(json.load(sys.stdin)['secret'])")
$K --home "$D/ada" totp confirm "$($K totp code "$SECRET")" >/dev/null
echo "waiting for the next TOTP window…"; sleep $((31 - $(date +%s) % 30))
$K --home "$D/ada" login --aud api://invoices --totp "$($K totp code "$SECRET")"

if [[ "$(uname)" == Darwin ]]; then
  step "keychain: move Bob's keys out of identity.json into the login keychain, then keep using them"
  test "$(grep -c '"secret"' "$D/bob/identity.json")" -gt 0
  $K --home "$D/bob" keys migrate
  if grep -q '"secret"' "$D/bob/identity.json"; then echo "FAIL: secrets left in identity.json"; exit 1; fi
  $K --home "$D/bob" keys list | python3 -c "import sys,json;ks=json.load(sys.stdin)['keys'];assert all(k['where']=='keychain' for k in ks),ks;print('bob keys in keychain:', len(ks))"
fi

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

WF=$((PORT+1))
step "public alias: a host serves Ada's WebFinger back-link; it resolves only once her KEL links it; Bob names her"
mkdir -p "$D/wf/.well-known"
# The host names both Ada and Bob; only a root whose KEL links the alias back counts.
printf '{"links":[{"rel":"urn:kith:root","href":"%s"},{"rel":"urn:kith:root","href":"%s"}]}' "$(cat "$D/ada.did")" "$(cat "$D/bob.did")" > "$D/wf/.well-known/webfinger"
(cd "$D/wf" && exec python3 -m http.server "$WF") > "$D/wf.log" 2>&1 &
WFS=$!
for _ in $(seq 50); do curl -sf "http://localhost:$WF/.well-known/webfinger" >/dev/null && break; sleep 0.1; done
if $K --home "$D/bob" resolve "mailto:ada@localhost:$WF" 2>/dev/null; then echo "FAIL: resolved before Ada linked the alias"; exit 1; fi
echo "a back-link alone does not resolve (good)"
$K --home "$D/ada" alias link "mailto:ada@localhost:$WF"
$K --home "$D/bob" resolve "mailto:ada@localhost:$WF" | python3 -c "import sys,json;r=json.load(sys.stdin);assert r['did']==open('$D/ada.did').read().strip(),r;print('resolved via',r['via'])"
$K --home "$D/bob" name add ada "mailto:ada@localhost:$WF" >/dev/null
$K --home "$D/ada" name add bob "$(cat "$D/bob.did")" >/dev/null
$K --home "$D/bob" name list | python3 -c "import sys,json;ns=json.load(sys.stdin);assert [n['name'] for n in ns]==['ada'],ns;print('bob knows:',', '.join(n['name']+' via '+n.get('via','a pinned DID') for n in ns))"
if $K --home "$D/bob" name add ada "$(cat "$D/bob.did")" 2>/dev/null; then echo "FAIL: a name moved without --replace"; exit 1; fi
echo "a name does not move silently (good)"

step "collisions: two roots linking one alias is ambiguous, a pinned name is checked, a private label cannot repeat"
$K --home "$D/ada" alias link "mailto:team@localhost:$WF"
$K --home "$D/bob" alias link "mailto:team@localhost:$WF"
if OUT=$($K --home "$D/bob" resolve "mailto:team@localhost:$WF" 2>&1); then echo "FAIL: an alias two roots link resolved to one"; exit 1; fi
echo "$OUT" | grep -q "ambiguous" && echo "$OUT" | grep -q "$(cat "$D/ada.did")" && echo "$OUT" | grep -q "$(cat "$D/bob.did")" || { echo "FAIL: ambiguity error does not name both roots: $OUT"; exit 1; }
echo "ambiguous, and both roots are named (good)"
$K --home "$D/bob" resolve "mailto:ada@localhost:$WF" >/dev/null   # the host names Bob too, but his KEL does not link ada@
echo "a root the host names but whose KEL does not link back is ignored (good)"
$K --home "$D/bob" name check | python3 -c "import sys,json;r=json.load(sys.stdin);assert [x['status'] for x in r]==['ok'],r;print('name check:', r[0]['name'], r[0]['status'])"
$K --home "$D/ada" name check | python3 -c "import sys,json;r=json.load(sys.stdin);assert [x['status'] for x in r]==['pinned'],r;print('name check:', r[0]['name'], r[0]['status'])"
# Bob links ada@ too, and the host stops naming Ada: the alias now resolves to Bob.
$K --home "$D/bob" alias link "mailto:ada@localhost:$WF"
printf '{"links":[{"rel":"urn:kith:root","href":"%s"}]}' "$(cat "$D/bob.did")" > "$D/wf/.well-known/webfinger"
if CHK=$($K --home "$D/bob" name check 2>/dev/null); then echo "FAIL: a moved name passed the check"; exit 1; fi
echo "$CHK" | python3 -c "import sys,json;r=json.load(sys.stdin);assert r[0]['status']=='moved' and r[0]['now']==open('$D/bob.did').read().strip(),r;print('name check:', r[0]['name'], r[0]['status'])"
$K --home "$D/bob" name list | python3 -c "import sys,json;n=json.load(sys.stdin)[0];assert n['did']==open('$D/ada.did').read().strip(),n;print('the name still points at Ada (good)')"
# The host drops its back-link altogether.
printf '{"links":[]}' > "$D/wf/.well-known/webfinger"
if CHK=$($K --home "$D/bob" name check 2>/dev/null); then echo "FAIL: an unresolvable name passed the check"; exit 1; fi
echo "$CHK" | python3 -c "import sys,json;r=json.load(sys.stdin);assert r[0]['status']=='unresolved',r;print('name check:', r[0]['name'], r[0]['status'])"
SEQ=$($K --home "$D/ada" status | python3 -c "import sys,json;print(json.load(sys.stdin)['seq'])")
if $K --home "$D/ada" alias new gaming 2>/dev/null; then echo "FAIL: a second private alias took the label gaming"; exit 1; fi
test "$($K --home "$D/ada" status | python3 -c "import sys,json;print(json.load(sys.stdin)['seq'])")" = "$SEQ" || { echo "FAIL: the refused alias still committed to the KEL"; exit 1; }
echo "the label gaming cannot be reused, and nothing was committed (good)"

step "delegation: Ada lets Bob read invoices on her behalf"
DT=$($K --home "$D/ada" delegate --to bob --action 'Query.*' --action 'Invoice.read')
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
# Lose all but one recovery key: drop them from identity.json and, on macOS, from the keychain.
python3 - "$D/ada/identity.json" <<'PY' | while read -r acct; do [[ "$(uname)" == Darwin ]] && security delete-generic-password -s kith -a "$acct" >/dev/null 2>&1 || true; done
import json,sys; p=sys.argv[1]; v=json.load(open(p)); lost=v["recovery"][1:]; v["recovery"]=v["recovery"][:1]; json.dump(v,open(p,"w"))
for k in lost: print(v["did"]+"/"+k["id"])
PY
echo "(deleted all but one of the local recovery keys)"
if $K --home "$D/ada" rotate 2>/dev/null; then echo "FAIL: rotated without enough signers"; exit 1; fi
echo "one key alone cannot rotate (good)"
sleep $((31 - $(date +%s) % 30))
$K --home "$D/ada" rotate --revoke-devices --totp "$($K totp code "$SECRET")"
$K --home "$D/ada" status | python3 -c "import sys,json;s=json.load(sys.stdin);print('seq',s['seq'],'devices',s['devices'],'revoked',s['revoked'])"

step "all CLI flows passed"
