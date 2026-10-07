#!/usr/bin/env bash
# Lab 20: a purchase order between two companies, signed with KERI and checked against the vLEI chain.
# REQUIRES start-witnesses.sh, and Lab 18 to have been run first and NOT cleaned (it uses gleif, qvi, le, per).
# Creates two more parties: dana (an officer at the legal entity) and nwd (the supplier, Northwind, which runs a service on :7700).
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"
PC="$LAB_PASSCODE"; URL=http://127.0.0.1:7700
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -d "$HOME/.keri/db/le" ] || { echo "Run ./ch18-vlei-chain.sh first (and do not clean)."; exit 1; }
aid() { kli aid --name "$1" --alias "$1" --passcode "$PC"; }
sid() { python3 -c "import json; print(json.load(open('vlei-schemas/$1.json'))['\$id'])"; }
find_cred() { # find_cred <store> <schema> <attribute> <value>: the SAID of the credential with that attribute value
python3 - "$@" <<'PY'
import sys, kerihttp as kh
store, schema, field, value = sys.argv[1:]
hby, rgy = kh.open_store(store)
for _, c in rgy.reger.creds.getItemIter():
    if c.schema == schema and c.attrib.get(field) == value: print(c.said)
hby.close()
PY
}
give() { # give <from> <to-aid> <to-name> <said>: IPEX grant, the receiver polls its mailbox, the receiver admits
  to 90 kli ipex grant --name "$1" --alias "$1" --passcode "$PC" --said "$4" --recipient "$2" >/dev/null 2>&1
  local g="" i; touch "admitted-$3.txt"
  for i in 1 2 3 4; do
    g=$(to 90 kli ipex list --name "$3" --alias "$3" --passcode "$PC" --poll --type grant --said 2>&1 | grep -E "^E" | grep -vxFf "admitted-$3.txt" | head -1)
    [ -n "$g" ] && break; done
  [ -n "$g" ] && echo "$g" >> "admitted-$3.txt"
  to 90 kli ipex admit --name "$3" --alias "$3" --passcode "$PC" --said "$g" >/dev/null 2>&1; sleep 3; }
edges() { python3 - "$@" > "$1" <<'PY'
import json, sys
f, *pairs = sys.argv[1:]
e = {"d": ""}
for p in pairs:
    label, n, s, *o = p.split(":"); e[label] = {"n": n, "s": s, **({"o": o[0]} if o else {})}
print(json.dumps(e))
PY
  kli saidify --file "$1"; }
party() { kli init --name $1 --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $1 $w
    kli oobi resolve --name $1 --passcode "$PC" --oobi-alias $2 --oobi "http://127.0.0.1:$3/oobi/$4/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $1-icp.json
  kli incept --name $1 --alias $1 --passcode "$PC" --file $1-icp.json >/dev/null
  for f in vlei-schemas/*.json; do kli vc schema import --name $1 --passcode "$PC" --schema $f >/dev/null; done; }
oobi() { kli oobi resolve --name "$1" --passcode "$PC" --oobi-alias "$2" --oobi "http://127.0.0.1:5642/oobi/$3/witness" >/dev/null 2>&1; }

GL=$(aid gleif); QV=$(aid qvi); LE=$(aid le); PE=$(aid per)
LE_S=$(sid legal-entity-vLEI-credential); ECRA_S=$(sid ecr-authorization-vlei-credential); ECR_S=$(sid legal-entity-engagement-context-role-vLEI-credential)
LE_LEI=$(python3 -c "import json; print(json.load(open('le-data.json'))['LEI'])")

echo "### 1. two new parties: an officer at the legal entity (dana) and a supplier (nwd)"
party dana; party nwd; BU=$(aid dana); SU=$(aid nwd)
for p in "le $LE" "qvi $QV"; do set -- $p; oobi dana $1 $2; oobi $1 dana $BU; done
echo "officer (dana) $BU"; echo "supplier (nwd) $SU"

echo; echo "### 2. the legal entity authorizes a Procurement Officer, and its QVI issues the role"
LE_C=$(find_cred le "$LE_S" LEI "$LE_LEI" | head -1); edges edges-po-auth.json "le:$LE_C:$LE_S" >/dev/null
echo "{\"AID\": \"$BU\", \"LEI\": \"$LE_LEI\", \"personLegalName\": \"Dana Whitfield\", \"engagementContextRole\": \"Procurement Officer\"}" > po-auth-data.json
to 150 kli vc create --name le --alias le --passcode "$PC" --registry-name reg-le --schema "$ECRA_S" --recipient "$QV" --data @po-auth-data.json --edges @edges-po-auth.json --rules @ecr-auth-rules.json >/dev/null 2>&1
AUTH=$(find_cred le "$ECRA_S" AID "$BU"); give le $QV qvi "$AUTH"
edges edges-po-ecr.json "auth:$AUTH:$ECRA_S:I2I" >/dev/null
echo "{\"LEI\": \"$LE_LEI\", \"personLegalName\": \"Dana Whitfield\", \"engagementContextRole\": \"Procurement Officer\"}" > po-ecr-data.json
to 150 kli vc create --name qvi --alias qvi --passcode "$PC" --private --registry-name reg-qvi --schema "$ECR_S" --recipient "$BU" --data @po-ecr-data.json --edges @edges-po-ecr.json --rules @ecr-rules.json >/dev/null 2>&1
ECR=$(find_cred qvi "$ECR_S" i "$BU"); give qvi $BU dana "$ECR"
echo "ECR Authorization (le -> qvi): $AUTH"; echo "ECR credential  (qvi -> dana): $ECR"
kli vc list --name dana --alias dana --passcode "$PC" 2>&1 | grep -E "Type:|Status:" | sed 's/\x1b\[[0-9;]*m//g; s/^ *//' | paste - - | sed 's/\t/   /'

echo; echo "### 3. the supplier starts its Order API"
python3 "$HERE/ch20-supplier.py" --port 7700 --root "$GL" --oobi "http://127.0.0.1:5642/oobi/$SU/witness" \
        --account "$LE_LEI=Acme Health" > supplier.log 2>&1 &
SPID=$!; trap 'kill $SPID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf $URL/.well-known/keri >/dev/null && break; sleep 1; done
cat supplier.log; echo "GET /.well-known/keri:"; curl -s $URL/.well-known/keri | sed 's/^/  /'
B() { python3 "$HERE/ch20-buyer.py" "$@"; }

echo; echo "### 4. DISCOVERY: the buyer learns the supplier's identifier and fetches its order schema"
B discover $URL dana

echo; echo "### 5. ONBOARDING: the officer presents the role credential and its chain"
B onboard $URL dana "$ECR"

echo; echo "### 6. the CEO presents his Auditor role credential: a valid credential, the wrong role"
PE_ECR=$(find_cred per "$ECR_S" engagementContextRole Auditor | head -1); oobi per nwd $SU
B onboard $URL per "$PE_ECR" | grep -E "HTTP|FAIL"

O() { B order $URL dana "$@" --credential "$ECR" --lei "$LE_LEI"; }
echo; echo "### 7. a PURCHASE ORDER: signed, anchored, checked, accepted"
O PO-1001 GLV-NITRILE-M:200:8.40 MSK-SURG-L3:40:12.75

echo; echo "### 8. the same request replayed"
O PO-1001 --replay | grep -E "HTTP|FAIL"

echo; echo "### 9. tampered in transit"
O PO-1002 SYR-3ML:20:22.10 --tamper | grep -E "IN TRANSIT|HTTP|FAIL"

echo; echo "### 10. signed but never anchored in the officer's key log"
O PO-1003 SYR-3ML:20:22.10 --no-anchor | grep -E "NOT|HTTP|FAIL"

echo; echo "### 11. over the officer's limit"
O PO-1004 MSK-SURG-L3:500:12.75 | grep -E "total|HTTP|FAIL"

echo; echo "### 12. the legal entity revokes the officer's authorization, and tells the supplier"
to 90 kli vc revoke --name le --alias le --passcode "$PC" --registry-name reg-le --said "$AUTH" >/dev/null 2>&1
kli vc export --name le --alias le --passcode "$PC" --said "$AUTH" --full > po-auth-revoked.cesr 2>/dev/null
curl -s -X POST --data-binary @po-auth-revoked.cesr $URL/status | python3 -c "import json,sys; d=json.load(sys.stdin); print('POST /status:', d['decision']); [print('   ', c) for c in d['checks']]"
O PO-1005 SYR-3ML:20:22.10 | grep -E "HTTP|FAIL"

echo; echo "### 13. what the supplier kept"
python3 -c "import json; s=json.load(open('supplier-state.json')); [print(f'  order {v[\"number\"]}  po {k[:12]}...  ack {v[\"ack\"][:12]}...') for k,v in s['orders'].items()]"
echo "  the supplier's own log:"; kli export --name nwd --alias nwd --passcode "$PC" 2>/dev/null | python3 -c "
import sys,re; s=sys.stdin.read()
for m in re.finditer(r'\{\"v\":\"KERI10JSON[^}]*?\"t\":\"(\w+)\".*?\"s\":\"(\w+)\".*?\"a\":(\[.*?\])\}', s): print(f'    {m.group(1)} s={m.group(2)} a={m.group(3)[:70]}')"
