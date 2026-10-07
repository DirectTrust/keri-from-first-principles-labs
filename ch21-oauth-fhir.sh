#!/usr/bin/env bash
# Lab 21: an OAuth 2.0 client and a FHIR server that use KERI identifiers and a vLEI-chained credential
# where UDAP uses X.509 certificates. REQUIRES start-witnesses.sh, and Lab 18 run first and NOT cleaned.
# Creates two more parties: app (Acme Health's backend application) and hdx (the health data exchange, on :7800).
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"
PC="$LAB_PASSCODE"; BASE=http://127.0.0.1:7800
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -d "$HOME/.keri/db/le" ] || { echo "Run ./ch18-vlei-chain.sh first (and do not clean)."; exit 1; }
aid() { kli aid --name "$1" --alias "$1" --passcode "$PC"; }
sid() { python3 -c "import json; print(json.load(open('vlei-schemas/$1.json'))['\$id'])"; }
find_cred() { python3 - "$@" <<'PY'
import sys, kerihttp as kh
store, schema, field, value = sys.argv[1:]
hby, rgy = kh.open_store(store)
for _, c in rgy.reger.creds.getItemIter():
    if c.schema == schema and c.attrib.get(field) == value: print(c.said)
hby.close()
PY
}
give() {
  to 90 kli ipex grant --name "$1" --alias "$1" --passcode "$PC" --said "$4" --recipient "$2" >/dev/null 2>&1
  local g="" i; touch "admitted-$3.txt"
  for i in 1 2 3 4; do
    g=$(to 90 kli ipex list --name "$3" --alias "$3" --passcode "$PC" --poll --type grant --said 2>&1 | grep -E "^E" | grep -vxFf "admitted-$3.txt" | head -1)
    [ -n "$g" ] && break; done
  [ -n "$g" ] && echo "$g" >> "admitted-$3.txt"
  to 90 kli ipex admit --name "$3" --alias "$3" --passcode "$PC" --said "$g" >/dev/null 2>&1; sleep 3; }
party() { kli init --name $1 --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $1 $w
    kli oobi resolve --name $1 --passcode "$PC" --oobi-alias $2 --oobi "http://127.0.0.1:$3/oobi/$4/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $1-icp.json
  kli incept --name $1 --alias $1 --passcode "$PC" --file $1-icp.json >/dev/null
  for f in vlei-schemas/*.json health-app-schema.json; do kli vc schema import --name $1 --passcode "$PC" --schema $f >/dev/null; done; }
oobi() { kli oobi resolve --name "$1" --passcode "$PC" --oobi-alias "$2" --oobi "http://127.0.0.1:5642/oobi/$3/witness" >/dev/null 2>&1; }

GL=$(aid gleif); LE=$(aid le); LE_S=$(sid legal-entity-vLEI-credential)
LE_LEI=$(python3 -c "import json; print(json.load(open('le-data.json'))['LEI'])")

echo "### 1. the app credential's schema: a content schema with an edge PINNED to the Legal Entity vLEI schema"
python3 - "$LE_S" <<'PY'
import json, sys, kerihttp as kh
S = {"type": "string"}
def block(props, req): return {"type": "object", "properties": {"d": S, **props}, "required": ["d"] + req, "additionalProperties": False}
le_schema = sys.argv[1]
schema = kh.saidify({
  "$id": "", "$schema": "http://json-schema.org/draft-07/schema#", "title": "Health App Authorization",
  "description": "A legal entity authorizes one of its software applications to act for it on a health data network.",
  "type": "object", "credentialType": "HealthAppAuthorization", "version": "1.0.0",
  "properties": {"v": S, "d": S, "u": S, "i": S, "ri": S, "s": S,
    "a": {"oneOf": [S, block({"i": S, "dt": {"type": "string", "format": "date-time"}, "appName": S,
                               "LEI": {"type": "string", "pattern": "^[0-9A-Z]{18}[0-9]{2}$"},
                               "scopes": {"type": "array", "minItems": 1, "items": {"type": "string", "pattern": "^system/[A-Za-z]+\\.(read|write)$"}},
                               "purposeOfUse": {"enum": ["TREAT", "HPAYMT", "HOPERAT"]}},
                              ["i", "dt", "appName", "LEI", "scopes", "purposeOfUse"])]},
    "e": {"oneOf": [S, block({"le": {"type": "object", "additionalProperties": False, "required": ["n", "s", "o"],
                                       "properties": {"n": S, "s": {"type": "string", "const": le_schema}, "o": {"type": "string", "const": "I2I"}}}}, ["le"])]}},
  "required": ["v", "d", "i", "ri", "s", "a", "e"], "additionalProperties": False}, label="$id")
json.dump(schema, open("health-app-schema.json", "w"), indent=1)
print("Health App Authorization schema:", schema["$id"])
print("  its le edge pins s =", schema["properties"]["e"]["oneOf"][1]["properties"]["le"]["properties"]["s"]["const"][:12] + "...  and o = I2I")
PY
APP_S=$(python3 -c "import json; print(json.load(open('health-app-schema.json'))['\$id'])")
kli vc schema import --name le --passcode "$PC" --schema health-app-schema.json >/dev/null

echo; echo "### 2. two new parties: Acme Health's backend app, and the health data exchange"
party app; party hdx; AP=$(aid app); HX=$(aid hdx)
oobi app le $LE; oobi le app $AP
echo "app (client)  $AP"; echo "hdx (server)  $HX"

echo; echo "### 3. Acme Health issues its app a Health App Authorization, chained to Acme's vLEI"
LE_C=$(find_cred le "$LE_S" LEI "$LE_LEI" | head -1)
python3 - "$LE_C" "$LE_S" > app-edges.json <<'PY'
import json, sys; print(json.dumps({"d": "", "le": {"n": sys.argv[1], "s": sys.argv[2], "o": "I2I"}}))
PY
kli saidify --file app-edges.json
echo "{\"appName\": \"Acme Care Coordinator\", \"LEI\": \"$LE_LEI\", \"scopes\": [\"system/Patient.read\", \"system/Observation.read\"], \"purposeOfUse\": \"TREAT\"}" > app-data.json
to 150 kli vc create --name le --alias le --passcode "$PC" --registry-name reg-le --schema "$APP_S" --recipient "$AP" --data @app-data.json --edges @app-edges.json >/dev/null 2>&1
APPC=$(find_cred le "$APP_S" i "$AP"); give le $AP app "$APPC"
echo "credential: $APPC"
kli vc list --name app --alias app --passcode "$PC" 2>&1 | grep -E "Type:|Status:" | sed 's/\x1b\[[0-9;]*m//g; s/^ *//' | paste - - | sed 's/\t/   /'

echo; echo "### 4. the health data exchange starts its authorization server and FHIR server"
python3 "$HERE/ch21-health-server.py" --port 7800 --root "$GL" --oobi "http://127.0.0.1:5642/oobi/$HX/witness" \
        --app-schema "$APP_S" --participant "$LE_LEI=Acme Health" > hdx.log 2>&1 &
SPID=$!; trap 'kill $SPID 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -sf $BASE/.well-known/smart-configuration >/dev/null && break; sleep 1; done; cat hdx.log
C() { python3 "$HERE/ch21-health-client.py" "$@"; }

echo; echo "### 5. DISCOVERY"; C discover $BASE app
echo; echo "### 6. REGISTRATION: the KERI counterpart of a UDAP software statement"; C register $BASE app "$APPC"
echo; echo "### 7. a TOKEN: client_credentials, authenticated by a JWT signed with the app's KERI key"
C token $BASE app system/Patient.read system/Observation.read --save at1.jwt
echo; echo "### 8. FHIR reads with the access token"
C read $BASE /fhir/Patient/p-1001 --token at1.jwt; C read $BASE "/fhir/Observation?patient=p-1001" --token at1.jwt
echo; echo "### 9. asking for a scope the credential does not grant"; C token $BASE app system/Patient.write | grep -E "HTTP|FAIL"
echo; echo "### 10. the same client assertion, replayed"; C token $BASE app system/Patient.read --assertion at1.jwt.assertion | grep -E "using|HTTP|FAIL"
echo; echo "### 11. a forged access token"; C read $BASE /fhir/Patient/p-1001 --token at1.jwt --forge-scope system/Patient.write
echo; echo "### 12. KEY ROTATION: no new certificate, no re-registration"
C assertion $BASE app old-key.jwt
kli rotate --name app --alias app --passcode "$PC" >/dev/null 2>&1; echo "the app rotates its keys: $(kli status --name app --alias app --passcode "$PC" | grep -E 'Seq No' | tr -s ' \t' ' ')"
C token $BASE app system/Patient.read --assertion old-key.jwt | grep -E "using|HTTP|FAIL"
C token $BASE app system/Patient.read | grep -E "fresh|HTTP|FAIL|current key"
echo; echo "### 13. Acme Health revokes the app's credential, and the exchange learns of it"
to 90 kli vc revoke --name le --alias le --passcode "$PC" --registry-name reg-le --said "$APPC" >/dev/null 2>&1
kli vc export --name le --alias le --passcode "$PC" --said "$APPC" --full > app-revoked.cesr 2>/dev/null
curl -s -X POST --data-binary @app-revoked.cesr $BASE/status; echo
C token $BASE app system/Patient.read | grep -E "HTTP|FAIL"
