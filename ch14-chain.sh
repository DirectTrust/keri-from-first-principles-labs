#!/usr/bin/env bash
# Lab 14b: a chain of authority: regulator -> accreditor -> clinic. REQUIRES start-witnesses.sh.
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
python3 "$HERE/ch14-schemas.py" >/dev/null
AUTH=$(python3 -c 'import json; print(json.load(open("authority-schema.json"))["$id"])')
CH=$(python3 -c 'import json; print(json.load(open("chained-schema.json"))["$id"])')
held() { kli vc list --name "$1" --alias "$1" --passcode "$PC" 2>&1 | grep -E "Credential #|Type:|Status:" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//'; echo "  ($(kli vc list --name "$1" --alias "$1" --passcode "$PC" 2>&1 | grep -c 'Credential #') credential(s) held)"; }

echo "### 1. three parties: a regulator (reg), an accreditor (acr), a clinic (cli)"
for n in reg acr cli; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null
  kli vc schema import --name $n --passcode "$PC" --schema authority-schema.json >/dev/null
  kli vc schema import --name $n --passcode "$PC" --schema chained-schema.json >/dev/null; done
REG=$(kli aid --name reg --alias reg --passcode "$PC"); ACR=$(kli aid --name acr --alias acr --passcode "$PC"); CLI=$(kli aid --name cli --alias cli --passcode "$PC")
for a in "reg $ACR acr" "reg $CLI cli" "acr $REG reg" "acr $CLI cli" "cli $REG reg" "cli $ACR acr"; do set -- $a
  kli oobi resolve --name $1 --passcode "$PC" --oobi-alias $3 --oobi "http://127.0.0.1:5642/oobi/$2/witness" >/dev/null; done
echo "reg $REG"; echo "acr $ACR"; echo "cli $CLI"
kli vc registry incept --name reg --alias reg --passcode "$PC" --registry-name authority >/dev/null 2>&1
kli vc registry incept --name acr --alias acr --passcode "$PC" --registry-name clinics >/dev/null 2>&1

echo; echo "### 2. the regulator issues an authority credential to the accreditor: the PARENT"
echo '{"scope": "accredit clinics in region 7"}' > auth-data.json
to 120 kli vc create --name reg --alias reg --passcode "$PC" --registry-name authority --schema "$AUTH" --recipient "$ACR" --data @auth-data.json >/dev/null 2>&1
PARENT=$(kli vc list --name reg --alias reg --passcode "$PC" --issued --said | tail -1); echo "parent credential: $PARENT"
kli vc export --name reg --alias reg --passcode "$PC" --said "$PARENT" --full > parent.cesr 2>/dev/null
kli vc import --name acr --passcode "$PC" --file parent.cesr >/dev/null 2>&1
echo "the accreditor now holds:"; held acr

echo; echo "### 3. the accreditor writes an EDGE to that parent, and some RULES, then SAIDifies both blocks"
echo "{\"d\": \"\", \"authority\": {\"n\": \"$PARENT\", \"s\": \"$AUTH\", \"o\": \"I2I\"}}" > edges.json
echo '{"d": "", "disclaimer": {"l": "Accreditation reflects the review date only."}}' > rules.json
kli saidify --file edges.json; kli saidify --file rules.json
python3 -c "import json; print(json.dumps(json.load(open('edges.json')), indent=2)); print(json.dumps(json.load(open('rules.json')), indent=2))"

echo; echo "### 4. the accreditor issues the CHILD: chained to the parent, with rules, and with salts (--private)"
echo '{"clinicName": "Riverside Family Clinic", "status": "accredited"}' > cdata.json
to 150 kli vc create --name acr --alias acr --passcode "$PC" --registry-name clinics --schema "$CH" --recipient "$CLI" --data @cdata.json --edges @edges.json --rules @rules.json --private >/dev/null 2>&1
CHILD=$(kli vc list --name acr --alias acr --passcode "$PC" --issued --said | tail -1); echo "child credential: $CHILD"
kli vc list --name acr --alias acr --passcode "$PC" --issued --verbose 2>&1 | sed -n '/^\t{/,/^\t}/p' | sed 's/^\t//' > child.json
python3 - <<'PY'
import json
d = json.load(open("child.json"))
print("top-level fields:", list(d))
print("u (credential salt)  :", d["u"]); print("a.u (attribute salt) :", d["a"]["u"])
print("e.authority.n        :", d["e"]["authority"]["n"][:14] + "...  operator", d["e"]["authority"]["o"])
print("r.disclaimer         :", d["r"]["disclaimer"]["l"])
PY

echo; echo "### 5. the clinic receives the child WITHOUT its parent (key logs and TELs only)"
kli vc export --name acr --alias acr --passcode "$PC" --said "$CHILD" --tels --kels > child-only.cesr 2>/dev/null
echo "streams: child $(wc -c < child-only.cesr | tr -d " ") bytes, parent and proof $(wc -c < parent.cesr | tr -d " ") bytes"
kli vc import --name cli --passcode "$PC" --file child-only.cesr >/dev/null 2>&1; sleep 3
echo "after importing the child alone:"; held cli
echo "...and after importing the parent and its proof (the child leaves escrow by itself):"
kli vc import --name cli --passcode "$PC" --file parent.cesr >/dev/null 2>&1; sleep 5; held cli

echo; echo "### 6. the regulator REVOKES the parent. The accreditor tries to issue another child under it"
to 90 kli vc revoke --name reg --alias reg --passcode "$PC" --registry-name authority --said "$PARENT" >/dev/null 2>&1
kli vc export --name reg --alias reg --passcode "$PC" --said "$PARENT" --full > parent-revoked.cesr 2>/dev/null
kli vc import --name acr --passcode "$PC" --file parent-revoked.cesr >/dev/null 2>&1
echo "the accreditor's view of its authority:"; held acr
echo '{"clinicName": "Hillside Clinic", "status": "accredited"}' > cdata2.json
echo "the accreditor tries to issue a second child under the revoked parent (60 seconds, then I stop it):"
to 60 kli vc create --name acr --alias acr --passcode "$PC" --registry-name clinics --schema "$CH" --recipient "$CLI" --data @cdata2.json --edges @edges.json --rules @rules.json --private > create2.log 2>&1
echo "lines of output from the tool: $(grep -vc "Alarm clock" create2.log)"
echo "credentials the accreditor has issued: $(kli vc list --name acr --alias acr --passcode "$PC" --issued --said | wc -l | tr -d ' ')"
echo "the clinic's earlier credential is unchanged:"; held cli
