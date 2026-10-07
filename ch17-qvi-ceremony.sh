#!/usr/bin/env bash
# Lab 17: the QVI creation ceremony. Two "GARs" jointly control a stand-in for GLEIF's external identifier (GEDA);
# two "QARs" jointly create a QVI identifier that the GEDA group must approve. REQUIRES start-witnesses.sh.
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
aid()    { kli aid --name "$1" --alias "${2:-$1}" --passcode "$PC"; }
status() { kli status --name "$1" --alias "$2" --passcode "$PC" | sed 's/\x1b\[[0-9;]*m//g' | sed -n "${3:-1,10}p"; }
oobi()   { kli oobi resolve --name "$1" --passcode "$PC" --oobi-alias "$2" --oobi "http://127.0.0.1:5642/oobi/$3/witness" >/dev/null 2>&1; }
fields() { python3 - "$1" <<'PY'
import re, json, sys
for o in re.findall(r'\{"v":"KERI10JSON[0-9a-f]{6}_".*?\}(?=-V|-A|\{"v"|$)', open(sys.argv[1]).read()):
    try: d = json.loads(o)
    except ValueError: continue
    x = f' di={d["di"][:10]}...' if "di" in d else ""
    k = d.get("k"); y = f' keys={len(k)} kt={",".join(d["kt"]) if isinstance(d["kt"], list) else d["kt"]}' if k else ""
    sl = f' seal={{i:{d["a"][0]["i"][:8]}.., s:{d["a"][0]["s"]}}}' if d.get("a") else ""
    print(f'  {d["t"]:3} s={d["s"]}{x}{y}{sl}')
PY
}

echo "### 1. four people, each with an ordinary witnessed identifier: two GARs and two QARs"
for n in gar1 gar2 qar1 qar2; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null; done
G1=$(aid gar1); G2=$(aid gar2); Q1=$(aid qar1); Q2=$(aid qar2)
echo "gar1 $G1"; echo "gar2 $G2"; echo "qar1 $Q1"; echo "qar2 $Q2"
oobi gar1 gar2 $G2; oobi gar2 gar1 $G1; oobi qar1 qar2 $Q2; oobi qar2 qar1 $Q1

echo; echo "### 2. the two GARs create the GEDA group together: two members, both must sign"
cat > geda-icp.json <<JSON
{"aids": ["$G1","$G2"], "transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2, "isith": ["1/2","1/2"], "nsith": ["1/2","1/2"]}
JSON
for n in gar1 gar2; do kli multisig incept --name $n --alias $n --passcode "$PC" --group geda --file geda-icp.json > $n-geda.log 2>&1 & done; wait
GEDA=$(aid gar1 geda); echo "GEDA group: $GEDA"; status gar1 geda 3,5

echo; echo "### 3. the QARs resolve the GEDA's OOBI, then ask to become its delegate"
oobi qar1 geda $GEDA; oobi qar2 geda $GEDA
cat > qvi-icp.json <<JSON
{"delpre": "$GEDA", "aids": ["$Q1","$Q2"], "transferable": true, "wits": ["$WAN"], "toad": 1, "isith": ["1/2","1/2"], "nsith": ["1/2","1/2"]}
JSON
cat qvi-icp.json
for n in qar1 qar2; do to 240 kli multisig incept --name $n --alias $n --passcode "$PC" --group qvi --file qvi-icp.json > $n-qvi.log 2>&1 & done
sleep 15
echo "the QVI group's own view, before the GARs act:"; status qar1 qvi 3,5

echo; echo "### 4. BOTH GARs approve. The seal lands in the GEDA group's log, signed by its members"
for n in gar1 gar2; do to 200 kli delegate confirm --name $n --alias geda --passcode "$PC" --interact -Y > $n-confirm.log 2>&1 & done
wait
QVI=$(aid qar1 qvi); echo "QVI group: $QVI"
echo "the QVI group's view:"; status qar1 qvi 3,5
echo "the GEDA group is now at:"; status gar1 geda 3,3

echo; echo "### 5. the logs: the QVI's inception names its delegator, and the GEDA's log holds the seal"
kli export --name qar1 --alias qvi --passcode "$PC" > qvi.cesr 2>/dev/null; kli export --name gar1 --alias geda --passcode "$PC" > geda.cesr 2>/dev/null
echo "QVI group's log:"; fields qvi.cesr; echo "GEDA group's log:"; fields geda.cesr

echo; echo "### 6. a second candidate (qvi2, members qar3 and qar4): only ONE GAR approves"
for n in qar3 qar4; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null; done
Q3=$(aid qar3); Q4=$(aid qar4); oobi qar3 qar4 $Q4; oobi qar4 qar3 $Q3; oobi qar3 geda $GEDA; oobi qar4 geda $GEDA
cat > qvi2-icp.json <<JSON
{"delpre": "$GEDA", "aids": ["$Q3","$Q4"], "transferable": true, "wits": ["$WAN"], "toad": 1, "isith": ["1/2","1/2"], "nsith": ["1/2","1/2"]}
JSON
for n in qar3 qar4; do to 400 kli multisig incept --name $n --alias $n --passcode "$PC" --group qvi2 --file qvi2-icp.json > $n-qvi2.log 2>&1 & done
sleep 15
to 300 kli delegate confirm --name gar1 --alias geda --passcode "$PC" --interact -Y > gar1-confirm2.log 2>&1 &
sleep 40
echo "after gar1 alone approves:"; echo "  qvi2 group: $(status qar3 qvi2 5,5 | sed 's/^ *//')"; echo "  GEDA group at: $(status gar1 geda 3,3)"
to 250 kli delegate confirm --name gar2 --alias geda --passcode "$PC" --interact -Y > gar2-confirm2.log 2>&1 &
wait
echo "after gar2 joins:"; echo "  qvi2 group: $(status qar3 qvi2 5,5 | sed 's/^ *//')"; echo "  GEDA group at: $(status gar1 geda 3,3)"

echo; echo "### 7. a stand-in for the GEDA issues GLEIF's REAL QVI credential schema to the QVI group"
[ -f vlei-schemas/qualified-vLEI-issuer-vLEI-credential.json ] || python3 "$HERE/ch16-vlei-schemas.py" >/dev/null 2>&1
QSCHEMA=$(python3 -c 'import json; print(json.load(open("vlei-schemas/qualified-vLEI-issuer-vLEI-credential.json"))["$id"])')
kli init --name gleif --passcode "$PC" >/dev/null
for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
  kli oobi resolve --name gleif --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > gleif-icp.json
kli incept --name gleif --alias gleif --passcode "$PC" --file gleif-icp.json >/dev/null
kli vc schema import --name gleif --passcode "$PC" --schema vlei-schemas/qualified-vLEI-issuer-vLEI-credential.json >/dev/null
kli vc registry incept --name gleif --alias gleif --passcode "$PC" --registry-name qvis >/dev/null 2>&1
# the issuer must know the QVI group, and its delegator, before it can name the group as a recipient
oobi gleif geda "$GEDA"; oobi gleif qvi "$QVI"
for i in 1 2 3 4 5 6; do kli kevers --name gleif --passcode "$PC" --prefix "$QVI" 2>&1 | grep -q Anchored && break; sleep 5; done
echo '{"LEI": "5493001KJTIIGC8Y1R12"}' > qvi-data.json
to 150 kli vc create --name gleif --alias gleif --passcode "$PC" --registry-name qvis --schema "$QSCHEMA" --recipient "$QVI" --data @qvi-data.json >/dev/null 2>&1
kli vc list --name gleif --alias gleif --passcode "$PC" --issued --verbose 2>&1 | sed -n '/^\t{/,/^\t}/p' | sed 's/^\t//' > qvi-cred.json
python3 - "$QVI" <<'PY'
import json, sys
d = json.load(open("qvi-cred.json"))
print("credential type    :", "Qualified vLEI Issuer Credential" if d["s"].startswith("EBfdlu8R") else d["s"])
print("schema             :", d["s"])
print("issuer             :", d["i"][:16] + "...  (the stand-in for the GEDA)")
print("issuee (a.i)       :", d["a"]["i"][:16] + "...  is the QVI group:", d["a"]["i"] == sys.argv[1])
print("LEI claimed        :", d["a"]["LEI"])
PY
