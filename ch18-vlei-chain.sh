#!/usr/bin/env bash
# Lab 18: the whole vLEI credential set, issued with GLEIF's REAL schemas, from a root stand-in to a person.
# Single-signature participants (as in keripy's own vLEI demo). REQUIRES start-witnesses.sh and network access
# the first time (the schemas come from Lab 16b). Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -f vlei-schemas/qualified-vLEI-issuer-vLEI-credential.json ] || python3 "$HERE/ch16-vlei-schemas.py" >/dev/null 2>&1
DEMO="$LAB_DIR/keripy/scripts/demo/data"
sid() { python3 -c "import json,sys; print(json.load(open('vlei-schemas/$1.json'))['\$id'])"; }
QVI_S=$(sid qualified-vLEI-issuer-vLEI-credential); LE_S=$(sid legal-entity-vLEI-credential)
OORA_S=$(sid oor-authorization-vlei-credential); OOR_S=$(sid legal-entity-official-organizational-role-vLEI-credential)
ECRA_S=$(sid ecr-authorization-vlei-credential); ECR_S=$(sid legal-entity-engagement-context-role-vLEI-credential)
lei() { python3 - "$1" <<'PY'
import sys
d = lambda s: "".join(str(int(c, 36)) for c in s)
b = sys.argv[1]; print(b + f"{98 - int(d(b + '00')) % 97:02d}")
PY
}
QVI_LEI=$(lei 6383001AJTYIGC8Y1X); LE_LEI=$(lei 5493001KJTIIGC8Y1R)
held()  { kli vc list --name "$1" --alias "$1" --passcode "$PC" 2>&1 | grep -E "Type:|Status:" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//' | paste - - | sed 's/\t/   /'; }
said()  { kli vc list --name "$1" --alias "$1" --passcode "$PC" --issued --said --schema "$2" 2>&1 | tail -1; }
saidh() { kli vc list --name "$1" --alias "$1" --passcode "$PC" --said --schema "$2" 2>&1 | tail -1; }   # a credential the party HOLDS
give()  { # give <from> <to-aid> <to-name> <said>: grant, the receiver polls, the receiver admits
  to 90 kli ipex grant --name "$1" --alias "$1" --passcode "$PC" --said "$4" --recipient "$2" >/dev/null 2>&1
  touch "admitted-$3.txt"      # the poll order is not chronological, so take the first grant not already admitted
  local g="" i
  for i in 1 2 3 4; do
    g=$(to 90 kli ipex list --name "$3" --alias "$3" --passcode "$PC" --poll --type grant --said 2>&1 | grep -E "^E" | grep -vxFf "admitted-$3.txt" | head -1)
    [ -n "$g" ] && break
  done
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

echo "### 1. four parties, each witnessed, each knowing the others, each holding all six GLEIF schemas"
P="gleif qvi le per"
for n in $P; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null
  for f in vlei-schemas/*.json; do kli vc schema import --name $n --passcode "$PC" --schema $f >/dev/null; done
  kli vc registry incept --name $n --alias $n --passcode "$PC" --registry-name reg-$n >/dev/null 2>&1; done
for a in $P; do for b in $P; do [ $a != $b ] && kli oobi resolve --name $a --passcode "$PC" --oobi-alias $b --oobi "http://127.0.0.1:5642/oobi/$(kli aid --name $b --alias $b --passcode "$PC")/witness" >/dev/null 2>&1; done; done
GL=$(kli aid --name gleif --alias gleif --passcode "$PC"); QV=$(kli aid --name qvi --alias qvi --passcode "$PC")
LE=$(kli aid --name le --alias le --passcode "$PC"); PE=$(kli aid --name per --alias per --passcode "$PC")
echo "gleif (stand-in for the GEDA) $GL"; echo "qvi $QV"; echo "legal entity $LE"; echo "person $PE"
echo "LEIs used (valid check digits): QVI $QVI_LEI, legal entity $LE_LEI"

echo; echo "### 2. QVI credential: gleif -> qvi   (no edge: the chain starts here)"
echo "{\"LEI\": \"$QVI_LEI\"}" > qvi-data.json
to 150 kli vc create --name gleif --alias gleif --passcode "$PC" --registry-name reg-gleif --schema "$QVI_S" --recipient "$QV" --data @qvi-data.json >/dev/null 2>&1
give gleif $QV qvi "$(said gleif $QVI_S)"; echo "qvi holds:"; held qvi

echo; echo "### 3. Legal Entity credential: qvi -> le   (edge qvi, to the QVI credential)"
QVI_C=$(saidh qvi $QVI_S); edges edges-le.json "qvi:$QVI_C:$QVI_S" >/dev/null
echo "{\"LEI\": \"$LE_LEI\"}" > le-data.json
python3 - <<PY
import json, hashlib
from keri.core import coring
r = json.load(open("$DEMO/rules.json")); _, r = coring.Saider.saidify(sad=dict(r, d=""), label="d"); json.dump(r, open("rules.json", "w"))
for n in ("ecr-auth-rules", "ecr-rules"):
    r = json.load(open("$DEMO/%s.json" % n)); _, r = coring.Saider.saidify(sad=dict(r, d=""), label="d"); json.dump(r, open(n + ".json", "w"))
PY
to 150 kli vc create --name qvi --alias qvi --passcode "$PC" --registry-name reg-qvi --schema "$LE_S" --recipient "$LE" --data @le-data.json --edges @edges-le.json --rules @rules.json >/dev/null 2>&1
give qvi $LE le "$(said qvi $LE_S)"; echo "le holds:"; held le

echo; echo "### 4. OOR Authorization: le -> qvi   (edge le: the entity instructs its QVI to issue a role)"
LE_C=$(saidh le $LE_S); edges edges-oora.json "le:$LE_C:$LE_S" >/dev/null
echo "{\"AID\": \"$PE\", \"LEI\": \"$LE_LEI\", \"personLegalName\": \"John Smith\", \"officialRole\": \"Chief Executive Officer\"}" > oora-data.json
to 150 kli vc create --name le --alias le --passcode "$PC" --registry-name reg-le --schema "$OORA_S" --recipient "$QV" --data @oora-data.json --edges @edges-oora.json --rules @rules.json >/dev/null 2>&1
give le $QV qvi "$(said le $OORA_S)"; echo "qvi now holds:"; held qvi

echo; echo "### 5. OOR credential: qvi -> person   (edge auth, operator I2I)"
OORA_C=$(saidh qvi $OORA_S); edges edges-oor.json "auth:$OORA_C:$OORA_S:I2I" >/dev/null
echo "{\"LEI\": \"$LE_LEI\", \"personLegalName\": \"John Smith\", \"officialRole\": \"Chief Executive Officer\"}" > oor-data.json
to 150 kli vc create --name qvi --alias qvi --passcode "$PC" --registry-name reg-qvi --schema "$OOR_S" --recipient "$PE" --data @oor-data.json --edges @edges-oor.json --rules @rules.json >/dev/null 2>&1
give qvi $PE per "$(said qvi $OOR_S)"; echo "person holds:"; held per

echo; echo "### 6. the engagement-context branch: ECR Authorization (le -> qvi), then ECR (qvi -> person, with salts)"
edges edges-ecra.json "le:$LE_C:$LE_S" >/dev/null
echo "{\"AID\": \"$PE\", \"LEI\": \"$LE_LEI\", \"personLegalName\": \"John Smith\", \"engagementContextRole\": \"Auditor\"}" > ecra-data.json
to 150 kli vc create --name le --alias le --passcode "$PC" --registry-name reg-le --schema "$ECRA_S" --recipient "$QV" --data @ecra-data.json --edges @edges-ecra.json --rules @ecr-auth-rules.json >/dev/null 2>&1
give le $QV qvi "$(said le $ECRA_S)"
ECRA_C=$(saidh qvi $ECRA_S); edges edges-ecr.json "auth:$ECRA_C:$ECRA_S:I2I" >/dev/null
echo "{\"LEI\": \"$LE_LEI\", \"personLegalName\": \"John Smith\", \"engagementContextRole\": \"Auditor\"}" > ecr-data.json
to 150 kli vc create --name qvi --alias qvi --passcode "$PC" --private --registry-name reg-qvi --schema "$ECR_S" --recipient "$PE" --data @ecr-data.json --edges @edges-ecr.json --rules @ecr-rules.json >/dev/null 2>&1
give qvi $PE per "$(said qvi $ECR_S)"; echo "person now holds:"; held per

echo; echo "### 7. everything issued, as a table: who issued what to whom, and which edge it carries"
for n in gleif qvi le; do kli vc list --name $n --alias $n --passcode "$PC" --issued --verbose 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > issued-$n.txt; done
python3 - <<'PY'
import json, re
who = {}
for line in open("gleif-icp.json"): pass
import subprocess, os
names = {}
for n in ("gleif", "qvi", "le", "per"):
    names[subprocess.run(["kli", "aid", "--name", n, "--alias", n, "--passcode", os.environ["LAB_PASSCODE"]], capture_output=True, text=True).stdout.strip()] = n
titles = {json.load(open(f"vlei-schemas/{f}.json"))["$id"]: json.load(open(f"vlei-schemas/{f}.json"))["title"].replace(" vLEI Credential", "").replace("Legal Entity ", "LE ") for f in (
    "qualified-vLEI-issuer-vLEI-credential", "legal-entity-vLEI-credential", "oor-authorization-vlei-credential",
    "legal-entity-official-organizational-role-vLEI-credential", "ecr-authorization-vlei-credential", "legal-entity-engagement-context-role-vLEI-credential")}
rows = []
for n in ("gleif", "qvi", "le"):
    txt = open(f"issued-{n}.txt").read()
    for m in re.finditer(r"Full Credential:\n(\t\{.*?\n\t\})", txt, re.S):
        d = json.loads(m.group(1).replace("\t", ""))
        e = d.get("e", {}); edge = ", ".join(f"{k}" + (f"[{v['o']}]" if "o" in v else "") for k, v in e.items() if k != "d") or "none"
        rows.append((d["s"], f'{titles[d["s"]]:34} {names.get(d["i"], "?"):5} -> {names.get(d["a"].get("i"), "?"):5} edge: {edge}'))
order = list(titles)
for _, r in sorted(rows, key=lambda x: order.index(x[0])): print(" ", r)
PY

echo; echo "### 8. does the schema's  format: ISO 17442  stop an LEI with bad check digits?"
echo '{"LEI": "5493001KJTIIGC8Y1R17"}' > le-bad-data.json
echo "the LEI 5493001KJTIIGC8Y1R17 has valid check digits: $(python3 -c "print(int(''.join(str(int(c,36)) for c in '5493001KJTIIGC8Y1R17'))%97==1)")"
BEFORE=$(kli vc list --name qvi --alias qvi --passcode "$PC" --issued --said | wc -l | tr -d ' ')
to 150 kli vc create --name qvi --alias qvi --passcode "$PC" --registry-name reg-qvi --schema "$LE_S" --recipient "$LE" --data @le-bad-data.json --edges @edges-le.json --rules @rules.json 2>&1 | tail -1 | cut -c1-110
AFTER=$(kli vc list --name qvi --alias qvi --passcode "$PC" --issued --said | wc -l | tr -d ' ')
echo "credentials the QVI has issued: $BEFORE before, $AFTER after"
