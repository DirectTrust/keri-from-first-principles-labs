#!/usr/bin/env bash
# Lab 10: one identifier (dan) exists only with another's (dora's) permission. REQUIRES start-witnesses.sh.
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
aid()    { kli aid --name "$1" --alias "${2:-$1}" --passcode "$PC"; }
status() { kli status --name "$1" --alias "$2" --passcode "$PC" | sed -n "${3:-1,12}p"; }
fields() { python3 - "$1" <<'PY'
import re, json, sys
for o in re.findall(r'\{"v":"KERI10JSON[0-9a-f]{6}_".*?\}(?=-V|-A|\{"v"|$)', open(sys.argv[1]).read()):
    try: d = json.loads(o)
    except ValueError: continue
    extra = f' di={d["di"][:12]}…' if "di" in d else ""
    seal = f' seal={{i:{d["a"][0]["i"][:8]}…, s:{d["a"][0]["s"]}, d:{d["a"][0]["d"][:8]}…}}' if d.get("a") else ""
    print(f'{d["t"]:3} s={d["s"]}{extra}{seal}')
PY
}
# what a verifier believes about an identifier, polled until it reaches the expected sn or 30 seconds pass
seen() { local want=$3 got=""; for i in 1 2 3 4 5 6; do
    got=$(kli kevers --name "$1" --passcode "$PC" --prefix "$2" 2>&1 | sed -n 2p | tr -d '\t'); [ "$got" = "Seq No:$want" ] && break; sleep 5; done; echo "$got"; }

echo "### 1. dora, the delegator: an ordinary identifier with three witnesses"
for n in dora dan; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done; done
cat > dora-icp.json <<JSON
{"transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}
JSON
kli incept --name dora --alias dora --passcode "$PC" --file dora-icp.json >/dev/null
DORA=$(aid dora); echo "dora: $DORA"
kli oobi resolve --name dan --passcode "$PC" --oobi-alias dora --oobi "http://127.0.0.1:5642/oobi/$DORA/witness" >/dev/null

echo; echo "### 2. dan asks to be delegated: the delegated inception names dora in delpre"
cat > dan-icp.json <<JSON
{"delpre": "$DORA", "transferable": true, "wits": ["$WAN"], "toad": 1, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}
JSON
cat dan-icp.json
# dan needs an ordinary identifier (a proxy) to talk to dora's witnesses while his own event is waiting
kli incept --name dan --alias proxy --passcode "$PC" --file dora-icp.json >/dev/null
to 120 kli incept --name dan --alias dan --passcode "$PC" --proxy proxy --file dan-icp.json > dan-icp.log 2>&1 &
sleep 20
echo "dan, before dora approves:"; status dan dan 3,5

echo; echo "### 3. dora approves. The seal goes into HER log."
to 90 kli delegate confirm --name dora --alias dora --passcode "$PC" -Y 2>&1 | grep -E "Anchored|committed"
wait; sleep 3
echo "dan, after:"; status dan dan 3,5
echo "dora is now at sn $(status dora dora 3,3 | awk '{print $NF}')"
kli export --name dan --alias dan --passcode "$PC" > dan1.cesr; kli export --name dora --alias dora --passcode "$PC" > dora1.cesr
echo "dan's log:"; fields dan1.cesr; echo "dora's log:"; fields dora1.cesr

echo; echo "### 4. a stranger (val) resolves ONLY dan's OOBI. The software goes and finds dora's log"
DAN=$(aid dan)
for s in val val2; do kli init --name $s --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $s --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done; done
to 40 kli oobi resolve --name val --passcode "$PC" --oobi-alias dan --oobi "http://127.0.0.1:5642/oobi/$DAN/witness" >/dev/null 2>&1
echo "val sees dan at: $(seen val $DAN 0)"
echo "val sees dora at: $(seen val $DORA 1)"
kli kevers --name val --passcode "$PC" --prefix $DAN 2>&1 | sed -n 3,4p

echo; echo "### 5. dan rotates and dora has not approved yet"
to 400 kli rotate --name dan --alias dan --passcode "$PC" --proxy proxy > dan-rot.log 2>&1 &
ROT=$!
sleep 12
echo "dan's own view:"; status dan dan 3,5
to 40 kli oobi resolve --name val2 --passcode "$PC" --oobi-alias dan --oobi "http://127.0.0.1:5642/oobi/$DAN/witness" >/dev/null 2>&1
echo "a second stranger (val2) sees dan at: $(seen val2 $DAN 0)"

echo; echo "### 6. dora approves, this time anchoring in an interaction event, and dan's waiting process finishes"
to 90 kli delegate confirm --name dora --alias dora --passcode "$PC" --interact -Y 2>&1 | grep -E "Anchored|committed"
wait $ROT; sleep 3
echo "dan's own view:"; status dan dan 3,5
kli export --name dan --alias dan --passcode "$PC" > dan2.cesr; kli export --name dora --alias dora --passcode "$PC" > dora2.cesr
echo "dan's log:"; fields dan2.cesr; echo "dora's log:"; fields dora2.cesr
# an OOBI that was already resolved is cached, so a third stranger shows what a verifier learns now
kli init --name val3 --passcode "$PC" >/dev/null
for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
  kli oobi resolve --name val3 --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
to 40 kli oobi resolve --name val3 --passcode "$PC" --oobi-alias dan --oobi "http://127.0.0.1:5642/oobi/$DAN/witness" >/dev/null 2>&1
echo "a third stranger (val3), after the approval, sees dan at: $(seen val3 $DAN 1)"
