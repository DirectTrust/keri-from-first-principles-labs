#!/usr/bin/env bash
# Lab 11: when the thief holds the NEXT key too, and the emergency exit (abandonment).
# REQUIRES start-witnesses.sh. Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
key()    { kli status --name "$1" --alias "$2" --passcode "$PC" | grep -E "^\s+1\. D" | sed -E 's/^[[:space:]]*1\.[[:space:]]*//'; }
sn()     { kli status --name "$1" --alias "$2" --passcode "$PC" | sed -n 3p | tr -d '\t'; }
wlog()   { curl -s "http://127.0.0.1:$1/oobi/$2/witness" > w.cesr; python3 "$HERE/cesr_describe.py" w.cesr | grep -E "^(icp|rot|ixn)" | sed 's/^/    /'; }
witoobis() { for p in "5642 $WAN" "5643 $WIL" "5644 $WES"; do set -- $p
  kli oobi resolve --name "$s" --passcode "$PC" --oobi-alias "w$1" --oobi "http://127.0.0.1:$1/oobi/$2/controller" >/dev/null; done; }

echo "### 1. gia, a controller with three witnesses"
s=gia; kli init --name gia --passcode "$PC" >/dev/null; witoobis
cat > gia-icp.json <<JSON
{"transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}
JSON
kli incept --name gia --alias gia --passcode "$PC" --file gia-icp.json --receipt-endpoint >/dev/null
GIA=$(kli aid --name gia --alias gia --passcode "$PC"); echo "gia: $GIA"; echo "gia's key now: $(key gia gia)"

echo; echo "### 2. a thief copies gia's WHOLE keystore: the current key AND the pre-rotated next key"
for d in ks db reg cf; do rm -rf "$HOME/.keri/$d/mal"; [ -e "$HOME/.keri/$d/gia" ] && cp -R "$HOME/.keri/$d/gia" "$HOME/.keri/$d/mal"; done
echo "thief's copy is at: $(sn mal gia)"

echo; echo "### 3. the thief rotates FIRST, using the next key, committing to TWO new next keys of his own"
to 90 kli rotate --name mal --alias gia --passcode "$PC" --receipt-endpoint --toad 2 --next-count 2 2>&1 | tail -3
echo "the thief's new key: $(key mal gia)"
for p in 5642 5643 5644; do echo "witness :$p"; wlog $p $GIA; done

echo; echo "### 4. gia notices, and rotates with the very same next key"
to 90 kli rotate --name gia --alias gia --passcode "$PC" --receipt-endpoint --toad 2 > gia-rot.log 2>&1; cat gia-rot.log | cut -c1-150
echo "gia's own log:"; kli export --name gia --alias gia --passcode "$PC" > gia.cesr; python3 "$HERE/cesr_describe.py" gia.cesr | grep -E "^(icp|rot|ixn)" | sed 's/^/    /'
echo "the thief's log:"; kli export --name mal --alias gia --passcode "$PC" > mal.cesr; python3 "$HERE/cesr_describe.py" mal.cesr | grep -E "^(icp|rot|ixn)" | sed 's/^/    /'
echo "what the witnesses hold, again:"
for p in 5642 5643 5644; do echo "witness :$p"; wlog $p $GIA | tail -1; done

echo; echo "### 5. a stranger (vic) resolves gia through a witness"
s=vic; kli init --name vic --passcode "$PC" >/dev/null; witoobis
to 40 kli oobi resolve --name vic --passcode "$PC" --oobi-alias gia --oobi "http://127.0.0.1:5642/oobi/$GIA/witness" >/dev/null 2>&1; sleep 3
echo "vic sees: $(kli kevers --name vic --passcode "$PC" --prefix $GIA | sed -n 2p | tr -d '\t'), key $(kli kevers --name vic --passcode "$PC" --prefix $GIA | grep -E '^\s+1\. D' | sed -E 's/^[[:space:]]*1\.[[:space:]]*//')"
kli kevers --name vic --passcode "$PC" --prefix $GIA --verbose 2>&1 | python3 -c '
import sys, re, json
t = sys.stdin.read()
for m in re.finditer(r"\{\n \"v\".*?\n\}", t, re.S):
    d = json.loads(m.group(0))
    if d["t"] in ("icp", "rot"): print("vic holds", d["t"], "s=%s" % d["s"], "with", len(d["n"]), "next-key digest(s), SAID", d["d"][:12] + "...")
'

echo; echo "### 6. the emergency exit: abandonment. hal rotates with NO next key"
s=hal; kli init --name hal --passcode "$PC" >/dev/null
echo '{"transferable": true, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1", "toad": 0, "wits": []}' > hal-icp.json
kli incept --name hal --alias hal --passcode "$PC" --file hal-icp.json >/dev/null
kli rotate --name hal --alias hal --passcode "$PC" --next-count 0 --nsith 0 2>&1 | tail -3
kli export --name hal --alias hal --passcode "$PC" > hal.cesr
python3 - <<'PY'
import re, json
t = open("hal.cesr").read()
for o in re.findall(r'\{"v":"KERI10JSON[0-9a-f]{6}_".*?\}(?=-V|-A|\{"v"|$)', t):
    d = json.loads(o)
    print(d["t"], "s=" + d["s"], "n=" + json.dumps(d["n"]), "nt=" + str(d["nt"]))
PY

echo; echo "### 7. nothing can happen to hal ever again"
echo "a further rotation:"; kli rotate --name hal --alias hal --passcode "$PC" 2>&1 | tail -1 | cut -c1-160
echo "an interaction event:"; echo '[{"x":1}]' > hal-seal.json; kli interact --name hal --alias hal --passcode "$PC" --data @hal-seal.json 2>&1 | tail -1 | cut -c1-160
echo "hal is still at: $(sn hal hal)"
