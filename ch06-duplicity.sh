#!/usr/bin/env bash
# Lab 6: staleness, duplicity, and recovery with real witnesses. REQUIRES start-witnesses.sh running.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
state() { kli kevers --name "$1" --passcode "$PC" --prefix "$2" | grep -E "Seq No|^\s+1\. D" | tr -s "\t " " " | sed "s/^/    /"; }
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
branch() {   # which key does verifier $1 currently hold for $ERIN: the recovered one, or the thief's?
  local k; k=$(kli kevers --name "$1" --passcode "$PC" --prefix "$ERIN" | grep -E "^\s+1\. D" | sed -E 's/^[[:space:]]*1\.[[:space:]]*//')
  if [ "$k" = "$ERIN_KEY" ]; then echo "    $1 holds erin's RECOVERED key"; elif [ "$k" = "$THIEF_KEY" ]; then echo "    $1 holds the THIEF's key"; else echo "    $1 holds another key: $k"; fi; }

echo "### 1. erin: a controller with three witnesses (toad 2)"
kli init --name erin --passcode "$PC" >/dev/null
for pair in "5642 $WAN" "5643 $WIL" "5644 $WES"; do set -- $pair
  kli oobi resolve --name erin --passcode "$PC" --oobi-alias "w$1" --oobi "http://127.0.0.1:$1/oobi/$2/controller" >/dev/null; done
cat > erin-icp.json <<JSON
{"transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}
JSON
kli incept --name erin --alias erin --passcode "$PC" --file erin-icp.json --receipt-endpoint | head -2
ERIN=$(kli aid --name erin --alias erin --passcode "$PC")

echo; echo "### 2. vic: a verifier. A verifier needs a witness of its own: that is its MAILBOX (Chapter 7)"
kli init --name vic --passcode "$PC" >/dev/null
kli oobi resolve --name vic --passcode "$PC" --oobi-alias wan --oobi "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null
echo "{\"transferable\": true, \"wits\": [\"$WAN\"], \"toad\": 1, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > vic-icp.json
kli incept --name vic --alias vic --passcode "$PC" --file vic-icp.json --receipt-endpoint | head -2
kli oobi resolve --name vic --passcode "$PC" --oobi-alias erin --oobi "http://127.0.0.1:5642/oobi/$ERIN/witness"
echo "vic's view of erin:"; state vic "$ERIN"

echo; echo "### 3. STALENESS: erin rotates; vic does not know"
kli rotate --name erin --alias erin --passcode "$PC" --receipt-endpoint --toad 2 | head -2
echo "vic (stale):"; state vic "$ERIN"
echo "vic asks the witnesses for updates:"; kli query --name vic --alias vic --passcode "$PC" --prefix "$ERIN" >/dev/null; state vic "$ERIN"

echo; echo "### 4. DUPLICITY: a thief copies erin's keystore (keys + passcode) and publishes an interaction event"
for d in ks db reg cf; do [ -e "$HOME/.keri/$d/erin" ] && rm -rf "$HOME/.keri/$d/mallory" && cp -R "$HOME/.keri/$d/erin" "$HOME/.keri/$d/mallory"; done
echo '{"d":"EDPrbne4nB8tNzlROw7E_tSDzs0F16uSvfU54pAVKP3x"}' > thief-seal.json
kli interact --name mallory --alias erin --passcode "$PC" --data @thief-seal.json | head -2
echo "...and the real erin, unaware, rotates to recover (same sequence number):"
kli rotate --name erin --alias erin --passcode "$PC" --receipt-endpoint --toad 2 | head -2

echo; ERIN_KEY=$(kli status --name erin --alias erin --passcode "$PC" | grep -E "^\s+1\. D" | sed -E 's/^[[:space:]]*1\.[[:space:]]*//')
THIEF_KEY=$(kli status --name mallory --alias erin --passcode "$PC" | grep -E "^\s+1\. D" | sed -E 's/^[[:space:]]*1\.[[:space:]]*//')
echo "erin's current key : $ERIN_KEY"; echo "the thief's key    : $THIEF_KEY"

echo; echo "### 5. what each witness now holds for erin:"
for p in 5642 5643 5644; do echo "witness :$p"; curl -s "http://127.0.0.1:$p/oobi/$ERIN/witness" > w.cesr
  python3 "$HERE/cesr_describe.py" w.cesr | grep -E "^(icp|rot|ixn)" | sed 's/^/    /'; done

echo; echo "### 6. vic asks 'anything newer?'"
kli query --name vic --alias vic --passcode "$PC" --prefix "$ERIN" >/dev/null; state vic "$ERIN"; branch vic
echo "(Which branch vic lands on first depends on which event reached it first: that is the first-seen rule.)"

echo; echo "### 7. vic fetches the full log from a DIFFERENT witness (a fresh OOBI URL, not the cached one)"
kli oobi resolve --name vic --passcode "$PC" --oobi-alias erin2 --oobi "http://127.0.0.1:5643/oobi/$ERIN/witness"
sleep 2
state vic "$ERIN"; branch vic
python3 "$HERE/ch04-inspect-db.py" vic "$ERIN" | grep -A4 -E "^\[(kels|fels)\."
echo "(Two events share one sequence number; the rotation superseded the interaction event: rule A0.)"
echo "However vic arrived here, the recovered key wins."
