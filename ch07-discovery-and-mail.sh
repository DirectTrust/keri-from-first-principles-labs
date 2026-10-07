#!/usr/bin/env bash
# Lab 7c: OOBI anatomy, contacts, a mailbox, and a challenge-response. REQUIRES start-witnesses.sh.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"; PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }

mk() {   # mk <name>: a controller with the three demo witnesses, toad 2
  kli init --name "$1" --passcode "$PC" >/dev/null
  for pair in "5642 $WAN" "5643 $WIL" "5644 $WES"; do set -- "$1" $pair
    kli oobi resolve --name "$1" --passcode "$PC" --oobi-alias "w$2" --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > "$1-icp.json"
  kli incept --name "$1" --alias "$1" --passcode "$PC" --file "$1-icp.json" --receipt-endpoint | head -1
}
echo "### 1. two controllers: gina and hal"
mk gina; mk hal
GINA=$(kli aid --name gina --alias gina --passcode "$PC"); HAL=$(kli aid --name hal --alias hal --passcode "$PC")

echo; echo "### 2. an OOBI is an HTTP GET. Look at the response headers of a witness's own OOBI:"
curl -si "http://127.0.0.1:5642/oobi/$WAN/controller" | tr -d '\r' | sed -n '1,/^$/p' | grep -E "^HTTP|^Keri-Aid|^Content-Type"

echo; echo "### 3. the same identifier through different OOBI paths (what comes back):"
for path in "$HAL" "$HAL/witness" "$HAL/witness/$WAN"; do
  echo "GET /oobi/${path//$HAL/<hal>}"; curl -s "http://127.0.0.1:5642/oobi/$path" | python3 "$HERE/cesr_describe.py" | grep -E "^(icp|rot|ixn|rpy)" | sed 's/^/    /'
done

echo; echo "### 4. what the server refuses"
for path in "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "../x"; do
  printf "GET /oobi/%s -> HTTP %s\n" "$path" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:5642/oobi/$path")"; done

echo; echo "### 5. gina and hal become contacts by resolving each other's OOBI"
kli oobi resolve --name gina --passcode "$PC" --oobi-alias hal --oobi "http://127.0.0.1:5642/oobi/$HAL/witness"
kli oobi resolve --name hal  --passcode "$PC" --oobi-alias gina --oobi "http://127.0.0.1:5642/oobi/$GINA/witness"

echo; echo "### 6. challenge-response: gina challenges hal; hal proves, in a signed message, that he controls his AID"
WORDS=$(kli challenge generate --out string)
echo "gina's challenge words: $WORDS"
echo "-- hal responds (the response is wrapped in a /fwd envelope and posted to one of gina's witnesses):"
to 90 kli challenge respond --name hal --alias hal --passcode "$PC" --recipient gina --words "$WORDS" || true
sleep 3
echo "-- which witnesses hold mail for gina? (a witness that is not gina's mailbox for this message just times out)"
for w in "$WAN" "$WIL" "$WES"; do
  out=$(to 12 kli mailbox debug --name gina --alias gina --passcode "$PC" --witness "$w" 2>&1 || true)
  if echo "$out" | grep -q "^Topic"; then echo "witness ${w:0:12}... holds:"; echo "$out" | grep -E "^Topic" | cut -c1-110 | sed 's/^/    /'; fi
done
echo "-- gina collects her mail and verifies:"
to 90 kli challenge verify --name gina --alias gina --passcode "$PC" --words "$WORDS" --signer hal 2>&1 | grep -v "^$"
