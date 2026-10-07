#!/usr/bin/env bash
# Lab 5: bind a controller to three witnesses and watch the receipts. REQUIRES start-witnesses.sh
# to be running in another terminal.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }

echo "### 1. what a witness serves when you resolve its OOBI (this is Step 1 of Chapter 5)"
curl -s "http://127.0.0.1:5642/oobi/$WAN/controller" > wan-oobi.cesr
python3 "$HERE/cesr_describe.py" wan-oobi.cesr

echo; echo "### 2. a controller (carol) resolves the three witness OOBIs"
kli init --name carol --passcode "$PC" >/dev/null
kli oobi resolve --name carol --passcode "$PC" --oobi-alias wan --oobi "http://127.0.0.1:5642/oobi/$WAN/controller"
kli oobi resolve --name carol --passcode "$PC" --oobi-alias wil --oobi "http://127.0.0.1:5643/oobi/$WIL/controller"
kli oobi resolve --name carol --passcode "$PC" --oobi-alias wes --oobi "http://127.0.0.1:5644/oobi/$WES/controller"

echo; echo "### 3. inception with three witnesses and a threshold (toad) of 2"
cat > carol-icp.json <<JSON
{"transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}
JSON
kli incept --name carol --alias carol --passcode "$PC" --file carol-icp.json --receipt-endpoint
kli status --name carol --alias carol --passcode "$PC" | sed -n 1,12p

echo; echo "### 4. the fully receipted event: controller signature (-A) plus indexed witness signatures (-B)"
kli export --name carol --alias carol --passcode "$PC" > carol.cesr
python3 "$HERE/cesr_describe.py" carol.cesr
CAROL=$(kli aid --name carol --alias carol --passcode "$PC")
echo "carol's AID: $CAROL"

echo; echo "### 5. carol's OOBI, as she would hand it to a stranger"
kli oobi generate --name carol --alias carol --passcode "$PC" --role witness | head -1

echo; echo "### 6. a stranger (dave) resolves that OOBI and validates her log without ever contacting carol"
kli init --name dave --passcode "$PC" >/dev/null
kli oobi resolve --name dave --passcode "$PC" --oobi-alias carol --oobi "http://127.0.0.1:5642/oobi/$CAROL/witness"
kli kevers --name dave --passcode "$PC" --prefix "$CAROL" | sed -n 1,10p

echo; echo "### 7. carol rotates WITHOUT --toad: watch what happens to the witness threshold"
kli rotate --name carol --alias carol --passcode "$PC" --receipt-endpoint
kli status --name carol --alias carol --passcode "$PC" | sed -n 1,9p
echo "(Threshold changed from 2 to 3. keripy recomputes the default toad on rotation unless you pass --toad.)"
