#!/usr/bin/env bash
# Lab 3: create an identifier, rotate it, anchor data, and look at the log. No witnesses needed.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"

echo "### 1. create a key store + event database (keystore is encrypted with the passcode)"
kli init --name alice --passcode "$PC"

echo; echo "### 2. inception: one signing key, one pre-rotated next key, no witnesses"
echo '{"transferable": true, "wits": [], "toad": 0, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}' > alice-icp.json
kli incept --name alice --alias alice --passcode "$PC" --file alice-icp.json

echo; echo "### 3. status (shows the inception event)"
kli status --name alice --alias alice --passcode "$PC" --verbose | sed -n 1,40p

echo; echo "### 4. rotate: reveals the next key, commits to a new one"
kli rotate --name alice --alias alice --passcode "$PC"

echo; echo "### 5. interact: anchor a digest seal of a document in the log"
printf '{"d":"","doc":"example document body"}' > doc.json
kli saidify --file doc.json --label d
python3 -c "import json; d=json.load(open('doc.json')); json.dump({'d': d['d']}, open('seal.json','w'))"
echo "seal: $(cat seal.json)"
kli interact --name alice --alias alice --passcode "$PC" --data @seal.json

echo; echo "### 6. export the whole log as a CESR stream, and take it apart"
kli export --name alice --alias alice --passcode "$PC" > alice.cesr
python3 "$HERE/cesr_describe.py" alice.cesr
echo; echo "(raw stream is in $LAB_DIR/alice.cesr; the first event is):"
head -c 560 alice.cesr; echo " ..."
