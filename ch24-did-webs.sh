#!/usr/bin/env bash
# Lab 24: publish a KERI identifier the did:webs way, resolve it, and try to cheat. No witnesses needed.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"; W="$LAB_DIR/webroot"; PORT=8765; rm -rf "$W"; mkdir -p "$W"
trap 'kill $SRV 2>/dev/null' EXIT

echo "### 1. an ordinary KERI identifier that has rotated once (no witnesses, to keep this offline)"
kli init --name alice22 --passcode "$PC" >/dev/null
echo '{"transferable": true, "wits": [], "toad": 0, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}' > alice22-icp.json
kli incept --name alice22 --alias alice22 --passcode "$PC" --file alice22-icp.json >/dev/null
kli rotate --name alice22 --alias alice22 --passcode "$PC" >/dev/null 2>&1
AID=$(kli aid --name alice22 --alias alice22 --passcode "$PC"); echo "AID: $AID"

echo; echo "### 2. publish: two static files, served by any web server"
python3 "$HERE/ch24-did-webs.py" make alice22 alice22 "$W" "localhost:$PORT" people/alice
(cd "$W" && python3 -m http.server $PORT --bind 127.0.0.1 >/dev/null 2>&1) & SRV=$!; sleep 1
DID="did:webs:localhost%3a$PORT:people:alice:$AID"
echo "the DID document:"; python3 -c "
import json; d=json.load(open('$W/people/alice/$AID/did.json')); print(json.dumps(d, indent=1)[:700])" | sed 's/^/  /'

echo; echo "### 3. resolve it, the honest way"
python3 "$HERE/ch24-did-webs.py" resolve "$DID"

echo; echo "### 4. an attacker who controls the web server swaps the key in did.json for their own"
python3 - <<PY
import json, base64
p = "$W/people/alice/$AID/did.json"; d = json.load(open(p))
d["verificationMethod"][0]["publicKeyJwk"]["x"] = base64.urlsafe_b64encode(bytes(32)).decode().rstrip("=")
json.dump(d, open(p, "w"), indent=2)
PY
python3 "$HERE/ch24-did-webs.py" resolve "$DID" | tail -4

echo; echo "### 5. a cleverer attacker corrupts the event stream too, to match"
python3 - <<PY
p = "$W/people/alice/$AID/keri.cesr"; b = bytearray(open(p, "rb").read()); b[200] = (b[200] + 1) % 256; open(p, "wb").write(bytes(b))
PY
python3 "$HERE/ch24-did-webs.py" resolve "$DID" | tail -3
