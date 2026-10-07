#!/usr/bin/env bash
# Lab 15b: a credential travels by IPEX: granted, admitted, presented, spurned. REQUIRES start-witnesses.sh.
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -f clinic-schema.json ] || python3 "$HERE/ch12-acdc.py" >/dev/null
SCHEMA=$(python3 -c 'import json; print(json.load(open("clinic-schema.json"))["$id"])')
held() { kli vc list --name "$1" --alias "$1" --passcode "$PC" 2>&1 | grep -E "Credential #|Status:" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^ *//'; echo "  ($(kli vc list --name "$1" --alias "$1" --passcode "$PC" 2>&1 | grep -c 'Credential #') credential(s) held)"; }
msgs() { kli ipex list --name "$1" --alias "$1" --passcode "$PC" --poll ${2:-} --said 2>&1 | grep -E "^E" ; }

echo "### 1. an issuer (acc), a holder (cli), and a verifier (buy), each witnessed and each knowing the others"
for n in acc cli buy; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null
  kli vc schema import --name $n --passcode "$PC" --schema clinic-schema.json >/dev/null; done
ACC=$(kli aid --name acc --alias acc --passcode "$PC"); CLI=$(kli aid --name cli --alias cli --passcode "$PC"); BUY=$(kli aid --name buy --alias buy --passcode "$PC")
for a in "acc $CLI cli" "acc $BUY buy" "cli $ACC acc" "cli $BUY buy" "buy $ACC acc" "buy $CLI cli"; do set -- $a
  kli oobi resolve --name $1 --passcode "$PC" --oobi-alias $3 --oobi "http://127.0.0.1:5642/oobi/$2/witness" >/dev/null; done
echo "issuer acc $ACC"; echo "holder cli $CLI"; echo "buyer  buy $BUY"

echo; echo "### 2. the issuer issues a credential to the holder. Nothing has been delivered yet"
kli vc registry incept --name acc --alias acc --passcode "$PC" --registry-name clinics >/dev/null 2>&1
echo '{"clinicName": "Riverside Family Clinic", "status": "accredited"}' > clinic-data.json
to 120 kli vc create --name acc --alias acc --passcode "$PC" --registry-name clinics --schema "$SCHEMA" --recipient "$CLI" --data @clinic-data.json >/dev/null 2>&1
SAID=$(kli vc list --name acc --alias acc --passcode "$PC" --issued --said | tail -1); echo "credential: $SAID"
echo "the holder holds:"; held cli

echo; echo "### 3. the issuer GRANTS it; the holder polls its mailbox"
to 90 kli ipex grant --name acc --alias acc --passcode "$PC" --said "$SAID" --recipient "$CLI" --message "Your accreditation" 2>&1 | tail -2
GRANT=$(to 90 kli ipex list --name cli --alias cli --passcode "$PC" --poll --said 2>&1 | grep -E "^E" | head -1)
echo "grant message SAID found by the holder: $GRANT"
kli ipex list --name cli --alias cli --passcode "$PC" --verbose 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | head -14 | cut -c1-110

echo "what the grant carried:"; python3 "$HERE/ch15-thread.py" cli

echo; echo "### 4. the holder ADMITS the grant, and now holds the credential"
to 90 kli ipex admit --name cli --alias cli --passcode "$PC" --said "$GRANT" --message "Thank you" 2>&1 | tail -2
sleep 3; echo "the holder holds:"; held cli
echo "the issuer is told:"; to 60 kli ipex list --name acc --alias acc --passcode "$PC" --poll --type admit --said 2>&1 | grep -E "^E" | head -2

echo; echo "### 5. the holder PRESENTS it: the same grant, to a verifier"
to 90 kli ipex grant --name cli --alias cli --passcode "$PC" --said "$SAID" --recipient "$BUY" --message "Here is my accreditation" 2>&1 | tail -2
PRES=$(to 90 kli ipex list --name buy --alias buy --passcode "$PC" --poll --said 2>&1 | grep -E "^E" | head -1)
echo "grant message SAID found by the verifier: $PRES"

echo; echo "### 6. the verifier SPURNS it. The holder hears about it"
to 90 kli ipex spurn --name buy --alias buy --passcode "$PC" --said "$PRES" --message "I asked for a different credential" 2>&1 | tail -2
sleep 3; echo "the holder's spurn messages:"; to 60 kli ipex list --name cli --alias cli --passcode "$PC" --poll --type spurn --said 2>&1 | grep -E "^E" | head -2
echo "the verifier holds:"; held buy

echo; echo "### 7. each party's record, and which message answers which"
for n in acc cli buy; do echo "$n:"; python3 "$HERE/ch15-thread.py" $n | sed 's/^/  /'; done
