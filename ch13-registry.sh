#!/usr/bin/env bash
# Lab 13: a credential's life in its registry: issued, checked, revoked, checked again. REQUIRES start-witnesses.sh.
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -f clinic-schema.json ] || python3 "$HERE/ch12-acdc.py" >/dev/null
SCHEMA=$(python3 -c 'import json; print(json.load(open("clinic-schema.json"))["$id"])')
tel() { python3 - "$1" <<'PY'
import re, json, sys
t = open(sys.argv[1]).read()
for o in re.findall(r'\{"v":"(?:KERI|ACDC)10JSON[0-9a-f]{6}_".*?\}(?=-V|-I|-A|-G|\{"v"|$)', t, re.S):
    try: d = json.loads(o)
    except ValueError: continue
    k = d.get("t", "acdc"); s = lambda x: x[:10] + "..."
    if k == "vcp": print(f'  vcp  registry={s(d["i"])} issuer={s(d["ii"])} traits={d["c"]} backers={len(d["b"])} bt={d["bt"]}')
    if k == "iss": print(f'  iss  credential={s(d["i"])} s={d["s"]} registry={s(d["ri"])}')
    if k == "rev": print(f'  rev  credential={s(d["i"])} s={d["s"]} prior={s(d["p"])}')
    if k == "ixn" and d["a"]: print(f'  ixn  s={d["s"]} anchors {s(d["a"][0]["i"])} s={d["a"][0]["s"]} d={s(d["a"][0]["d"])}')
PY
}
status() { kli vc list --name "$1" --alias "$1" --passcode "$PC" ${2:-} 2>&1 | grep -E "Status:|Credential #" | sed 's/\x1b\[[0-9;]*m//g'; }

echo "### 1. an issuer (acc) and a holder (cli), each witnessed, each knowing the other and the schema"
for n in acc cli; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null
  kli vc schema import --name $n --passcode "$PC" --schema clinic-schema.json >/dev/null; done
ACC=$(kli aid --name acc --alias acc --passcode "$PC"); CLI=$(kli aid --name cli --alias cli --passcode "$PC")
kli oobi resolve --name acc --passcode "$PC" --oobi-alias cli --oobi "http://127.0.0.1:5642/oobi/$CLI/witness" >/dev/null
kli oobi resolve --name cli --passcode "$PC" --oobi-alias acc --oobi "http://127.0.0.1:5642/oobi/$ACC/witness" >/dev/null
echo "issuer acc: $ACC"; echo "holder cli: $CLI"

echo; echo "### 2. the issuer creates a registry. The registry has its own log, a TEL"
kli vc registry incept --name acc --alias acc --passcode "$PC" --registry-name clinics >/dev/null 2>&1
kli vc registry status --name acc --registry-name clinics --passcode "$PC" --verbose 2>&1 | sed -n '/^{/,/^}/p'

echo; echo "### 3. the issuer issues a credential: one new event in the registry, one seal in the issuer's log"
echo '{"clinicName": "Riverside Family Clinic", "status": "accredited"}' > clinic-data.json
to 120 kli vc create --name acc --alias acc --passcode "$PC" --registry-name clinics --schema "$SCHEMA" --recipient "$CLI" --data @clinic-data.json >/dev/null 2>&1
SAID=$(kli vc list --name acc --alias acc --passcode "$PC" --issued --said 2>&1 | tail -1); echo "credential: $SAID"
kli vc export --name acc --alias acc --passcode "$PC" --said "$SAID" --full > issued.cesr 2>/dev/null
tel issued.cesr

echo; echo "### 4. the holder imports what the issuer exported, and checks status"
kli vc import --name cli --passcode "$PC" --file issued.cesr >/dev/null 2>&1
status cli

echo; echo "### 5. the issuer revokes. Nothing about the credential changes. The TEL grows by one event"
to 90 kli vc revoke --name acc --alias acc --passcode "$PC" --registry-name clinics --said "$SAID" >/dev/null 2>&1
echo "issuer's own view:"; status acc --issued
kli vc export --name acc --alias acc --passcode "$PC" --said "$SAID" --full > revoked.cesr 2>/dev/null
echo "stream size: $(wc -c < issued.cesr) -> $(wc -c < revoked.cesr) bytes"; tel revoked.cesr

echo; echo "### 6. the holder's view depends on which proof it has seen"
echo "still holding the old stream, status is whatever the holder last imported:"; status cli
kli vc import --name cli --passcode "$PC" --file revoked.cesr >/dev/null 2>&1
echo "after importing the newer stream:"; status cli
kli vc import --name cli --passcode "$PC" --file issued.cesr >/dev/null 2>&1
echo "after importing the OLD stream again (the TEL does not go backwards):"; status cli

echo; echo "### 7. revoking twice is a conflict, not a no-op"
to 60 kli vc revoke --name acc --alias acc --passcode "$PC" --registry-name clinics --said "$SAID" 2>&1 | tail -1 | cut -c1-110

echo; echo "### 8. a registry with backers of its own: the inception event looks different"
to 150 kli vc registry incept --name acc --alias acc --passcode "$PC" --registry-name backed --no-backers "" --backers $WAN --backers $WIL --backers $WES >/dev/null 2>&1
kli vc registry status --name acc --registry-name backed --passcode "$PC" --verbose 2>&1 | sed -n '/^{/,/^}/p' | python3 -c "
import sys, json; d = json.load(sys.stdin); print('  vcp traits=%s backers=%d bt=%s' % (d['c'], len(d['b']), d['bt']))"
