#!/usr/bin/env bash
# Lab 12b: issue a real ACDC with kli. REQUIRES start-witnesses.sh. Run ch12-acdc.py first (it writes the schema).
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -f clinic-schema.json ] || python3 "$HERE/ch12-acdc.py" >/dev/null
SCHEMA=$(python3 -c 'import json; print(json.load(open("clinic-schema.json"))["$id"])')

echo "### 1. an issuer (acc) and a holder (cli), each an ordinary witnessed identifier"
for n in acc cli; do kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
  echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > $n-icp.json
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null; done
ACC=$(kli aid --name acc --alias acc --passcode "$PC"); CLI=$(kli aid --name cli --alias cli --passcode "$PC")
echo "issuer acc: $ACC"; echo "holder cli: $CLI"
kli oobi resolve --name acc --passcode "$PC" --oobi-alias cli --oobi "http://127.0.0.1:5642/oobi/$CLI/witness" >/dev/null

echo; echo "### 2. the issuer loads the schema it will issue against"
kli vc schema import --name acc --passcode "$PC" --schema clinic-schema.json 2>&1 | tail -1
echo "schema SAID: $SCHEMA"

echo; echo "### 3. a registry: the place that will record this credential's status (Chapter 13 explains it)"
kli vc registry incept --name acc --alias acc --passcode "$PC" --registry-name clinics 2>&1 | tail -2
kli vc registry list --name acc --passcode "$PC" 2>&1 | tail -1

echo; echo "### 4. issue the credential"
echo '{"clinicName": "Riverside Family Clinic", "status": "accredited"}' > clinic-data.json
to 120 kli vc create --name acc --alias acc --passcode "$PC" --registry-name clinics --schema "$SCHEMA" --recipient "$CLI" --data @clinic-data.json 2>&1 | tail -3
SAID=$(kli vc list --name acc --alias acc --passcode "$PC" --issued --said 2>&1 | tail -1)
echo "credential SAID: $SAID"

echo; echo "### 5. the credential as issued, read back"
kli vc list --name acc --alias acc --passcode "$PC" --issued --verbose 2>&1 | head -40

echo; echo "### 6. what the issuer would hand over: the credential plus the proof around it"
kli vc export --name acc --alias acc --passcode "$PC" --said "$SAID" --full > cred.cesr 2>/dev/null
python3 - "$SAID" <<'PY'
import json, re, sys
t = open("cred.cesr").read()
print("stream size:", len(t), "bytes")
for o in re.findall(r'\{"v":"(?:KERI|ACDC)10JSON[0-9a-f]{6}_".*?\}(?=-V|-I|-A|\{"v"|$)', t, re.S):
    try: d = json.loads(o)
    except ValueError: continue
    kind = d.get("t", "acdc")
    seal = f'  anchors {[ {k: v[:10] + "..." for k, v in x.items()} for x in d["a"] ]}' if kind == "ixn" and d.get("a") else ""
    print(f'  {kind:4} d={d["d"][:14]}...' + (f' s={d["s"]}' if "s" in d and kind != "acdc" else "") + seal)
m = re.search(r'-IAB(E[\w-]{43})(0A\w{22})(E[\w-]{43})', t)
print("trailing seal-source triple: pre=%s... sn=%s dig=%s..." % (m.group(1)[:12], "0", m.group(3)[:12]))
PY
