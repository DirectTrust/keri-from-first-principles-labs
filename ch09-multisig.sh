#!/usr/bin/env bash
# Lab 9: three people jointly control one identifier. REQUIRES start-witnesses.sh in another terminal.
# Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }

# helpers --------------------------------------------------------------------------------------
aid()   { kli aid --name "$1" --alias "${2:-$1}" --passcode "$PC"; }
query() { to 40 kli query --name "$1" --alias "$1" --passcode "$PC" --prefix "$2" >/dev/null 2>&1; }  # $1 asks a witness about $2
status(){ kli status --name "$1" --alias "$2" --passcode "$PC" | sed -n "${3:-1,12}p"; }
events(){ kli export --name ann --alias acme --passcode "$PC" > "$1"; python3 "$HERE/cesr_describe.py" "$1" | grep -E '^(icp|rot|ixn)|controller sigs'; }
fields(){ python3 - "$1" <<'PY'
import re, json, sys
for o in re.findall(r'\{"v":"KERI10JSON[0-9a-f]{6}_".*?\}(?=-V|\{"v"|$)', open(sys.argv[1]).read()):
    d = json.loads(o); k = d.get("k")
    w = lambda t: ",".join(t) if isinstance(t, list) else t
    if d["t"] in ("icp", "rot"):
        print(f'{d["t"]} s={d["s"]} kt={w(d["kt"])} keys={len(k)} nt={w(d["nt"])} ndigests={len(d["n"])} bt={d["bt"]}')
    else:
        print(f'{d["t"]} s={d["s"]} a={d["a"]}')
PY
}
# run the same group command for several members at once; every member must run it for it to finish
together() { local cmd=$1; shift; local who=$1; shift
  for n in $who; do to 90 kli multisig $cmd --name $n --alias acme --passcode "$PC" "$@" > "$n-$cmd.log" 2>&1 & done; wait; }

echo "### 1. three people, each with an ordinary single-key identifier and the same three witnesses"
for n in ann ben cat; do
  kli init --name $n --passcode "$PC" >/dev/null
  for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
    kli oobi resolve --name $n --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null
  done
  cat > $n-icp.json <<JSON
{"transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}
JSON
  kli incept --name $n --alias $n --passcode "$PC" --file $n-icp.json >/dev/null
  echo "$n: $(aid $n)"
done
A=$(aid ann); B=$(aid ben); C=$(aid cat)

echo; echo "### 2. everyone resolves everyone else's OOBI, so each can verify the others' logs"
oobi() { kli oobi resolve --name $1 --passcode "$PC" --oobi-alias $2 --oobi "http://127.0.0.1:5642/oobi/$3/witness" >/dev/null; }
oobi ann ben $B; oobi ann cat $C; oobi ben ann $A; oobi ben cat $C; oobi cat ann $A; oobi cat ben $B
echo "ann now knows: $(kli contacts list --name ann --passcode "$PC" | grep '"alias"' | tr -d ' \n')"

echo; echo "### 3. the group inception file: members, witnesses, and a weighted threshold"
cat > group-icp.json <<JSON
{"aids": ["$A","$B","$C"], "transferable": true, "wits": ["$WAN","$WIL","$WES"], "toad": 2,
 "isith": ["1/2","1/2","1/2"], "nsith": ["1/2","1/2","1/2"]}
JSON
cat group-icp.json

echo; echo "### 4. all three members run the group inception at the same time"
for n in ann ben cat; do
  kli multisig incept --name $n --alias $n --passcode "$PC" --group acme --file group-icp.json > $n-incept.log 2>&1 &
done; wait
status ann acme 1,9
G=$(aid ann acme); echo "group AID: $G"

echo; echo "### 5. the group's inception event: three keys, three next digests, three controller signatures"
events acme1.cesr; fields acme1.cesr

echo; echo "### 6. what the members sent each other to coordinate (ben's database)"
python3 "$HERE/ch09-exns.py" ben

echo; echo "### 7. ann proposes an interaction event ALONE: one weight of 1/2 is not enough, nothing is finalized"
to 25 kli multisig interact --name ann --alias acme --passcode "$PC" --data '[{"note":"first group ixn"}]' >/dev/null 2>&1
status ann acme 3,4

echo; echo "### 8. ann and ben propose the same event: two weights of 1/2 reach 1"
together interact "ann ben" --data '[{"note":"first group ixn"}]'
status ann acme 3,4; events acme2.cesr | tail -3
echo "cat did not take part and has not heard yet:"; status cat acme 3,4

echo; echo "### 9. cat catches up by asking a witness"
query cat $G; status cat acme 3,4

echo; echo "### 10. a partial rotation: ann and ben reveal keys, but all three stay committed to the next set"
for n in ann ben; do kli rotate --name $n --alias $n --passcode "$PC" --receipt-endpoint >/dev/null 2>&1; done
query ben $A; query ann $B
together rotate "ann ben" --smids $A --smids $B --rmids $A --rmids $B --rmids $C --isith '["1/2","1/2"]' --nsith '["1/2","1/2","1/2"]'
kli export --name ann --alias acme --passcode "$PC" > acme3.cesr; fields acme3.cesr | tail -1
query cat $G; echo "cat caught up to sn $(status cat acme 3,3 | awk '{print $NF}')"
echo "cat tries to sign an interaction anyway:"
to 20 kli multisig interact --name cat --alias acme --passcode "$PC" --data '[{"x":1}]' 2>&1 | tail -1

echo; echo "### 11. removing cat: ann and ben rotate again and commit only to themselves"
for n in ann ben; do kli rotate --name $n --alias $n --passcode "$PC" --receipt-endpoint >/dev/null 2>&1; done
query ben $A; query ann $B
together rotate "ann ben" --smids $A --smids $B --rmids $A --rmids $B --isith '["1/2","1/2"]' --nsith '["1/2","1/2"]'
kli export --name ann --alias acme --passcode "$PC" > acme4.cesr; fields acme4.cesr
query cat $G
echo "cat tries once more:"; to 20 kli multisig interact --name cat --alias acme --passcode "$PC" --data '[{"x":1}]' 2>&1 | tail -1
