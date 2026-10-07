#!/usr/bin/env bash
# Lab 5b: what the software enforces about witness thresholds. REQUIRES start-witnesses.sh.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; cd "$LAB_DIR"; PC="$LAB_PASSCODE"
rm -rf "$HOME/.keri"/{ks,db,reg,cf}/x5; kli init --name x5 --passcode "$PC" >/dev/null
for p in "5642 $WAN" "5643 $WIL" "5644 $WES"; do set -- $p
  kli oobi resolve --name x5 --passcode "$PC" --oobi-alias "w$1" --oobi "http://127.0.0.1:$1/oobi/$2/controller" >/dev/null; done
try() {   # try <alias> <toad> <witness1> [<witness2> ...]
  local alias=$1 toad=$2; shift 2; local w; w=$(printf '"%s",' "$@"); w="[${w%,}]"
  echo "{\"transferable\": true, \"wits\": $w, \"toad\": $toad, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > "$alias.json"
  echo "--- $# witness(es), toad $toad:"; kli incept --name x5 --alias "$alias" --passcode "$PC" --file "$alias.json" --receipt-endpoint 2>&1 | head -2 || true; }
try t0  0 "$WAN" "$WIL" "$WES"      # toad 0 with witnesses
try t4  4 "$WAN" "$WIL" "$WES"      # toad larger than N
try dup 1 "$WAN" "$WAN"             # a duplicate witness
try t1  1 "$WAN" "$WIL" "$WES"      # toad 1 of 3: accepted, but is it SAFE? (see KAWA)
echo "--- the witnesses of the accepted identifier:"; kli witness list --name x5 --alias t1 --passcode "$PC"
