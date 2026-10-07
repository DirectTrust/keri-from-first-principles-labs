#!/usr/bin/env bash
# Lab 4b: events that arrive early. Splits the book's three-event log and imports it in other orders.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"; PC="$LAB_PASSCODE"
AID=EDtDtkoN6MZZlQD2Ke1kKLppIX0gHhNYvg0mZz6MQLLj          # the book's identifier (see make_book_kel.py)
python3 "$HERE/make_book_kel.py" >/dev/null
python3 - "$HERE/book-kel.cesr" <<'PY'
import re, sys
m = [p for p in re.split(r'(?=\{"v":"KERI10JSON)', open(sys.argv[1]).read()) if p]   # icp, rot, ixn
open("order-rot-only.cesr", "w").write(m[1])
open("order-rot-icp-ixn.cesr", "w").write(m[1] + m[0] + m[2])
open("order-ixn-rot-icp.cesr", "w").write(m[2] + m[1] + m[0])
PY
summary() { kli escrow list --name "$1" --passcode "$PC" | python3 -c "
import sys, json
d = json.load(sys.stdin); e = {k: len(v) for k, v in d.items() if isinstance(v, list) and v}
print('   escrows:', e or 'none')"; }
for f in rot-only rot-icp-ixn ixn-rot-icp; do
  n="arr_$f"; rm -rf "$HOME/.keri"/{ks,db,reg,cf}/$n; kli init --name "$n" --passcode "$PC" >/dev/null
  echo "### import order: $f"
  kli import --name "$n" --passcode "$PC" --file "order-$f.cesr"
  echo "   $(kli kevers --name "$n" --passcode "$PC" --prefix "$AID" 2>&1 | grep -E 'Seq No|rror' | head -1)"
  summary "$n"
done
