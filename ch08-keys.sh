#!/usr/bin/env bash
# Lab 8: where keys come from, how a salt recreates them, and what a key store holds at rest.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"; PC="$LAB_PASSCODE"; PC2=abcdefghijklmnopqrstu
echo '{"transferable": true, "wits": [], "toad": 0, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1"}' > me.json
for n in orig restored plain; do for d in ks db reg cf; do rm -rf "$HOME/.keri/$d/$n"; done; done

echo "### 1. a salty key store: one random salt is the root of every key"
SALT=$(kli salt); echo "salt: $SALT"
kli init --name orig --salt "$SALT" --passcode "$PC" >/dev/null
kli incept --name orig --alias me --passcode "$PC" --file me.json | head -1
kli rotate --name orig --alias me --passcode "$PC" | sed -n 2p
kli rotate --name orig --alias me --passcode "$PC" | sed -n 2p
kli export --name orig --alias me --passcode "$PC" > orig.cesr

echo; echo "### 2. derive the keys BY HAND from the salt (no key store involved)"
python3 "$HERE/ch08-derive.py" "$SALT" me orig.cesr

echo; echo "### 3. DISASTER RECOVERY: lose the key store, keep only the salt. Rebuild with a DIFFERENT passcode."
kli init --name restored --salt "$SALT" --passcode "$PC2" >/dev/null
kli incept --name restored --alias me --passcode "$PC2" --file me.json | head -1
kli rotate --name restored --alias me --passcode "$PC2" | sed -n 2p
kli rotate --name restored --alias me --passcode "$PC2" | sed -n 2p
kli export --name restored --alias me --passcode "$PC2" > restored.cesr
python3 - <<'PY'
import re
ev = lambda f: [(m[0], m[1]) for m in re.findall(r'"t":"(icp|rot|ixn)","d":"([^"]+)"', open(f).read())]
a, b = ev("orig.cesr"), ev("restored.cesr")
for (t, d1), (_, d2) in zip(a, b): print(f"  {t}  original {d1[:22]}...  restored {d2[:22]}...  {'IDENTICAL' if d1 == d2 else 'different'}")
PY

echo; echo "### 4. what the key store holds at rest, WITH a passcode"
python3 "$HERE/ch08-inspect-keystore.py" orig

echo; echo "### 5. the same, with NO passcode (kli init --nopasscode): do not do this with real keys"
kli init --name plain --nopasscode >/dev/null
kli incept --name plain --alias me --file me.json | head -1
python3 "$HERE/ch08-inspect-keystore.py" plain | sed -n '/\[gbls/,/\[pubs/p'
