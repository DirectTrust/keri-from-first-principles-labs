#!/usr/bin/env bash
# Lab 3b: the identifier variants from Chapter 3: establishment-only, 2-of-3 multi-key, non-transferable.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; cd "$LAB_DIR"; PC="$LAB_PASSCODE"
kli init --name exp --passcode "$PC" >/dev/null

echo "### 1. establishment-only (the EO trait): interaction events are forbidden"
echo '{"transferable": true, "wits": [], "toad": 0, "icount": 1, "ncount": 1, "isith": "1", "nsith": "1", "estOnly": true}' > eo.json
kli incept --name exp --alias eo --passcode "$PC" --file eo.json | head -1
kli status --name exp --alias eo --passcode "$PC" --verbose | grep -A2 '"c"'
kli interact --name exp --alias eo --passcode "$PC" --data '{"d":"EDPrbne4nB8tNzlROw7E_tSDzs0F16uSvfU54pAVKP3x"}' || true

echo; echo "### 2. three keys, two required to sign (kt = 2)"
echo '{"transferable": true, "wits": [], "toad": 0, "icount": 3, "ncount": 3, "isith": "2", "nsith": "2"}' > multi.json
kli incept --name exp --alias group --passcode "$PC" --file multi.json
kli status --name exp --alias group --passcode "$PC" --verbose | grep -E '"kt"|"nt"'

echo; echo "### 3. non-transferable: the identifier IS the key, there is no next key, and it cannot rotate"
echo '{"transferable": false, "wits": [], "toad": 0, "icount": 1, "ncount": 0, "isith": "1", "nsith": "0"}' > nt.json
kli incept --name exp --alias nt --passcode "$PC" --file nt.json | head -1
kli status --name exp --alias nt --passcode "$PC" --verbose | grep -E '"(i|nt|n)"' -A1
kli rotate --name exp --alias nt --passcode "$PC" || true
