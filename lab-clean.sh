#!/usr/bin/env bash
# Resets the lab identities (alice, bob, carol, dave, erin, vic, mallory, gina, hal, ...) so a lab can be re-run.
# Leaves the demo witnesses (wan, wil, wes, ...) alone, so the witness pool can keep running.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"
for n in alice bob carol dave erin vic mallory exp good evil x5 gina hal plain ann ben cat dora dan val val2 val3 gia mal hal acc cli ver reg acr buy gar1 gar2 qar1 qar2 qar3 qar4 gleif qvi le per ver ops ops2 ops3 ops4 w1 w2 w3 wt alice22 arr_rot-only arr_rot-icp-ixn arr_ixn-rot-icp orig restored dana nwd app hdx; do
  for d in ks db reg cf; do rm -rf "$HOME/.keri/$d/$n"; done
done
rm -f "$LAB_DIR"/*.json "$LAB_DIR"/*.cesr
echo "lab identities reset"
