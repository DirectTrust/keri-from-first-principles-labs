#!/usr/bin/env bash
# Runs keripy's three demo witnesses in the FOREGROUND. Leave this running in its own terminal
# for Labs 5 and 6.      HTTP: wan 5642, wil 5643, wes 5644     TCP: 5632, 5633, 5634
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"
cd "$LAB_DIR/keripy"           # the demo reads its witness configs from ./scripts/keri/cf
exec kli witness demo
