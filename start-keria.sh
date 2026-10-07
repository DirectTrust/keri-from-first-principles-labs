#!/usr/bin/env bash
# Runs a KERIA cloud agent in the FOREGROUND for Lab 8d. Needs ./lab-setup.sh agent first.
# Ports: 3901 admin API (signed requests from Signify), 3902 KERI protocol, 3903 boot.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"
mkdir -p "$AGENT_HOME"; export HOME="$AGENT_HOME"
exec "$AGENT_VENV/bin/keria" start --name keria --passcode 0123456789abcdefghijkl --loglevel INFO
