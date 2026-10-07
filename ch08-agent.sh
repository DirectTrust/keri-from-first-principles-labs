#!/usr/bin/env bash
# Runs ch08-agent.py with the agent virtualenv and the agent's HOME. Requires start-keria.sh running.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"
curl -s -o /dev/null "http://127.0.0.1:3903/" || { echo "Start ./start-keria.sh first."; exit 1; }
export HOME="$AGENT_HOME"
exec "$AGENT_VENV/bin/python" "$HERE/ch08-agent.py"
