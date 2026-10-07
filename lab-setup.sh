#!/usr/bin/env bash
# One-time setup: Python virtualenv + keripy, and a checkout of keripy's demo configuration.
# Requires: python 3.12+, git, and the libsodium library (macOS: brew install libsodium).
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"
python3 -m venv "$LAB_DIR/venv"
. "$LAB_DIR/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet "keri==$KERIPY_VERSION"
if [ ! -d "$LAB_DIR/keripy" ]; then
  git clone --quiet --depth 1 --branch "$KERIPY_VERSION" https://github.com/WebOfTrust/keripy "$LAB_DIR/keripy"
fi
kli version
if [ "${1:-}" = "agent" ]; then      # ./lab-setup.sh agent : also install KERIA + SignifyPy for Lab 8d
  python3 -m venv "$AGENT_VENV"
  "$AGENT_VENV/bin/pip" install --quiet --upgrade pip
  "$AGENT_VENV/bin/pip" install --quiet keria==0.4.0 signifypy==0.4.2
  echo "agent virtualenv ready: $AGENT_VENV"
fi
echo "Lab setup complete. Lab files live in: $LAB_DIR"
