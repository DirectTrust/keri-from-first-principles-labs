# Source this file at the top of every lab:   . ./lab-env.sh
#
# It isolates everything the labs create under $LAB_DIR so your real ~/.keri is never touched.
LAB_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LAB_DIR="${LAB_DIR:-$LAB_SRC/lab-run}"
mkdir -p "$LAB_DIR/home"
export HOME="$LAB_DIR/home"                   # keripy keeps its stores under ~/.keri
export LAB_PASSCODE="0123456789abcdefghijk"   # 21 characters; for LABS ONLY, never reuse
export KERIPY_VERSION="1.3.6"

# If libsodium is not installed system-wide, point at its lib directory, e.g.
#   export LIBSODIUM_LIB=/opt/homebrew/lib
if [ -n "${LIBSODIUM_LIB:-}" ]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$LIBSODIUM_LIB${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

# Use the lab virtualenv (created by lab-setup.sh), or one you name in LAB_VENV.
VENV="${LAB_VENV:-$LAB_DIR/venv}"
if [ -f "$VENV/bin/activate" ]; then . "$VENV/bin/activate"; fi

# The agent lab (KERIA + Signify) needs its own virtualenv (KERIA pins an older keripy) and its own HOME.
export AGENT_VENV="${AGENT_VENV:-$LAB_DIR/venv-agent}"
export AGENT_HOME="$LAB_DIR/home-agent"

# The three demo witnesses (fixed, well-known identifiers from the keripy demo configuration).
export WAN=BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha   # http://127.0.0.1:5642
export WIL=BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM   # http://127.0.0.1:5643
export WES=BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX   # http://127.0.0.1:5644

# A portable timeout (macOS has no `timeout`). Restores DYLD_* that system perl would strip.
to() { local secs=$1; shift; perl -e 'alarm shift; $ENV{DYLD_FALLBACK_LIBRARY_PATH}=$ENV{LIBSODIUM_LIB} if $ENV{LIBSODIUM_LIB}; exec @ARGV' "$secs" "$@"; }
