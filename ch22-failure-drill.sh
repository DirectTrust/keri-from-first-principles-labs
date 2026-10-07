#!/usr/bin/env bash
# Lab 22: operate your own witness pool, then break it on purpose.
# Starts three witnesses of its own on ports 6642-6644 (HTTP) and 6632-6634 (TCP), so it does not disturb the demo
# witnesses. Run ./lab-clean.sh first if you have run this lab before.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"; CF="$LAB_DIR/w20cf"; rm -rf "$LAB_DIR/backup" "$CF"; mkdir -p "$CF/keri/cf/main"      # keripy reads config files from <config-dir>/keri/cf/main/; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; }; trap cleanup EXIT

start_witness() {   # start_witness <name> <http> <tcp>
  cat > "$CF/keri/cf/main/$1.json" <<JSON
{"dt": "2022-01-20T12:57:59.823350+00:00", "$1": {"dt": "2022-01-20T12:57:59.823350+00:00", "curls": ["tcp://127.0.0.1:$3/", "http://127.0.0.1:$2/"]}}
JSON
  kli witness start --name $1 --alias $1 --passcode "$PC" --http $2 --tcp $3 --config-dir "$CF" --config-file $1 > "$1.log" 2>&1 &
  PIDS+=($!); eval "PID_$1=$!"
}
waitup() { for i in $(seq 1 30); do curl -sf -m 2 "http://127.0.0.1:$1/oobi/$2/controller" >/dev/null && return 0; sleep 1; done; return 1; }
status() { kli status --name "$1" --alias "$2" --passcode "$PC" | sed 's/\x1b\[[0-9;]*m//g'; }
receipts() { status ops ops | grep -E "Receipts|Threshold" | tr -d '\t' | tr '\n' ' '; echo; }

echo "### 1. three witnesses, each its own process with its own keystore and database"
for w in "w1 6642 6632" "w2 6643 6633" "w3 6644 6634"; do set -- $w; start_witness $1 $2 $3; sleep 4; done     # one at a time: they share a config directory on first start
for n in w1 w2 w3; do eval "A_$n=\$(kli aid --name $n --alias $n --passcode \"\$PC\" 2>/dev/null)"; done
for w in "w1 6642 $A_w1" "w2 6643 $A_w2" "w3 6644 $A_w3"; do set -- $w; waitup $2 $3 && echo "$1 up: $3 on http port $2"; done
echo "what a witness keeps on disk:"; ls "$HOME/.keri/ks/w1" "$HOME/.keri/db/w1" | sed 's/^/  /' | head -6

echo; echo "### 2. a controller (ops) with all three as witnesses and a threshold of 2"
kli init --name ops --passcode "$PC" >/dev/null
for w in "w1 6642 $A_w1" "w2 6643 $A_w2" "w3 6644 $A_w3"; do set -- $w
  kli oobi resolve --name ops --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
echo "{\"transferable\": true, \"wits\": [\"$A_w1\",\"$A_w2\",\"$A_w3\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > ops-icp.json
kli incept --name ops --alias ops --passcode "$PC" --file ops-icp.json >/dev/null
OPS=$(kli aid --name ops --alias ops --passcode "$PC"); echo "ops: $OPS"; echo "healthy:        $(receipts)"

echo; echo "### 3. DRILL 1: w3 dies. One witness down, threshold 2 of 3"
kill $PID_w3 2>/dev/null; sleep 2; curl -sf -m 2 "http://127.0.0.1:6644/oobi/$A_w3/controller" >/dev/null && echo "w3 still answering?" || echo "w3 is down"
to 90 kli rotate --name ops --alias ops --passcode "$PC" --receipt-endpoint --toad 2 > rot1.log 2>&1; echo "rotate with w3 down: $(tail -1 rot1.log | cut -c1-80)"
echo "after rotation: $(receipts)   sn $(status ops ops | sed -n 3p | tr -d '\t')"

echo; echo "### 4. DRILL 2: w2 dies too. Two of three down, threshold 2"
kill $PID_w2 2>/dev/null; sleep 2
to 60 kli rotate --name ops --alias ops --passcode "$PC" --receipt-endpoint --toad 2 > rot2.log 2>&1
echo "rotate with w2 and w3 down, stopped after 60 seconds. Output: $(grep -vc 'Alarm clock' rot2.log) lines"
echo "ops thinks:    $(receipts)   sn $(status ops ops | sed -n 3p | tr -d '\t')"

echo; echo "### 5. RECOVERY: the witnesses come back with the SAME keystores, so the same identifiers"
start_witness w2 6643 6633; start_witness w3 6644 6634; sleep 5
for w in "w2 6643 $A_w2" "w3 6644 $A_w3"; do set -- $w; waitup $2 $3 && echo "$1 back: $(kli aid --name $1 --alias $1 --passcode "$PC") (same as before: $([ "$(kli aid --name $1 --alias $1 --passcode "$PC")" = "$3" ] && echo yes || echo NO))"; done
to 90 kli rotate --name ops --alias ops --passcode "$PC" --receipt-endpoint --toad 2 > rot3.log 2>&1
echo "rotate with all three back: $(tail -1 rot3.log | cut -c1-70)"
echo "now: $(receipts)   sn $(status ops ops | sed -n 3p | tr -d '\t')"

echo; echo "### 6. LOSING a witness's keystore is not the same as losing its process"
kill $PID_w1 2>/dev/null; sleep 2
mkdir -p backup; for d in ks db cf; do [ -e "$HOME/.keri/$d/w1" ] && cp -R "$HOME/.keri/$d/w1" backup/$d-w1; done
for d in ks db cf; do rm -rf "$HOME/.keri/$d/w1"; done
start_witness w1 6642 6632; sleep 5; NEW=$(kli aid --name w1 --alias w1 --passcode "$PC" 2>/dev/null)
echo "w1 restarted from NOTHING:      $NEW  (original $A_w1)  $([ "$NEW" = "$A_w1" ] && echo SAME || echo "DIFFERENT: a new witness")"
kill $PID_w1 2>/dev/null; sleep 2; for d in ks db cf; do rm -rf "$HOME/.keri/$d/w1"; [ -e backup/$d-w1 ] && cp -R backup/$d-w1 "$HOME/.keri/$d/w1"; done
start_witness w1 6642 6632; sleep 5; RESTORED=$(kli aid --name w1 --alias w1 --passcode "$PC" 2>/dev/null)
echo "w1 restored from the backup:    $RESTORED  $([ "$RESTORED" = "$A_w1" ] && echo "SAME identifier" || echo DIFFERENT)"
waitup 6642 $A_w1 && curl -s "http://127.0.0.1:6642/oobi/$OPS/witness" > w1b.cesr && echo "and it still serves ops's log: $(python3 "$HERE/cesr_describe.py" w1b.cesr | grep -cE '^(icp|rot)') events"
