#!/usr/bin/env bash
# Lab 3c: change ONE character of an exported log and see what a validator does. Run ch03-kel.sh first.
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; cd "$LAB_DIR"; PC="$LAB_PASSCODE"
AID=$(kli aid --name alice --alias alice --passcode "$PC")
python3 - <<'PY'
s = open("alice.cesr").read()
i = s.index('"t":"rot"'); j = s.index('"n":["', i) + 6          # first character of the rotation's next-key digest
t = s[:j] + ("A" if s[j] != "A" else "B") + s[j + 1:]
open("tampered.cesr", "w").write(t); print(f"changed character {j} of the stream: {s[j]!r} -> {t[j]!r}")
PY
for n in good evil; do rm -rf "$HOME/.keri"/{ks,db,reg,cf}/$n; kli init --name $n --passcode "$PC" >/dev/null; done
kli import --name good --passcode "$PC" --file alice.cesr
kli import --name evil --passcode "$PC" --file tampered.cesr          # note: no error message is printed
echo "untampered log -> $(kli kevers --name good --passcode "$PC" --prefix "$AID" | grep 'Seq No')"
echo "tampered log   -> $(kli kevers --name evil --passcode "$PC" --prefix "$AID" | grep 'Seq No')"
