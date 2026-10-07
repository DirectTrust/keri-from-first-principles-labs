#!/usr/bin/env bash
# Lab 4: the wire format, the database, and importing the BOOK'S log into the reference implementation.
# Run ch03-kel.sh first (it creates the 'alice' identifier used below).
set -euo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"

echo "### 1. inspect the event database that ch03-kel.sh produced"
python3 "$HERE/ch04-inspect-db.py" alice "$(kli aid --name alice --alias alice --passcode "$PC")"

echo "### 2. a hand-built log from the book's script, validated by an independent validator"
python3 "$HERE/make_book_kel.py"

echo; echo "### 3. import that log into a fresh keripy keystore: does the reference implementation accept it?"
kli init --name bob --passcode "$PC" >/dev/null
kli import --name bob --passcode "$PC" --file "$HERE/book-kel.cesr"
kli kevers --name bob --passcode "$PC" --prefix EDtDtkoN6MZZlQD2Ke1kKLppIX0gHhNYvg0mZz6MQLLj | sed -n 1,12p
echo "(Seq No 2 and the rotated key DPoKK... mean all three events were accepted.)"

echo; echo "### 4. what is in escrow? (nothing, in this lab)"
kli escrow list --name bob --passcode "$PC" | sed -n 1,9p
