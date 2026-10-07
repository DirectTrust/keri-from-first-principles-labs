#!/usr/bin/env bash
# Lab 2b: the reference implementation computes the same SAID.
. "$(dirname "$0")/lab-env.sh"; cd "$LAB_DIR"
printf '{"d":"","name":"Alice Nguyen","role":"Nurse Practitioner"}' > doc.json
kli saidify --file doc.json --label d
cat doc.json; echo
echo "expected: EBZEqVMjJNJSVGOOOqXaCINVOTABb7BnNg2s9Og_y1mr"
