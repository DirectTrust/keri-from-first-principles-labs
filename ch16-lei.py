#!/usr/bin/env python3
"""Lab 16a: the LEI is a 20-character code whose last two characters are check digits (ISO 7064 MOD 97-10).
Validates one, finds a bad sample in keripy's own demo data, and measures what the check digits catch."""
import itertools, json, os

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def digits(s): return "".join(str(int(c, 36)) for c in s)            # A=10 ... Z=35
def valid(lei):
    return len(lei) == 20 and lei.isalnum() and lei == lei.upper() and int(digits(lei)) % 97 == 1
def check_digits(body18): return f"{98 - int(digits(body18 + '00')) % 97:02d}"

print("### 1. an LEI is 18 characters plus two check digits")
body = "5493001KJTIIGC8Y1R"
good = body + check_digits(body)
print("body         :", body, f"({len(body)} characters)")
print("check digits :", check_digits(body))
print("full LEI     :", good, " valid:", valid(good))

print("\n### 2. the sample LEI in keripy's own demo data")
HERE = os.environ.get("LAB_DIR", ".")
path = os.path.join(HERE, "keripy", "scripts", "demo", "data", "credential-data.json")
try:
    demo = json.load(open(path))["LEI"]
    print("credential-data.json says:", demo, " valid:", valid(demo))
    print("the check digits for that body would be", check_digits(demo[:18]), "so the valid LEI is", demo[:18] + check_digits(demo[:18]))
except OSError:
    print("(keripy checkout not found at", path + ")")

print("\n### 3. what do two check digits catch? Every single-character error, and every adjacent swap?")
single = swap = ss = sw = 0
for pos in range(18):
    for ch in ALPHABET:
        if ch != good[pos]:
            bad = good[:pos] + ch + good[pos + 1:]; ss += 1; single += not valid(bad)
for pos in range(19):
    if good[pos] != good[pos + 1]:
        bad = good[:pos] + good[pos + 1] + good[pos] + good[pos + 2:]; sw += 1; swap += not valid(bad)
print(f"single-character substitutions in the body: {single} of {ss} detected")
print(f"adjacent swaps                              : {swap} of {sw} detected")
print("\nThe check digits catch typing mistakes. They do NOT say the entity exists, who it is, or who may speak for it.")
