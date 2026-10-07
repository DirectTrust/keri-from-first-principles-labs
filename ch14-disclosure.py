#!/usr/bin/env python3
"""Lab 14a: why a salt matters, and how graduated disclosure verifies one block at a time.
No witnesses needed."""
import copy, itertools, json
from keri.core import coring
from keri.vc import proving

issuer = "EDPrbne4nB8tNzlROw7E_tSDzs0F16uSvfU54pAVKP3x"
holder = "EC1DiBo8iPLsHJdd-3sX0CCvtG0kD5tGTBQCg6tR-8qM"
registry = "EHN5T1lYXEMhIWqnq3Q_yVcYGd0OFZnKcXj3ESdyQ6wU"
schema = "EHx7qJh2CoO0qc217ltGkpQS-ZgWOrDQ0apmUD8dCNvZ"
parent = "EGKRzKgdM372mvr_JTsdn6BhbZ6B2kv9geCH22XLMf4T"
DT = "2026-10-06T14:13:49.015467+00:00"          # the attacker knows roughly when it was issued

def saidify(block):
    _, out = coring.Saider.saidify(sad=dict(d="", **block), label="d"); return out
edge = saidify({"authority": {"n": parent, "s": "ELj2zmW65ztEBv9Ovg6GW5baPwb2Bc01eBIk1EgvIE-H", "o": "I2I"}})
rules = saidify({"disclaimer": {"l": "Accreditation reflects the review date only."}})

def build(private):
    return proving.credential(schema=schema, issuer=issuer, recipient=holder, status=registry,
                              data=dict(dt=DT, clinicName="Riverside Family Clinic", status="accredited"),
                              source=copy.deepcopy(edge), rules=copy.deepcopy(rules), private=private).sad

print("### 1. the same credential, without and with salts")
plain, salted = build(False), build(True)
for name, c in (("plain ", plain), ("salted", salted)):
    print(f'{name}: fields {list(c)}   a has u: {"u" in c["a"]}')

print("\n### 2. a COMPACT presentation shows only digests. Can a guesser recover the claims?")
def guess(target, extra=None):
    hits = []
    for status in ("accredited", "suspended", "revoked", "pending", "provisional"):
        cand = ({"u": extra} if extra else {}) | {"i": holder, "dt": DT, "clinicName": "Riverside Family Clinic", "status": status}
        if saidify(cand)["d"] == target: hits.append(status)
    return hits
print("attacker sees only a.d, and tries every plausible status value:")
print("  plain  credential, a.d =", plain["a"]["d"][:16] + "...  guesser finds:", guess(plain["a"]["d"]))
print("  salted credential, a.d =", salted["a"]["d"][:16] + "...  guesser finds:", guess(salted["a"]["d"], extra="0AAAAAAAAAAAAAAAAAAAAAAA"))
print("  (the guesser would need the 128-bit salt as well)")

print("\n### 3. GRADUATED disclosure: the holder reveals one block at a time, the verifier checks each")
digests = {k: salted[k]["d"] for k in ("a", "e", "r")}
print("stage 0: the verifier holds only three digests:")
for k, v in digests.items(): print(f"  {k}: {v[:16]}...")
def check(label, block, key):
    ok = coring.Saider(sad=copy.deepcopy(block), label="d").verify(sad=copy.deepcopy(block), prefixed=True, label="d") and block["d"] == digests[key]
    print(f"  {label:34}: {'matches its digest' if ok else 'DOES NOT MATCH'}")
for stage, key, label in ((1, "r", "rules"), (2, "e", "edge to the parent"), (3, "a", "attributes")):
    print(f"stage {stage}: the holder reveals the {label}")
    check(f"the {label}, as issued", salted[key], key)
forged = copy.deepcopy(salted["a"]); forged["status"] = "suspended"
check("attributes with status edited", forged, "a")

print("\n### 4. the salt is part of the block, so it travels with it")
print("a.u =", salted["a"]["u"], "(revealed only when the attribute block is revealed)")
