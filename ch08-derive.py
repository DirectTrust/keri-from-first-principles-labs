#!/usr/bin/env python3
"""
Lab 8b: derive an identifier's keys BY HAND from the salt, the way a 'salty' key store does.
usage: ch08-derive.py <salt> <alias> <exported-stream.cesr>

path = stem + hex(rotation index) + hex(key index)         (stem = the identifier's alias in kli)
seed = Argon2id(salt, path)  at a cost set by the tier     (libsodium crypto_pwhash)
key  = Ed25519(seed)
"""
import json, re, sys, time
from keri.core import Salter
from keri.core.coring import Tiers

salt, alias, stream = sys.argv[1], sys.argv[2], open(sys.argv[3]).read()
salter = Salter(qb64=salt, tier=Tiers.low)
events = [json.loads(m) for m in re.findall(r'\{"v":"KERI10JSON[0-9a-f]{6}_".*?\}(?=-V|\{"v"|$)', stream)]
print(f"salt {salt}   alias {alias!r}   tier low (Argon2id, 2 passes, 64 MiB)\n")
print(f"{'event':<6}{'path':<8}{'derived public key':<48}{'key in the log':<48}match")
for ev in events:
    if ev["t"] not in ("icp", "rot"): continue
    n = int(ev["s"], 16)                                  # the n-th establishment event reveals the keys at ridx = n, kidx = n
    path = f"{alias}{n:x}{n:x}"
    t = time.time(); derived = salter.signer(path=path, transferable=True, tier=Tiers.low).verfer.qb64
    print(f"{ev['t']+' '+str(n):<6}{path:<8}{derived:<48}{ev['k'][0]:<48}{'YES' if derived == ev['k'][0] else 'no'}")
