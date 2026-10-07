#!/usr/bin/env python3
"""Lab 8c: open a keripy KEY STORE (not the event database) read-only. usage: ch08-inspect-keystore.py <name>"""
import json, os, sys, lmdb
from keri.core import Signer

name = sys.argv[1]
env = lmdb.open(os.path.expanduser(f"~/.keri/ks/{name}"), max_dbs=64, readonly=True, lock=False)
def rows(n):
    for dup in (False, True):
        try:
            db = env.open_db(n.encode(), create=False, dupsort=dup)
            with env.begin(db=db) as t: return [(k.decode(), v.decode()) for k, v in t.cursor()]
        except lmdb.IncompatibleError: continue
short = lambda v, n=64: v if len(v) <= n else v[:n] + "..."
print(f"~/.keri/ks/{name}\n")
print("[gbls.]  global settings"); [print(f"    {k:<5}-> {short(v)}") for k, v in rows("gbls.")]
print("\n[pris.]  public key -> PRIVATE key")
for k, v in rows("pris."):
    print(f"    {k[:20]}... -> {short(v, 50)}")
    if v[0] == "A":                                       # 'A' = a raw Ed25519 seed: the secret in the clear
        ok = Signer(qb64=v, transferable=not k.startswith('B')).verfer.qb64 == k
        print(f"       ^ this value is a plain Ed25519 seed; its public key matches the row key: {ok}")
print("\n[pubs.]  public key lists by rotation index (public, always readable)")
for k, v in rows("pubs.")[:4]: print(f"    {k[:20]}....{k[-16:]} -> {short(v, 70)}")
print("\n[sits.]  old / new / next key bookkeeping (Chapter 4's three states)")
for k, v in rows("sits."):
    d = json.loads(v); print(f"    {k[:20]}... old ridx={d['old']['ridx']} kidx={d['old']['kidx']}  new ridx={d['new']['ridx']} kidx={d['new']['kidx']}  nxt ridx={d['nxt']['ridx']} kidx={d['nxt']['kidx']}")
