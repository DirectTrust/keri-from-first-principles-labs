#!/usr/bin/env python3
"""
Lab 4: open a keripy event database read-only and show how one identifier's log is stored.
usage: ch04-inspect-db.py <keystore-name> [AID]      (reads  ~/.keri/db/<name>  under the lab HOME)
"""
import os, sys, lmdb

name = sys.argv[1]
path = os.path.expanduser(f"~/.keri/db/{name}")
env = lmdb.open(path, max_dbs=256, readonly=True, lock=False)
with env.begin() as txn:                                   # the unnamed main db lists the named sub-dbs
    subs = sorted(k.decode() for k, _ in txn.cursor())
print(f"{path}\n{len(subs)} named sub-databases; first few: {', '.join(subs[:12])} ...\n")

def rows(dbname, dupsort):
    db = env.open_db(dbname.encode(), dupsort=dupsort, create=False)
    with env.begin(db=db) as txn:
        return list(txn.cursor())

aid = sys.argv[2] if len(sys.argv) > 2 else None
if aid is None:                                             # default: the identifier with the longest log
    from collections import Counter
    aid = Counter(k.decode().split(".")[0] for k, _ in rows("kels.", True)).most_common(1)[0][0]
print("identifier:", aid, "\n")
SHOW = (("evts.", False, "events by SAID"), ("kels.", True, "log by sequence number (duplicates allowed)"),
        ("fels.", False, "log by first-seen number"), ("dtss.", False, "first-seen datetimes"),
        ("sigs.", True, "controller indexed signatures"), ("wigs.", True, "witness indexed signatures"))
for dbn, dup, label in SHOW:
    try: rs = [(k.decode(), v.decode()) for k, v in rows(dbn, dup) if k.decode().startswith(aid)]
    except lmdb.NotFoundError: continue
    print(f"[{dbn}] {label}: {len(rs)} rows")
    for k, v in rs[:8]:
        print("   ", k.replace(aid, "<AID>"), "->", (v[:70] + "…") if len(v) > 70 else v)
    print()
