#!/usr/bin/env python3
"""Lab 15b: list the IPEX messages a party's database holds, and which message each one answers.
usage: ch15-thread.py <name>"""
import os, sys
from keri.app import habbing

hby = habbing.Habery(name=sys.argv[1], base="", bran=os.environ["LAB_PASSCODE"], temp=False)
msgs = [(s.ked["dt"], s) for (_,), s in hby.db.exns.getItemIter() if s.ked["r"].startswith("/ipex/")]
names = {s.said: s.ked["r"].split("/")[-1] for _, s in msgs}
for dt, s in sorted(msgs, key=lambda x: x[0]):
    k = s.ked; ans = names.get(k["p"], "(new thread)" if not k["p"] else k["p"][:10] + "...")
    emb = [x for x in k.get("e", {}) if x != "d"]
    print(f'{k["r"].split("/")[-1]:6} {s.said[:10]}...  re: {ans:12} embeds {",".join(emb) or "-"}')
hby.close()
