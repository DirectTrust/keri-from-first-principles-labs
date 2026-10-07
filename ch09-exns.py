#!/usr/bin/env python3
"""Lab 9: list the /multisig/* exchange messages a member's database has stored.   usage: ch09-exns.py <name>"""
import os, sys
from keri.app import habbing

hby = habbing.Habery(name=sys.argv[1], base="", bran=os.environ["LAB_PASSCODE"], temp=False)
for (said,), serder in hby.db.exns.getItemIter():
    d = serder.ked
    print(f'{d["r"]:15} from {d["i"][:12]}…  payload={sorted(d["a"])}  embeds={[k for k in d.get("e", {}) if k != "d"]}')
hby.close()
