#!/usr/bin/env python3
"""
Lab 7b: BADA, the 'best available data acceptance' rule for signed replies. Deterministic, no network.
A sender signs authorizations of an endpoint role at different times; a receiver processes them in
different orders and we watch what it believes.
"""
from keri.app import habbing
from keri.core import Salter

SALT = lambda raw: Salter(raw=raw).qb64
EID = "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"

with habbing.openHby(name="sender", salt=SALT(b"sender-demo-salt"), temp=True) as s, \
     habbing.openHby(name="recv", salt=SALT(b"recver-demo-salt"), temp=True) as r:
    hab = s.makeHab(name="s", transferable=True)
    r.psr.parse(ims=bytearray(hab.replay()))                    # the receiver learns the sender's key event log
    d = dict(cid=hab.pre, role="watcher", eid=EID)
    msg = lambda route, t: bytes(hab.reply(route=route, data=d, stamp=f"2026-10-05T{t}:00:00.000000+00:00"))
    add10, cut11, add12 = msg("/end/role/add", "10"), msg("/end/role/cut", "11"), msg("/end/role/add", "12")

    def believes():
        e = r.db.ends.get(keys=(hab.pre, "watcher", EID))
        return "no opinion" if e is None else ("AUTHORIZED" if e.allowed else "not authorized")

    print(f"{'receiver processes':<38}{'it now believes the watcher role is':<40}")
    print(f"{'(nothing yet)':<38}{believes()}")
    for label, m in (("add  signed 10:00", add10), ("cut  signed 11:00", cut11),
                     ("add  signed 10:00 AGAIN (a replay)", add10), ("add  signed 12:00", add12),
                     ("cut  signed 11:00 AGAIN (a replay)", cut11)):
        r.psr.parse(ims=bytearray(m)); print(f"{label:<38}{believes()}")

    # Same three messages, delivered in the opposite order to a fresh receiver
    with habbing.openHby(name="recv2", salt=SALT(b"recv2-demo-salt0"), temp=True) as r2:
        r2.psr.parse(ims=bytearray(hab.replay()))
        print("\nthe same three messages, delivered newest first:")
        for label, m in (("add  signed 12:00", add12), ("cut  signed 11:00", cut11), ("add  signed 10:00", add10)):
            r2.psr.parse(ims=bytearray(m))
            e = r2.db.ends.get(keys=(hab.pre, "watcher", EID))
            print(f"{label:<38}{'AUTHORIZED' if e and e.allowed else 'not authorized'}")


# ---- Part 3: a ROTATION outranks any timestamp (the stolen-key case) -------------------------------
print("\nthe rotation rule: the OLD keys sign an 'add' dated 13:00; the sender then ROTATES and the NEW keys sign")
print("a 'cut' dated 09:00 (an EARLIER time). BADA prefers the reply from later keys, whatever the dates say.")
with habbing.openHby(name="sender2", salt=SALT(b"sender2-demo-salt"), temp=True) as s2:
    hab2 = s2.makeHab(name="s2", transferable=True)
    d2 = dict(cid=hab2.pre, role="watcher", eid=EID)
    old_keys_add = bytes(hab2.reply(route="/end/role/add", data=d2, stamp="2026-10-05T13:00:00.000000+00:00"))
    hab2.rotate()
    new_keys_cut = bytes(hab2.reply(route="/end/role/cut", data=d2, stamp="2026-10-05T09:00:00.000000+00:00"))
    for order in (("old-key add @13:00", old_keys_add, "new-key cut @09:00", new_keys_cut),
                  ("new-key cut @09:00", new_keys_cut, "old-key add @13:00", old_keys_add)):
        with habbing.openHby(name="recv3", salt=SALT(b"recv3-demo-salt0"), temp=True) as r3:
            r3.psr.parse(ims=bytearray(hab2.replay()))
            print(f"\n  delivered: {order[0]}, then {order[2]}")
            for label, m in ((order[0], order[1]), (order[2], order[3])):
                r3.psr.parse(ims=bytearray(m))
                e = r3.db.ends.get(keys=(hab2.pre, "watcher", EID))
                print(f"    after {label:<20} -> {'AUTHORIZED' if e and e.allowed else 'not authorized'}")
