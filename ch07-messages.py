#!/usr/bin/env python3
"""
Lab 7a: build one of each message type from Chapter 7 with the reference implementation's library,
and print it. Fixed salts and timestamps make the output reproducible (no network, no witnesses).
"""
import json
from keri.app import habbing
from keri.core import Salter, eventing
from keri.peer import exchanging

STAMP = "2026-10-05T14:00:00.000000+00:00"
SALT = lambda raw: Salter(raw=raw).qb64
WAN = "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"            # a demo witness

def show(title, msg):
    msg = bytes(msg); end = msg.index(b"}") if False else None
    body_len = int(msg[len(b'{"v":"KERI10JSON'):len(b'{"v":"KERI10JSON') + 6], 16)
    body, att = msg[:body_len], msg[body_len:]
    print(f"\n--- {title}"); print(json.dumps(json.loads(body), indent=1)); print("attachment:", att.decode()[:170] + ("..." if len(att) > 170 else ""))

with habbing.openHby(name="gina", salt=SALT(b"gina-demo-salt00"), temp=True) as g, \
     habbing.openHby(name="hal", salt=SALT(b"hal--demo-salt00"), temp=True) as h:
    gina = g.makeHab(name="gina", transferable=True)
    hal = h.makeHab(name="hal", transferable=True)
    print("gina:", gina.pre); print("hal :", hal.pre)

    # 1. Queries: ask witness WAN for hal's log, hal's key state, and gina's own mailbox
    show("qry: route 'logs'  (replay hal's key event log)", gina.query(pre=hal.pre, src=WAN, route="logs", stamp=STAMP))
    show("qry: route 'ksn'   (hal's current key state)", gina.query(pre=hal.pre, src=WAN, route="ksn", stamp=STAMP))
    show("qry: route 'mbx'   (collect gina's mail, topics and the index already read)",
         gina.query(pre=gina.pre, src=WAN, route="mbx", stamp=STAMP, query=dict(topics={"/challenge": 0, "/receipt": 0})))

    # 2. A reply: gina authorizes witness WAN as her mailbox
    show("rpy: /end/role/add  (a signed, dated statement)", gina.reply(route="/end/role/add", stamp=STAMP,
         data=dict(cid=gina.pre, role="mailbox", eid=WAN)))

    # 3. An exchange message from hal to gina, and its /fwd envelope for store-and-forward delivery
    exn, _ = exchanging.exchange(route="/challenge/response", sender=hal.pre, recipient=gina.pre, date=STAMP,
                                 payload=dict(i=hal.pre, words=["balcony", "brief", "huge"]))
    signed = hal.endorse(serder=exn, last=False, pipelined=False)
    show("exn: /challenge/response  (peer-to-peer message, signed by hal)", signed)
    fwd, atc = exchanging.exchange(route="/fwd", sender=hal.pre, date=STAMP, payload={},
                                   modifiers=dict(pre=gina.pre, topic="challenge"), embeds=dict(evt=bytearray(signed)))
    env = hal.endorse(serder=fwd, last=False, pipelined=False)
    show("exn: /fwd  (envelope addressed to gina's mailbox; the message above rides in 'e')", bytes(env) + bytes(atc))
