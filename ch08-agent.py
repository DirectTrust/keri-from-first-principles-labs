#!/usr/bin/env python3
"""
Lab 8d: the edge/cloud split with Signify (edge: keys and signing) and KERIA (cloud agent: everything else).
Run it through ch08-agent.sh. Requires start-keria.sh running.
"""
import glob, json, os, random, time
import lmdb
from signify.app.clienting import SignifyClient
from keri.core.coring import Tiers

URL, BOOT = "http://127.0.0.1:3901", "http://127.0.0.1:3903"
BRAN = "0123456789abcdefghijk"                       # the 21-character passcode: the ONLY secret the edge keeps

def client(bran=BRAN, tier=Tiers.low, connect=True):
    c = SignifyClient(passcode=bran, url=URL, boot_url=BOOT, tier=tier)
    if connect: c.connect()
    return c

print("### 1. the controller identifier is a pure function of (passcode, tier)")
for label, c in (("passcode A, tier low ", client(connect=False)),
                 ("passcode A, tier low ", client(connect=False)),
                 ("passcode A, tier med ", client(tier=Tiers.med, connect=False)),
                 ("passcode B, tier low ", client(bran="abcdefghijklmnopqrstu", connect=False))):
    print(f"  {label} -> {c.ctrl.pre}")

print("\n### 2. boot the agent (first time only) and connect")
c = client(connect=False)
try: c.boot()
except Exception as e: print("  (agent already booted)")
c.connect()
print("  client (controller) AID :", c.ctrl.pre)
print("  agent AID               :", c.agent.pre)
print("  agent's delegator (di)  :", c.agent.delpre, "  <- the agent is DELEGATED by the client's identifier")
print("  client's own latest event:", c.ctrl.serder.ked["t"], "s=" + c.ctrl.serder.ked["s"], "(the ixn that APPROVED the delegation)")

print("\n### 3. create an identifier: the EDGE builds and signs the inception; the agent stores and serves it")
name = f"edge-{random.randint(1000, 9999)}"
serder, sigs, op = c.identifiers().create(name)
time.sleep(2)
rec = [a for a in c.identifiers().list()["aids"] if a["name"] == name][0]
print(f"  identifier {name}: {rec['prefix']}")
print("  what the agent stored about its keys (note: no private key):")
for k, v in rec["salty"].items(): print(f"      {k:<12} {str(v)[:70]}")
key = c.identifiers().get(name)["state"]["k"][0]

print("\n### 4. does ANY of the agent's key stores hold a private key for that identifier?")
home = os.path.expanduser("~/.keri")
for ks in sorted(glob.glob(os.path.join(home, "ks", "*"))):
    env = lmdb.open(ks, max_dbs=64, readonly=True, lock=False)
    with env.begin() as t: subs = [k.decode() for k, _ in t.cursor()]
    for n in subs:
        if n.startswith("pris"):
            for dup in (False, True):
                try:
                    db = env.open_db(n.encode(), create=False, dupsort=dup)
                    with env.begin(db=db) as t: keys = [k.decode() for k, _ in t.cursor()]
                    break
                except lmdb.IncompatibleError: continue
            print(f"  agent key store {os.path.basename(ks)[:12]}...: {len(keys)} private keys; holds {name}'s key? {key in keys}")

print("\n### 5. a BRAND-NEW client (no local state, only the passcode) rotates and interacts")
c2 = client()
before = c2.identifiers().get(name)["state"]
c2.identifiers().rotate(name); time.sleep(2)
mid = c2.identifiers().get(name)["state"]
c2.identifiers().interact(name, data=[{"d": "EDPrbne4nB8tNzlROw7E_tSDzs0F16uSvfU54pAVKP3x"}]); time.sleep(2)
end = c2.identifiers().get(name)["state"]
print(f"  before          s={before['s']}  key={before['k'][0]}")
print(f"  after rotate    s={mid['s']}  key={mid['k'][0]}")
print(f"  after interact  s={end['s']}  et={end['et']}")

print("\n### 6. a client with the WRONG passcode is a different controller, and is not recognized by this agent's data")
bad = client(bran="abcdefghijklmnopqrstu", connect=False)
try:
    bad.connect(); print("  connected as", bad.ctrl.pre, "(a different, unrelated controller; it sees none of the above)")
    print("  identifiers visible to it:", [a["name"] for a in bad.identifiers().list()["aids"]])
except Exception as e:
    print("  refused:", type(e).__name__, str(e)[:100])
