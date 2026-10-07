"""
Lab 3d: the schema of a key event.

Every KERI message type has a fixed field set, in a fixed order. This lab prints the field sets that
the reference implementation enforces, then hands it events that break the rules one at a time.
The valid events are the book's own, built by bookgen.py from published seeds.
"""
import json, logging
logging.disable(logging.CRITICAL)        # keripy logs every rejection; the lab prints its own summary
from keri.core import serdering, eventing, indexing
from keri.db import basing
from keri.kering import Vrsn_1_0, Vrsn_2_0, Protocols, Ilks
import bookgen as bg

F = serdering.SerderKERI.Fields[Protocols.keri]

def show(ilk, vrsn=Vrsn_1_0):
    fd = F[vrsn][ilk]
    req = [k for k in fd.alls if k not in fd.opts]
    said = list(fd.saids)
    print(f"  {ilk:4} fields, in order: {' '.join(fd.alls)}")
    print(f"       required: {'all' if len(req) == len(fd.alls) else ' '.join(req)}   "
          f"extras allowed: {not fd.strict}   computed as SAIDs: {' '.join(said)}")

print("### 1. the field sets the reference implementation enforces (KERI v1)")
for ilk in (Ilks.icp, Ilks.rot, Ilks.ixn): show(ilk)

print("\n### 2. what the default values tell you about each field's type")
fd = F[Vrsn_1_0][Ilks.icp]
for k, v in fd.alls.items():
    kind = "list" if isinstance(v, list) else "map" if isinstance(v, dict) else "string"
    print(f"  {k:3} {kind:7} default {json.dumps(v)}")

def check(label, d, labels=("d",), signer=None):
    """Two gates: the schema (does the message have the right shape?) and the validator (do the values make sense?)."""
    raw = bg.saidify(d, labels)            # a correct version string and SAID, so only the shape or the values are wrong
    try:
        serder = serdering.SerderKERI(raw=raw)
    except Exception as ex:
        cause = ex.__cause__ or ex
        print(f"  {label:44} -> schema REJECTS: {type(cause).__name__}")
        return
    if signer is None:
        print(f"  {label:44} -> schema accepts")
        return
    with basing.openDB(name="schema-lab", temp=True) as db:
        try:
            eventing.Kever(serder=serder, sigers=[indexing.Siger(qb64=bg.isig(signer, raw, 0))], db=db)
            print(f"  {label:44} -> schema accepts, validator accepts")
        except Exception as ex:
            print(f"  {label:44} -> schema accepts, validator REJECTS: {str(ex)[:34]}...")

aid, msgs = bg.build()
k0 = bg.keypair("signing-key-0")[0]
icp = json.loads(msgs[0][:msgs[0].index("}-") + 1])
rot = json.loads(msgs[1][:msgs[1].index("}-") + 1])

print("\n### 3. break the inception event's schema, one rule at a time")
check("the book's inception, unchanged", dict(icp), ("d", "i"), k0)
d = dict(icp); del d["c"];                       check("a required field removed (c)", d, ("d", "i"))
d = dict(icp); d["x"] = "extra";                 check("an extra field added (x)", d, ("d", "i"))
d = {k: icp[k] for k in ["v","t","d","i","s","k","kt","nt","n","bt","b","c","a"]}
check("two fields swapped (k before kt)", d, ("d", "i"))
d = dict(icp); d["kt"] = "2";                    check("right shape, wrong value: kt 2 with one key", d, ("d", "i"), k0)
d = dict(icp); d["k"] = [];                      check("right shape, wrong value: k is empty", d, ("d", "i"), k0)

print("\n### 4. the rotation, and the field that is not in it")
check("the book's rotation, unchanged", dict(rot))
d = {}
for k, v in rot.items():
    d[k] = v
    if k == "ba": d["c"] = []
check("a c field added, as in my first draft", d)

print("\n### 5. the schema has versions: KERI v2 field sets")
for ilk in (Ilks.rot, Ilks.rpy, Ilks.exn): show(ilk, Vrsn_2_0)

print("\n### 6. the schemas of the seals that can sit in an a list")
from keri.core import structing as st
for name, meaning in (("SealDigest", "a digest of outside data, usually its SAID"),
                      ("SealRoot", "the root digest of a Merkle tree of data"),
                      ("SealEvent", "one specific event in some identifier's log"),
                      ("SealLast", "whatever the latest establishment event of an identifier is"),
                      ("SealBacker", "a backer's identifier and a digest of its metadata")):
    print(f"  {name:11} {{{', '.join(getattr(st, name)._fields)}}}  {meaning}")
