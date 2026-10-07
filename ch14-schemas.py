#!/usr/bin/env python3
"""Lab 14: writes two SAIDified schemas into the lab directory:
   authority-schema.json  a regulator's "Accreditor Authority" credential (the PARENT in the chain)
   chained-schema.json    a "Chained Clinic Accreditation" credential with edges (e), rules (r), and salts (u)"""
import json, os
from keri.core import coring, scheming

OUT = os.environ.get("LAB_DIR", ".")
S = {"type": "string"}
def block(props, required):
    return {"type": "object", "properties": {"d": S, **props}, "required": ["d"] + required, "additionalProperties": False}

authority = {
    "$id": "", "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Accreditor Authority", "description": "A regulator authorises a party to accredit clinics.",
    "type": "object", "credentialType": "AccreditorAuthority", "version": "1.0.0",
    "properties": {"v": S, "d": S, "u": S, "i": S, "ri": S, "s": S,
                   "a": {"oneOf": [S, block({"u": S, "i": S, "dt": {"type": "string", "format": "date-time"}, "scope": S}, ["i", "dt", "scope"])]}},
    "required": ["v", "d", "i", "ri", "s", "a"], "additionalProperties": False}

edge = block({"authority": {"type": "object", "properties": {"n": S, "s": S, "o": S}, "required": ["n", "s"], "additionalProperties": False}}, ["authority"])
rules = block({"disclaimer": {"type": "object", "properties": {"l": S}, "required": ["l"], "additionalProperties": False}}, ["disclaimer"])
chained = {
    "$id": "", "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Chained Clinic Accreditation", "description": "A clinic is accredited, under a regulator's authority.",
    "type": "object", "credentialType": "ChainedClinicAccreditation", "version": "1.0.0",
    "properties": {"v": S, "d": S, "u": S, "i": S, "ri": S, "s": S,
                   "a": {"oneOf": [S, block({"u": S, "i": S, "dt": {"type": "string", "format": "date-time"}, "clinicName": S, "status": S}, ["i", "dt", "clinicName", "status"])]},
                   "e": {"oneOf": [S, edge]}, "r": {"oneOf": [S, rules]}},
    "required": ["v", "d", "i", "ri", "s", "a", "e", "r"], "additionalProperties": False}

done = {}
for name, sch in (("authority", authority), ("chained", chained)):
    _, sch = coring.Saider.saidify(sad=sch, label="$id")
    done[name] = sch
    assert scheming.Schemer(sed=sch).said == sch["$id"]
    json.dump(sch, open(os.path.join(OUT, f"{name}-schema.json"), "w"), indent=1)
    print(f'{name:9} schema SAID: {sch["$id"]}')

# ---- what the edge schema does and does not pin (printed only; the files above are what Lab 14b imports)
import copy
from keri.vc import proving
authority, chained = done["authority"], done["chained"]
print("\n### edges: a loose edge schema versus one that pins the parent")
pinned = copy.deepcopy(chained)
pe = pinned["properties"]["e"]["oneOf"][1]["properties"]["authority"]
pe["properties"]["s"] = {"type": "string", "const": authority["$id"]}       # the parent MUST use this schema
pe["properties"]["o"] = {"type": "string", "const": "I2I"}                 # and the operator MUST be I2I
pe["required"] = ["n", "s", "o"]
pinned["$id"] = ""
_, pinned = coring.Saider.saidify(sad=pinned, label="$id")
loose_s, pinned_s = scheming.Schemer(sed=chained), scheming.Schemer(sed=pinned)
print(f"  pinned schema SAID: {pinned['$id']}  (a different schema, so a different name)")

def cred(sch, edge):
    e = {"d": "", "authority": edge}; _, e = coring.Saider.saidify(sad=e, label="d")
    r = {"d": "", "disclaimer": {"l": "Accreditation reflects the review date only."}}; _, r = coring.Saider.saidify(sad=r, label="d")
    return proving.credential(schema=sch["$id"], issuer="EDPrbne4nB8tNzlROw7E_tSDzs0F16uSvfU54pAVKP3x",
                              recipient="EC1DiBo8iPLsHJdd-3sX0CCvtG0kD5tGTBQCg6tR-8qM",
                              status="EHN5T1lYXEMhIWqnq3Q_yVcYGd0OFZnKcXj3ESdyQ6wU",
                              data=dict(clinicName="Riverside Family Clinic", status="accredited"), source=e, rules=r).sad

def judge(sch, schemer, label, edge):
    raw = json.dumps(cred(sch, edge)).encode()
    try:
        schemer.verify(raw); print(f"  {label:58}: valid")
    except Exception as ex:
        print(f"  {label:58}: INVALID, {str(ex).splitlines()[0].replace('Credential validation exception: ', '')[:60]}")

parent = "EAxrd91kGeIIS6mBhhOSGwci1-jWMMH6WjoNtZNpTO4H"
right = {"n": parent, "s": authority["$id"], "o": "I2I"}
wrong = {"n": parent, "s": "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao", "o": "I2I"}   # some other schema
noop  = {"n": parent, "s": authority["$id"], "o": "NI2I"}
for sch, schemer, name in ((chained, loose_s, "loose "), (pinned, pinned_s, "pinned")):
    judge(sch, schemer, f"{name}: edge to an Accreditor Authority, I2I", right)
    judge(sch, schemer, f"{name}: edge to a parent of some OTHER schema", wrong)
    judge(sch, schemer, f"{name}: edge with the operator weakened to NI2I", noop)
