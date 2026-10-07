#!/usr/bin/env python3
"""Lab 12a: build a schema and an ACDC by hand with keripy's own primitives. No witnesses needed.
Writes clinic-schema.json (a SAIDified schema) into the lab directory for Lab 12b to import."""
import copy, json, os
from keri.core import coring, scheming, serdering
from keri.vc import proving

OUT = os.environ.get("LAB_DIR", ".")

schema = {
    "$id": "", "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Clinic Accreditation", "description": "A clinic has passed its accreditation review.",
    "type": "object", "credentialType": "ClinicAccreditation", "version": "1.0.0",
    "properties": {
        "v": {"type": "string"}, "d": {"type": "string"}, "u": {"type": "string"}, "i": {"type": "string"},
        "ri": {"type": "string"}, "s": {"description": "schema SAID", "type": "string"},
        "a": {"oneOf": [
            {"description": "attribute block SAID", "type": "string"},
            {"type": "object",
             "properties": {"d": {"type": "string"}, "i": {"type": "string"},
                            "dt": {"type": "string", "format": "date-time"},
                            "clinicName": {"type": "string"}, "status": {"type": "string"}},
             "required": ["d", "i", "dt", "clinicName", "status"], "additionalProperties": False}]}},
    "required": ["v", "d", "i", "ri", "s", "a"], "additionalProperties": False}

print("### 1. the schema names itself: its $id is its own SAID")
_, schema = coring.Saider.saidify(sad=schema, label="$id")
print("schema $id :", schema["$id"])
sch = scheming.Schemer(sed=schema)
print("Schemer says:", sch.said, "(same)" if sch.said == schema["$id"] else "(DIFFERENT)")
json.dump(schema, open(os.path.join(OUT, "clinic-schema.json"), "w"), indent=1)

print("\n### 2. an ACDC: issuer, registry, schema, and an attribute block that has its OWN SAID")
issuer = "EDPrbne4nB8tNzlROw7E_tSDzs0F16uSvfU54pAVKP3x"
holder = "EC1DiBo8iPLsHJdd-3sX0CCvtG0kD5tGTBQCg6tR-8qM"
registry = "EHN5T1lYXEMhIWqnq3Q_yVcYGd0OFZnKcXj3ESdyQ6wU"      # a stand-in; registries are Chapter 13
creder = proving.credential(schema=sch.said, issuer=issuer, recipient=holder, status=registry,
                            data=dict(clinicName="Riverside Family Clinic", status="accredited"))
sad = creder.sad
print(json.dumps(sad, indent=1))
print("size on the wire:", len(creder.raw), "bytes; version string:", sad["v"])

print("\n### 3. three SAIDs, three different jobs")
print("schema SAID     :", sad["s"], " <- names the rules")
print("attributes SAID :", sad["a"]["d"], " <- names the claims")
print("credential SAID :", sad["d"], " <- names the whole thing")

print("\n### 4. tamper with one claim, at each level")
def check(label, s):
    try:
        serdering.SerderACDC(sad=copy.deepcopy(s), verify=True); print(f"  {label}: ACCEPTED")
    except Exception as e:
        print(f"  {label}: REJECTED ({type(e).__name__})")
check("untouched credential          ", sad)
bad = copy.deepcopy(sad); bad["a"]["status"] = "revoked-by-mallory"
check("status edited inside a        ", bad)
bad2 = copy.deepcopy(sad); bad2["a"]["clinicName"] = "Mallory Medical"     # a.d left as it was
check("clinicName edited, a.d kept   ", bad2)
a = copy.deepcopy(sad["a"]); s1 = coring.Saider(sad=a, label="d")
print("  the attribute block checks out on its own :", s1.verify(sad=a, prefixed=True, label="d"))
a["status"] = "x"
print("  ...and fails once a claim is edited       :", s1.verify(sad=a, prefixed=True, label="d"))

print("\n### 5. the compact form: replace the attribute block with its SAID")
comp = copy.deepcopy(sad); comp["a"] = sad["a"]["d"]
print("a =", comp["a"])
check("compact form, original SAID kept ", comp)
c2 = serdering.SerderACDC(sad=copy.deepcopy(comp), makify=True)
print("  a compact form, SAID-ified on its own, gets a NEW credential SAID:", c2.said)
print("  the original, expanded, SAID                                    :", sad["d"])

print("\n### 6. a schema is checked like everything else: tamper with it and its $id gives it away")
tampered = copy.deepcopy(schema); tampered["description"] = "A clinic has paid for its accreditation review."
try:
    scheming.Schemer(raw=json.dumps(tampered).encode()); print("  tampered schema: ACCEPTED")
except Exception as e:
    print(f"  tampered schema, original $id kept: REJECTED ({type(e).__name__})")

print("\n### 7. the schema checks the credential's SHAPE: one credential at a time")
def against(label, data=None, a_compact=False, extra_top=None):
    c = proving.credential(schema=sch.said, issuer=issuer, recipient=holder, status=registry,
                           data=data if data is not None else dict(clinicName="Riverside Family Clinic", status="accredited"))
    sad = copy.deepcopy(c.sad)
    if a_compact: sad["a"] = sad["a"]["d"]
    if extra_top: sad.update(extra_top)
    try:
        ok = sch.verify(json.dumps(sad).encode())
        print(f"  {label:46}: {'valid' if ok else 'INVALID'}")
    except Exception as e:                       # keripy raises with jsonschema's reason as the first line
        why = str(e).split("\n")[0].replace("Credential validation exception: ", "")
        print(f"  {label:46}: INVALID, {why}")
against("the credential as issued")
against("the compact form, a is just its SAID", a_compact=True)
against("a claim missing (no status)", data=dict(clinicName="Riverside Family Clinic"))
against("a claim of the wrong type (status is a number)", data=dict(clinicName="Riverside Family Clinic", status=7))
against("a claim the schema never mentions", data=dict(clinicName="Riverside Family Clinic", status="accredited", beds=40))
against("an edge block the schema does not allow", extra_top={"e": {}})
