#!/usr/bin/env python3
"""Lab 16b: fetch GLEIF's real vLEI credential schemas, check each one names itself, and read the chain they encode.
Needs network access to raw.githubusercontent.com. Saves the files under $LAB_DIR/vlei-schemas/."""
import json, os, subprocess
from keri.core import coring, scheming

BASE = "https://raw.githubusercontent.com/WebOfTrust/vLEI/main/schema/acdc/"
FILES = ["qualified-vLEI-issuer-vLEI-credential", "legal-entity-vLEI-credential", "oor-authorization-vlei-credential",
         "legal-entity-official-organizational-role-vLEI-credential", "ecr-authorization-vlei-credential",
         "legal-entity-engagement-context-role-vLEI-credential"]
OUT = os.path.join(os.environ.get("LAB_DIR", "."), "vlei-schemas"); os.makedirs(OUT, exist_ok=True)

def obj(x):
    for y in x.get("oneOf", [x]):
        if y.get("type") == "object": return y
    return x

print("### 1. fetch the six credential schemas from GLEIF's public repository")
schemas = {}
for f in FILES:
    dest = os.path.join(OUT, f + ".json")
    try:
        data = subprocess.run(["curl", "-sfL", "-m", "30", BASE + f + ".json"], capture_output=True, check=True).stdout; open(dest, "wb").write(data)
    except Exception as e:
        if not os.path.exists(dest): print("  cannot fetch", f, type(e).__name__, "(and no saved copy)"); continue
    schemas[f] = json.load(open(dest))
print(f"  {len(schemas)} schemas in {OUT}")

print("\n### 2. does each schema's $id equal its own SAID?")
for f, d in schemas.items():
    ok = scheming.Schemer(sed=d).said == d["$id"]
    print(f"  {'yes' if ok else 'NO ':3} {d['$id'][:16]}...  {d['title']}")

print("\n### 3. the chain the schemas encode: each edge pins the SAID of its parent's schema")
by_id = {d["$id"]: d["title"] for d in schemas.values()}
for f, d in schemas.items():
    edges = obj(d["properties"]["e"]).get("properties", {}) if "e" in d["properties"] else {}
    parents = []
    for label, node in edges.items():
        if label == "d": continue
        n = obj(node); props = n.get("properties", {})
        sid = props.get("s", {}).get("const"); op = props.get("o", {}).get("const")
        parents.append(f"edge '{label}' -> {by_id.get(sid, sid)}" + (f"  [operator {op}]" if op else ""))
    print(f"  {d['title']}")
    print("      " + ("; ".join(parents) if parents else "no edge: issued directly from the root's authority"))

print("\n### 4. what each credential says about its subject (required attribute fields)")
for f, d in schemas.items():
    a = obj(d["properties"]["a"]); req = [x for x in a.get("required", []) if x not in ("i", "dt")]
    print(f"  {d['title'][:52]:52} {req}")

print("\n### 5. the rules block: real vLEI wording, bound by a SAID that must be recomputed after any edit")
path = os.path.join(os.environ.get("LAB_DIR", "."), "keripy", "scripts", "demo", "data", "ecr-auth-rules.json")
try:
    rules = json.load(open(path)); stated = rules["d"]
    _, fresh = coring.Saider.saidify(sad=dict(rules, d=""), label="d")
    print("  fields               :", [k for k in rules if k != "d"])
    print("  d as stored in file  :", stated[:20] + "...")
    print("  d recomputed         :", fresh["d"][:20] + "...", "(MATCH)" if fresh["d"] == stated else "(DIFFERENT: the stored value is stale)")
    print("  usageDisclaimer begins:", rules["usageDisclaimer"]["l"][:70] + "...")
except OSError:
    print("  (keripy checkout not found)")
